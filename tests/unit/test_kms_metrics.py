import json
import logging
import re
import threading
from typing import Any, Final

import pytest

pytest.importorskip("boto3")
pytest.importorskip("aws_encryption_sdk")

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

from pydantic_encryption.adapters.encryption.kms_metrics import (
    KMS_ROUND_TRIP_LOG_PREFIX,
    KmsRoundTrip,
    KmsRoundTripRecord,
    MeteredMaterialsCache,
    key_reference,
)
from tests.unit.aws_offline import KEY_ID, StaticRawMasterKeyProvider, offline_key_provider

CACHE_CAPACITY: Final[int] = 16
UNBOUNDED_MESSAGES: Final[int] = 1_000_000
UNBOUNDED_BYTES: Final[int] = 2**30
CACHE_LIFETIME_SECONDS: Final[float] = 60.0
BARRIER_TIMEOUT_SECONDS: Final[float] = 10.0
KEY_REFERENCE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{8}")


class GatedMeteredCache(MeteredMaterialsCache):
    """Metered cache holding every fresh data key outside the cache until its peers arrive."""

    def __init__(self, capacity: int, barrier: threading.Barrier) -> None:
        """Start gated on the barrier every newly generated data key has to pass."""

        super().__init__(capacity=capacity)

        self.barrier = barrier

    def put_encryption_materials(
        self,
        cache_key: bytes,
        encryption_materials: Any,
        plaintext_length: int,
        entry_hints: Any = None,
    ) -> Any:
        """Hold the round trip open until every other caller has one open too."""

        self.barrier.wait(timeout=BARRIER_TIMEOUT_SECONDS)

        return super().put_encryption_materials(
            cache_key, encryption_materials, plaintext_length, entry_hints
        )


def round_trip_records(caplog: pytest.LogCaptureFixture) -> list[KmsRoundTripRecord]:
    """Return the round trips reported during a captured run, oldest first."""

    return [
        json.loads(record.getMessage().removeprefix(KMS_ROUND_TRIP_LOG_PREFIX))
        for record in caplog.records
        if record.getMessage().startswith(KMS_ROUND_TRIP_LOG_PREFIX)
    ]


def caching_manager(
    cache: MeteredMaterialsCache, provider: StaticRawMasterKeyProvider
) -> CachingCryptoMaterialsManager:
    """Build a caching materials manager over one cache and one offline key provider."""

    return CachingCryptoMaterialsManager(
        cache=cache,  # pyright: ignore[reportCallIssue]
        max_age=CACHE_LIFETIME_SECONDS,  # pyright: ignore[reportCallIssue]
        max_messages_encrypted=UNBOUNDED_MESSAGES,  # pyright: ignore[reportCallIssue]
        max_bytes_encrypted=UNBOUNDED_BYTES,  # pyright: ignore[reportCallIssue]
        master_key_provider=provider,  # pyright: ignore[reportCallIssue]
    )


@pytest.fixture
def metered_cache() -> MeteredMaterialsCache:
    """Return a metered cache with room for every data key a test mints."""

    return MeteredMaterialsCache(capacity=CACHE_CAPACITY)


@pytest.fixture
def crypto_client() -> aws_encryption_sdk.EncryptionSDKClient:
    """Return an Encryption SDK client requiring key commitment on both paths."""

    return aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )


class TestMeteredMaterialsCache:
    """Test that the cache reports the KMS round trips its misses force, and only those."""

    def test_generating_a_data_key(
        self,
        caplog: pytest.LogCaptureFixture,
        metered_cache: MeteredMaterialsCache,
        crypto_client: aws_encryption_sdk.EncryptionSDKClient,
    ) -> None:
        """Test that a first encrypt reports one round trip carrying a positive elapsed time."""

        materials = caching_manager(metered_cache, offline_key_provider())

        with caplog.at_level(logging.INFO):
            crypto_client.encrypt(source=b"a value", materials_manager=materials)

        records = round_trip_records(caplog)

        assert len(records) == 1
        assert records[0]["round_trip"] == KmsRoundTrip.GENERATE.value
        assert records[0]["elapsed_seconds"] > 0

    def test_a_reused_data_key_is_silent(
        self,
        caplog: pytest.LogCaptureFixture,
        metered_cache: MeteredMaterialsCache,
        crypto_client: aws_encryption_sdk.EncryptionSDKClient,
    ) -> None:
        """Test that encrypts served from the cache report no round trip at all."""

        materials = caching_manager(metered_cache, offline_key_provider())
        crypto_client.encrypt(source=b"first value", materials_manager=materials)

        with caplog.at_level(logging.INFO):
            for index in range(10):
                crypto_client.encrypt(source=f"value {index}".encode(), materials_manager=materials)

        assert round_trip_records(caplog) == []

    def test_unwrapping_a_data_key(
        self,
        caplog: pytest.LogCaptureFixture,
        crypto_client: aws_encryption_sdk.EncryptionSDKClient,
    ) -> None:
        """Test that decrypting against a cold cache reports one unwrap round trip."""

        provider = offline_key_provider()
        ciphertext, _header = crypto_client.encrypt(
            source=b"a value",
            materials_manager=caching_manager(MeteredMaterialsCache(capacity=CACHE_CAPACITY), provider),
        )
        cold_materials = caching_manager(MeteredMaterialsCache(capacity=CACHE_CAPACITY), provider)

        with caplog.at_level(logging.INFO):
            crypto_client.decrypt(source=ciphertext, materials_manager=cold_materials)

        records = round_trip_records(caplog)

        assert len(records) == 1
        assert records[0]["round_trip"] == KmsRoundTrip.UNWRAP.value

    def test_the_key_reference_is_a_digest(
        self,
        caplog: pytest.LogCaptureFixture,
        metered_cache: MeteredMaterialsCache,
        crypto_client: aws_encryption_sdk.EncryptionSDKClient,
    ) -> None:
        """Test that a reported round trip names a short digest rather than its cache key."""

        materials = caching_manager(metered_cache, offline_key_provider())

        with caplog.at_level(logging.INFO):
            crypto_client.encrypt(source=b"a value", materials_manager=materials)

        reported = round_trip_records(caplog)[0]["key_reference"]

        assert KEY_REFERENCE_PATTERN.fullmatch(reported)


class TestKeyReference:
    """Test the non-reversible reference a reported round trip names its cache key by."""

    def test_distinct_keys_get_distinct_references(self) -> None:
        """Test that two cache keys are told apart by the references reported for them."""

        assert key_reference(KEY_ID) != key_reference(KEY_ID + b"-other")

    def test_a_reference_reveals_no_cache_key(self) -> None:
        """Test that a reference is a fixed-length digest carrying none of the key it came from."""

        reference = key_reference(KEY_ID)

        assert KEY_REFERENCE_PATTERN.fullmatch(reference)
        assert KEY_ID.hex() not in reference

    def test_materials_arriving_without_a_miss(
        self,
        caplog: pytest.LogCaptureFixture,
        metered_cache: MeteredMaterialsCache,
    ) -> None:
        """Test that materials landing in the cache without a miss behind them report nothing."""

        with caplog.at_level(logging.INFO):
            metered_cache.finish_round_trip(KmsRoundTrip.UNWRAP, KEY_ID)

        assert round_trip_records(caplog) == []

    def test_concurrent_misses_report_their_overlap(
        self,
        caplog: pytest.LogCaptureFixture,
        crypto_client: aws_encryption_sdk.EncryptionSDKClient,
    ) -> None:
        """Test that data keys wrapped at the same time report a concurrency above one."""

        wrappers = 3
        cache = GatedMeteredCache(capacity=CACHE_CAPACITY, barrier=threading.Barrier(wrappers))
        managers = [caching_manager(cache, offline_key_provider()) for _ in range(wrappers)]

        with caplog.at_level(logging.INFO):
            threads = [
                threading.Thread(
                    target=crypto_client.encrypt,
                    kwargs={"source": b"a value", "materials_manager": manager},
                )
                for manager in managers
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join(timeout=BARRIER_TIMEOUT_SECONDS)

        concurrency = [record["concurrent_round_trips"] for record in round_trip_records(caplog)]

        assert len(concurrency) == wrappers
        assert max(concurrency) > 1
