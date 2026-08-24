from typing import Any, Final

import pytest

pytest.importorskip("boto3")
pytest.importorskip("aws_encryption_sdk")

from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

from pydantic_encryption.adapters.encryption import aws
from pydantic_encryption.adapters.encryption.aws import (
    DATA_KEY_MAX_AGE_SECONDS,
    DATA_KEY_MAX_BYTES,
    DATA_KEY_MAX_USES,
    MATERIALS_CACHE_SIZE,
    AWSAdapter,
    botocore_session,
    ciphertext_bytes,
    crypto_client,
    crypto_materials,
    kms_key_ids,
)
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue
from tests.unit.aws_offline import offline_key_provider

TEST_REGION: Final[str] = "us-east-1"
TEST_KEY_ARN: Final[str] = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"


class CountingCache(LocalCryptoMaterialsCache):
    """Materials cache that records how many fresh data keys the adapter had to have wrapped."""

    def __init__(self, capacity: int) -> None:
        """Start with no recorded data keys."""

        super().__init__(capacity=capacity)  # pyright: ignore[reportCallIssue]

        self.data_keys_generated = 0

    def put_encryption_materials(self, *args: Any, **kwargs: Any) -> Any:
        """Count each newly generated data key as it enters the cache."""

        self.data_keys_generated += 1

        return super().put_encryption_materials(*args, **kwargs)


@pytest.fixture
def kms_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the adapter at a configured KMS key without letting it reach the service."""

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", TEST_KEY_ARN)
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", TEST_REGION)
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "testing")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "testing")

    AWSAdapter.reset_cache()


@pytest.fixture
def offline_materials(monkeypatch: pytest.MonkeyPatch) -> CountingCache:
    """Point the adapter at an offline materials manager so no KMS call is made."""

    cache = CountingCache(capacity=MATERIALS_CACHE_SIZE)
    manager = CachingCryptoMaterialsManager(
        cache=cache,  # pyright: ignore[reportCallIssue]
        max_age=DATA_KEY_MAX_AGE_SECONDS,  # pyright: ignore[reportCallIssue]
        max_messages_encrypted=DATA_KEY_MAX_USES,  # pyright: ignore[reportCallIssue]
        max_bytes_encrypted=DATA_KEY_MAX_BYTES,  # pyright: ignore[reportCallIssue]
        master_key_provider=offline_key_provider(),  # pyright: ignore[reportCallIssue]
    )

    def _offline_materials() -> CachingCryptoMaterialsManager:
        """Stand in for the KMS-backed materials manager."""

        return manager

    monkeypatch.setattr(aws, "crypto_materials", _offline_materials)

    return cache


class TestAWSAdapter:
    """Test envelope encryption through the Encryption SDK's caching materials manager."""

    def test_round_trip(self, offline_materials: CountingCache) -> None:
        """Test that a value survives an encrypt and decrypt unchanged."""

        ciphertext = AWSAdapter.encrypt("secret value")

        assert isinstance(ciphertext, EncryptedValue)
        assert AWSAdapter.decrypt(ciphertext) == "secret value"

    def test_already_encrypted_value_passes_through(self, offline_materials: CountingCache) -> None:
        """Test that re-encrypting a ciphertext returns it untouched."""

        ciphertext = AWSAdapter.encrypt("secret value")

        assert AWSAdapter.encrypt(ciphertext) is ciphertext

    def test_one_data_key_serves_many_values(self, offline_materials: CountingCache) -> None:
        """Test that encrypting repeatedly reuses a cached data key instead of minting one each time."""

        for index in range(25):
            AWSAdapter.encrypt(f"value {index}")

        assert offline_materials.data_keys_generated == 1

    def test_every_value_decrypts_independently(self, offline_materials: CountingCache) -> None:
        """Test that values sharing one cached data key each decrypt to their own plaintext."""

        values = [f"value {index}" for index in range(10)]
        ciphertexts = [AWSAdapter.encrypt(value) for value in values]

        assert [AWSAdapter.decrypt(ciphertext) for ciphertext in ciphertexts] == values

    def test_session_carries_the_configured_region(self, kms_settings: None) -> None:
        """Test that the botocore session is built with the configured region and credentials."""

        session = botocore_session()

        assert session.get_config_variable("region") == TEST_REGION
        assert session.get_credentials().access_key == "testing"

    def test_materials_manager_is_built_once(self, kms_settings: None) -> None:
        """Test that the materials manager is built from settings and reused by later calls."""

        materials = crypto_materials()

        assert isinstance(materials, CachingCryptoMaterialsManager)
        assert crypto_materials() is materials

    def test_client_is_reused(self, kms_settings: None) -> None:
        """Test that one Encryption SDK client serves every call in the process."""

        assert crypto_client() is crypto_client()

    def test_reset_drops_the_cached_manager(self, kms_settings: None) -> None:
        """Test that resetting forces the next call to rebuild from current settings."""

        materials = crypto_materials()
        client = crypto_client()

        AWSAdapter.reset_cache()

        assert crypto_materials() is not materials
        assert crypto_client() is not client

    @pytest.mark.parametrize(
        ("arns", "expected"),
        [
            ({"AWS_KMS_KEY_ARN": "arn:shared"}, ["arn:shared"]),
            (
                {"AWS_KMS_ENCRYPT_KEY_ARN": "arn:encrypt", "AWS_KMS_DECRYPT_KEY_ARN": "arn:decrypt"},
                ["arn:encrypt", "arn:decrypt"],
            ),
            ({"AWS_KMS_DECRYPT_KEY_ARN": "arn:decrypt"}, ["arn:decrypt"]),
        ],
        ids=["shared_key", "split_keys", "decrypt_only"],
    )
    def test_key_ids_resolve_from_settings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        arns: dict[str, str],
        expected: list[str],
    ) -> None:
        """Test that the configured ARNs decide which keys the provider is built with."""

        for name in ("AWS_KMS_KEY_ARN", "AWS_KMS_ENCRYPT_KEY_ARN", "AWS_KMS_DECRYPT_KEY_ARN"):
            monkeypatch.setattr(settings, name, arns.get(name))

        assert kms_key_ids() == expected

    def test_missing_key_arn_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that building the provider without any key ARN reports the missing configuration."""

        for name in ("AWS_KMS_KEY_ARN", "AWS_KMS_ENCRYPT_KEY_ARN", "AWS_KMS_DECRYPT_KEY_ARN"):
            monkeypatch.setattr(settings, name, None)

        with pytest.raises(ValueError, match="at least one key ARN"):
            kms_key_ids()

    def test_missing_credentials_are_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that building a session without region or credentials reports what is missing."""

        monkeypatch.setattr(settings, "AWS_KMS_REGION", None)

        with pytest.raises(ValueError, match="AWS_KMS_REGION"):
            botocore_session()

    def test_bytes_coercion_preserves_every_byte(self) -> None:
        """Test that string ciphertext round-trips to bytes without altering any byte value."""

        raw = bytes(range(256))

        assert ciphertext_bytes(raw.decode("latin-1")) == raw
