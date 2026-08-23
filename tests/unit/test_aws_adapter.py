import os
from typing import Any, Final

import pytest

pytest.importorskip("boto3")
pytest.importorskip("aws_encryption_sdk")

from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

from pydantic_encryption.adapters.encryption.aws import AWSAdapter, to_bytes
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue

PROVIDER_ID: Final[str] = "pydantic-encryption-tests"
KEY_ID: Final[bytes] = b"static-test-key"
WRAPPING_KEY: Final[bytes] = os.urandom(32)
TEST_REGION: Final[str] = "us-east-1"
TEST_KEY_ARN: Final[str] = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    """Offline key provider standing in for KMS, counting how often a data key is wrapped."""

    provider_id = PROVIDER_ID  # pyright: ignore[reportAssignmentType]

    def _get_raw_key(self, key_id: bytes) -> WrappingKey:  # pyright: ignore[reportIncompatibleMethodOverride]
        """Return the single symmetric wrapping key backing every key id."""

        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=WRAPPING_KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


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
    monkeypatch.setattr(AWSAdapter, "materials_manager", None)
    monkeypatch.setattr(AWSAdapter, "client", None)


@pytest.fixture
def offline_materials(monkeypatch: pytest.MonkeyPatch) -> CountingCache:
    """Point the adapter at an offline materials manager so no KMS call is made."""

    provider = StaticRawMasterKeyProvider()
    provider.add_master_key(KEY_ID)
    cache = CountingCache(capacity=settings.KMS_MATERIALS_CACHE_SIZE)

    monkeypatch.setattr(
        AWSAdapter,
        "materials_manager",
        CachingCryptoMaterialsManager(
            cache=cache,  # pyright: ignore[reportCallIssue]
            max_age=float(settings.KMS_DATA_KEY_MAX_AGE_SECONDS),  # pyright: ignore[reportCallIssue]
            max_messages_encrypted=settings.KMS_DATA_KEY_MAX_USES,  # pyright: ignore[reportCallIssue]
            max_bytes_encrypted=settings.KMS_DATA_KEY_MAX_BYTES,  # pyright: ignore[reportCallIssue]
            master_key_provider=provider,  # pyright: ignore[reportCallIssue]
        ),
    )
    monkeypatch.setattr(AWSAdapter, "client", None)

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

        session = AWSAdapter.botocore_session()

        assert session.get_config_variable("region") == TEST_REGION
        assert session.get_credentials().access_key == "testing"

    def test_materials_manager_is_built_once(self, kms_settings: None) -> None:
        """Test that the materials manager is built from settings and reused by later calls."""

        materials = AWSAdapter.crypto_materials()

        assert isinstance(materials, CachingCryptoMaterialsManager)
        assert AWSAdapter.crypto_materials() is materials

    def test_client_is_reused(self, kms_settings: None) -> None:
        """Test that one Encryption SDK client serves every call in the process."""

        assert AWSAdapter.crypto_client() is AWSAdapter.crypto_client()

    def test_reset_drops_the_cached_manager(self, kms_settings: None) -> None:
        """Test that resetting forces the next call to rebuild from current settings."""

        materials = AWSAdapter.crypto_materials()

        AWSAdapter.reset_cache()

        assert AWSAdapter.materials_manager is None
        assert AWSAdapter.client is None
        assert AWSAdapter.crypto_materials() is not materials

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

        assert AWSAdapter.kms_key_ids() == expected

    def test_missing_key_arn_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that building the provider without any key ARN reports the missing configuration."""

        for name in ("AWS_KMS_KEY_ARN", "AWS_KMS_ENCRYPT_KEY_ARN", "AWS_KMS_DECRYPT_KEY_ARN"):
            monkeypatch.setattr(settings, name, None)

        with pytest.raises(ValueError, match="at least one key ARN"):
            AWSAdapter.kms_key_ids()

    def test_missing_credentials_are_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that building a session without region or credentials reports what is missing."""

        monkeypatch.setattr(settings, "AWS_KMS_REGION", None)

        with pytest.raises(ValueError, match="AWS_KMS_REGION"):
            AWSAdapter.botocore_session()

    def test_bytes_coercion_preserves_every_byte(self) -> None:
        """Test that string ciphertext round-trips to bytes without altering any byte value."""

        raw = bytes(range(256))

        assert to_bytes(raw.decode("latin-1")) == raw
