import os
from typing import Final

from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

PROVIDER_ID: Final[str] = "pydantic-encryption-tests"
KEY_ID: Final[bytes] = b"static-test-key"
WRAPPING_KEY: Final[bytes] = os.urandom(32)


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    """Offline key provider standing in for KMS, wrapping every data key with one static key."""

    provider_id = PROVIDER_ID  # pyright: ignore[reportAssignmentType]

    def _get_raw_key(self, key_id: bytes) -> WrappingKey:  # pyright: ignore[reportIncompatibleMethodOverride]
        """Return the single symmetric wrapping key backing every key id."""

        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=WRAPPING_KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def offline_key_provider() -> StaticRawMasterKeyProvider:
    """Return a key provider already holding the static wrapping key."""

    provider = StaticRawMasterKeyProvider()
    provider.add_master_key(KEY_ID)

    return provider
