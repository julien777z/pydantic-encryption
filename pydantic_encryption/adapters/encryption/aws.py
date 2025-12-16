from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")
require_optional_dependency("aws_encryption_sdk", "aws")

import aws_encryption_sdk
import boto3
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import CreateAwsKmsKeyringInput
from aws_encryption_sdk import CommitmentPolicy

from pydantic_encryption.config import settings
from pydantic_encryption.types import DecryptedValue, EncryptedValue, EncryptionMethod

KMS_CLIENT = None
CLIENT = None
MAT_PROV = None
KMS_KEYRING = None


def _ensure_clients() -> None:
    """Initialize AWS encryption clients lazily and validate configuration."""
    global KMS_CLIENT, CLIENT, MAT_PROV, KMS_KEYRING

    if settings.ENCRYPTION_METHOD != EncryptionMethod.AWS:
        return

    if not (
        settings.AWS_KMS_KEY_ARN
        and settings.AWS_KMS_REGION
        and settings.AWS_ACCESS_KEY_ID
        and settings.AWS_SECRET_ACCESS_KEY
    ):
        raise ValueError(
            "AWS KMS settings are not configured. Please set AWS_KMS_KEY_ARN, AWS_KMS_REGION, "
            "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY."
        )

    if KMS_CLIENT is None:
        KMS_CLIENT = boto3.client(
            "kms",
            region_name=settings.AWS_KMS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )

    if CLIENT is None:
        CLIENT = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
        )

    if MAT_PROV is None:
        MAT_PROV = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())

    if KMS_KEYRING is None:
        keyring_input = CreateAwsKmsKeyringInput(
            kms_key_id=settings.AWS_KMS_KEY_ARN,
            kms_client=KMS_CLIENT,
        )
        KMS_KEYRING = MAT_PROV.create_aws_kms_keyring(input=keyring_input)


def _check_aws_encryption():
    _ensure_clients()

    if not (KMS_CLIENT and CLIENT and MAT_PROV and KMS_KEYRING):
        raise ValueError("AWS encryption is not available. Please install this package with the `aws` extra.")


def aws_encrypt(plaintext: bytes | str | EncryptedValue) -> EncryptedValue:
    """Encrypt data using AWS KMS."""

    _check_aws_encryption()

    if isinstance(plaintext, EncryptedValue):
        return plaintext

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    ciphertext, _ = CLIENT.encrypt(
        source=plaintext,
        keyring=KMS_KEYRING,
    )

    return EncryptedValue(ciphertext)


def aws_decrypt(ciphertext: bytes | str | EncryptedValue) -> DecryptedValue:
    """Decrypt data using AWS KMS."""
    _check_aws_encryption()

    if isinstance(ciphertext, DecryptedValue):
        return ciphertext

    if isinstance(ciphertext, str):
        try:
            ciphertext_bytes = ciphertext.encode("utf-8")
        except UnicodeDecodeError:
            ciphertext_bytes = str(ciphertext)
    else:
        ciphertext_bytes = ciphertext

    plaintext, _ = CLIENT.decrypt(
        source=ciphertext_bytes,
        keyring=KMS_KEYRING,
    )
    return DecryptedValue(plaintext)
