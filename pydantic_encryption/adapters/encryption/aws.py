from typing import Any, ClassVar

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
from pydantic_encryption.types import DecryptedValue, EncryptedValue


class AWSAdapter:
    """Adapter for AWS KMS encryption."""

    _kms_client: ClassVar[Any | None] = None
    _encryption_client: ClassVar[Any | None] = None
    _mat_prov: ClassVar[Any | None] = None
    _keyring: ClassVar[Any | None] = None

    @classmethod
    def _get_clients(cls) -> tuple[Any, Any, Any, Any]:
        if cls._kms_client is None:
            if not (
                settings.AWS_KMS_KEY_ARN
                and settings.AWS_KMS_REGION
                and settings.AWS_ACCESS_KEY_ID
                and settings.AWS_SECRET_ACCESS_KEY
            ):
                raise ValueError(
                    "AWS KMS requires AWS_KMS_KEY_ARN, AWS_KMS_REGION, "
                    "AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY to be set."
                )

            cls._kms_client = boto3.client(
                "kms",
                region_name=settings.AWS_KMS_REGION,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )

        if cls._encryption_client is None:
            cls._encryption_client = aws_encryption_sdk.EncryptionSDKClient(
                commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
            )

        if cls._mat_prov is None:
            cls._mat_prov = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())

        if cls._keyring is None:
            keyring_input = CreateAwsKmsKeyringInput(
                kms_key_id=settings.AWS_KMS_KEY_ARN,
                kms_client=cls._kms_client,
            )
            cls._keyring = cls._mat_prov.create_aws_kms_keyring(input=keyring_input)

        return cls._kms_client, cls._encryption_client, cls._mat_prov, cls._keyring

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        _, encryption_client, _, keyring = cls._get_clients()

        ciphertext, _ = encryption_client.encrypt(
            source=plaintext,
            keyring=keyring,
        )

        return EncryptedValue(ciphertext)

    @classmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue) -> DecryptedValue:
        if isinstance(ciphertext, DecryptedValue):
            return ciphertext

        if isinstance(ciphertext, str):
            try:
                ciphertext_bytes = ciphertext.encode("utf-8")
            except UnicodeDecodeError:
                ciphertext_bytes = str(ciphertext)
        else:
            ciphertext_bytes = ciphertext

        _, encryption_client, _, keyring = cls._get_clients()

        plaintext, _ = encryption_client.decrypt(
            source=ciphertext_bytes,
            keyring=keyring,
        )

        return DecryptedValue(plaintext)
