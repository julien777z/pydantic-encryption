import boto3
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import CreateAwsKmsKeyringInput
from pydantic_encryption.config import settings

kms_client = boto3.client(
    "kms",
    region_name=settings.AWS_KMS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

client = aws_encryption_sdk.EncryptionSDKClient(
    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
)


mat_prov = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())

keyring_input = CreateAwsKmsKeyringInput(
    kms_key_id=settings.AWS_KMS_KEY_ARN,
    kms_client=kms_client,
)

kms_keyring = mat_prov.create_aws_kms_keyring(input=keyring_input)


def aws_encrypt(data: bytes) -> bytes:
    """Encrypt data using AWS KMS."""

    ciphertext, _ = client.encrypt(
        source=data,
        keyring=kms_keyring,
    )

    return ciphertext


def aws_decrypt(data: bytes) -> str:
    """Decrypt data using AWS KMS."""

    plaintext, _ = client.decrypt(
        source=data,
        keyring=kms_keyring,
    )

    return plaintext.decode("utf-8")
