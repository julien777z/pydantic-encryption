from typing import NotRequired, TypedDict

from botocore.config import Config
from pydantic import BaseModel, Field


class KMSClientOptions(TypedDict):
    """Keyword arguments for the boto3 KMS client: its region, credentials and transport bounds."""

    region_name: str
    aws_access_key_id: str
    aws_secret_access_key: str
    config: Config


class GeneratedDataKey(TypedDict):
    """The fields read from a KMS ``GenerateDataKey`` response."""

    Plaintext: bytes
    CiphertextBlob: bytes


class DecryptedDataKey(TypedDict):
    """The field read from a KMS ``Decrypt`` response unwrapping one data key."""

    Plaintext: bytes


class DataKeyGenerateRequest(TypedDict):
    """Keyword arguments for a KMS ``GenerateDataKey`` call minting one data key."""

    KeyId: str
    KeySpec: str


class DataKeyDecryptRequest(TypedDict):
    """Keyword arguments for a KMS ``Decrypt`` call unwrapping one data key."""

    CiphertextBlob: bytes
    KeyId: NotRequired[str]


class HeldDataKey(BaseModel):
    """A plaintext data key held in memory until it expires."""

    plaintext: bytes = Field(repr=False)
    expires_at: float

    def has_expired(self, now: float) -> bool:
        """Return whether this key has reached the end of its lifetime."""

        return now >= self.expires_at


class DataKey(HeldDataKey):
    """A KMS data key sealing values, with how many more values it may seal."""

    wrapped: bytes = Field(repr=False)
    uses_left: int
