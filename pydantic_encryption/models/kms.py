from pydantic import BaseModel, Field
from typing_extensions import NotRequired, TypedDict


class GeneratedDataKey(TypedDict):
    """The fields read from a KMS ``GenerateDataKey`` response."""

    Plaintext: bytes
    CiphertextBlob: bytes


class DataKeyGenerateRequest(TypedDict):
    """Keyword arguments for a KMS ``GenerateDataKey`` call minting one data key."""

    KeyId: str
    KeySpec: str


class DataKeyDecryptRequest(TypedDict):
    """Keyword arguments for a KMS ``Decrypt`` call unwrapping one data key."""

    CiphertextBlob: bytes
    KeyId: NotRequired[str]


class DataKey(BaseModel):
    """A KMS data key held in memory, with how far its reuse has gone."""

    plaintext: bytes = Field(repr=False)
    wrapped: bytes = Field(repr=False)
    issued_at: float
    uses: int = 0

    def is_spent(self, max_uses: int, max_age_seconds: float, now: float) -> bool:
        """Return whether this key has exhausted either of its reuse bounds."""

        return self.uses >= max_uses or now - self.issued_at >= max_age_seconds


class UnwrappedDataKey(BaseModel):
    """A data key KMS has unwrapped for this process, kept until it expires."""

    plaintext: bytes = Field(repr=False)
    unwrapped_at: float

    def has_expired(self, max_age_seconds: float, now: float) -> bool:
        """Return whether this unwrapped key has outlived its retention."""

        return now - self.unwrapped_at >= max_age_seconds
