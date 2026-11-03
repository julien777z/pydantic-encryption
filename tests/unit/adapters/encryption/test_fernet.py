import pytest
from cryptography.fernet import InvalidToken

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter, derive_context_key
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue
from tests.cases import FOREIGN_CONTEXT, PLAINTEXT_IDS, PLAINTEXTS, SEALED_CONTEXT


async def seal(
    plaintext: str | bytes | EncryptedValue, key: str | None, asynchronous: bool
) -> EncryptedValue:
    """Seal a value under the shared context through the sync or async path."""

    if asynchronous:
        return await FernetAdapter.async_encrypt(plaintext, key=key, associated_data=SEALED_CONTEXT)

    return FernetAdapter.encrypt(plaintext, key=key, associated_data=SEALED_CONTEXT)


async def open_sealed(ciphertext: EncryptedValue, key: str, context: bytes, asynchronous: bool) -> str:
    """Open a value through the sync or async path."""

    if asynchronous:
        return await FernetAdapter.async_decrypt(ciphertext, key=key, associated_data=context)

    return FernetAdapter.decrypt(ciphertext, key=key, associated_data=context)


@pytest.mark.asyncio
class TestFernetAdapter:
    """Test Fernet encryption under a key derived for each bound context."""

    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    @pytest.mark.parametrize("plaintext", [*PLAINTEXTS, b"secret bytes"], ids=[*PLAINTEXT_IDS, "bytes"])
    async def test_round_trip(self, fernet_key: str, asynchronous: bool, plaintext: str | bytes):
        """Test that a value opens back to its text under the context it was sealed with."""

        sealed = await seal(plaintext, fernet_key, asynchronous)
        expected = plaintext.decode("utf-8") if isinstance(plaintext, bytes) else plaintext

        assert await open_sealed(sealed, fernet_key, SEALED_CONTEXT, asynchronous) == expected

    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_sync_and_async_ciphertexts_interchange(self, fernet_key: str, asynchronous: bool):
        """Test that a value sealed through one path opens through the other."""

        sealed = await seal("secret data", fernet_key, asynchronous)

        assert await open_sealed(sealed, fernet_key, SEALED_CONTEXT, not asynchronous) == "secret data"

    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_foreign_context_refused(self, fernet_key: str, asynchronous: bool):
        """Test that a value lifted into another context fails to open there."""

        sealed = await seal("secret data", fernet_key, asynchronous)

        with pytest.raises(InvalidToken):
            await open_sealed(sealed, fernet_key, FOREIGN_CONTEXT, asynchronous)

    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_ciphertext_passes_through(self, fernet_key: str, asynchronous: bool):
        """Test that sealing an existing ciphertext returns it unchanged."""

        sealed = await seal("secret data", fernet_key, asynchronous)

        assert await seal(sealed, fernet_key, asynchronous) is sealed

    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_missing_root_key_refused(self, monkeypatch: pytest.MonkeyPatch, asynchronous: bool):
        """Test that sealing raises when neither an explicit key nor ENCRYPTION_KEY is set."""

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)

        with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
            await seal("secret data", None, asynchronous)

    @pytest.mark.parametrize(
        "root_key",
        ["sample-root-key", "c2hvcnQ=", "!" * 44],
        ids=["passphrase", "short", "not-base64"],
    )
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_weak_root_key_refused(self, asynchronous: bool, root_key: str):
        """Test that a root key that is not a Fernet key is refused before any key is derived."""

        with pytest.raises(ValueError, match="must be 32 url-safe base64-encoded bytes"):
            await seal("secret data", root_key, asynchronous)

    async def test_each_context_derives_own_key(self, fernet_key: str):
        """Test that one root key derives a stable, different key for each context."""

        first = derive_context_key(fernet_key, SEALED_CONTEXT)

        assert first == derive_context_key(fernet_key, SEALED_CONTEXT)
        assert first != derive_context_key(fernet_key, FOREIGN_CONTEXT)
