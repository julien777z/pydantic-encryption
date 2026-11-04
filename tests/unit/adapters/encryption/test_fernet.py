import base64

import pytest
from cryptography.fernet import InvalidToken

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter, derive_context_key
from pydantic_encryption.config import settings
from tests.cases import FOREIGN_CONTEXT, PLAINTEXT_IDS, PLAINTEXTS, SEALED_CONTEXT
from tests.unit.utils import ASYNC_PATHS, call_path


@pytest.mark.asyncio
class TestFernetAdapter:
    """Test Fernet encryption under a key derived for each bound context."""

    @ASYNC_PATHS
    @pytest.mark.parametrize("plaintext", [*PLAINTEXTS, b"secret bytes"], ids=[*PLAINTEXT_IDS, "bytes"])
    async def test_round_trip(self, fernet_key: str, asynchronous: bool, plaintext: str | bytes):
        """Test that a value opens back to its text under the context it was sealed with."""

        sealed = await call_path(
            asynchronous,
            FernetAdapter.encrypt,
            FernetAdapter.async_encrypt,
            plaintext,
            key=fernet_key,
            associated_data=SEALED_CONTEXT,
        )
        expected = plaintext.decode("utf-8") if isinstance(plaintext, bytes) else plaintext

        assert (
            await call_path(
                asynchronous,
                FernetAdapter.decrypt,
                FernetAdapter.async_decrypt,
                sealed,
                key=fernet_key,
                associated_data=SEALED_CONTEXT,
            )
            == expected
        )

    @ASYNC_PATHS
    async def test_sync_and_async_ciphertexts_interchange(self, fernet_key: str, asynchronous: bool):
        """Test that a value sealed through one path opens through the other."""

        sealed = await call_path(
            asynchronous,
            FernetAdapter.encrypt,
            FernetAdapter.async_encrypt,
            "secret data",
            key=fernet_key,
            associated_data=SEALED_CONTEXT,
        )

        assert (
            await call_path(
                not asynchronous,
                FernetAdapter.decrypt,
                FernetAdapter.async_decrypt,
                sealed,
                key=fernet_key,
                associated_data=SEALED_CONTEXT,
            )
            == "secret data"
        )

    @ASYNC_PATHS
    async def test_foreign_context_refused(self, fernet_key: str, asynchronous: bool):
        """Test that a value lifted into another context fails to open there."""

        sealed = await call_path(
            asynchronous,
            FernetAdapter.encrypt,
            FernetAdapter.async_encrypt,
            "secret data",
            key=fernet_key,
            associated_data=SEALED_CONTEXT,
        )

        with pytest.raises(InvalidToken):
            await call_path(
                asynchronous,
                FernetAdapter.decrypt,
                FernetAdapter.async_decrypt,
                sealed,
                key=fernet_key,
                associated_data=FOREIGN_CONTEXT,
            )

    @ASYNC_PATHS
    async def test_ciphertext_passes_through(self, fernet_key: str, asynchronous: bool):
        """Test that sealing an existing ciphertext returns it unchanged."""

        sealed = await call_path(
            asynchronous,
            FernetAdapter.encrypt,
            FernetAdapter.async_encrypt,
            "secret data",
            key=fernet_key,
            associated_data=SEALED_CONTEXT,
        )

        assert (
            await call_path(
                asynchronous,
                FernetAdapter.encrypt,
                FernetAdapter.async_encrypt,
                sealed,
                key=fernet_key,
                associated_data=SEALED_CONTEXT,
            )
            is sealed
        )

    @ASYNC_PATHS
    async def test_missing_root_key_refused(self, monkeypatch: pytest.MonkeyPatch, asynchronous: bool):
        """Test that sealing raises when neither an explicit key nor ENCRYPTION_KEY is set."""

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)

        with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
            await call_path(
                asynchronous,
                FernetAdapter.encrypt,
                FernetAdapter.async_encrypt,
                "secret data",
                key=None,
                associated_data=SEALED_CONTEXT,
            )

    @pytest.mark.parametrize(
        "root_key",
        ["sample-root-key", "c2hvcnQ=", "!" * 44],
        ids=["passphrase", "short", "not-base64"],
    )
    @ASYNC_PATHS
    async def test_weak_root_key_refused(self, asynchronous: bool, root_key: str):
        """Test that a root key that is not a Fernet key is refused before any key is derived."""

        with pytest.raises(ValueError, match="must be 32 url-safe base64-encoded bytes"):
            await call_path(
                asynchronous,
                FernetAdapter.encrypt,
                FernetAdapter.async_encrypt,
                "secret data",
                key=root_key,
                associated_data=SEALED_CONTEXT,
            )

    async def test_each_context_derives_own_key(self, fernet_key: str):
        """Test that one root key derives a stable, different key for each context."""

        first = derive_context_key(fernet_key, SEALED_CONTEXT)

        assert first == derive_context_key(fernet_key, SEALED_CONTEXT)
        assert first != derive_context_key(fernet_key, FOREIGN_CONTEXT)

    async def test_context_key_derived_from_decoded_root_key(self):
        """Test that a context's key is derived from the root key's decoded bytes, which stored tokens pin."""

        root_key = base64.urlsafe_b64encode(bytes(32)).decode()

        assert derive_context_key(root_key, SEALED_CONTEXT) == b"AsDVitAdPHhdZT87qf4tNDaZuPZ_YKxFsTKzCor3PRs="
