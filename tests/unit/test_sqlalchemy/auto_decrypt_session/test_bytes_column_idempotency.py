import asyncio

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import configure_mappers

from pydantic_encryption.integrations.sqlalchemy.bulk import collect_encrypted_cells
from pydantic_encryption.types import EncryptedValue
from tests.unit.test_sqlalchemy.utils import encrypt_through_column
from tests.unit.test_sqlalchemy.tables import AutoDecryptBlob


class TestBytesColumnIdempotency:
    """Regression test that BYTES-typed columns do not double-decrypt under repeated load events."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_collect_skips_already_decrypted_bytes_plaintext(self):
        """Test that a decrypted bytes column is not collected for decryption again."""

        blob = AutoDecryptBlob(
            id=1, payload=encrypt_through_column(AutoDecryptBlob.__table__.c.payload, b"shh")
        )

        asyncio.run(AutoDecryptBlob.decrypt_many([blob]))

        assert sa_inspect(blob).dict["payload"] == b"shh"
        assert not isinstance(sa_inspect(blob).dict["payload"], EncryptedValue)

        collected: dict[tuple[type[object], str], list[object]] = {}
        visited: set[int] = set()
        collect_encrypted_cells(blob, collected, visited)

        assert collected == {}
