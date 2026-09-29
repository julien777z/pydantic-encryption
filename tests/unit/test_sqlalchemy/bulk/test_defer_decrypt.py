from sqlalchemy.engine import Dialect
from sqlalchemy.orm import configure_mappers

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue
from tests.unit.test_sqlalchemy.tables import DeferMixed, DeferPlain
from tests.unit.test_sqlalchemy.utils import column_type_of


class TestDeferDecrypt:
    """Test that DeferredDecryptMixin defers encrypted columns on the read path."""

    @classmethod
    def setup_class(cls):
        """Configure the mappers, which marks the mixed-in columns deferred."""

        configure_mappers()

    def test_mixin_column_reads_ciphertext(self, sqlite_dialect: Dialect):
        """Test that a column of a mixed-in class reads back as undecrypted ciphertext."""

        column_type = column_type_of(DeferMixed.__table__.c.secret, SQLAlchemyEncryptedValue)
        ciphertext = column_type.process_bind_param("hello", sqlite_dialect)

        assert column_type._deferred is True
        assert ciphertext is not None

        result = column_type.process_result_value(ciphertext, sqlite_dialect)

        assert isinstance(result, EncryptedValue)
        assert result != "hello"

    def test_mixin_column_reads_none(self, sqlite_dialect: Dialect):
        """Test that a mixed-in column reads a stored None as None."""

        column_type = column_type_of(DeferMixed.__table__.c.secret, SQLAlchemyEncryptedValue)

        assert column_type.process_result_value(None, sqlite_dialect) is None

    def test_plain_column_reads_plaintext(self, sqlite_dialect: Dialect):
        """Test that a column of a class without the mixin decrypts on read."""

        column_type = column_type_of(DeferPlain.__table__.c.secret, SQLAlchemyEncryptedValue)
        ciphertext = column_type.process_bind_param("hello", sqlite_dialect)

        assert column_type._deferred is False
        assert column_type.process_result_value(ciphertext, sqlite_dialect) == "hello"
