import pytest
from sqlalchemy import Integer, MetaData, Table
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic_encryption.context import derive_column_context
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
    encrypted_column_type,
)
from pydantic_encryption.serialization import EncryptableValue
from pydantic_encryption.types import EncryptedValue
from tests.unit.test_sqlalchemy.tables import (
    ArchivedEntry,
    ArrayRow,
    ContextBase,
    ContextRecord,
    ContextUser,
    Member,
    Organization,
    PublicEntry,
)
from tests.unit.test_sqlalchemy.utils import column_type_of


class TestEncryptedColumnTypes:
    """Test how encrypted column types bind their cells to a context and process the values they hold."""

    @pytest.mark.parametrize(
        ("column", "expected"),
        [
            (ContextUser.__table__.c.email, b"context_users.email"),
            (ContextUser.__table__.c.secret, b"context_users.secret"),
            (ContextRecord.__table__.c.secret, b"context_records.secret"),
            (ContextUser.__table__.c.envelope, b"records.draft"),
            (ArchivedEntry.__table__.c.note, b"archive.entries.note"),
        ],
        ids=["column", "mixin-first-table", "mixin-second-table", "declared", "schema"],
    )
    def test_column_context(self, column: object, expected: bytes):
        """Test that a column binds to its table and column, or keeps the context it declared."""

        assert column_type_of(column, SQLAlchemyEncryptedValue).context == expected

    @pytest.mark.parametrize(
        ("column", "expected"),
        [
            (ContextUser.__table__.c.tags, b"context_users.tags"),
            (ContextUser.__table__.c.aliases, b"context_users.aliases"),
            (ContextRecord.__table__.c.aliases, b"context_records.aliases"),
            (ArchivedEntry.__table__.c.tags, b"archive.entries.tags"),
        ],
        ids=["column", "mixin-first-table", "mixin-second-table", "schema"],
    )
    def test_array_elements_follow_column_context(self, column: object, expected: bytes):
        """Test that an encrypted array and every element it holds bind to the array column's context."""

        column_type = column_type_of(column, SQLAlchemyPGEncryptedArray)

        assert column_type.context == expected
        assert column_type.element_type.context == expected

    def test_mixin_array_gets_element_type_per_table(self):
        """Test that an inherited array column gives each table an element type of its own."""

        user_type = column_type_of(ContextUser.__table__.c.aliases, SQLAlchemyPGEncryptedArray)
        record_type = column_type_of(ContextRecord.__table__.c.aliases, SQLAlchemyPGEncryptedArray)

        assert user_type.element_type is not record_type.element_type

    @pytest.mark.parametrize(
        ("mapped_class", "table", "schema"),
        [
            (ArchivedEntry, "entries", "archive"),
            (PublicEntry, "entries", "public"),
            (ContextUser, "context_users", None),
        ],
        ids=["archive", "public", "unqualified"],
    )
    def test_helper_matches_derived_context(
        self, mapped_class: type[ContextBase], table: str, schema: str | None
    ):
        """Test that the documented helper names the context a column derives itself."""

        column_name = "email" if schema is None else "note"
        column_type = column_type_of(mapped_class.__table__.c[column_name], SQLAlchemyEncryptedValue)

        assert column_type.context == derive_column_context(table, column_name, schema=schema)

    def test_detached_type_refused(self):
        """Test that a type attached to no column refuses to encrypt rather than binding nothing."""

        with pytest.raises(ValueError, match="attached to no column"):
            SQLAlchemyEncryptedValue().encrypt_cell("secret data")

    @pytest.mark.parametrize(
        ("column", "context"),
        [
            (Member.__table__.c.first_name, b"members.first_name"),
            (ArrayRow.__table__.c.tags, b"array_rows.tags"),
        ],
        ids=["value", "array"],
    )
    def test_encrypted_column_type_found(self, column: object, context: bytes):
        """Test that an encrypted column, scalar or array, reports the type binding its context."""

        assert encrypted_column_type(column).bound_context() == context

    def test_plain_column_type_refused(self):
        """Test that a column that stores plaintext binds no context and raises instead."""

        with pytest.raises(ValueError, match="does not encrypt its values"):
            encrypted_column_type(Organization.__table__.c.name)

    def test_row_bound_column_refuses_one_context(self):
        """Test that asking a row-bound column for a single context raises rather than binding the column."""

        with pytest.raises(ValueError, match="binds each row separately"):
            SQLAlchemyEncryptedValue("users.secret", row_bound=True).bound_context()

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            (
                SQLAlchemyEncryptedValue("users.secret"),
                SQLAlchemyEncryptedValue("users.secret", row_bound=True),
            ),
            (SQLAlchemyPGEncryptedArray("users.tags"), SQLAlchemyPGEncryptedArray("records.tags")),
        ],
        ids=["row-binding", "array-context"],
    )
    def test_cache_key_distinguishes_bindings(self, first: object, second: object):
        """Test that types binding differently never share a statement cache key."""

        assert first._static_cache_key != second._static_cache_key

    def test_one_type_refuses_second_column(self):
        """Test that a type already bound to a column refuses to rebind what that column wrote."""

        shared = SQLAlchemyEncryptedValue()

        class SharedBase(DeclarativeBase):
            """Declarative base for the shared-type case."""

        class FirstOwner(SharedBase):
            """Mapped class claiming the shared type first."""

            __tablename__ = "first_owners"

            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            secret: Mapped[bytes | None] = mapped_column(shared, nullable=True, default=None)

        with pytest.raises(ValueError, match="already bound to"):

            class SecondOwner(SharedBase):
                """Mapped class reaching for a type another column already owns."""

                __tablename__ = "second_owners"

                id: Mapped[int] = mapped_column(Integer, primary_key=True)
                secret: Mapped[bytes | None] = mapped_column(shared, nullable=True, default=None)

    def test_copied_table_derives_own_context(self):
        """Test that copying a table re-derives the copy's context and its statement cache key."""

        table = Organization.__table__

        assert isinstance(table, Table)

        source_cache_key = column_type_of(table.c.secret, SQLAlchemyEncryptedValue)._static_cache_key
        copied = column_type_of(
            table.to_metadata(MetaData(), name="copies").c.secret, SQLAlchemyEncryptedValue
        )

        assert copied.context == b"copies.secret"
        assert copied._static_cache_key != source_cache_key

    @pytest.mark.parametrize("bind", [False, True], ids=["encrypt-cell", "bind"])
    def test_ciphertext_passes_through(self, sqlite_dialect: Dialect, bind: bool):
        """Test that encrypting or binding an existing ciphertext stores it unchanged."""

        column_type = SQLAlchemyEncryptedValue("tests.records.secret")
        sealed = column_type.encrypt_cell("secret data")

        if bind:
            assert column_type.process_bind_param(EncryptedValue(sealed), sqlite_dialect) == sealed
        else:
            assert column_type.encrypt_cell(sealed) is sealed

    def test_none_cell_stays_none(self):
        """Test that encrypting or decrypting None returns None."""

        column_type = SQLAlchemyEncryptedValue("tests.records.secret")

        assert column_type.encrypt_cell(None) is None
        assert column_type.decrypt_cell(None) is None

    @pytest.mark.parametrize(
        ("column_type", "python_type"),
        [
            (SQLAlchemyEncryptedValue("tests.records.secret"), bytes),
            (SQLAlchemyPGEncryptedArray("tests.records.tags"), list),
        ],
        ids=["value", "array"],
    )
    def test_python_type(self, column_type: object, python_type: type):
        """Test that each column type reports the Python type its values are stored as."""

        assert column_type.python_type is python_type

    @pytest.mark.parametrize("value", [None, []], ids=["none", "empty"])
    def test_empty_array_binds_unchanged(
        self, sqlite_dialect: Dialect, value: list[EncryptableValue | None] | None
    ):
        """Test that None and an empty list bind as themselves."""

        assert (
            SQLAlchemyPGEncryptedArray("tests.records.tags").process_bind_param(value, sqlite_dialect)
            == value
        )

    @pytest.mark.parametrize("value", [None, [], [None, None]], ids=["none", "empty", "none-elements"])
    def test_empty_array_reads_unchanged(self, sqlite_dialect: Dialect, value: list[bytes | None] | None):
        """Test that None, an empty list and empty elements read back as themselves."""

        assert (
            SQLAlchemyPGEncryptedArray("tests.records.tags").process_result_value(value, sqlite_dialect)
            == value
        )

    def test_array_elements_round_trip(self, sqlite_dialect: Dialect):
        """Test that an array's elements are each sealed on bind and opened on read."""

        column_type = SQLAlchemyPGEncryptedArray("tests.records.tags")
        bound = column_type.process_bind_param(["first", None, "second"], sqlite_dialect)

        assert bound is not None
        assert isinstance(bound[0], EncryptedValue)
        assert column_type.process_result_value(bound, sqlite_dialect) == ["first", None, "second"]
