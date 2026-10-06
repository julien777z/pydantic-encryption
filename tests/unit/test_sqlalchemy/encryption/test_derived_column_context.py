import pytest

from pydantic_encryption.context import derive_column_context
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from tests.unit.test_sqlalchemy.tables import (
    ArchivedEntry,
    ContextBase,
    ContextRecord,
    ContextUser,
    PublicEntry,
)
from tests.unit.test_sqlalchemy.utils import column_type_of


class TestDerivedColumnContext:
    """Test that an encrypted column binds its cells to the table and column it is attached to."""

    def test_column_derives_its_table_and_column(self):
        """Test that a column with no declared context names the schema it is attached to."""

        assert (
            column_type_of(ContextUser.__table__.c.email, SQLAlchemyEncryptedValue).context
            == b"context_users.email"
        )

    def test_array_column_derives_its_table_and_column(self):
        """Test that an encrypted array derives the context every element is bound to."""

        assert (
            column_type_of(ContextUser.__table__.c.tags, SQLAlchemyPGEncryptedArray).context
            == b"context_users.tags"
        )
        assert (
            column_type_of(ContextUser.__table__.c.tags, SQLAlchemyPGEncryptedArray)._element_type.context
            == b"context_users.tags"
        )

    def test_one_mixin_column_binds_each_table_separately(self):
        """Test that a column inherited from a mixin binds to each inheriting table's own name."""

        assert (
            column_type_of(ContextUser.__table__.c.secret, SQLAlchemyEncryptedValue).context
            == b"context_users.secret"
        )
        assert (
            column_type_of(ContextRecord.__table__.c.secret, SQLAlchemyEncryptedValue).context
            == b"context_records.secret"
        )

    def test_one_mixin_array_column_binds_each_table_separately(self):
        """Test that an inherited array column gives each table its own element type and context."""

        user_type = column_type_of(ContextUser.__table__.c.aliases, SQLAlchemyPGEncryptedArray)
        member_type = column_type_of(ContextRecord.__table__.c.aliases, SQLAlchemyPGEncryptedArray)

        assert user_type._element_type.context == b"context_users.aliases"
        assert member_type._element_type.context == b"context_records.aliases"
        assert user_type._element_type is not member_type._element_type

    def test_declared_context_survives_attachment(self):
        """Test that a column given a context keeps it rather than deriving one."""

        assert (
            column_type_of(ContextUser.__table__.c.envelope, SQLAlchemyEncryptedValue).context
            == b"records.draft"
        )

    def test_column_in_a_schema_derives_the_qualified_table(self):
        """Test that a column in a named schema binds to the schema-qualified table."""

        column_type = column_type_of(ArchivedEntry.__table__.c.note, SQLAlchemyEncryptedValue)

        assert column_type.context == b"archive.entries.note"

    def test_one_table_name_in_two_schemas_binds_separately(self):
        """Test that same-named columns in two schemas do not share one context."""

        secure_type = column_type_of(ArchivedEntry.__table__.c.note, SQLAlchemyEncryptedValue)
        public_type = column_type_of(PublicEntry.__table__.c.note, SQLAlchemyEncryptedValue)

        assert secure_type.context != public_type.context

    def test_array_elements_follow_the_column_context_exactly(self):
        """Test that an array's elements bind to the same context the array column binds to."""

        column_type = column_type_of(ArchivedEntry.__table__.c.tags, SQLAlchemyPGEncryptedArray)

        assert column_type._element_type.context == column_type.context
        assert column_type.context == b"archive.entries.tags"

    @pytest.mark.parametrize(
        "mapped_class, schema",
        [(ArchivedEntry, "archive"), (PublicEntry, "public")],
        ids=["archive", "public"],
    )
    def test_derive_column_context_matches_what_a_column_derives(
        self, mapped_class: type[ContextBase], schema: str
    ):
        """Test that the documented helper names the same context the column itself resolves."""

        column_type = column_type_of(mapped_class.__table__.c.note, SQLAlchemyEncryptedValue)

        assert column_type.context == derive_column_context("entries", "note", schema=schema)

    def test_derive_column_context_matches_an_unqualified_column(self):
        """Test that the helper names an unqualified column's context too."""

        column_type = column_type_of(ContextUser.__table__.c.email, SQLAlchemyEncryptedValue)

        assert column_type.context == derive_column_context("context_users", "email")

    def test_detached_type_without_a_context_raises(self):
        """Test that a type attached to no column refuses to encrypt rather than binding nothing."""

        with pytest.raises(ValueError, match="attached to no column"):
            SQLAlchemyEncryptedValue().encrypt_cell("secret")
