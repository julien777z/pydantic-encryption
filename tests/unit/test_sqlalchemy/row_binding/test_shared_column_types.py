import pytest
from sqlalchemy import Integer, MetaData, Table
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from tests.unit.test_sqlalchemy.utils import column_type_of


class TestSharedColumnTypes:
    """Test what one encrypted type does when more than one column reaches for it."""

    def test_one_type_refuses_a_second_column(self):
        """Test that a type already bound to a column refuses to rebind what that column wrote."""

        shared = SQLAlchemyEncryptedValue()

        class SharedBase(DeclarativeBase):
            """Isolated declarative base for the shared-type test."""

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

    def test_copied_type_derives_own_context(self):
        """Test that copying a table re-derives the copy's context and its statement cache key."""

        class CopiedBase(DeclarativeBase):
            """Isolated declarative base for the copied-table test."""

        class Original(CopiedBase):
            """Mapped class whose table is copied to another name."""

            __tablename__ = "originals"

            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            secret: Mapped[bytes | None] = mapped_column(
                SQLAlchemyEncryptedValue(), nullable=True, default=None
            )

        table = Original.__table__

        assert isinstance(table, Table)

        source_cache_key = column_type_of(table.c.secret, SQLAlchemyEncryptedValue)._static_cache_key
        copied = column_type_of(
            table.to_metadata(MetaData(), name="copies").c.secret, SQLAlchemyEncryptedValue
        )

        assert copied.context == b"copies.secret"
        assert copied._static_cache_key != source_cache_key
