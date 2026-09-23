import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import Integer, String, inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, configure_mappers, mapped_column

from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin
from pydantic_encryption.integrations.sqlalchemy.deferred import install_descriptors
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue


class DescriptorBase(DeclarativeBase):
    """Isolated declarative base for the descriptor-installation tests."""


class MixedColumns(DescriptorBase, DeferredDecryptMixin):
    """Mapped class carrying one encrypted column beside one that is not."""

    __tablename__ = "mixed_columns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


@pytest.fixture(autouse=True)
def configured_mappers():
    """Configure the mappers, which is what installs the descriptors on the mapped classes."""

    configure_mappers()


class TestInstallDescriptors:
    """Test which class attributes the deferred read path takes over."""

    def test_only_encrypted_columns_are_wrapped(self):
        """Test that a column storing plaintext keeps the attribute SQLAlchemy gave it."""

        assert isinstance(MixedColumns.__dict__["secret"], DecryptOnAccessDescriptor)
        assert not isinstance(MixedColumns.__dict__.get("name"), DecryptOnAccessDescriptor)

    def test_installing_twice_keeps_the_first_descriptor(self):
        """Test that configuring a mapper again does not wrap an already wrapped attribute."""

        installed = MixedColumns.__dict__["secret"]

        install_descriptors(inspect(MixedColumns), MixedColumns)

        assert MixedColumns.__dict__["secret"] is installed

    def test_a_column_the_class_does_not_expose_is_skipped(self):
        """Test that a column with no class attribute to wrap is passed over."""

        class Detached:
            """Class carrying none of the mapped attributes the columns name."""

        install_descriptors(inspect(MixedColumns), Detached)

        assert "secret" not in Detached.__dict__

    def test_a_class_that_refuses_assignment_is_skipped(self):
        """Test that a class whose attributes cannot be set is left as it is."""

        class Sealed(type):
            """Metaclass refusing every attribute assignment on its classes."""

            def __setattr__(cls, name: str, value: object) -> None:
                raise AttributeError(name)

        class Immutable(metaclass=Sealed):
            """Class whose attributes cannot be reassigned."""

            secret = "sealed"

        install_descriptors(inspect(MixedColumns), Immutable)

        assert Immutable.__dict__["secret"] == "sealed"
