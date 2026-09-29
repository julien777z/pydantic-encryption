from sqlalchemy import inspect
from sqlalchemy.orm import Session, configure_mappers

from pydantic_encryption.integrations.sqlalchemy.deferred import install_descriptors
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from tests.unit.test_sqlalchemy.tables import MixedColumns, RenamedColumnRow


class TestInstallDescriptors:
    """Test which class attributes the deferred read path takes over."""

    @classmethod
    def setup_class(cls):
        """Configure the mappers, which installs the descriptors on the mapped classes."""

        configure_mappers()

    def test_only_encrypted_columns_wrapped(self):
        """Test that a column storing plaintext keeps the attribute SQLAlchemy gave it."""

        assert isinstance(MixedColumns.__dict__["secret"], DecryptOnAccessDescriptor)
        assert not isinstance(MixedColumns.__dict__.get("name"), DecryptOnAccessDescriptor)

    def test_second_install_keeps_descriptor(self):
        """Test that installing again does not wrap an already wrapped attribute."""

        installed = MixedColumns.__dict__["secret"]

        install_descriptors(inspect(MixedColumns), MixedColumns)

        assert MixedColumns.__dict__["secret"] is installed

    def test_renamed_column_wrapped(self):
        """Test that an attribute stored under another column name is wrapped under its attribute name."""

        assert isinstance(RenamedColumnRow.__dict__["secret"], DecryptOnAccessDescriptor)

    def test_renamed_column_decrypts_on_read(self, sqlite_session: Session):
        """Test that reading an attribute stored under another column name returns its plaintext."""

        sqlite_session.add(RenamedColumnRow(id=1, secret="sealed value"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        row = sqlite_session.get(RenamedColumnRow, 1)

        assert row is not None
        assert row.secret == "sealed value"
