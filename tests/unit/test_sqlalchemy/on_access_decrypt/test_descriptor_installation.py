from sqlalchemy import inspect as sa_inspect, select
from sqlalchemy.orm import configure_mappers

from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from tests.factories import User
from tests.unit.test_sqlalchemy.tables import OnAccessRow


class TestDescriptorInstallation:
    """Test that the on-access descriptor is installed on every encrypted column."""

    @classmethod
    def setup_class(cls):
        """Configure mappers before running tests in this class."""

        configure_mappers()

    def test_encrypted_columns_wrapped_in_descriptor(self):
        """Test that each encrypted column is wrapped in the on-access descriptor."""

        for column_key in ("first_name", "last_name"):
            descriptor = OnAccessRow.__dict__[column_key]

            assert isinstance(descriptor, DecryptOnAccessDescriptor)

    def test_non_encrypted_columns_untouched(self):
        """Test that non-encrypted columns keep their default SA attribute."""

        assert not isinstance(OnAccessRow.__dict__["id"], DecryptOnAccessDescriptor)

    def test_class_level_access_returns_instrumented_attribute(self):
        """Test that class-level attribute access returns the SA InstrumentedAttribute."""

        attr = OnAccessRow.first_name

        assert not isinstance(attr, DecryptOnAccessDescriptor)
        assert hasattr(attr, "key")
        assert attr.key == "first_name"

    def test_orm_query_expressions_still_work(self, user: User):
        """Test that ORM query expressions still compile against encrypted columns."""

        stmt = select(OnAccessRow).where(OnAccessRow.first_name == user.first_name)

        compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        assert "first_name" in compiled

    def test_descriptor_set_delegates_to_wrapped(self, user: User):
        """Test that assigning through the descriptor stores on SA state."""

        row = OnAccessRow(id=user.id)

        row.first_name = user.first_name

        assert sa_inspect(row).dict["first_name"] == user.first_name

    def test_descriptor_delete_delegates_to_wrapped(self, user: User):
        """Test that deleting through the descriptor removes the column from SA state."""

        row = OnAccessRow.from_user(user)

        del row.first_name

        assert "first_name" not in sa_inspect(row).dict

    def test_descriptor_exposes_wrapped_key(self):
        """Test that the descriptor exposes the wrapped attribute's column key."""

        descriptor = OnAccessRow.__dict__["first_name"]

        assert descriptor.key == "first_name"
