import pytest
from sqlalchemy.orm import Session

from tests.unit.test_sqlalchemy.tables import ExpressionKeyedRow


class TestRowBoundPrimaryKeyDefaults:
    """Test which primary-key defaults can name a row before the insert that stores it."""

    def test_expression_default_key_refused(self, sqlite_session: Session):
        """Test that a key the database computes raises rather than naming the row by its expression."""

        sqlite_session.add(ExpressionKeyedRow(secret="secret data"))

        with pytest.raises(ValueError, match="defaults to a SQL expression"):
            sqlite_session.flush()
