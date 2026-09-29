from collections import defaultdict
from weakref import WeakSet

from sqlalchemy.orm import Session

from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY, pending_siblings
from tests.factories import User
from tests.unit.test_sqlalchemy.tables import OnAccessRow


class TestPendingSiblings:
    """Test that pending_siblings extracts the bucket list for a given class."""

    def test_no_bucket_returns_empty(self):
        """Test that a session with no pending-decrypt bucket has no siblings."""

        assert pending_siblings(Session(), OnAccessRow) == []

    def test_returns_bucketed_instances(self, user: User, other_user: User):
        """Test that the instances bucketed for a class are returned."""

        row_a = OnAccessRow(id=user.id)
        row_b = OnAccessRow(id=other_user.id)
        bucket: defaultdict[type[object], WeakSet[object]] = defaultdict(WeakSet)
        bucket[OnAccessRow].add(row_a)
        bucket[OnAccessRow].add(row_b)
        session = Session()
        session.info[PENDING_DECRYPT_KEY] = bucket

        assert set(pending_siblings(session, OnAccessRow)) == {row_a, row_b}
