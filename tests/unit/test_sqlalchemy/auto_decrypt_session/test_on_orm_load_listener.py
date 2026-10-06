from sqlalchemy.orm import Session, make_transient_to_detached

from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from tests.unit.test_sqlalchemy.tables import AutoDecryptBlob, AutoDecryptUser


class TestOnOrmLoadListener:
    """Test that loading an instance collects it into its session's pending-decrypt bucket."""

    def test_collects_into_session_bucket(self, sqlite_session: Session):
        """Test that a queried instance joins its session's pending-decrypt bucket."""

        sqlite_session.add(AutoDecryptUser(id=1))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        loaded = sqlite_session.get(AutoDecryptUser, 1)

        assert loaded in sqlite_session.info[PENDING_DECRYPT_KEY][AutoDecryptUser]

    def test_load_without_query_ignored(self, sqlite_session: Session):
        """Test that an instance loaded outside a query, as a merge without load is, starts no bucket."""

        detached = AutoDecryptUser(id=1)
        make_transient_to_detached(detached)

        sqlite_session.merge(detached, load=False)

        assert PENDING_DECRYPT_KEY not in sqlite_session.info

    def test_groups_by_class(self, sqlite_session: Session):
        """Test that the bucket groups loaded instances by their mapped class."""

        sqlite_session.add_all([AutoDecryptUser(id=1), AutoDecryptUser(id=2), AutoDecryptBlob(id=1)])
        sqlite_session.commit()
        sqlite_session.expunge_all()

        users = sqlite_session.query(AutoDecryptUser).all()
        blob = sqlite_session.get(AutoDecryptBlob, 1)
        bucket = sqlite_session.info[PENDING_DECRYPT_KEY]

        assert set(bucket[AutoDecryptUser]) == set(users)
        assert set(bucket[AutoDecryptBlob]) == {blob}

    def test_repeated_loads_tracked_once(self, sqlite_session: Session):
        """Test that refreshing one instance repeatedly tracks it once."""

        sqlite_session.add(AutoDecryptUser(id=1))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        loaded = sqlite_session.get(AutoDecryptUser, 1)
        sqlite_session.refresh(loaded)
        sqlite_session.refresh(loaded)

        assert len(sqlite_session.info[PENDING_DECRYPT_KEY][AutoDecryptUser]) == 1
