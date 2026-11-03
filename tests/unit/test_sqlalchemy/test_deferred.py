import uuid

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import CHAR, DateTime, Numeric, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.engine import Dialect
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, make_transient_to_detached, mapped_column
from sqlalchemy.types import TypeEngine

from pydantic_encryption.context import derive_row_context
from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin
from pydantic_encryption.integrations.sqlalchemy.deferred import install_descriptors
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY, read_raw_cell
from pydantic_encryption.serialization import decode_value
from pydantic_encryption.types import EncryptedValue
from tests.unit.test_sqlalchemy.tables import (
    ContextKeyedRow,
    ExpressionKeyedRow,
    Organization,
    PayloadRow,
    PlainSecretRow,
    RenamedColumnRow,
    RowBoundRecord,
    SecretRow,
    ServerKeyedRow,
    TextUuidKeyedRow,
    UndeferredRow,
)
from tests.unit.test_sqlalchemy.utils import column_type_of


class TestDeferredDecryptMixin:
    """Test the deferred read path and row binding the mixin installs on a mapped class."""

    @pytest.mark.parametrize(
        ("row_class", "deferred"), [(SecretRow, True), (PlainSecretRow, False)], ids=["mixin", "plain"]
    )
    def test_mixin_defers_decryption(
        self, sqlite_dialect: Dialect, row_class: type[SecretRow], deferred: bool
    ):
        """Test that a mixed-in class reads ciphertext back sealed while a plain class decrypts on read."""

        column_type = column_type_of(row_class.__table__.c.secret, SQLAlchemyEncryptedValue)
        ciphertext = column_type.process_bind_param("secret data", sqlite_dialect)
        result = column_type.process_result_value(ciphertext, sqlite_dialect)

        assert column_type.deferred is deferred
        assert isinstance(result, EncryptedValue) is deferred
        assert (result == "secret data") is not deferred
        assert column_type.process_result_value(None, sqlite_dialect) is None

    def test_only_encrypted_columns_wrapped(self):
        """Test that encrypted attributes, renamed or not, are wrapped while plain ones keep theirs."""

        assert isinstance(Organization.__dict__["secret"], DecryptOnAccessDescriptor)
        assert isinstance(RenamedColumnRow.__dict__["secret"], DecryptOnAccessDescriptor)
        assert not isinstance(Organization.__dict__["name"], DecryptOnAccessDescriptor)
        assert not isinstance(Organization.__dict__["id"], DecryptOnAccessDescriptor)

    def test_second_install_keeps_descriptor(self):
        """Test that installing again does not wrap an already wrapped attribute."""

        installed = Organization.__dict__["secret"]

        install_descriptors(sa_inspect(Organization), Organization)

        assert Organization.__dict__["secret"] is installed

    def test_load_collects_into_session_bucket(self, sqlite_session: Session):
        """Test that queried instances join their session's bucket once each, grouped by class."""

        sqlite_session.add_all([SecretRow(id=1), SecretRow(id=2), PayloadRow(id=1)])
        sqlite_session.commit()
        sqlite_session.expunge_all()

        rows = sqlite_session.query(SecretRow).all()
        payload = sqlite_session.get(PayloadRow, 1)
        sqlite_session.refresh(rows[0])
        sqlite_session.refresh(rows[0])
        bucket = sqlite_session.info[PENDING_DECRYPT_KEY]

        assert set(bucket[SecretRow]) == set(rows)
        assert len(bucket[SecretRow]) == 2
        assert set(bucket[PayloadRow]) == {payload}

    def test_load_without_query_ignored(self, sqlite_session: Session):
        """Test that an instance loaded outside a query, as a merge without load is, starts no bucket."""

        detached = SecretRow(id=1)
        make_transient_to_detached(detached)

        sqlite_session.merge(detached, load=False)

        assert PENDING_DECRYPT_KEY not in sqlite_session.info

    def test_row_bound_cell_opens_from_own_row(self, sqlite_session: Session):
        """Test that a row-bound cell is sealed under the context naming its row and reads back there."""

        record = RowBoundRecord(secret="secret data")
        sqlite_session.add(record)
        sqlite_session.commit()
        sqlite_session.refresh(record)

        cell = read_raw_cell(record, "secret")
        context = derive_row_context("row_bound_records", "secret", str(record.id), schema="main")
        column_type = column_type_of(RowBoundRecord.__table__.c.secret, SQLAlchemyEncryptedValue)
        sqlite_session.expunge_all()

        assert isinstance(cell, EncryptedValue)
        assert decode_value(column_type.decrypt_cell(cell, context=context)) == "secret data"
        assert sqlite_session.execute(select(RowBoundRecord)).scalar_one().secret == "secret data"

    def test_ciphertext_moved_to_another_row_refused(self, sqlite_session: Session):
        """Test that a cell carrying another row's ciphertext raises instead of decrypting."""

        first = RowBoundRecord(secret="first secret")
        second = RowBoundRecord(secret="second secret")
        sqlite_session.add_all([first, second])
        sqlite_session.commit()
        first_id, second_id = first.id, second.id
        sqlite_session.expunge_all()

        rows = {row.id: row for row in sqlite_session.execute(select(RowBoundRecord)).scalars()}
        stolen = read_raw_cell(rows[second_id], "secret")

        assert isinstance(stolen, EncryptedValue)

        sa_inspect(rows[first_id]).dict["secret"] = stolen

        with pytest.raises(InvalidToken):
            rows[first_id].secret

    def test_update_reseals_under_same_row(self, sqlite_session: Session):
        """Test that updating a row-bound cell keeps it readable from its own row."""

        record = RowBoundRecord(secret="first secret")
        sqlite_session.add(record)
        sqlite_session.commit()

        record.secret = "second secret"
        sqlite_session.commit()
        sqlite_session.expunge_all()

        assert sqlite_session.execute(select(RowBoundRecord)).scalar_one().secret == "second secret"

    @pytest.mark.parametrize("row_class", [RowBoundRecord, SecretRow], ids=["row-bound", "column-bound"])
    def test_empty_cell_stays_empty(self, sqlite_session: Session, row_class: type[SecretRow]):
        """Test that a cell holding nothing is stored and read back as nothing."""

        sqlite_session.add(row_class())
        sqlite_session.commit()
        sqlite_session.expunge_all()

        assert sqlite_session.execute(select(row_class)).scalar_one().secret is None

    def test_column_bound_row_round_trips(self, sqlite_session: Session):
        """Test that a mixed-in class with no row-bound column writes and reads as it otherwise would."""

        sqlite_session.add(SecretRow(secret="secret data"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        assert sqlite_session.execute(select(SecretRow)).scalar_one().secret == "secret data"

    def test_cell_follows_new_primary_key(self, sqlite_session: Session):
        """Test that changing a primary key re-seals the cells bound to the row it named."""

        sqlite_session.add(RowBoundRecord(secret="secret data"))
        sqlite_session.flush()
        sqlite_session.expunge_all()

        moved = sqlite_session.execute(select(RowBoundRecord)).scalar_one()
        moved.id = uuid.uuid4()
        sqlite_session.flush()
        moved_id = moved.id
        sqlite_session.expunge_all()

        reloaded = sqlite_session.get(RowBoundRecord, moved_id)

        assert reloaded is not None
        assert reloaded.secret == "secret data"

    @pytest.mark.parametrize("read_first", [False, True], ids=["sealed", "read"])
    def test_cell_untouched_when_key_kept(self, sqlite_session: Session, read_first: bool):
        """Test that updating another column leaves a cell's ciphertext as it was, read or not."""

        record = RowBoundRecord(secret="secret data", label="before")
        sqlite_session.add(record)
        sqlite_session.flush()
        record_id = record.id
        sqlite_session.expunge_all()

        stored = sqlite_session.get(RowBoundRecord, record_id)
        assert stored is not None
        sealed = read_raw_cell(stored, "secret")

        if read_first:
            assert stored.secret == "secret data"

        stored.label = "after"
        sqlite_session.flush()
        sqlite_session.expunge_all()

        reloaded = sqlite_session.get(RowBoundRecord, record_id)

        assert reloaded is not None
        assert reloaded.label == "after"
        assert read_raw_cell(reloaded, "secret") == sealed

    @pytest.mark.parametrize(
        ("row_class", "error", "message"),
        [
            (ExpressionKeyedRow, ValueError, "has no id yet"),
            (ContextKeyedRow, ValueError, "has no id yet"),
            (ServerKeyedRow, ValueError, "has no id yet"),
            (UndeferredRow, StatementError, "binds each row separately"),
        ],
        ids=["expression-key", "context-key", "server-key", "undeferred"],
    )
    def test_unnameable_row_refused(
        self, sqlite_session: Session, row_class: type[RowBoundRecord], error: type[Exception], message: str
    ):
        """Test that a row-bound cell raises where no row key exists before the insert that stores it."""

        sqlite_session.add(row_class(secret="secret data"))

        with pytest.raises(error, match=message):
            sqlite_session.flush()

    @pytest.mark.parametrize("spelling", [str.upper, lambda key: key.replace("-", "")], ids=["upper", "hex"])
    def test_uuid_key_spelling_ignored(self, sqlite_session: Session, spelling):
        """Test that a UUID key assigned in another spelling binds to the form the row reads back with."""

        key = str(uuid.uuid4())

        sqlite_session.add(TextUuidKeyedRow(id=spelling(key), secret="secret data"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        stored = sqlite_session.execute(select(TextUuidKeyedRow)).scalar_one()

        assert stored.id == key
        assert stored.secret == "secret data"

    @pytest.mark.parametrize(
        "key_type", [Numeric(10, 2), DateTime(timezone=True), CHAR(8)], ids=["numeric", "datetime", "char"]
    )
    def test_unreadable_key_type_refused(self, key_type: TypeEngine[object]):
        """Test that a row-bound mapping refuses a primary key whose values can read back changed."""

        class KeyTypeBase(DeclarativeBase):
            """Declarative base holding only the mapping under test."""

        class KeyTypeRow(KeyTypeBase, DeferredDecryptMixin):
            """Row-bound row keyed by the type under test."""

            __tablename__ = "key_type_rows"
            __table_args__ = {"schema": "main"}

            id: Mapped[object] = mapped_column(key_type, primary_key=True)
            secret: Mapped[str | None] = mapped_column(
                SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
            )

        try:
            with pytest.raises(ValueError, match=r"main\.key_type_rows\.id is a primary key of type"):
                KeyTypeBase.registry.configure()
        finally:
            KeyTypeBase.registry.dispose()
