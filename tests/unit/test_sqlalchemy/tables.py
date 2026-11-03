import uuid
from typing import Self

from sqlalchemy import ForeignKey, Integer, String, Uuid, func
from sqlalchemy.engine.default import DefaultExecutionContext
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin
from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.integrations.sqlalchemy.hashing import SQLAlchemyHashedValue
from pydantic_encryption.types import BlindIndexMethod
from tests.factories import SampleRecord
from tests.unit.test_sqlalchemy.utils import encrypt_through_column


class RecordBase(DeclarativeBase):
    """Declarative base for every table the unit suite creates in SQLite."""


class Organization(RecordBase, DeferredDecryptMixin):
    """Parent row holding a plain column, an encrypted column and its members."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    members: Mapped[list["Member"]] = relationship(back_populates="organization")


class Member(RecordBase, DeferredDecryptMixin):
    """Child row with two deferred encrypted columns, reached through its organization."""

    __tablename__ = "members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, default=None
    )
    label: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    caption: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    organization: Mapped[Organization | None] = relationship(back_populates="members")

    @classmethod
    def sealed(cls, label: str | None, caption: str | None, **kwargs: object) -> Self:
        """Build a row whose cells hold the given names encrypted under their own columns."""

        return cls(
            label=(None if label is None else encrypt_through_column(cls.__table__.c.label, label)),
            caption=(None if caption is None else encrypt_through_column(cls.__table__.c.caption, caption)),
            **kwargs,
        )

    @classmethod
    def from_sample(cls, sample: SampleRecord) -> Self:
        """Build a row holding a sample's names encrypted."""

        return cls.sealed(sample.label, sample.caption, id=sample.id)


class SecretRow(RecordBase, DeferredDecryptMixin):
    """Row on the deferred read path with one text column bound to its column."""

    __tablename__ = "secret_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)

    @classmethod
    def sealed(cls, secret: str, **kwargs: object) -> Self:
        """Build a row holding a secret encrypted under its column."""

        return cls(secret=encrypt_through_column(cls.__table__.c.secret, secret), **kwargs)


class PayloadRow(RecordBase, DeferredDecryptMixin):
    """Row on the deferred read path with one bytes column."""

    __tablename__ = "payload_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    payload: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)

    @classmethod
    def from_sample(cls, sample: SampleRecord) -> Self:
        """Build a row holding a sample's payload encrypted."""

        return cls(id=sample.id, payload=encrypt_through_column(cls.__table__.c.payload, sample.payload))


class PlainSecretRow(RecordBase):
    """Row outside the deferred read path, whose encrypted column decrypts as it loads."""

    __tablename__ = "plain_secret_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class RenamedColumnRow(RecordBase, DeferredDecryptMixin):
    """Row whose encrypted attribute is stored under a different column name."""

    __tablename__ = "renamed_column_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret: Mapped[str | None] = mapped_column(
        "stored_secret", SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


class RowBoundRecord(RecordBase, DeferredDecryptMixin):
    """Row whose encrypted column binds each row separately."""

    __tablename__ = "row_bound_records"
    __table_args__ = {"schema": "main"}

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    label: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ExpressionKeyedRow(RecordBase, DeferredDecryptMixin):
    """Row-bound row whose primary key defaults to an expression the database evaluates."""

    __tablename__ = "expression_keyed_rows"
    __table_args__ = {"schema": "main"}

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=func.gen_random_uuid())
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class TextUuidKeyedRow(RecordBase, DeferredDecryptMixin):
    """Row-bound row whose UUID primary key is assigned and read back as text."""

    __tablename__ = "text_uuid_keyed_rows"
    __table_args__ = {"schema": "main"}

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


def key_from_label(context: DefaultExecutionContext) -> uuid.UUID:
    """Derive a row's key from the label its insert carries, as a context-reading default does."""

    return uuid.uuid5(uuid.NAMESPACE_URL, context.get_current_parameters()["label"])


class ContextKeyedRow(RecordBase, DeferredDecryptMixin):
    """Row-bound row whose primary key default reads the insert it runs in."""

    __tablename__ = "context_keyed_rows"
    __table_args__ = {"schema": "main"}

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=key_from_label)
    label: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ServerKeyedRow(RecordBase, DeferredDecryptMixin):
    """Row-bound row whose primary key does not exist until its insert returns."""

    __tablename__ = "server_keyed_rows"
    __table_args__ = {"schema": "main"}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class UndeferredRow(RecordBase):
    """Row-bound row that never mixes in the deferred read path."""

    __tablename__ = "undeferred_rows"
    __table_args__ = {"schema": "main"}

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class LiteralRecord(RecordBase):
    """Row holding one column of every scalar binary column type."""

    __tablename__ = "literal_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    password: Mapped[bytes | None] = mapped_column(SQLAlchemyHashedValue(), nullable=True, default=None)
    lookup_index: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256), nullable=True, default=None
    )


class UnmappedRow:
    """Object standing in for a row loaded outside the ORM."""

    def __init__(self, secret: str | None = None) -> None:
        self.secret = secret


class ContextBase(DeclarativeBase):
    """Declarative base for tables SQLite cannot create, which only derive contexts."""


class ArrayRow(ContextBase):
    """Table with an encrypted array column, which SQLite cannot store."""

    __tablename__ = "array_rows"

    id: Mapped[int] = mapped_column(primary_key=True)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True, default=None)


class SecretMixin:
    """Mixin whose encrypted columns are inherited by more than one table."""

    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    aliases: Mapped[list[str] | None] = mapped_column(
        SQLAlchemyPGEncryptedArray(), nullable=True, default=None
    )


class ExtendedContextRecord(ContextBase, SecretMixin):
    """Table carrying the mixin columns plus columns of its own."""

    __tablename__ = "extended_context_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    note: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True, default=None)
    envelope: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue("records.draft"), nullable=True, default=None
    )


class ContextRecord(ContextBase, SecretMixin):
    """Second table carrying the same mixin columns."""

    __tablename__ = "context_records"

    id: Mapped[int] = mapped_column(primary_key=True)


class ArchivedEntry(ContextBase):
    """Table whose name is shared with another table in a different schema."""

    __tablename__ = "entries"
    __table_args__ = {"schema": "archive"}

    id: Mapped[int] = mapped_column(primary_key=True)
    note: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True, default=None)


class PublicEntry(ContextBase):
    """Same table name in a second schema, whose columns must bind separately."""

    __tablename__ = "entries"
    __table_args__ = {"schema": "public"}

    id: Mapped[int] = mapped_column(primary_key=True)
    note: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
