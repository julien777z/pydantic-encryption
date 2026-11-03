import warnings

import pytest
from argon2 import PasswordHasher
from sqlalchemy import insert, literal, select, text
from sqlalchemy.dialects import mssql, mysql, oracle, postgresql, sqlite
from sqlalchemy.engine import Dialect
from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.exc import CompileError, SAWarning
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator

from pydantic_encryption.integrations.sqlalchemy.binary import BinaryStorage
from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.integrations.sqlalchemy.hashing import SQLAlchemyHashedValue
from pydantic_encryption.types import BlindIndexMethod
from tests.factories import SampleRecord
from tests.unit.test_sqlalchemy.tables import LiteralRecord
from tests.unit.test_sqlalchemy.utils import column_type_of


class TestBinaryLiteral:
    """Test that binary column storage renders literal values in its dialect's binary literal syntax."""

    @pytest.mark.parametrize(
        ("dialect", "expected"),
        [
            (postgresql.dialect(), "decode('00ff27', 'hex')"),
            (sqlite.dialect(), "X'00ff27'"),
            (mysql.dialect(), "X'00ff27'"),
            (mssql.dialect(), "0x00ff27"),
            (oracle.dialect(), "HEXTORAW('00ff27')"),
        ],
        ids=["postgresql", "sqlite", "mysql", "mssql", "oracle"],
    )
    def test_dialect_literal(self, dialect: Dialect, expected: str):
        """Test that bytes no text encoding can hold render as the dialect's binary literal."""

        statement = select(literal(b"\x00\xff'", BinaryStorage()))

        assert expected in str(statement.compile(dialect=dialect, compile_kwargs={"literal_binds": True}))

    def test_unknown_dialect_refused(self):
        """Test that a dialect with no known binary literal syntax is refused without echoing the value."""

        statement = select(literal(b"\x00\xff", BinaryStorage()))

        with pytest.raises(CompileError, match="No binary literal syntax") as refusal:
            statement.compile(dialect=DefaultDialect(), compile_kwargs={"literal_binds": True})

        assert "00ff" not in str(refusal.value)

    def test_literal_round_trip(self, sqlite_session: Session, sample: SampleRecord):
        """Test that each column type written and queried through literal SQL reads back as bound SQL."""

        dialect = sqlite_session.get_bind().dialect
        lookup_index_type = column_type_of(LiteralRecord.__table__.c.lookup_index, SQLAlchemyBlindIndexValue)
        insert_statement = insert(LiteralRecord).values(
            id=sample.id, secret=sample.label, password=sample.caption, lookup_index=sample.name
        )

        sqlite_session.execute(
            text(str(insert_statement.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
        )

        lookup = select(LiteralRecord).where(LiteralRecord.lookup_index == sample.name)
        record = sqlite_session.scalars(
            select(LiteralRecord).from_statement(
                text(str(lookup.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
            )
        ).one()

        assert record.secret == sample.label
        assert record.password is not None
        assert PasswordHasher().verify(record.password.decode("utf-8"), sample.caption)
        assert record.lookup_index == lookup_index_type.compute_blind_index(sample.name)

    @pytest.mark.parametrize(
        "column_type",
        [
            SQLAlchemyEncryptedValue("tests.records.secret"),
            SQLAlchemyPGEncryptedArray("tests.records.tags"),
            SQLAlchemyHashedValue(),
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256),
        ],
        ids=["encrypted", "encrypted-array", "hashed", "blind-index"],
    )
    def test_column_type_produces_cache_key(self, column_type: TypeDecorator[object]):
        """Test that every binary column type is safe to cache, so statements using it are cached."""

        with warnings.catch_warnings():
            warnings.simplefilter("error", SAWarning)

            assert column_type._static_cache_key
