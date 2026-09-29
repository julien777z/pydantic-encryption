import pytest
from argon2 import PasswordHasher
from sqlalchemy import insert, literal, select, text
from sqlalchemy.dialects import mssql, mysql, oracle, postgresql, sqlite
from sqlalchemy.engine import Dialect
from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.exc import CompileError
from sqlalchemy.orm import Session

from pydantic_encryption.integrations.sqlalchemy.binary import BinaryStorage
from tests.factories import User
from tests.unit.test_sqlalchemy.tables import LiteralRecord
from tests.unit.test_sqlalchemy.utils import column_type_of
from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue


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

    def test_literal_round_trip(self, sqlite_session: Session, user: User):
        """Test that each column type written and queried through literal SQL reads back as bound SQL would."""

        dialect = sqlite_session.get_bind().dialect
        email_index_type = column_type_of(LiteralRecord.__table__.c.email_index, SQLAlchemyBlindIndexValue)
        insert_statement = insert(LiteralRecord).values(
            id=user.id, secret=user.first_name, password=user.last_name, email_index=user.username
        )

        sqlite_session.execute(
            text(str(insert_statement.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
        )

        lookup = select(LiteralRecord).where(LiteralRecord.email_index == user.username)
        record = sqlite_session.scalars(
            select(LiteralRecord).from_statement(
                text(str(lookup.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
            )
        ).one()

        assert record.secret == user.first_name
        assert record.password is not None
        assert PasswordHasher().verify(record.password.decode("utf-8"), user.last_name)
        assert record.email_index == email_index_type.compute_blind_index(user.username)
