import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic_encryption.integrations.sqlalchemy.state import read_raw_cell, set_decrypted


class StateBase(DeclarativeBase):
    """Isolated declarative base for the ORM-state helpers."""


class StateRow(StateBase):
    """Mapped class the ORM-state helpers read from and write to."""

    __tablename__ = "state_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret: Mapped[str | None] = mapped_column(String, nullable=True, default=None)


class PlainRow:
    """Unmapped object standing in for a row loaded outside the ORM."""

    def __init__(self, secret: str | None = None) -> None:
        self.secret = secret


class TestReadRawCell:
    """Test reading a stored cell from whatever the row turns out to be."""

    def test_reads_through_orm_state(self):
        """Test that a mapped instance is read from its ORM state rather than its attribute."""

        assert read_raw_cell(StateRow(id=1, secret="sealed"), "secret") == "sealed"

    def test_reads_an_unmapped_row_by_attribute(self):
        """Test that an object with no ORM state falls back to the plain attribute."""

        assert read_raw_cell(PlainRow("sealed"), "secret") == "sealed"

    def test_absent_on_an_unmapped_row_reads_as_none(self):
        """Test that a column an unmapped row does not carry reads as absent."""

        assert read_raw_cell(PlainRow(), "missing") is None


class TestSetDecrypted:
    """Test committing a decrypted value onto whatever the row turns out to be."""

    def test_commits_onto_a_mapped_row_without_dirtying_it(self):
        """Test that a mapped instance takes the value without becoming dirty for the next flush."""

        row = StateRow(id=1, secret="sealed")

        set_decrypted(row, "secret", "plaintext")

        assert row.secret == "plaintext"

    def test_assigns_onto_an_unmapped_row(self):
        """Test that an object with no ORM state takes the value by plain assignment."""

        row = PlainRow("sealed")

        set_decrypted(row, "secret", "plaintext")

        assert row.secret == "plaintext"
