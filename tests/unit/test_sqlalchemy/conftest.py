from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects import sqlite
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Session

from tests.unit.test_sqlalchemy.tables import AutoDecryptBase, LiteralBase, RowBoundBase


@pytest.fixture
def sqlite_session() -> Iterator[Session]:
    """Open a session against a fresh in-memory database holding the unit suite's tables."""

    engine = create_engine("sqlite://")
    for base in (AutoDecryptBase, LiteralBase, RowBoundBase):
        base.metadata.create_all(engine)

    with Session(engine) as open_session:
        yield open_session


@pytest.fixture
def sqlite_dialect() -> Dialect:
    """Return the SQLite dialect a column type processes values for."""

    return sqlite.dialect()
