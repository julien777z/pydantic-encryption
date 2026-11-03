from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects import sqlite
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Session, configure_mappers

from tests.unit.test_sqlalchemy.tables import RecordBase


@pytest.fixture(autouse=True, scope="session")
def configured_mappers() -> None:
    """Configure the suite's mappers, which installs the deferred read path on mixed-in classes."""

    configure_mappers()


@pytest.fixture
def sqlite_session() -> Iterator[Session]:
    """Open a session against a fresh in-memory database holding the unit suite's tables."""

    engine = create_engine("sqlite://")

    RecordBase.metadata.create_all(engine)

    with Session(engine) as open_session:
        yield open_session


@pytest.fixture
def sqlite_dialect() -> Dialect:
    """Return the SQLite dialect a column type processes values for."""

    return sqlite.dialect()
