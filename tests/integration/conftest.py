import asyncio
import time
from typing import Final
import pytest
import pytest_asyncio
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from tests.integration.database.tables import Base

DATABASE_CONNECTION_MAX_TRIES: Final[int] = 10


@pytest_asyncio.fixture(scope="session")
def event_loop(request):
    """Create an instance of the default event loop for each test case."""

    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
def start_docker_services(docker_services):
    """Start the Docker services."""


@pytest.fixture(scope="session")
def docker_setup():
    """Stop the stack before starting a new one."""

    return ["down -v", "up --build -d"]


@pytest.fixture(scope="session")
def sqlalchemy_connect_url() -> str:
    """Return the SQLAlchemy connection URL."""

    return "postgresql://admin:admin123@localhost:5432/pydantic_encryption"


@pytest.fixture(scope="session")
def async_sqlalchemy_connect_url(sqlalchemy_connect_url: str) -> str:
    """Return the asyncpg-flavoured connection URL for the same Postgres instance."""

    return sqlalchemy_connect_url.replace("postgresql://", "postgresql+asyncpg://", 1)


@pytest.fixture(scope="session")
def wait_for_database(sqlalchemy_connect_url: str) -> None:
    """Wait for the database to be ready."""

    tries_remaining = DATABASE_CONNECTION_MAX_TRIES

    while not database_exists(sqlalchemy_connect_url):
        tries_remaining -= 1

        if not tries_remaining:
            raise RuntimeError("Failed to connect to the database")

        time.sleep(1)


@pytest.fixture(scope="session")
def db_session(
    start_docker_services,
    sqlalchemy_connect_url: str,
    engine: Engine,
    wait_for_database,
):
    """Create a SQLAlchemy engine."""

    if not database_exists(sqlalchemy_connect_url):
        create_database(sqlalchemy_connect_url)

    Base.metadata.create_all(engine)

    session = sessionmaker(bind=engine)

    yield session()

    engine.dispose()


@pytest_asyncio.fixture
async def async_engine(
    db_session,
    async_sqlalchemy_connect_url: str,
):
    """Create an AsyncEngine against the docker-managed Postgres.

    Scoped per test with ``NullPool`` so asyncpg connections never outlive
    the test's event loop - pytest-asyncio creates a fresh loop per test
    under the default function scope, and a pooled connection opened on a
    previous loop would otherwise raise "attached to a different loop" on
    reuse. Depends on ``db_session`` so the docker stack is up and the sync
    side has already created the schema before any async query runs.
    """

    engine = create_async_engine(async_sqlalchemy_connect_url, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def async_session(async_engine):
    """Yield a fresh AsyncSession bound to the per-test AsyncEngine."""

    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with factory() as session:
        yield session
