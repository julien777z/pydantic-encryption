import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Final

import pytest
import pytest_asyncio
from sqlalchemy import Engine, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy_utils import create_database, database_exists

from tests.integration.database.tables import Base, User

DATABASE_CONNECTION_MAX_TRIES: Final[int] = 10


@pytest.fixture(scope="session")
def start_docker_services(docker_services: object) -> None:
    """Start the Docker services."""


@pytest.fixture(scope="session")
def docker_setup() -> list[str]:
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
    start_docker_services: None,
    sqlalchemy_connect_url: str,
    engine: Engine,
    wait_for_database: None,
) -> Iterator[Session]:
    """Open a session against the docker-managed Postgres holding the integration tables."""

    if not database_exists(sqlalchemy_connect_url):
        create_database(sqlalchemy_connect_url)

    Base.metadata.create_all(engine)

    session = sessionmaker(bind=engine)

    yield session()

    engine.dispose()


@pytest_asyncio.fixture
async def async_engine(db_session: Session, async_sqlalchemy_connect_url: str) -> AsyncIterator[AsyncEngine]:
    """Create a per-test AsyncEngine against the docker-managed Postgres."""

    engine = create_async_engine(async_sqlalchemy_connect_url, poolclass=NullPool)

    yield engine

    await engine.dispose()


@pytest_asyncio.fixture
async def async_session(async_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Yield a fresh AsyncSession bound to the per-test AsyncEngine."""

    factory = async_sessionmaker(async_engine, expire_on_commit=False)

    async with factory() as session:
        yield session


@pytest.fixture
def create_user(db_session: Session) -> Callable[[User], User]:
    """Store users and return each as read back from the database."""

    def _build(user: User) -> User:
        """Store one user and read it back."""

        db_session.add(user)
        db_session.commit()

        return db_session.scalars(select(User).where(User.id == user.id)).one()

    return _build
