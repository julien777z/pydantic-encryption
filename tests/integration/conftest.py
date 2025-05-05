import asyncio
import time
from typing import Final
import pytest
import pytest_asyncio
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Engine
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
