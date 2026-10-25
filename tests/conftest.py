from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine

from pen15 import db


@pytest.fixture(scope="session")
def engine() -> Engine:
    config = Config("alembic.ini")
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    return db.connect()


@pytest.fixture
def conn(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        transaction = connection.begin()
        yield connection
        transaction.rollback()
