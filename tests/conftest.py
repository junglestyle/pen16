from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text

from pen16 import db, scope
from pen16.scope import Scope

FIXTURES = Path(__file__).parent / "fixtures"
LAB_SCAN = FIXTURES / "nmap-lab.xml"
CLOSED_SCAN = FIXTURES / "nmap-lab-closed.xml"


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


@pytest.fixture
def committed(engine: Engine) -> Iterator[Engine]:
    """For tests that go through a service's own transactions. Wipes everything but schedules afterwards."""
    yield engine
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE assets, bindings, expected_services, observations, findings, jobs, tokens, "
                "notifications CASCADE"
            )
        )


@pytest.fixture
def lab_scope() -> Scope:
    return scope.parse([{"name": "lab", "cidr": "192.0.2.0/24", "gateway": "192.0.2.1"}], ["192.0.2.12/32"])
