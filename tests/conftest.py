from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import make_url

from pen16 import db, scope

FIXTURES = Path(__file__).parent / "fixtures"
LAB_SCAN = FIXTURES / "nmap-lab.xml"
CLOSED_SCAN = FIXTURES / "nmap-lab-closed.xml"


@pytest.fixture(scope="session")
def engine():
    host = make_url(db.database_url()).host
    if host not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit(
            f"tests drop and recreate the schema, so they run only against localhost, not {host!r}"
        )
    config = Config("alembic.ini")
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    return db.connect()


@pytest.fixture
def conn(engine):
    with engine.connect() as connection:
        transaction = connection.begin()
        yield connection
        transaction.rollback()


@pytest.fixture
def committed(engine):
    """For tests that go through a service's own transactions. Wipes everything but schedules afterwards."""
    yield engine
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE assets, bindings, expected_services, observations, findings, jobs, tokens, "
                "notifications, backups CASCADE"
            )
        )


@pytest.fixture
def lab_scope():
    return scope.parse([{"name": "lab", "cidr": "192.0.2.0/24", "gateway": "192.0.2.1"}], ["192.0.2.12/32"])
