import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from pen16 import db, scope

FIXTURES = Path(__file__).parent / "fixtures"
LAB_SCAN = FIXTURES / "nmap-lab.xml"
CLOSED_SCAN = FIXTURES / "nmap-lab-closed.xml"
# A real RHEL 9 STIG evaluation (SSG 0.1.82, OpenSCAP 1.3.9) of a UBI 9 filesystem, trimmed to 20 rules, with
# the target's facts and OVAL results removed. The DISA RHEL 9 STIG V2R9 manual benchmark is trimmed to match.
STIG_RESULT = FIXTURES / "arf-rhel9-stig.xml"
DISA_STIG = FIXTURES / "disa-rhel9-stig-xccdf.xml"


# Each run creates its own scratch database through this admin URL and drops it afterwards. make test sets it to
# make db's Postgres; it's never PEN16_DATABASE_URL, so a run can't touch a database it didn't create.
ADMIN_URL = "PEN16_TEST_ADMIN_URL"


@pytest.fixture(scope="session")
def engine():
    url = os.environ.get(ADMIN_URL)
    if not url:
        _unavailable(f"{ADMIN_URL} is not set (make test sets it)")
    admin_url = make_url(url)
    if admin_url.host not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit(f"tests create and drop databases, so only on localhost, not {admin_url.host!r}")
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    name = f"pen16_test_{uuid.uuid4().hex[:12]}"
    try:
        with admin.connect() as connection:
            connection.execute(text(f"CREATE DATABASE {name}"))
    except OperationalError:
        _unavailable(f"no Postgres at {admin_url.render_as_string()!r} (make db starts one)")
    with pytest.MonkeyPatch.context() as env:
        env.setenv("PEN16_DATABASE_URL", admin_url.set(database=name).render_as_string(hide_password=False))
        # Down and up again, so every migration's downgrade runs too.
        config = Config("alembic.ini")
        command.upgrade(config, "head")
        command.downgrade(config, "base")
        command.upgrade(config, "head")
        engine = db.connect()
        yield engine
        engine.dispose()
    with admin.connect() as connection:
        connection.execute(text(f"DROP DATABASE {name} WITH (FORCE)"))
    admin.dispose()


def _unavailable(reason):
    """Database tests skip without Postgres, except in CI, where they must run."""
    if os.environ.get("CI"):
        pytest.fail(reason)
    pytest.skip(reason)


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
                "notifications, backups, compliance_scans, compliance_rules, compliance_results, "
                "compliance_waivers, stigs, stig_rules, decisions, mac_sightings CASCADE"
            )
        )


@pytest.fixture
def lab_scope():
    return scope.parse([{"name": "lab", "cidr": "192.0.2.0/24", "gateway": "192.0.2.1"}], ["192.0.2.12/32"])
