import os
import re
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from pen16 import db, exposure, nmap, scope

FIXTURES = Path(__file__).parent / "fixtures"
LAB_SCAN = FIXTURES / "nmap-lab.xml"
CLOSED_SCAN = FIXTURES / "nmap-lab-closed.xml"
# A real RHEL 9 STIG evaluation (SSG 0.1.82, OpenSCAP 1.3.9) of a UBI 9 filesystem, trimmed to 20 rules, with
# the target's facts and OVAL results removed. The DISA RHEL 9 STIG V2R9 manual benchmark is trimmed to match.
STIG_RESULT = FIXTURES / "arf-rhel9-stig.xml"
DISA_STIG = FIXTURES / "disa-rhel9-stig-xccdf.xml"
LAB_FINISHED = 1767225612
# The lab network: its gateway answers in the closed scan, not the first one, and one host inside it is excluded.
LAB = scope.parse([{"name": "lab", "cidr": "192.0.2.0/24", "gateway": "192.0.2.1"}], ["192.0.2.12/32"])


def lab_xml(shift: int = 0, version: bytes = b'version="3.0.1"') -> bytes:
    """The lab scan, `shift` seconds later, with 8080's version attribute replaced."""
    raw = LAB_SCAN.read_bytes().replace(
        b'<finished time="%d"' % LAB_FINISHED, b'<finished time="%d"' % (LAB_FINISHED + shift)
    )
    return raw.replace(b'version="3.0.1"', version)


def closed_xml(*, gateway: bool = True) -> bytes:
    """A day after the lab scan, with 8080 closed. Without the gateway, as if it didn't answer."""
    raw = CLOSED_SCAN.read_bytes()
    if not gateway:
        raw = re.sub(rb'<host [^\n]*\n<address addr="192\.0\.2\.1".*?</host>\n', b"", raw, flags=re.DOTALL)
    return raw


def lab(shift: int = 0, version: bytes = b'version="3.0.1"') -> nmap.Scan:
    return nmap.parse(lab_xml(shift, version))


def closed(*, gateway: bool = True) -> nmap.Scan:
    return nmap.parse(closed_xml(gateway=gateway))


def ingest(conn, scan):
    """Record a scan from the lab network, as a job does."""
    return exposure.ingest(conn, scan, LAB.networks, "internal")


def open_incidents(conn):
    """The keys of the open incidents."""
    return sorted(conn.scalars(select(db.incidents.c.key).where(db.incidents.c.cleared_at.is_(None))))


def alerts(conn):
    """Each queued notification's kind and body, oldest first."""
    rows = conn.execute(
        select(db.notifications.c.kind, db.notifications.c.body).order_by(db.notifications.c.id)
    )
    return [tuple(row) for row in rows]


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
    tables = ", ".join(table.name for table in db.metadata.sorted_tables if table.name != "schedules")
    with engine.begin() as connection:
        connection.execute(text(f"TRUNCATE {tables} CASCADE"))


@pytest.fixture
def lab_scope():
    return LAB
