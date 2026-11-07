from datetime import timedelta

from sqlalchemy import func, insert, select

from pen16 import backups
from pen16.db import backups as backups_table
from tests.conftest import alerts, open_incidents


def test_no_backups_yet_stays_quiet(conn):
    backups.check(conn)

    assert alerts(conn) == []


def test_stale_backup_alerts_once_then_recovers(conn):
    old = func.now() - timedelta(days=3)
    conn.execute(insert(backups_table).values(name="2026-10-24", size_bytes=1, finished_at=old))

    backups.check(conn)
    backups.check(conn)
    assert open_incidents(conn) == [backups.INCIDENT]

    backups.record(conn, "2026-10-27", 2)
    backups.check(conn)

    assert open_incidents(conn) == []
    assert [kind for kind, _ in alerts(conn)] == ["health", "health"]


def test_fresh_backup_neither_alerts_nor_recovers(conn):
    backups.record(conn, "2026-10-26", 1)
    backups.record(conn, "2026-10-27", 1)
    backups.check(conn)

    assert alerts(conn) == []


def test_rerun_the_same_day_replaces_the_record(conn):
    backups.record(conn, "2026-10-27", 1)
    backups.record(conn, "2026-10-27", 5)

    assert list(conn.scalars(select(backups_table.c.size_bytes))) == [5]
