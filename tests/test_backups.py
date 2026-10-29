from datetime import UTC, datetime, timedelta

from sqlalchemy import insert, select

from pen16 import backups
from pen16.db import backups as backups_table
from pen16.db import notifications


def titles(conn):
    return list(conn.scalars(select(notifications.c.title).order_by(notifications.c.id)))


def test_no_backups_yet_stays_quiet(conn):
    backups.check(conn)

    assert titles(conn) == []


def test_stale_backup_alerts_once_then_recovers(conn):
    old = datetime.now(UTC) - timedelta(days=3)
    conn.execute(insert(backups_table).values(name="2026-10-24", size_bytes=1, finished_at=old))

    backups.check(conn)
    backups.check(conn)
    backups.record(conn, "2026-10-27", 2)
    backups.check(conn)

    assert titles(conn) == ["Backups are stale", "Backups recovered"]


def test_fresh_backup_neither_alerts_nor_recovers(conn):
    backups.record(conn, "2026-10-26", 1)
    backups.record(conn, "2026-10-27", 1)
    backups.check(conn)

    assert titles(conn) == []


def test_rerun_the_same_day_replaces_the_record(conn):
    backups.record(conn, "2026-10-27", 1)
    backups.record(conn, "2026-10-27", 5)

    assert list(conn.scalars(select(backups_table.c.size_bytes))) == [5]
