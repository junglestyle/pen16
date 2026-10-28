"""Backup freshness. deploy/pen16-backup verifies each backup, then records it here."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import Connection, exists, func, select
from sqlalchemy.dialects.postgresql import insert

from pen16 import notify
from pen16.db import NotificationKind, backups, notifications

STALE = timedelta(hours=48)
STALE_TITLE = "Backups are stale"


def record(conn: Connection, name: str, size_bytes: int) -> None:
    """Record a verified backup, and send a recovery notice if the last one was reported stale. A rerun
    the same day replaces that day's backup, so it updates the row."""
    previous = latest(conn)
    row = insert(backups).values(name=name, size_bytes=size_bytes)
    conn.execute(
        row.on_conflict_do_update(
            index_elements=[backups.c.name], set_={"size_bytes": size_bytes, "finished_at": func.now()}
        )
    )
    if previous is not None and _warned_since(conn, previous):
        notify.enqueue(
            conn, NotificationKind.HEALTH, "Backups recovered", f"Backup {name} finished and verified."
        )


def check(conn: Connection) -> None:
    """Alert once when the newest backup is too old. Silent until the first backup, so a deployment
    without backups never alerts; the dashboard shows "never" instead."""
    last = latest(conn)
    if last is None or datetime.now(UTC) - last < STALE or _warned_since(conn, last):
        return
    notify.enqueue(
        conn,
        NotificationKind.HEALTH,
        STALE_TITLE,
        f"The last verified backup finished {last:%Y-%m-%d %H:%M} UTC.",
    )


def latest(conn: Connection) -> datetime | None:
    finished: datetime | None = conn.scalar(select(func.max(backups.c.finished_at)))
    return finished


def _warned_since(conn: Connection, when: datetime) -> bool:
    return bool(
        conn.scalar(
            select(
                exists().where(
                    notifications.c.kind == NotificationKind.HEALTH,
                    notifications.c.title == STALE_TITLE,
                    notifications.c.created_at > when,
                )
            )
        )
    )
