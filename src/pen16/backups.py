"""Backup freshness. deploy/pen16-backup verifies each backup, then records it here."""

from datetime import datetime, timedelta

from sqlalchemy import Connection, func, select
from sqlalchemy.dialects.postgresql import insert

from pen16 import db, notify
from pen16.db import backups

STALE = timedelta(hours=48)
INCIDENT = "backups"


def record(conn: Connection, name: str, size_bytes: int) -> None:
    """Record a verified backup, and clear the stale-backup incident if one is open. A rerun the same day
    replaces that day's backup, so it updates the row."""
    row = insert(backups).values(name=name, size_bytes=size_bytes)
    conn.execute(
        row.on_conflict_do_update(
            index_elements=[backups.c.name], set_={"size_bytes": size_bytes, "finished_at": func.now()}
        )
    )
    notify.clear_incident(conn, INCIDENT, "Backups recovered", f"Backup {name} finished and verified.")


def check(conn: Connection) -> None:
    """Open the stale-backup incident when the newest backup is too old. Silent until the first backup, so a
    deployment without backups never alerts; the dashboard shows "never" instead."""
    last = latest(conn)
    if last is None or db.now(conn) - last < STALE:
        return
    notify.raise_incident(
        conn, INCIDENT, "Backups are stale", f"The last verified backup finished {last:%Y-%m-%d %H:%M} UTC."
    )


def latest(conn: Connection) -> datetime | None:
    finished: datetime | None = conn.scalar(select(func.max(backups.c.finished_at)))
    return finished
