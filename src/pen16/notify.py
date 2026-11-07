"""Alerts: the notification queue and its delivery, and incidents, the monitoring problems that alert once."""

import logging
from datetime import timedelta

import httpx
from sqlalchemy import Connection, Engine, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as upsert

from pen16.db import NotificationKind, NotificationStatus, incidents, notifications

log = logging.getLogger(__name__)

GIVE_UP_AFTER = timedelta(hours=24)
MAX_BACKOFF = timedelta(hours=1)
DELIVERY = "delivery"


def enqueue(conn: Connection, kind: NotificationKind, title: str, body: str) -> None:
    """Queue a notification in the caller's transaction, so it exists exactly when its change does."""
    conn.execute(insert(notifications).values(kind=kind, title=title, body=body))


def raise_incident(conn: Connection, key: str, title: str, detail: str) -> bool:
    """Open the incident for `key` and alert, or do nothing while it's already open. Returns whether it alerted."""
    opened = conn.scalar(
        upsert(incidents)
        .values(key=key, title=title, detail=detail)
        .on_conflict_do_nothing(index_elements=["key"], index_where=incidents.c.cleared_at.is_(None))
        .returning(incidents.c.id)
    )
    if opened is None:
        return False
    enqueue(conn, NotificationKind.HEALTH, title, detail)
    return True


def clear_incident(conn: Connection, key: str, title: str, detail: str) -> bool:
    """Close the open incident for `key` with one recovery notice, or do nothing if none is open."""
    cleared = conn.scalar(
        update(incidents)
        .where(incidents.c.key == key, incidents.c.cleared_at.is_(None))
        .values(cleared_at=func.now())
        .returning(incidents.c.id)
    )
    if cleared is None:
        return False
    enqueue(conn, NotificationKind.HEALTH, title, detail)
    return True


def dismiss_incident(conn: Connection, key: str) -> None:
    """Close the open incident for `key` without a recovery notice: its subject is gone, so nothing recovered."""
    conn.execute(
        update(incidents)
        .where(incidents.c.key == key, incidents.c.cleared_at.is_(None))
        .values(cleared_at=func.now())
    )


def replay_failed(conn: Connection) -> None:
    """Send every notification that failed for good again, with a fresh day of retries."""
    conn.execute(
        update(notifications)
        .where(notifications.c.status == NotificationStatus.FAILED)
        .values(
            status=NotificationStatus.PENDING,
            next_attempt_at=func.now(),
            retry_until=func.now() + GIVE_UP_AFTER,
        )
    )


def deliver_due(engine: Engine, client: httpx.Client, url: str, token: str, click: str) -> None:
    """POST each due notification to an ntfy-compatible URL, retrying transient failures with backoff. A
    notification that fails for good opens the delivery incident; the next one delivered clears it."""
    while True:
        with engine.begin() as conn:
            row = conn.execute(
                select(notifications, (func.now() > notifications.c.retry_until).label("expired"))
                .where(
                    notifications.c.status == NotificationStatus.PENDING,
                    notifications.c.next_attempt_at <= func.now(),
                )
                .order_by(notifications.c.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if row is None:
                return
            error, permanent = _post(client, url, token, click, row.kind, row.title, row.body)
            attempts = row.attempts + 1
            if error is None:
                values = {
                    "status": NotificationStatus.DELIVERED,
                    "delivered_at": func.now(),
                    "attempts": attempts,
                }
                clear_incident(
                    conn, DELIVERY, "Alerts are being delivered again", f"Notification {row.id} went out."
                )
            elif permanent or row.expired:
                log.warning("notification %s failed for good: %s", row.id, error)
                values = {"status": NotificationStatus.FAILED, "attempts": attempts, "last_error": error}
                raise_incident(
                    conn,
                    DELIVERY,
                    "Alerts aren't being delivered",
                    f"Notification {row.id} ({row.title}) failed: {error}. Resend it from the dashboard.",
                )
            else:
                delay = min(timedelta(minutes=2**attempts), MAX_BACKOFF)
                values = {"attempts": attempts, "last_error": error, "next_attempt_at": func.now() + delay}
            conn.execute(update(notifications).where(notifications.c.id == row.id).values(**values))


def _post(
    client: httpx.Client, url: str, token: str, click: str, kind: str, title: str, body: str
) -> tuple[str | None, bool]:
    """Returns (error, permanent). ntfy takes the title and link as headers, the message as the body."""
    headers = {"Title": title, "Tags": "rotating_light" if kind == NotificationKind.FINDING else "warning"}
    if click:
        headers["Click"] = click
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = client.post(url, content=body.encode(), headers=headers, timeout=10)
    except httpx.HTTPError as error:
        return f"{type(error).__name__}", False
    if response.is_success:
        return None, False
    transient = response.status_code == 429 or response.status_code >= 500
    return f"HTTP {response.status_code}", not transient
