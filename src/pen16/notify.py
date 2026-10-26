import logging
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import Connection, Engine, insert, select, update

from pen16.db import notifications

log = logging.getLogger(__name__)

GIVE_UP_AFTER = timedelta(hours=24)
MAX_BACKOFF = timedelta(hours=1)


def enqueue(conn: Connection, kind: str, title: str, body: str) -> None:
    """Queue a notification in the caller's transaction, so it exists exactly when its change does."""
    conn.execute(insert(notifications).values(kind=kind, title=title, body=body))


def deliver_due(engine: Engine, client: httpx.Client, url: str, token: str, click: str) -> None:
    """POST each due notification to an ntfy-compatible URL, retrying transient failures with backoff."""
    while True:
        with engine.begin() as conn:
            row = conn.execute(
                select(notifications)
                .where(
                    notifications.c.status == "pending", notifications.c.next_attempt_at <= datetime.now(UTC)
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
                values = {"status": "delivered", "delivered_at": datetime.now(UTC), "attempts": attempts}
            elif permanent or datetime.now(UTC) - row.created_at > GIVE_UP_AFTER:
                log.warning("notification %s failed for good: %s", row.id, error)
                values = {"status": "failed", "attempts": attempts, "last_error": error}
            else:
                delay = min(timedelta(minutes=2**attempts), MAX_BACKOFF)
                values = {
                    "attempts": attempts,
                    "last_error": error,
                    "next_attempt_at": datetime.now(UTC) + delay,
                }
            conn.execute(update(notifications).where(notifications.c.id == row.id).values(**values))


def _post(
    client: httpx.Client, url: str, token: str, click: str, kind: str, title: str, body: str
) -> tuple[str | None, bool]:
    """Returns (error, permanent). ntfy takes the title and link as headers, the message as the body."""
    headers = {"Title": title, "Tags": "rotating_light" if kind == "finding" else "warning"}
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
