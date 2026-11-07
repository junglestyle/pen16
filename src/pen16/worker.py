"""Background work: start due scheduled scans and sweep chunks, expire late jobs, watch backups, sweeps and
compliance results, and deliver notifications."""

import logging
import os
import signal
import threading
from collections.abc import Callable
from functools import partial

import httpx
from sqlalchemy import Connection, Engine, func
from sqlalchemy.dialects.postgresql import insert

from pen16 import backups, compliance, config, coverage, db, jobs, notify
from pen16.db import heartbeats
from pen16.scope import Scope

log = logging.getLogger(__name__)

TICK = 15
COMPONENT = "worker"


def run_forever() -> None:
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    settings = config.load()
    engine = db.connect()
    url = os.environ.get("PEN16_NTFY_URL", "")
    token = os.environ.get("PEN16_NTFY_TOKEN", "")
    if not url:
        log.warning("PEN16_NTFY_URL is not set: notifications stay queued on the dashboard")
    with httpx.Client() as client:
        deliver = (
            partial(notify.deliver_due, engine, client, url, token, settings.dashboard_url) if url else None
        )
        while not stop.is_set():
            tick(engine, settings.scope, deliver)
            stop.wait(TICK)


def tick(engine: Engine, scope: Scope, deliver: Callable[[], None] | None) -> None:
    """One round of work, then a heartbeat. Each task runs on its own, so one that keeps failing can't hold up
    the others, alert delivery included: it opens an incident instead, and clears it once it runs again."""
    tasks: list[tuple[str, Callable[[Connection], object]]] = [
        ("schedules", partial(jobs.run_due_schedules, scope=scope)),
        ("sweeps", partial(jobs.queue_sweep, scope=scope)),
        ("sweep-age", partial(coverage.check, scope=scope)),
        ("expiry", jobs.expire),
        ("backups", backups.check),
        ("compliance", compliance.check),
    ]
    for name, task in tasks:
        _guarded(engine, name, partial(_in_transaction, engine, task))
    if deliver is not None:
        _guarded(engine, "delivery", deliver)
    _write(
        engine,
        lambda conn: conn.execute(
            insert(heartbeats)
            .values(component=COMPONENT)
            .on_conflict_do_update(index_elements=["component"], set_={"at": func.now()})
        ),
    )


def _in_transaction(engine: Engine, task: Callable[[Connection], object]) -> None:
    with engine.begin() as conn:
        task(conn)


def _guarded(engine: Engine, name: str, work: Callable[[], None]) -> None:
    key = f"{COMPONENT}:{name}"
    try:
        work()
    except Exception as error:  # the loop's boundary: record the failure, then go on to the next task
        log.exception("%s task %s failed", COMPONENT, name)
        kind = type(error).__name__
        _write(
            engine,
            lambda conn: notify.raise_incident(
                conn,
                key,
                f"Background task {name} is failing",
                f"It raised {kind}; the worker's log has more.",
            ),
        )
        return
    _write(
        engine,
        lambda conn: notify.clear_incident(
            conn, key, f"Background task {name} recovered", "It ran without an error."
        ),
    )


def _write(engine: Engine, write: Callable[[Connection], object]) -> None:
    """Record the worker's own state. With the database unreachable that fails too, which the log shows and the
    dashboard's heartbeat gives away."""
    try:
        with engine.begin() as conn:
            write(conn)
    except Exception:  # the loop's boundary: nothing else to tell
        log.exception("couldn't record the %s's state", COMPONENT)
