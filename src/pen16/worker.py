"""Background work: start due scheduled scans, expire late jobs, watch backups, and deliver notifications."""

import logging
import os
import signal
import threading

import httpx

from pen16 import backups, config, db, jobs, notify

log = logging.getLogger(__name__)

TICK = 15


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
        while not stop.is_set():
            with engine.begin() as conn:
                jobs.run_due_schedules(conn, settings.scope)
                jobs.expire(conn)
                backups.check(conn)
            if url:
                notify.deliver_due(engine, client, url, token, settings.dashboard_url)
            stop.wait(TICK)
