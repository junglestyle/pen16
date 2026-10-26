"""Background work: start due scheduled scans, expire late jobs, and deliver notifications."""

import logging
import os
import time

import httpx

from pen15 import config, db, jobs, notify

log = logging.getLogger(__name__)

TICK = 15


def run_forever() -> None:
    settings = config.load()
    engine = db.connect()
    url = os.environ.get("PEN15_NTFY_URL", "")
    token = os.environ.get("PEN15_NTFY_TOKEN", "")
    if not url:
        log.warning("PEN15_NTFY_URL is not set: notifications stay queued on the dashboard")
    with httpx.Client() as client:
        while True:
            with engine.begin() as conn:
                jobs.run_due_schedules(conn, settings.scope)
                jobs.expire(conn)
            if url:
                notify.deliver_due(engine, client, url, token, settings.dashboard_url)
            time.sleep(TICK)
