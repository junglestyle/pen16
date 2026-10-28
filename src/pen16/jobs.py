import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Row, func, insert, select, union, update

from pen16 import exposure, notify
from pen16.db import expected_services, jobs, observations, schedules
from pen16.nmap import Scan
from pen16.scope import Scope

log = logging.getLogger(__name__)

DEADLINE = timedelta(minutes=30)
MAX_ATTEMPTS = 2
UNCLAIMED = timedelta(hours=1)


class StaleJobError(Exception):
    """The job isn't running on this runner any more, so its result can't change state."""


def request(conn: Connection, scope: Scope, requester: str, reason: str, schedule: str | None = None) -> int:
    """Queue a nightly-profile scan of the whole scope, or return the scan already waiting or running."""
    waiting = conn.scalar(select(jobs.c.id).where(jobs.c.status.in_(["queued", "running"])))
    if waiting is not None:
        return int(waiting)
    targets = [str(network.cidr) for network in scope.networks]
    exclude = [str(network) for network in scope.exclude]
    scope.check(targets, exclude)
    known = union(
        select(expected_services.c.port).where(expected_services.c.protocol == "tcp"),
        select(observations.c.port).where(observations.c.protocol == "tcp", observations.c.state == "open"),
    )
    job_id: int = conn.scalar(
        insert(jobs)
        .values(
            schedule=schedule,
            requester=requester,
            reason=reason,
            profile="nightly",
            targets=targets,
            exclude=exclude,
            extra_tcp=sorted(conn.scalars(known)),
            status="queued",
        )
        .returning(jobs.c.id)
    )
    log.info("queued job %s for %s: %s", job_id, requester, reason)
    return job_id


def run_due_schedules(conn: Connection, scope: Scope) -> None:
    now = datetime.now(UTC)
    due = conn.execute(
        select(schedules).where(schedules.c.enabled, schedules.c.next_run_at <= now).with_for_update()
    )
    for schedule in due.all():
        request(conn, scope, f"schedule:{schedule.name}", "scheduled scan", schedule=schedule.name)
        next_run = schedule.next_run_at
        while next_run <= now:
            next_run += timedelta(hours=schedule.every_hours)
        conn.execute(update(schedules).where(schedules.c.name == schedule.name).values(next_run_at=next_run))


def claim(conn: Connection, runner: str) -> Row[Any] | None:
    """Hand the runner the oldest queued job. Anything it was already running was lost in a restart."""
    abandoned = conn.execute(
        select(jobs).where(jobs.c.status == "running", jobs.c.runner == runner).with_for_update()
    )
    for job in abandoned.all():
        _retry_or_fail(conn, job, "runner restarted during the job")
    next_id = (
        select(jobs.c.id)
        .where(jobs.c.status == "queued")
        .order_by(jobs.c.id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    return conn.execute(
        update(jobs)
        .where(jobs.c.id == next_id)
        .values(
            status="running",
            runner=runner,
            attempts=jobs.c.attempts + 1,
            started_at=func.now(),
            deadline_at=func.now() + DEADLINE,
        )
        .returning(jobs)
    ).first()


def complete(conn: Connection, job_id: int, runner: str, scan: Scan, scope: Scope) -> list[exposure.Finding]:
    """Record a runner's scan, finding changes, alerts, and the job outcome in one transaction."""
    job = _running(conn, job_id, runner)
    up = {host.address for host in scan.hosts if host.up}
    silent = [str(network.gateway) for network in scope.networks if str(network.gateway) not in up]
    opened = exposure.ingest(conn, scan, vantage="internal", closures=not silent)
    if opened:
        lines = [f"{f.asset_id} {f.port}/{f.protocol}" for f in opened]
        notify.enqueue(conn, "finding", f"{len(opened)} unexpected service(s)", "\n".join(lines))
    if silent:
        notify.enqueue(
            conn,
            "health",
            "Gateway didn't answer",
            f"Gateway {', '.join(silent)} was down during job {job_id}, so closed ports resolved nothing.",
        )
    if job.schedule is not None and _last_scheduled_status(conn, job.schedule) == "failed":
        notify.enqueue(conn, "health", "Scans recovered", f"Scheduled job {job_id} succeeded.")
    conn.execute(
        update(jobs)
        .where(jobs.c.id == job_id)
        .values(status="succeeded", finished_at=func.now(), evidence_digest=scan.digest, error=None)
    )
    return opened


def fail(conn: Connection, job_id: int, runner: str, error: str) -> None:
    _retry_or_fail(conn, _running(conn, job_id, runner), error)


def expire(conn: Connection) -> None:
    """Retry or fail jobs past their deadline, and fail jobs no runner picked up."""
    now = datetime.now(UTC)
    late = conn.execute(
        select(jobs)
        .where(jobs.c.status == "running", jobs.c.deadline_at < now)
        .with_for_update(skip_locked=True)
    )
    for job in late.all():
        _retry_or_fail(conn, job, "missed its deadline")
    unclaimed = conn.execute(
        select(jobs)
        .where(jobs.c.status == "queued", jobs.c.created_at < now - UNCLAIMED)
        .with_for_update(skip_locked=True)
    )
    for job in unclaimed.all():
        _finish_failed(conn, job, "no runner claimed it")


def _running(conn: Connection, job_id: int, runner: str) -> Row[Any]:
    job = conn.execute(
        select(jobs)
        .where(
            jobs.c.id == job_id,
            jobs.c.status == "running",
            jobs.c.runner == runner,
            jobs.c.deadline_at > func.now(),
        )
        .with_for_update()
    ).first()
    if job is None:
        raise StaleJobError(f"job {job_id} isn't running on runner {runner}")
    return job


def _retry_or_fail(conn: Connection, job: Row[Any], error: str) -> None:
    if job.attempts < MAX_ATTEMPTS:
        log.warning("job %s: %s; retrying", job.id, error)
        conn.execute(
            update(jobs)
            .where(jobs.c.id == job.id)
            .values(status="queued", runner=None, started_at=None, deadline_at=None, error=error)
        )
        return
    _finish_failed(conn, job, error)


def _finish_failed(conn: Connection, job: Row[Any], error: str) -> None:
    log.warning("job %s failed: %s", job.id, error)
    conn.execute(
        update(jobs).where(jobs.c.id == job.id).values(status="failed", finished_at=func.now(), error=error)
    )
    notify.enqueue(conn, "health", "Scan failed", f"Job {job.id} ({job.reason}) failed: {error}")


def _last_scheduled_status(conn: Connection, schedule: str) -> str | None:
    status: str | None = conn.scalar(
        select(jobs.c.status)
        .where(jobs.c.schedule == schedule, jobs.c.status.in_(["succeeded", "failed"]))
        .order_by(jobs.c.finished_at.desc())
        .limit(1)
    )
    return status
