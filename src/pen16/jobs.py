import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from sqlalchemy import Connection, Row, func, insert, select, union, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert

from pen16 import db, exposure, notify
from pen16.db import (
    JobStatus,
    ObservationState,
    expected_services,
    jobs,
    mac_sightings,
    observations,
    schedules,
)
from pen16.neighbours import Neighbour
from pen16.nmap import Scan
from pen16.scope import Scope

log = logging.getLogger(__name__)

DEADLINE = timedelta(minutes=30)
MAX_ATTEMPTS = 2
UNCLAIMED = timedelta(hours=1)
FAILED_WINDOWS = 2


class StaleJobError(Exception):
    """The job isn't running on this runner any more, so its result can't change state."""


def request(conn: Connection, scope: Scope, requester: str, reason: str, schedule: str | None = None) -> int:
    """Queue a nightly-profile scan of the whole scope, or return the scan already waiting or running."""
    waiting = conn.scalar(select(jobs.c.id).where(jobs.c.status.in_([JobStatus.QUEUED, JobStatus.RUNNING])))
    if waiting is not None:
        return int(waiting)
    targets = [str(network.cidr) for network in scope.networks]
    exclude = [str(network) for network in scope.exclude]
    scope.check(targets, exclude)
    known = union(
        select(expected_services.c.port).where(
            expected_services.c.protocol == "tcp", expected_services.c.ended_at.is_(None)
        ),
        select(observations.c.port).where(
            observations.c.protocol == "tcp", observations.c.state == ObservationState.OPEN
        ),
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
            status=JobStatus.QUEUED,
        )
        .returning(jobs.c.id)
    )
    log.info("queued job %s for %s: %s", job_id, requester, reason)
    return job_id


def run_due_schedules(conn: Connection, scope: Scope) -> None:
    now = db.now(conn)
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
        select(jobs).where(jobs.c.status == JobStatus.RUNNING, jobs.c.runner == runner).with_for_update()
    )
    for job in abandoned.all():
        _retry_or_fail(conn, job, "runner restarted during the job")
    next_id = (
        select(jobs.c.id)
        .where(jobs.c.status == JobStatus.QUEUED)
        .order_by(jobs.c.id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    return conn.execute(
        update(jobs)
        .where(jobs.c.id == next_id)
        .values(
            status=JobStatus.RUNNING,
            runner=runner,
            attempts=jobs.c.attempts + 1,
            started_at=func.now(),
            deadline_at=func.now() + DEADLINE,
        )
        .returning(jobs)
    ).first()


def complete(
    conn: Connection, job_id: int, runner: str, scan: Scan, scope: Scope, neighbours: Mapping[str, Neighbour]
) -> list[exposure.Finding]:
    """Record a runner's scan, finding changes, alerts, and the job outcome in one transaction.

    neighbours is the scanner host's neighbour table (pen16.neighbours). An up host gets the MAC there only if
    the kernel confirmed it after this job started, so an entry left from before can't be pinned on this scan.
    """
    job = _running(conn, job_id, runner)
    up = scan.up()
    seen = [
        {"address": address, "mac": n.mac, "confirmed_at": n.confirmed_at, "evidence_digest": scan.digest}
        for address in sorted(up)
        if (n := neighbours.get(address)) is not None and n.confirmed_at >= job.started_at
    ]
    if seen:
        conn.execute(postgresql_insert(mac_sightings).values(seen).on_conflict_do_nothing())
    opened = exposure.ingest(conn, scan, scope.networks, vantage="internal")
    for network in scope.networks:
        if str(network.gateway) in up:
            notify.clear_incident(
                conn,
                _gateway(network.name),
                f"Gateway of {network.name} answers again",
                f"Gateway {network.gateway} answered during job {job_id}.",
            )
        else:
            notify.raise_incident(
                conn,
                _gateway(network.name),
                f"Gateway of {network.name} didn't answer",
                f"Gateway {network.gateway} was down during job {job_id}, so closed ports in {network.cidr} "
                "resolve nothing until it answers.",
            )
    if job.schedule is not None:
        notify.clear_incident(
            conn, _scheduled(job.schedule), "Scheduled scans recovered", f"Scheduled job {job_id} succeeded."
        )
    conn.execute(
        update(jobs)
        .where(jobs.c.id == job_id)
        .values(status=JobStatus.SUCCEEDED, finished_at=func.now(), evidence_digest=scan.digest, error=None)
    )
    return opened


def fail(conn: Connection, job_id: int, runner: str, error: str) -> None:
    _retry_or_fail(conn, _running(conn, job_id, runner), error)


def expire(conn: Connection) -> None:
    """Retry or fail jobs past their deadline, and fail jobs no runner picked up."""
    now = db.now(conn)
    late = conn.execute(
        select(jobs)
        .where(jobs.c.status == JobStatus.RUNNING, jobs.c.deadline_at < now)
        .with_for_update(skip_locked=True)
    )
    for job in late.all():
        _retry_or_fail(conn, job, "missed its deadline")
    unclaimed = conn.execute(
        select(jobs)
        .where(jobs.c.status == JobStatus.QUEUED, jobs.c.created_at < now - UNCLAIMED)
        .with_for_update(skip_locked=True)
    )
    for job in unclaimed.all():
        _finish_failed(conn, job, "no runner claimed it")


def _running(conn: Connection, job_id: int, runner: str) -> Row[Any]:
    job = conn.execute(
        select(jobs)
        .where(
            jobs.c.id == job_id,
            jobs.c.status == JobStatus.RUNNING,
            jobs.c.runner == runner,
            jobs.c.deadline_at > func.now(),
        )
        .with_for_update()
    ).first()
    if job is None:
        raise StaleJobError(f"job {job_id} isn't running on runner {runner!r}")
    return job


def _retry_or_fail(conn: Connection, job: Row[Any], error: str) -> None:
    if job.attempts < MAX_ATTEMPTS:
        log.warning("job %s: %s; retrying", job.id, error)
        conn.execute(
            update(jobs)
            .where(jobs.c.id == job.id)
            .values(status=JobStatus.QUEUED, runner=None, started_at=None, deadline_at=None, error=error)
        )
        return
    _finish_failed(conn, job, error)


def _finish_failed(conn: Connection, job: Row[Any], error: str) -> None:
    """Fail the job for good. A requested scan's failure shows on the dashboard; a schedule alerts once its
    last FAILED_WINDOWS runs have all failed, so one bad night stays quiet."""
    log.warning("job %s failed: %s", job.id, error)
    conn.execute(
        update(jobs)
        .where(jobs.c.id == job.id)
        .values(status=JobStatus.FAILED, finished_at=func.now(), error=error)
    )
    if job.schedule is None:
        return
    recent = conn.scalars(
        select(jobs.c.status)
        .where(jobs.c.schedule == job.schedule, jobs.c.status.in_([JobStatus.SUCCEEDED, JobStatus.FAILED]))
        .order_by(jobs.c.finished_at.desc(), jobs.c.id.desc())
        .limit(FAILED_WINDOWS)
    ).all()
    if len(recent) == FAILED_WINDOWS and all(status == JobStatus.FAILED for status in recent):
        notify.raise_incident(
            conn,
            _scheduled(job.schedule),
            "Scheduled scans are failing",
            f"The last {FAILED_WINDOWS} {job.schedule} scans failed. Job {job.id}: {error}",
        )


def _gateway(network: str) -> str:
    """The incident key for a network whose gateway didn't answer."""
    return f"gateway:{network}"


def _scheduled(schedule: str) -> str:
    """The incident key for a schedule whose runs keep failing."""
    return f"schedule:{schedule}"
