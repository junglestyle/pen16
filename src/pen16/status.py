"""What the owner sees: monitoring health, findings, exposure and compliance, read as typed records. The dashboard
renders these, and the read API will serve the same ones."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, Connection, Row, ScalarSelect, Text, cast, exists, func, select
from sqlalchemy.dialects.postgresql import distinct_on

from pen16 import backups, compliance, db, worker
from pen16.db import (
    DecisionKind,
    FindingStatus,
    JobStatus,
    NotificationStatus,
    ObservationState,
    TokenKind,
    assets,
    bindings,
    decisions,
    expected_services,
    findings,
    heartbeats,
    incidents,
    jobs,
    mac_sightings,
    notifications,
    observations,
    schedules,
    tokens,
)

# A nightly scan older than this is stale.
SCANS_STALE = timedelta(hours=48)
# The worker ticks every 15 seconds; this long without one means it has stopped.
WORKER_STALE = timedelta(minutes=2)
RECENTLY_RESOLVED = 20


@dataclass(frozen=True)
class Seen:
    """A service as a finding's last observation saw it."""

    address: str
    mac: str | None
    service: str | None
    product: str | None
    version: str | None
    observed_at: datetime


@dataclass(frozen=True)
class OpenFinding:
    id: int
    asset_id: str
    protocol: str
    port: int
    vantage: str
    opened_at: datetime
    seen: Seen
    # What changed, when a scan withdrew the owner's decision and brought it back.
    withdrawal: str | None


@dataclass(frozen=True)
class DecidedFinding:
    id: int
    asset_id: str
    protocol: str
    port: int
    resolved: bool
    seen: Seen
    decision_id: int
    kind: DecisionKind
    reason: str
    decided_at: datetime


@dataclass(frozen=True)
class ResolvedFinding:
    id: int
    asset_id: str
    protocol: str
    port: int
    resolved_at: datetime
    resolution: str | None
    seen: Seen


@dataclass(frozen=True)
class Exposed:
    """An open service as the latest observation of it saw it, and the reason it's expected, if it is."""

    asset_id: str
    address: str
    protocol: str
    port: int
    service: str | None
    product: str | None
    version: str | None
    observed_at: datetime
    expected: str | None


@dataclass(frozen=True)
class Expected:
    asset_id: str
    protocol: str
    port: int
    vantage: str
    reason: str


@dataclass(frozen=True)
class Unnamed:
    id: str
    address: str
    mac: str | None


@dataclass(frozen=True)
class Incident:
    title: str
    detail: str
    opened_at: datetime


@dataclass(frozen=True)
class Job:
    id: int
    status: JobStatus
    error: str | None


@dataclass(frozen=True)
class Health:
    now: datetime
    last_scan: datetime | None
    scans_stale: bool
    latest_job: Job | None
    next_run: datetime | None
    runner_seen: datetime | None
    worker_seen: datetime | None
    worker_stale: bool
    last_backup: datetime | None
    backup_stale: bool
    alerts_pending: int
    alerts_failed: int
    incidents: list[Incident]


@dataclass(frozen=True)
class HostCompliance:
    result: compliance.Latest
    rate: str
    stale: bool
    failing: list[compliance.FailingRule]
    checklist: bool


@dataclass(frozen=True)
class Dashboard:
    health: Health
    needs_attention: list[OpenFinding]
    decided: list[DecidedFinding]
    resolved: list[ResolvedFinding]
    exposed: list[Exposed]
    expected: list[Expected]
    unnamed: list[Unnamed]
    compliance: list[HostCompliance]


def dashboard(conn: Connection) -> Dashboard:
    now = db.now(conn)
    return Dashboard(
        health=health(conn, now),
        needs_attention=needs_attention(conn),
        decided=decided(conn),
        resolved=resolved(conn),
        exposed=exposed(conn),
        expected=[
            Expected(row.asset_id, row.protocol, row.port, row.vantage, row.reason)
            for row in conn.execute(
                select(expected_services)
                .where(expected_services.c.ended_at.is_(None))
                .order_by(
                    expected_services.c.asset_id, expected_services.c.protocol, expected_services.c.port
                )
            )
        ],
        unnamed=unnamed(conn),
        compliance=[
            HostCompliance(
                result=result,
                rate=compliance.pass_rate(result.passed, result.failed),
                stale=now - result.received_at > compliance.STALE,
                failing=compliance.failing(conn, result.scan_id),
                checklist=compliance.matching_stig(conn, result.scan_id) is not None,
            )
            for result in compliance.latest(conn)
        ],
    )


def health(conn: Connection, now: datetime) -> Health:
    last_scan = conn.scalar(select(func.max(jobs.c.finished_at)).where(jobs.c.status == JobStatus.SUCCEEDED))
    latest = conn.execute(
        select(jobs.c.id, jobs.c.status, jobs.c.error).order_by(jobs.c.id.desc()).limit(1)
    ).first()
    worker_seen = conn.scalar(select(heartbeats.c.at).where(heartbeats.c.component == worker.COMPONENT))
    last_backup = backups.latest(conn)
    return Health(
        now=now,
        last_scan=last_scan,
        scans_stale=last_scan is None or now - last_scan > SCANS_STALE,
        latest_job=None if latest is None else Job(latest.id, JobStatus(latest.status), latest.error),
        next_run=conn.scalar(select(func.min(schedules.c.next_run_at)).where(schedules.c.enabled)),
        runner_seen=conn.scalar(
            select(func.max(tokens.c.last_used_at)).where(tokens.c.kind == TokenKind.RUNNER)
        ),
        worker_seen=worker_seen,
        worker_stale=worker_seen is None or now - worker_seen > WORKER_STALE,
        last_backup=last_backup,
        backup_stale=last_backup is None or now - last_backup > backups.STALE,
        alerts_pending=_alerts(conn, NotificationStatus.PENDING),
        alerts_failed=_alerts(conn, NotificationStatus.FAILED),
        incidents=[
            Incident(row.title, row.detail, row.opened_at)
            for row in conn.execute(
                select(incidents).where(incidents.c.cleared_at.is_(None)).order_by(incidents.c.opened_at)
            )
        ],
    )


def needs_attention(conn: Connection) -> list[OpenFinding]:
    """Open findings the owner hasn't decided about, newest first."""
    seen = observations.alias("seen")
    # The latest withdrawn decision, shown on a finding that's back in Needs attention.
    withdrawn = (
        select(decisions.c.withdrawal)
        .where(decisions.c.finding_id == findings.c.id, decisions.c.withdrawn_at.is_not(None))
        .order_by(decisions.c.withdrawn_at.desc())
        .limit(1)
        .scalar_subquery()
    )
    rows = conn.execute(
        select(findings, *_seen_columns(seen), withdrawn.label("withdrawal"))
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .where(findings.c.status == FindingStatus.OPEN, ~exists().where(_active_decision()))
        .order_by(findings.c.opened_at.desc())
    )
    return [
        OpenFinding(
            row.id,
            row.asset_id,
            row.protocol,
            row.port,
            row.vantage,
            row.opened_at,
            _seen(row),
            row.withdrawal,
        )
        for row in rows
    ]


def decided(conn: Connection) -> list[DecidedFinding]:
    """Findings with an active accepted-risk or false-positive decision."""
    seen = observations.alias("seen")
    rows = conn.execute(
        select(
            findings,
            *_seen_columns(seen),
            decisions.c.id.label("decision_id"),
            decisions.c.kind.label("decision_kind"),
            decisions.c.reason,
            decisions.c.decided_at,
        )
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .join(decisions, _active_decision())
        .order_by(findings.c.asset_id, findings.c.protocol, findings.c.port)
    )
    return [
        DecidedFinding(
            row.id,
            row.asset_id,
            row.protocol,
            row.port,
            row.status == FindingStatus.RESOLVED,
            _seen(row),
            row.decision_id,
            DecisionKind(row.decision_kind),
            row.reason,
            row.decided_at,
        )
        for row in rows
    ]


def resolved(conn: Connection) -> list[ResolvedFinding]:
    """The most recently resolved findings."""
    seen = observations.alias("seen")
    rows = conn.execute(
        select(findings, *_seen_columns(seen))
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .where(findings.c.status == FindingStatus.RESOLVED)
        .order_by(findings.c.resolved_at.desc())
        .limit(RECENTLY_RESOLVED)
    )
    return [
        ResolvedFinding(
            row.id, row.asset_id, row.protocol, row.port, row.resolved_at, row.resolution, _seen(row)
        )
        for row in rows
    ]


def exposed(conn: Connection) -> list[Exposed]:
    """Every service whose latest observation saw it open, with why it's expected if it is."""
    latest = (
        select(observations)
        .ext(
            distinct_on(
                observations.c.asset_id, observations.c.protocol, observations.c.port, observations.c.vantage
            )
        )
        .order_by(
            observations.c.asset_id,
            observations.c.protocol,
            observations.c.port,
            observations.c.vantage,
            observations.c.observed_at.desc(),
        )
        .subquery()
    )
    expected = expected_services.alias("expected")
    rows = conn.execute(
        select(latest, expected.c.reason)
        .outerjoin(
            expected,
            (expected.c.asset_id == latest.c.asset_id)
            & (expected.c.protocol == latest.c.protocol)
            & (expected.c.port == latest.c.port)
            & (expected.c.vantage == latest.c.vantage)
            & expected.c.ended_at.is_(None),
        )
        .where(latest.c.state == ObservationState.OPEN)
        .order_by(latest.c.asset_id, latest.c.protocol, latest.c.port)
    )
    return [
        Exposed(
            row.asset_id,
            str(row.address),
            row.protocol,
            row.port,
            row.service,
            row.product,
            row.version,
            row.observed_at,
            row.reason,
        )
        for row in rows
    ]


def unnamed(conn: Connection) -> list[Unnamed]:
    """Provisional devices. Each is one address, so one row each."""
    rows = conn.execute(
        select(
            assets.c.id, func.host(bindings.c.address).label("address"), _mac(bindings.c.address).label("mac")
        )
        .join(bindings, bindings.c.asset_id == assets.c.id)
        .where(assets.c.provisional)
        .order_by(bindings.c.address)
    )
    return [Unnamed(row.id, row.address, row.mac) for row in rows]


def _active_decision() -> ColumnElement[bool]:
    return (decisions.c.finding_id == findings.c.id) & decisions.c.withdrawn_at.is_(None)


def _seen_columns(seen: Any) -> tuple[ColumnElement[Any], ...]:
    return (
        seen.c.address.label("seen_address"),
        _mac(seen.c.address).label("seen_mac"),
        seen.c.service.label("seen_service"),
        seen.c.product.label("seen_product"),
        seen.c.version.label("seen_version"),
        seen.c.observed_at.label("seen_at"),
    )


def _seen(row: Row[Any]) -> Seen:
    return Seen(
        str(row.seen_address), row.seen_mac, row.seen_service, row.seen_product, row.seen_version, row.seen_at
    )


def _mac(address: ColumnElement[Any]) -> ScalarSelect[str]:
    """The MAC most recently seen at an address, if any scan saw one."""
    return (
        select(cast(mac_sightings.c.mac, Text))
        .where(mac_sightings.c.address == address)
        .order_by(mac_sightings.c.confirmed_at.desc())
        .limit(1)
        .scalar_subquery()
    )


def _alerts(conn: Connection, status: NotificationStatus) -> int:
    return int(
        conn.scalar(select(func.count()).select_from(notifications).where(notifications.c.status == status))
        or 0
    )
