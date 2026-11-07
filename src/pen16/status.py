"""What the owner sees: monitoring health, findings, exposure and compliance, read as typed records. The dashboard
renders these, and the read API will serve the same ones."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import ColumnElement, Connection, Row, ScalarSelect, Text, cast, exists, func, or_, select
from sqlalchemy.dialects.postgresql import distinct_on

from pen16 import backups, compliance, db, worker
from pen16.db import (
    BindingChange,
    DecisionKind,
    FindingChange,
    FindingStatus,
    JobStatus,
    NotificationStatus,
    ObservationState,
    TokenKind,
    assets,
    binding_events,
    bindings,
    decisions,
    expected_services,
    finding_events,
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
# How many service changes, and how many address changes, the Recent changes view lists.
RECENT_CHANGES = 100


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
    # The device isn't at the address this was seen at any more: another took it over, or it was retired.
    away: bool


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
    # The device this one took the address over from, when a different MAC answered there.
    took_over_from: str | None
    # Whether either MAC was a private one, so it may be the same device after all.
    took_over_private: bool


@dataclass(frozen=True)
class Device:
    """A named device that isn't retired, with each address it's at and the MAC that answers there."""

    id: str
    addresses: list[tuple[str, str | None]]


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
    devices: list[Device]
    compliance: list[HostCompliance]


@dataclass(frozen=True)
class Address:
    address: str
    mac: str | None
    bound_at: datetime


@dataclass(frozen=True)
class Service:
    """A device's service at an address, as the latest observation of it saw it: open or filtered."""

    address: str
    protocol: str
    port: int
    vantage: str
    state: ObservationState
    service: str | None
    product: str | None
    version: str | None
    observed_at: datetime
    # The device is still at that address.
    here: bool
    expected: str | None


@dataclass(frozen=True)
class AssetFinding:
    id: int
    protocol: str
    port: int
    vantage: str
    status: FindingStatus
    opened_at: datetime
    resolved_at: datetime | None
    resolution: str | None
    decision: DecisionKind | None


@dataclass(frozen=True)
class Event:
    """One entry in a device's history: what happened, who did it (the owner, or a scan), and why."""

    at: datetime
    what: str
    by: str | None
    reason: str | None


@dataclass(frozen=True)
class Asset:
    """One device: where it is, what it runs, what's expected of it, its findings, and everything that changed."""

    id: str
    provisional: bool
    created_at: datetime
    # The device this one took the address over from, and whether either MAC was a private one, so it may be
    # the same device after all.
    took_over_from: str | None
    took_over_private: bool
    retired_at: datetime | None
    retirement: str | None
    addresses: list[Address]
    services: list[Service]
    expected: list[Expected]
    findings: list[AssetFinding]
    history: list[Event]


@dataclass(frozen=True)
class Evidence:
    """One observation: what a scan saw on a port, and the record it came from."""

    id: int
    asset_id: str
    address: str
    # The MAC that answered at the address during that scan, if the scanner host saw one.
    mac: str | None
    state: ObservationState
    service: str | None
    product: str | None
    version: str | None
    observed_at: datetime
    tool_version: str
    parser_version: str
    evidence_digest: str


@dataclass(frozen=True)
class StatusChange:
    at: datetime
    change: FindingChange
    by: str
    reason: str | None
    # The observation a scan changed it on.
    evidence: Evidence | None


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    reason: str
    decided_by: str
    decided_at: datetime
    # The service it was decided on.
    service: str | None
    product: str | None
    version: str | None
    withdrawn_at: datetime | None
    withdrawal: str | None


@dataclass(frozen=True)
class FindingDetail:
    """A finding with the evidence behind its state, every change to it, and every decision about it."""

    id: int
    kind: str
    asset_id: str
    protocol: str
    port: int
    vantage: str
    status: FindingStatus
    opened_at: datetime
    resolved_at: datetime | None
    resolution: str | None
    last: Evidence
    away: bool
    changes: list[StatusChange]
    decisions: list[Decision]


class Difference(StrEnum):
    """How a service differs from the observation of it before."""

    NEW = "new"
    REMOVED = "removed"
    CHANGED = "changed"


@dataclass(frozen=True)
class Observed:
    state: ObservationState
    service: str | None
    product: str | None
    version: str | None


@dataclass(frozen=True)
class ServiceChange:
    """A service that opened, closed, or changed between one observation of it and the next."""

    at: datetime
    asset_id: str
    address: str
    protocol: str
    port: int
    vantage: str
    difference: Difference
    before: Observed | None
    now: Observed


@dataclass(frozen=True)
class AddressChange:
    at: datetime
    address: str
    asset_id: str
    mac: str | None
    change: BindingChange
    by: str
    reason: str | None
    # False for a provisional device since named or merged away: the name is history only.
    known: bool


@dataclass(frozen=True)
class RecentChanges:
    services: list[ServiceChange]
    addresses: list[AddressChange]


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
        devices=devices(conn),
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
    here = exists().where(bindings.c.address == seen.c.address, bindings.c.asset_id == findings.c.asset_id)
    rows = conn.execute(
        select(findings, *_seen_columns(seen), withdrawn.label("withdrawal"), here.label("here"))
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
            not row.here,
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
    """Every service whose latest observation saw it open on a device still at that address, with why it's
    expected if it is. A device that left or was retired has nothing reachable."""
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
        .where(
            latest.c.state == ObservationState.OPEN,
            exists().where(bindings.c.address == latest.c.address, bindings.c.asset_id == latest.c.asset_id),
        )
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
            assets.c.id,
            assets.c.took_over_from,
            assets.c.took_over_private,
            func.host(bindings.c.address).label("address"),
            cast(bindings.c.mac, Text).label("mac"),
        )
        .join(bindings, bindings.c.asset_id == assets.c.id)
        .where(assets.c.provisional)
        .order_by(bindings.c.address)
    )
    return [Unnamed(row.id, row.address, row.mac, row.took_over_from, row.took_over_private) for row in rows]


def devices(conn: Connection) -> list[Device]:
    """Named devices that aren't retired, compliance hosts with no address included."""
    rows = conn.execute(
        select(
            assets.c.id,
            func.host(bindings.c.address).label("address"),
            cast(bindings.c.mac, Text).label("mac"),
        )
        .outerjoin(bindings, bindings.c.asset_id == assets.c.id)
        .where(~assets.c.provisional, assets.c.retired_at.is_(None))
        .order_by(assets.c.id, bindings.c.address)
    )
    named: dict[str, list[tuple[str, str | None]]] = {}
    for row in rows:
        addresses = named.setdefault(row.id, [])
        if row.address is not None:
            addresses.append((row.address, row.mac))
    return [Device(name, addresses) for name, addresses in named.items()]


def asset(conn: Connection, asset_id: str) -> Asset | None:
    """One device's page, or None if there's no such device. Provisional and retired devices have one too."""
    row = conn.execute(select(assets).where(assets.c.id == asset_id)).first()
    if row is None:
        return None
    addresses = conn.execute(
        select(
            func.host(bindings.c.address).label("address"),
            cast(bindings.c.mac, Text).label("mac"),
            bindings.c.bound_at,
        )
        .where(bindings.c.asset_id == asset_id)
        .order_by(bindings.c.address)
    )
    expected = conn.execute(
        select(expected_services)
        .where(expected_services.c.asset_id == asset_id, expected_services.c.ended_at.is_(None))
        .order_by(expected_services.c.protocol, expected_services.c.port, expected_services.c.vantage)
    )
    owned = conn.execute(
        select(findings, decisions.c.kind.label("decision"))
        .outerjoin(decisions, _active_decision())
        .where(findings.c.asset_id == asset_id)
        # Open sorts before resolved.
        .order_by(findings.c.status, findings.c.protocol, findings.c.port, findings.c.vantage)
    )
    return Asset(
        id=row.id,
        provisional=row.provisional,
        created_at=row.created_at,
        took_over_from=row.took_over_from,
        took_over_private=row.took_over_private,
        retired_at=row.retired_at,
        retirement=row.retirement,
        addresses=[Address(a.address, a.mac, a.bound_at) for a in addresses],
        services=_services(conn, asset_id),
        expected=[Expected(e.asset_id, e.protocol, e.port, e.vantage, e.reason) for e in expected],
        findings=[
            AssetFinding(
                f.id,
                f.protocol,
                f.port,
                f.vantage,
                FindingStatus(f.status),
                f.opened_at,
                f.resolved_at,
                f.resolution,
                DecisionKind(f.decision) if f.decision else None,
            )
            for f in owned
        ],
        history=_history(conn, row),
    )


def finding(conn: Connection, finding_id: int) -> FindingDetail | None:
    """One finding's page, or None if there's no such finding."""
    row = conn.execute(select(findings).where(findings.c.id == finding_id)).first()
    if row is None:
        return None
    events = conn.execute(
        select(finding_events).where(finding_events.c.finding_id == finding_id).order_by(finding_events.c.id)
    ).all()
    evidence = _evidence(
        conn, {row.last_observation_id} | {e.observation_id for e in events if e.observation_id is not None}
    )
    last = evidence[row.last_observation_id]
    here = conn.scalar(
        select(exists().where(bindings.c.address == last.address, bindings.c.asset_id == row.asset_id))
    )
    made = conn.execute(
        select(decisions).where(decisions.c.finding_id == finding_id).order_by(decisions.c.decided_at)
    )
    return FindingDetail(
        id=row.id,
        kind=row.kind,
        asset_id=row.asset_id,
        protocol=row.protocol,
        port=row.port,
        vantage=row.vantage,
        status=FindingStatus(row.status),
        opened_at=row.opened_at,
        resolved_at=row.resolved_at,
        resolution=row.resolution,
        last=last,
        away=not here,
        changes=[
            StatusChange(
                e.at,
                FindingChange(e.change),
                e.by,
                e.reason,
                evidence[e.observation_id] if e.observation_id is not None else None,
            )
            for e in events
        ],
        decisions=[
            Decision(
                DecisionKind(d.kind),
                d.reason,
                d.decided_by,
                d.decided_at,
                d.service,
                d.product,
                d.version,
                d.withdrawn_at,
                d.withdrawal,
            )
            for d in made
        ],
    )


def recent_changes(conn: Connection) -> RecentChanges:
    """The latest services that opened, closed, or changed what they run, and the latest changes to which device
    is at an address, newest first.

    Each observation is compared with the ones before it of the same service on the same device and address. A
    field the scan didn't report isn't a change, as with decisions: a scan without version detection says
    nothing about the version, so each field is compared with the last value a scan reported for it.
    """
    fields = ("service", "product", "version")
    o = observations.c
    key = (o.asset_id, o.address, o.protocol, o.port, o.vantage)
    # Each field's count of reported values so far numbers its runs: a reported value and the unreported ones
    # after it share a number, so the run's maximum is that value carried forward.
    numbered = select(
        *key,
        o.id,
        o.state,
        o.observed_at,
        *(o[field] for field in fields),
        *(
            func.count(o[field]).over(partition_by=key, order_by=(o.observed_at, o.id)).label(f"run_{field}")
            for field in fields
        ),
    ).subquery()
    n = numbered.c
    n_key = (n.asset_id, n.address, n.protocol, n.port, n.vantage)
    carried = select(
        *n_key,
        n.id,
        n.state,
        n.observed_at,
        *(n[field] for field in fields),
        *(
            func.max(n[field]).over(partition_by=(*n_key, n[f"run_{field}"])).label(f"known_{field}")
            for field in fields
        ),
    ).subquery()
    c = carried.c
    c_key = (c.asset_id, c.address, c.protocol, c.port, c.vantage)

    def before(column: ColumnElement[Any]) -> ColumnElement[Any]:
        return func.lag(column).over(partition_by=c_key, order_by=(c.observed_at, c.id))

    history = select(
        *c_key,
        c.state,
        c.observed_at,
        *(c[field] for field in fields),
        before(c.state).label("was_state"),
        *(before(c[f"known_{field}"]).label(f"was_{field}") for field in fields),
    ).subquery()
    h = history.c
    opened = (h.state == ObservationState.OPEN) & or_(
        h.was_state.is_(None), h.was_state != ObservationState.OPEN
    )
    left = (h.was_state == ObservationState.OPEN) & (h.state != ObservationState.OPEN)
    differs = or_(*(h[field].is_not(None) & h[field].is_distinct_from(h[f"was_{field}"]) for field in fields))
    changed = (h.state == ObservationState.OPEN) & (h.was_state == ObservationState.OPEN) & differs
    rows = conn.execute(
        select(history)
        .where(or_(opened, left, changed))
        .order_by(h.observed_at.desc(), h.asset_id, h.protocol, h.port)
        .limit(RECENT_CHANGES)
    )
    services = []
    for row in rows:
        now = Observed(ObservationState(row.state), row.service, row.product, row.version)
        before_it = (
            Observed(ObservationState(row.was_state), row.was_service, row.was_product, row.was_version)
            if row.was_state is not None
            else None
        )
        if now.state == ObservationState.OPEN and (
            before_it is None or before_it.state != ObservationState.OPEN
        ):
            difference = Difference.NEW
        elif now.state == ObservationState.CLOSED:
            difference = Difference.REMOVED
        else:
            difference = Difference.CHANGED
        services.append(
            ServiceChange(
                row.observed_at,
                row.asset_id,
                str(row.address),
                row.protocol,
                row.port,
                row.vantage,
                difference,
                before_it,
                now,
            )
        )
    addresses = conn.execute(
        select(
            binding_events.c.at,
            func.host(binding_events.c.address).label("address"),
            binding_events.c.asset_id,
            cast(binding_events.c.mac, Text).label("mac"),
            binding_events.c.change,
            binding_events.c.by,
            binding_events.c.reason,
            exists().where(assets.c.id == binding_events.c.asset_id).label("known"),
        )
        .order_by(binding_events.c.at.desc(), binding_events.c.id.desc())
        .limit(RECENT_CHANGES)
    )
    return RecentChanges(
        services,
        [
            AddressChange(
                a.at, a.address, a.asset_id, a.mac, BindingChange(a.change), a.by, a.reason, a.known
            )
            for a in addresses
        ],
    )


def _services(conn: Connection, asset_id: str) -> list[Service]:
    """The device's services whose latest observation at an address saw them open or filtered."""
    latest = (
        select(observations)
        .ext(
            distinct_on(
                observations.c.address, observations.c.protocol, observations.c.port, observations.c.vantage
            )
        )
        .where(observations.c.asset_id == asset_id)
        .order_by(
            observations.c.address,
            observations.c.protocol,
            observations.c.port,
            observations.c.vantage,
            observations.c.observed_at.desc(),
            observations.c.id.desc(),
        )
        .subquery()
    )
    expected = expected_services.alias("expected")
    here = exists().where(bindings.c.address == latest.c.address, bindings.c.asset_id == latest.c.asset_id)
    rows = conn.execute(
        select(latest, expected.c.reason, here.label("here"))
        .outerjoin(
            expected,
            (expected.c.asset_id == latest.c.asset_id)
            & (expected.c.protocol == latest.c.protocol)
            & (expected.c.port == latest.c.port)
            & (expected.c.vantage == latest.c.vantage)
            & expected.c.ended_at.is_(None),
        )
        .where(latest.c.state != ObservationState.CLOSED)
        .order_by(latest.c.address, latest.c.protocol, latest.c.port)
    )
    return [
        Service(
            str(row.address),
            row.protocol,
            row.port,
            row.vantage,
            ObservationState(row.state),
            row.service,
            row.product,
            row.version,
            row.observed_at,
            row.here,
            row.reason,
        )
        for row in rows
    ]


def _history(conn: Connection, device: Row[Any]) -> list[Event]:
    """Everything that happened to a device, newest first: its addresses, intent, findings and decisions."""
    events = []
    for b in conn.execute(
        select(
            binding_events.c.at,
            func.host(binding_events.c.address).label("address"),
            cast(binding_events.c.mac, Text).label("mac"),
            binding_events.c.change,
            binding_events.c.by,
            binding_events.c.reason,
        ).where(binding_events.c.asset_id == device.id)
    ):
        what = {
            BindingChange.BOUND: f"at {b.address}",
            BindingChange.LEARNED: f"{b.mac} answered at {b.address}",
            BindingChange.ENDED: f"no longer at {b.address}",
        }[BindingChange(b.change)]
        events.append(Event(b.at, what, b.by, b.reason))
    for e in conn.execute(select(expected_services).where(expected_services.c.asset_id == device.id)):
        service = f"{e.port}/{e.protocol}"
        events.append(Event(e.created_at, f"expected {service}", e.declared_by, e.reason))
        if e.ended_at is not None:
            events.append(Event(e.ended_at, f"stopped expecting {service}", e.ended_by, e.end_reason))
    events.extend(
        Event(f.at, f"{f.port}/{f.protocol} {f.change}", f.by, f.reason)
        for f in conn.execute(
            select(finding_events, findings.c.protocol, findings.c.port)
            .join(findings, findings.c.id == finding_events.c.finding_id)
            .where(findings.c.asset_id == device.id)
        )
    )
    for d in conn.execute(
        select(decisions, findings.c.protocol, findings.c.port)
        .join(findings, findings.c.id == decisions.c.finding_id)
        .where(findings.c.asset_id == device.id)
    ):
        decided = f"{d.port}/{d.protocol} {DecisionKind(d.kind).label}"
        events.append(Event(d.decided_at, decided, d.decided_by, d.reason))
        if d.withdrawn_at is not None:
            events.append(Event(d.withdrawn_at, f"{decided} withdrawn", None, d.withdrawal))
    events.append(Event(device.created_at, "first seen" if device.provisional else "added", None, None))
    if device.retired_at is not None:
        events.append(Event(device.retired_at, "retired", device.retired_by, device.retirement))
    return sorted(events, key=lambda event: event.at, reverse=True)


def _evidence(conn: Connection, observation_ids: Iterable[int]) -> dict[int, Evidence]:
    rows = conn.execute(
        select(observations, cast(mac_sightings.c.mac, Text).label("mac"))
        .outerjoin(
            mac_sightings,
            (mac_sightings.c.evidence_digest == observations.c.evidence_digest)
            & (mac_sightings.c.address == observations.c.address),
        )
        .where(observations.c.id.in_(list(observation_ids)))
    )
    return {
        row.id: Evidence(
            row.id,
            row.asset_id,
            str(row.address),
            row.mac,
            ObservationState(row.state),
            row.service,
            row.product,
            row.version,
            row.observed_at,
            row.tool_version,
            row.parser_version,
            row.evidence_digest,
        )
        for row in rows
    }


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
