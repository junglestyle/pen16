import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Connection, delete, exists, func, select, update
from sqlalchemy.dialects.postgresql import insert

from pen16 import notify
from pen16.db import (
    DecisionKind,
    FindingChange,
    FindingStatus,
    NotificationKind,
    ObservationState,
    assets,
    bindings,
    decisions,
    expected_services,
    finding_events,
    findings,
    observations,
)
from pen16.nmap import PARSER_VERSION, Port, Scan
from pen16.scope import Network

UNEXPECTED_EXPOSURE = "unexpected-exposure"
ASSET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
# Who changed a finding when no person did.
SCAN = "scan"


@dataclass(frozen=True)
class Finding:
    asset_id: str
    protocol: str
    port: int
    vantage: str
    # Why it needs attention again, when a scan withdrew the owner's decision about it.
    why: str | None = None


def ingest(conn: Connection, scan: Scan, networks: Sequence[Network], vantage: str) -> list[Finding]:
    """Record a scan's observations, open findings for unexpected open ports, resolve closed ones, and queue one
    alert for what's news.

    Returns the findings this scan newly opened or reopened, and those whose decision it withdrew: the ones
    alerted. A finding the owner decided about stays quiet while the service matches what they decided on. Run
    it inside one transaction, so the observations, finding changes and alert land together. Re-ingesting the
    same evidence changes nothing.

    A closed port resolves a finding only inside a network whose gateway answered this scan: without it, a
    closed port can't be told from a network that was down.
    """
    opened = []
    for port in scan.ports:
        asset_id = _asset_for(conn, port.address)
        observation_id = _observe(conn, scan, port, asset_id, vantage)
        if observation_id is None or port.state != ObservationState.OPEN:
            continue
        if _expected(conn, asset_id, port.protocol, port.port, vantage):
            continue
        finding_id, alert = _open(conn, asset_id, port, vantage, scan.finished_at, observation_id)
        decision = _active_decision(conn, finding_id)
        if decision is not None:
            change = _material_change(decision, port)
            if change is None:
                continue
            withdraw(conn, decision.id, change)
            why = f"{decision.kind.label} withdrawn: {change}"
            opened.append(Finding(asset_id, port.protocol, port.port, vantage, why))
        elif alert:
            opened.append(Finding(asset_id, port.protocol, port.port, vantage))
    up = scan.up()
    _close(conn, scan, vantage, [network for network in networks if str(network.gateway) in up])
    if opened:
        lines = [f"{f.asset_id} {f.port}/{f.protocol}" + (f": {f.why}" if f.why else "") for f in opened]
        notify.enqueue(
            conn, NotificationKind.FINDING, f"{len(opened)} unexpected service(s)", "\n".join(lines)
        )
    return opened


def expect(conn: Connection, finding_ids: list[int], reason: str, by: str) -> None:
    """Declare the services behind these findings expected, and resolve the findings."""
    if not reason.strip():
        raise ValueError("expected exposure needs a reason")
    rows = conn.execute(
        select(findings.c.asset_id, findings.c.protocol, findings.c.port, findings.c.vantage).where(
            findings.c.id.in_(finding_ids), findings.c.kind == UNEXPECTED_EXPOSURE
        )
    )
    for row in rows:
        conn.execute(
            insert(expected_services)
            .values(**row._asdict(), reason=reason.strip(), declared_by=by)
            .on_conflict_do_nothing(
                index_elements=["asset_id", "protocol", "port", "vantage"],
                index_where=expected_services.c.ended_at.is_(None),
            )
        )
    _resolve(conn, finding_ids, f"expected: {reason.strip()}", by)


def decide(
    conn: Connection, finding_ids: list[int], kind: DecisionKind, reason: str, decided_by: str
) -> None:
    """Accept the risk of these open findings, or mark them false positives, for the service seen now.

    They leave Needs attention and stop alerting until a scan sees a materially different service. Only named
    assets take decisions: a provisional asset is just an address, and a decision on it would pass to whatever
    device takes that address next.
    """
    if not reason.strip():
        raise ValueError("a decision needs a reason")
    seen = observations.alias("seen")
    rows = conn.execute(
        select(
            findings.c.id,
            findings.c.asset_id,
            assets.c.provisional,
            seen.c.service,
            seen.c.product,
            seen.c.version,
        )
        .join(assets, assets.c.id == findings.c.asset_id)
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .where(findings.c.id.in_(finding_ids), findings.c.status == FindingStatus.OPEN)
    ).all()
    unnamed = sorted({row.asset_id for row in rows if row.provisional})
    if unnamed:
        raise ValueError(f"name {', '.join(map(repr, unnamed))} first: decisions need a named device")
    for row in rows:
        active = _active_decision(conn, row.id)
        if active is not None:
            withdraw(conn, active.id, "replaced by a new decision")
        conn.execute(
            insert(decisions).values(
                finding_id=row.id,
                kind=kind,
                reason=reason.strip(),
                decided_by=decided_by,
                service=row.service,
                product=row.product,
                version=row.version,
            )
        )


def withdraw(conn: Connection, decision_id: int, why: str) -> None:
    """End a decision. Its finding, if still open, is back in Needs attention."""
    conn.execute(
        update(decisions)
        .where(decisions.c.id == decision_id, decisions.c.withdrawn_at.is_(None))
        .values(withdrawn_at=func.now(), withdrawal=why)
    )


def resolve(conn: Connection, finding_ids: list[int], reason: str, by: str) -> None:
    """Resolve open findings by hand, such as a filtered port or a device that's gone. A scan that sees the
    port open again reopens it."""
    if not reason.strip():
        raise ValueError("resolving by hand needs a reason")
    _resolve(conn, finding_ids, f"by hand: {reason.strip()}", by)


def reopen(conn: Connection, finding_id: int, by: str) -> None:
    """Put a resolved finding back in Needs attention. Its resolution stays in its history."""
    reopened = conn.scalars(
        update(findings)
        .where(findings.c.id == finding_id, findings.c.status == FindingStatus.RESOLVED)
        .values(status=FindingStatus.OPEN, resolved_at=None, resolution=None)
        .returning(findings.c.id)
    ).all()
    for reopened_id in reopened:
        _event(conn, reopened_id, FindingChange.REOPENED, by)


def unexpect(
    conn: Connection, asset_id: str, protocol: str, port: int, vantage: str, reason: str, by: str
) -> None:
    """Stop expecting a service. The next scan that sees it open reopens its finding."""
    if not reason.strip():
        raise ValueError("stopping expecting a service needs a reason")
    conn.execute(
        update(expected_services)
        .where(
            expected_services.c.asset_id == asset_id,
            expected_services.c.protocol == protocol,
            expected_services.c.port == port,
            expected_services.c.vantage == vantage,
            expected_services.c.ended_at.is_(None),
        )
        .values(ended_at=func.now(), ended_by=by, end_reason=reason.strip())
    )


def name_asset(conn: Connection, provisional_id: str, asset_id: str) -> None:
    """Give a provisional asset an owner-chosen ID, carrying its history and findings along.

    Only provisional assets can be renamed: they carry no owner decisions that a reused address could
    wrongly inherit. The name can't belong to another device. It can be a compliance host's, which has no
    address of its own until then: naming the device after it joins the two.
    """
    if not ASSET_ID.fullmatch(asset_id) or asset_id.startswith("new-"):
        raise ValueError(
            f"{asset_id!r} isn't an asset ID: lowercase letters, digits, and dashes, not starting with new-"
        )
    provisional = conn.scalar(select(assets.c.provisional).where(assets.c.id == provisional_id))
    if provisional is not True:
        raise ValueError(f"{provisional_id!r} isn't a provisional asset")
    if conn.scalar(select(exists().where(bindings.c.asset_id == asset_id))):
        raise ValueError(f"{asset_id!r} already names another device")
    conn.execute(insert(assets).values(id=asset_id, provisional=False).on_conflict_do_nothing())
    for table in (bindings, observations, findings, expected_services):
        conn.execute(update(table).where(table.c.asset_id == provisional_id).values(asset_id=asset_id))
    conn.execute(delete(assets).where(assets.c.id == provisional_id))


def _asset_for(conn: Connection, address: str) -> str:
    bound: str | None = conn.scalar(select(bindings.c.asset_id).where(bindings.c.address == address))
    if bound is not None:
        return bound
    asset_id = f"new-{address}"
    conn.execute(insert(assets).values(id=asset_id, provisional=True).on_conflict_do_nothing())
    conn.execute(insert(bindings).values(address=address, asset_id=asset_id))
    return asset_id


def _observe(conn: Connection, scan: Scan, port: Port, asset_id: str, vantage: str) -> int | None:
    observation_id: int | None = conn.scalar(
        insert(observations)
        .values(
            asset_id=asset_id,
            address=port.address,
            protocol=port.protocol,
            port=port.port,
            state=port.state,
            service=port.service,
            product=port.product,
            version=port.version,
            vantage=vantage,
            observed_at=scan.finished_at,
            tool_version=f"nmap {scan.nmap_version}",
            parser_version=PARSER_VERSION,
            evidence_digest=scan.digest,
        )
        .on_conflict_do_nothing()
        .returning(observations.c.id)
    )
    return observation_id


def _expected(conn: Connection, asset_id: str, protocol: str, port: int, vantage: str) -> bool:
    return (
        conn.scalar(
            select(expected_services.c.asset_id).where(
                expected_services.c.asset_id == asset_id,
                expected_services.c.protocol == protocol,
                expected_services.c.port == port,
                expected_services.c.vantage == vantage,
                expected_services.c.ended_at.is_(None),
            )
        )
        is not None
    )


@dataclass(frozen=True)
class _Decision:
    id: int
    kind: DecisionKind
    service: str | None
    product: str | None
    version: str | None


def _active_decision(conn: Connection, finding_id: int) -> _Decision | None:
    row = conn.execute(
        select(
            decisions.c.id, decisions.c.kind, decisions.c.service, decisions.c.product, decisions.c.version
        ).where(decisions.c.finding_id == finding_id, decisions.c.withdrawn_at.is_(None))
    ).first()
    if row is None:
        return None
    return _Decision(row.id, DecisionKind(row.kind), row.service, row.product, row.version)


def _material_change(decision: _Decision, port: Port) -> str | None:
    """What differs between the service a decision was made on and the one seen now, or None.

    A field the scan didn't report isn't a change: a scan without version detection says nothing about the
    version.
    """
    changes = []
    for field in ("service", "product", "version"):
        was, now = getattr(decision, field), getattr(port, field)
        if now is not None and now != was:
            changes.append(f"{field} changed from {was!r} to {now!r}" if was else f"{field} {now!r} appeared")
    return "; ".join(changes) or None


def _open(
    conn: Connection, asset_id: str, port: Port, vantage: str, observed_at: datetime, observation_id: int
) -> tuple[int, bool]:
    """Open, keep open, or reopen this service's finding. Returns its ID and whether that's news.

    Only evidence newer than the finding's last observation counts. A resolved finding's last observation is
    the one it was resolved on, closed by a scan or seen open before the owner resolved it by hand, so scanner
    time is only ever compared with scanner time.
    """
    key = (
        findings.c.kind == UNEXPECTED_EXPOSURE,
        findings.c.asset_id == asset_id,
        findings.c.protocol == port.protocol,
        findings.c.port == port.port,
        findings.c.vantage == vantage,
    )
    last = observations.alias("last")
    existing = conn.execute(
        select(findings.c.id, findings.c.status, last.c.observed_at.label("last_seen"))
        .join(last, last.c.id == findings.c.last_observation_id)
        .where(*key)
    ).first()
    if existing is None:
        finding_id: int = conn.scalar(
            insert(findings)
            .values(
                kind=UNEXPECTED_EXPOSURE,
                asset_id=asset_id,
                protocol=port.protocol,
                port=port.port,
                vantage=vantage,
                status=FindingStatus.OPEN,
                opened_at=observed_at,
                last_observation_id=observation_id,
            )
            .returning(findings.c.id)
        )
        _event(conn, finding_id, FindingChange.OPENED, SCAN, observation_id=observation_id)
        return finding_id, True
    if existing.last_seen >= observed_at:
        return existing.id, False
    if existing.status == FindingStatus.OPEN:
        conn.execute(update(findings).where(*key).values(last_observation_id=observation_id))
        return existing.id, False
    conn.execute(
        update(findings)
        .where(*key)
        .values(
            status=FindingStatus.OPEN, resolved_at=None, resolution=None, last_observation_id=observation_id
        )
    )
    _event(conn, existing.id, FindingChange.REOPENED, SCAN, observation_id=observation_id)
    return existing.id, True


def _close(conn: Connection, scan: Scan, vantage: str, trusted: Sequence[Network]) -> None:
    """Resolve open findings whose port this scan saw closed on every address bound to the asset, when every
    one of those addresses is in a trusted network."""
    last_open = observations.alias("last_open")
    rows = conn.execute(
        select(
            findings.c.id, findings.c.asset_id, findings.c.protocol, findings.c.port, last_open.c.observed_at
        )
        .join(last_open, last_open.c.id == findings.c.last_observation_id)
        .where(
            findings.c.kind == UNEXPECTED_EXPOSURE,
            findings.c.status == FindingStatus.OPEN,
            findings.c.vantage == vantage,
            last_open.c.observed_at < scan.finished_at,
        )
    )
    up = scan.up()
    for finding in rows.all():
        bound = conn.scalars(select(bindings.c.address).where(bindings.c.asset_id == finding.asset_id))
        addresses = [str(address) for address in bound]
        if not addresses or not all(
            address in up
            and any(ipaddress.IPv4Address(address) in network.cidr for network in trusted)
            and scan.state(address, finding.protocol, finding.port) == ObservationState.CLOSED
            for address in addresses
        ):
            continue
        for address in addresses:
            closed = Port(address, finding.protocol, finding.port, ObservationState.CLOSED, None, None, None)
            _observe(conn, scan, closed, finding.asset_id, vantage)
        closed_id = conn.scalar(
            select(observations.c.id).where(
                observations.c.evidence_digest == scan.digest,
                observations.c.asset_id == finding.asset_id,
                observations.c.protocol == finding.protocol,
                observations.c.port == finding.port,
                observations.c.vantage == vantage,
            )
        )
        conn.execute(
            update(findings)
            .where(findings.c.id == finding.id)
            .values(
                status=FindingStatus.RESOLVED,
                resolved_at=scan.finished_at,
                resolution="closed",
                last_observation_id=closed_id,
            )
        )
        _event(conn, finding.id, FindingChange.RESOLVED, SCAN, "closed", closed_id)


def _resolve(conn: Connection, finding_ids: list[int], resolution: str, by: str) -> None:
    """Resolve the open ones of these findings by an owner's hand, recording why in their history."""
    resolved = conn.scalars(
        update(findings)
        .where(findings.c.id.in_(finding_ids), findings.c.status == FindingStatus.OPEN)
        .values(status=FindingStatus.RESOLVED, resolved_at=func.now(), resolution=resolution)
        .returning(findings.c.id)
    ).all()
    for finding_id in resolved:
        _event(conn, finding_id, FindingChange.RESOLVED, by, resolution)


def _event(
    conn: Connection,
    finding_id: int,
    change: FindingChange,
    by: str,
    reason: str | None = None,
    observation_id: int | None = None,
) -> None:
    conn.execute(
        insert(finding_events).values(
            finding_id=finding_id, change=change, by=by, reason=reason, observation_id=observation_id
        )
    )
