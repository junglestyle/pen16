import ipaddress
import itertools
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, Row, Text, cast, delete, exists, func, select, update
from sqlalchemy.dialects.postgresql import distinct_on, insert

from pen16 import compliance, neighbours, notify
from pen16.db import (
    BindingChange,
    DecisionKind,
    FindingChange,
    FindingStatus,
    NotificationKind,
    ObservationState,
    TokenKind,
    assets,
    binding_events,
    bindings,
    decisions,
    expected_services,
    finding_events,
    findings,
    observations,
    tokens,
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


@dataclass(frozen=True)
class TookOver:
    """A different MAC answered at an address bound to a device, so a new device has it now."""

    address: str
    before: str
    mac_before: str
    mac_now: str
    device: str
    private: bool

    def alert(self) -> str:
        line = (
            f"{self.address} has a new device, {self.device}: {self.mac_now} answered instead of {self.before}'s "
            f"{self.mac_before}, so {self.before}'s expected services and decisions no longer apply there."
        )
        if self.private:
            line += " A private MAC can change on its own: say on the dashboard whether it's the same device."
        return line


def ingest(
    conn: Connection, scan: Scan, networks: Sequence[Network], vantage: str, macs: Mapping[str, str]
) -> list[Finding]:
    """Record a scan's observations, open findings for unexpected open ports, resolve closed ones, and queue one
    alert for what's news.

    Returns the findings this scan newly opened or reopened, and those whose decision it withdrew: the ones
    alerted. A finding the owner decided about stays quiet while the service matches what they decided on. Run
    it inside one transaction, so the observations, finding changes and alert land together. Re-ingesting the
    same evidence changes nothing.

    `macs` is the MAC each up address answered with during this scan, where the scanner host saw one. A bound
    address that answers with a different MAC than its binding's has a new device, which gets the address
    before anything is recorded, so the old device's intent and decisions don't apply to it and its closed
    ports resolve nothing of the old device's.

    A closed port resolves a finding only inside a network whose gateway answered this scan: without it, a
    closed port can't be told from a network that was down.
    """
    listed = {port.address for port in scan.ports}
    devices: dict[str, str] = {}
    took_over = []
    for address in sorted(listed | set(macs)):
        device, taken = _device_at(conn, address, macs.get(address), create=address in listed)
        if device is not None:
            devices[address] = device
        if taken is not None:
            took_over.append(taken)
    opened = []
    for port in scan.ports:
        asset_id = devices[port.address]
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
    trusted = [network for network in networks if str(network.gateway) in scan.up()]
    _record_closed(conn, scan, vantage, trusted)
    _close(conn, scan, vantage, trusted)
    _alert(conn, opened, took_over)
    return opened


def _alert(conn: Connection, opened: list[Finding], took_over: list[TookOver]) -> None:
    lines = [f"{f.asset_id} {f.port}/{f.protocol}" + (f": {f.why}" if f.why else "") for f in opened]
    lines.extend(t.alert() for t in took_over)
    titles = []
    if opened:
        titles.append(f"{len(opened)} unexpected service(s)")
    if took_over:
        titles.append(f"{len(took_over)} address(es) with a new device")
    if titles:
        notify.enqueue(conn, NotificationKind.FINDING, ", ".join(titles), "\n".join(lines))


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


def name_asset(conn: Connection, provisional_id: str, asset_id: str, by: str) -> None:
    """Give a provisional device an owner-chosen ID, carrying its addresses, history and findings along.

    Only provisional devices can be renamed: they carry no owner decisions that a reused address could wrongly
    inherit. The name can't belong to another device at an address. It can be one with no address: a
    compliance host, or the device an address was taken over from, when it's the same one after all. Then the
    two become one, and where both have a finding for the same service, the one with the newer evidence
    decides its state while the older one's decisions and history stay with it.
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
    if conn.scalar(select(assets.c.retired_at).where(assets.c.id == asset_id)) is not None:
        raise ValueError(f"{asset_id!r} is retired")
    conn.execute(insert(assets).values(id=asset_id, provisional=False).on_conflict_do_nothing())
    for finding in conn.execute(select(findings).where(findings.c.asset_id == provisional_id)).all():
        _merge_finding(conn, finding, asset_id, by)
    _merge_expected(conn, provisional_id, asset_id, by)
    # What the provisional device opened that this device expects isn't news once they're one.
    expected = expected_services.alias("expected")
    for finding_id, reason in conn.execute(
        select(findings.c.id, expected.c.reason)
        .join(
            expected,
            (expected.c.asset_id == findings.c.asset_id)
            & (expected.c.protocol == findings.c.protocol)
            & (expected.c.port == findings.c.port)
            & (expected.c.vantage == findings.c.vantage)
            & expected.c.ended_at.is_(None),
        )
        .where(findings.c.asset_id == asset_id, findings.c.status == FindingStatus.OPEN)
    ).all():
        _resolve(conn, [finding_id], f"expected: {reason}", by)
    conn.execute(
        update(observations).where(observations.c.asset_id == provisional_id).values(asset_id=asset_id)
    )
    for binding in conn.execute(select(bindings).where(bindings.c.asset_id == provisional_id)).all():
        mac = str(binding.mac) if binding.mac else None
        _binding_event(
            conn, binding.address, provisional_id, mac, BindingChange.ENDED, by, f"named {asset_id}"
        )
        _binding_event(
            conn, binding.address, asset_id, mac, BindingChange.BOUND, by, f"named from {provisional_id}"
        )
    conn.execute(update(bindings).where(bindings.c.asset_id == provisional_id).values(asset_id=asset_id))
    conn.execute(delete(assets).where(assets.c.id == provisional_id))


def separate(conn: Connection, provisional_id: str) -> None:
    """Say a device that took over an address isn't the one it took it from. It stays unnamed."""
    conn.execute(
        update(assets)
        .where(assets.c.id == provisional_id, assets.c.provisional)
        .values(took_over_from=None, took_over_private=False)
    )


def retire(conn: Connection, asset_id: str, reason: str, by: str) -> None:
    """Retire a device that's gone for good. Its addresses, expected services and decisions end, its open
    findings resolve, and its compliance tokens are revoked, all with the reason; its history stays. The next
    device at one of its addresses is a new, unnamed one."""
    if not reason.strip():
        raise ValueError("retiring a device needs a reason")
    why = f"retired: {reason.strip()}"
    retired = conn.execute(select(assets.c.retired_at).where(assets.c.id == asset_id)).first()
    if retired is None:
        raise ValueError(f"there's no device {asset_id!r}")
    if retired.retired_at is not None:
        raise ValueError(f"{asset_id!r} is already retired")
    for binding in conn.execute(select(bindings).where(bindings.c.asset_id == asset_id)).all():
        mac = str(binding.mac) if binding.mac else None
        _binding_event(conn, binding.address, asset_id, mac, BindingChange.ENDED, by, why)
    conn.execute(delete(bindings).where(bindings.c.asset_id == asset_id))
    conn.execute(
        update(expected_services)
        .where(expected_services.c.asset_id == asset_id, expected_services.c.ended_at.is_(None))
        .values(ended_at=func.now(), ended_by=by, end_reason=why)
    )
    owned = select(findings.c.id).where(findings.c.asset_id == asset_id)
    conn.execute(
        update(decisions)
        .where(decisions.c.finding_id.in_(owned), decisions.c.withdrawn_at.is_(None))
        .values(withdrawn_at=func.now(), withdrawal=why)
    )
    _resolve(conn, list(conn.scalars(owned)), why, by)
    conn.execute(
        update(tokens)
        .where(
            tokens.c.kind == TokenKind.COMPLIANCE, tokens.c.name == asset_id, tokens.c.revoked_at.is_(None)
        )
        .values(revoked_at=func.now())
    )
    conn.execute(
        update(assets)
        .where(assets.c.id == asset_id)
        .values(retired_at=func.now(), retired_by=by, retirement=why)
    )
    notify.dismiss_incident(conn, compliance.stale_incident(asset_id))


def move(conn: Connection, address: str, asset_id: str, reason: str, by: str) -> None:
    """Correct a binding by hand: the named device at `address` is really `asset_id`, another named device.

    Only what's seen there from now on is the new device's. Observations, findings and decisions already recorded
    stay with the device they were recorded for, and its open findings stay open, no longer at this address:
    missing coverage resolves nothing. Both devices' history records the move.
    """
    if not reason.strip():
        raise ValueError("moving an address needs a reason")
    address = str(ipaddress.IPv4Address(address))
    binding = conn.execute(
        select(bindings.c.asset_id, cast(bindings.c.mac, Text).label("mac"), assets.c.provisional)
        .join(assets, assets.c.id == bindings.c.asset_id)
        .where(bindings.c.address == address)
    ).first()
    if binding is None:
        raise ValueError(f"no device is at {address}")
    if binding.asset_id == asset_id:
        raise ValueError(f"{address} is already {asset_id}'s")
    if binding.provisional:
        raise ValueError(f"{binding.asset_id!r} is unnamed: name it first")
    target = conn.execute(
        select(assets.c.provisional, assets.c.retired_at).where(assets.c.id == asset_id)
    ).first()
    if target is None:
        raise ValueError(f"there's no device {asset_id!r}")
    if target.provisional:
        raise ValueError(f"{asset_id!r} is unnamed: name it first")
    if target.retired_at is not None:
        raise ValueError(f"{asset_id!r} is retired")
    why = reason.strip()
    _binding_event(
        conn, address, binding.asset_id, binding.mac, BindingChange.ENDED, by, f"moved to {asset_id}: {why}"
    )
    conn.execute(
        update(bindings).where(bindings.c.address == address).values(asset_id=asset_id, bound_at=func.now())
    )
    _binding_event(
        conn, address, asset_id, binding.mac, BindingChange.BOUND, by, f"moved from {binding.asset_id}: {why}"
    )


def _device_at(
    conn: Connection, address: str, mac: str | None, *, create: bool
) -> tuple[str | None, TookOver | None]:
    """The device at an address in this scan, and what changed hands if a different MAC answered there.

    An unbound address gets a new provisional device if `create`. A binding learns its first MAC from the first
    scan that sees one. A binding whose MAC differs from the one that answered now goes to a new provisional
    device: the address changed hands, whatever the old device's name.
    """
    binding = conn.execute(
        select(bindings.c.asset_id, cast(bindings.c.mac, Text).label("mac")).where(
            bindings.c.address == address
        )
    ).first()
    if binding is None:
        if not create:
            return None, None
        device = _new_provisional(conn, address)
        conn.execute(insert(bindings).values(address=address, asset_id=device, mac=mac))
        _binding_event(conn, address, device, mac, BindingChange.BOUND, SCAN)
        return device, None
    if mac is None or binding.mac == mac:
        return binding.asset_id, None
    if binding.mac is None:
        conn.execute(update(bindings).where(bindings.c.address == address).values(mac=mac))
        _binding_event(conn, address, binding.asset_id, mac, BindingChange.LEARNED, SCAN)
        return binding.asset_id, None
    private = neighbours.is_private(binding.mac) or neighbours.is_private(mac)
    device = _new_provisional(conn, address, took_over_from=binding.asset_id, private=private)
    why = f"{mac} answered instead of {binding.mac}"
    _binding_event(conn, address, binding.asset_id, binding.mac, BindingChange.ENDED, SCAN, why)
    conn.execute(
        update(bindings)
        .where(bindings.c.address == address)
        .values(asset_id=device, mac=mac, bound_at=func.now())
    )
    _binding_event(conn, address, device, mac, BindingChange.BOUND, SCAN, why)
    return device, TookOver(address, binding.asset_id, binding.mac, mac, device, private)


def _new_provisional(
    conn: Connection, address: str, took_over_from: str | None = None, *, private: bool = False
) -> str:
    """A provisional device named for the address, numbered so no name an earlier device there had, even one
    since named or merged away, is used again: binding_events keeps those names."""
    prefix = f"new-{address}"
    taken = set(conn.scalars(select(assets.c.id).where(assets.c.id.startswith(prefix)))) | set(
        conn.scalars(select(binding_events.c.asset_id).where(binding_events.c.asset_id.startswith(prefix)))
    )
    device = next(
        name
        for n in itertools.count(1)
        if (name := f"new-{address}" if n == 1 else f"new-{address}-{n}") not in taken
    )
    conn.execute(
        insert(assets).values(
            id=device, provisional=True, took_over_from=took_over_from, took_over_private=private
        )
    )
    return device


def _binding_event(
    conn: Connection,
    address: str,
    asset_id: str,
    mac: str | None,
    change: BindingChange,
    by: str,
    reason: str | None = None,
) -> None:
    conn.execute(
        insert(binding_events).values(
            address=address, asset_id=asset_id, mac=mac, change=change, by=by, reason=reason
        )
    )


def _merge_finding(conn: Connection, finding: Row[Any], asset_id: str, by: str) -> None:
    """Move a provisional device's finding to `asset_id`, or fold it into the finding there for the same service.
    The one with the newer evidence decides the state; the history of both stays."""
    seen = observations.alias("seen")
    existing = conn.execute(
        select(findings.c.id, findings.c.status, seen.c.observed_at.label("last_seen"))
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .where(
            findings.c.kind == finding.kind,
            findings.c.asset_id == asset_id,
            findings.c.protocol == finding.protocol,
            findings.c.port == finding.port,
            findings.c.vantage == finding.vantage,
        )
    ).first()
    if existing is None:
        conn.execute(update(findings).where(findings.c.id == finding.id).values(asset_id=asset_id))
        return
    observed = conn.scalar(
        select(observations.c.observed_at).where(observations.c.id == finding.last_observation_id)
    )
    if observed > existing.last_seen:
        conn.execute(
            update(findings)
            .where(findings.c.id == existing.id)
            .values(
                status=finding.status,
                resolved_at=finding.resolved_at,
                resolution=finding.resolution,
                last_observation_id=finding.last_observation_id,
            )
        )
        if finding.status != existing.status:
            change = (
                FindingChange.REOPENED if finding.status == FindingStatus.OPEN else FindingChange.RESOLVED
            )
            _event(conn, existing.id, change, by, f"newer evidence from {finding.asset_id}, the same device")
    conn.execute(
        update(finding_events).where(finding_events.c.finding_id == finding.id).values(finding_id=existing.id)
    )
    conn.execute(delete(findings).where(findings.c.id == finding.id))


def _merge_expected(conn: Connection, provisional_id: str, asset_id: str, by: str) -> None:
    """Move a provisional device's expected services to `asset_id`, ending the ones it already expects."""
    target = expected_services.alias("target")
    already = exists().where(
        target.c.asset_id == asset_id,
        target.c.protocol == expected_services.c.protocol,
        target.c.port == expected_services.c.port,
        target.c.vantage == expected_services.c.vantage,
        target.c.ended_at.is_(None),
    )
    conn.execute(
        update(expected_services)
        .where(
            expected_services.c.asset_id == provisional_id, expected_services.c.ended_at.is_(None), already
        )
        .values(ended_at=func.now(), ended_by=by, end_reason=f"{asset_id} already expects it")
    )
    conn.execute(
        update(expected_services)
        .where(expected_services.c.asset_id == provisional_id)
        .values(asset_id=asset_id)
    )


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


def _seen_closed(scan: Scan, address: str, protocol: str, port: int, trusted: Sequence[Network]) -> bool:
    """Whether this scan saw a port closed at an address whose negative results it can trust: the address
    answered, and so did its network's gateway."""
    return (
        address in scan.up()
        and any(ipaddress.IPv4Address(address) in network.cidr for network in trusted)
        and scan.state(address, protocol, port) == ObservationState.CLOSED
    )


def _record_closed(conn: Connection, scan: Scan, vantage: str, trusted: Sequence[Network]) -> None:
    """Record a closed observation for each service that was last seen open at a bound address and that this
    scan saw closed there, so a service that's gone shows as removed. nmap folds closed ports into a count
    rather than listing them, so otherwise only a listed port could ever be seen closing."""
    up = scan.up()
    for binding in conn.execute(select(bindings.c.address, bindings.c.asset_id)).all():
        address = str(binding.address)
        if address not in up:
            continue
        latest = conn.execute(
            select(observations.c.protocol, observations.c.port, observations.c.state)
            .ext(distinct_on(observations.c.protocol, observations.c.port))
            .where(
                observations.c.asset_id == binding.asset_id,
                observations.c.address == address,
                observations.c.vantage == vantage,
            )
            .order_by(
                observations.c.protocol,
                observations.c.port,
                observations.c.observed_at.desc(),
                observations.c.id.desc(),
            )
        ).all()
        for service in latest:
            if service.state == ObservationState.OPEN and _seen_closed(
                scan, address, service.protocol, service.port, trusted
            ):
                closed = Port(
                    address, service.protocol, service.port, ObservationState.CLOSED, None, None, None
                )
                _observe(conn, scan, closed, binding.asset_id, vantage)


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
    for finding in rows.all():
        bound = conn.scalars(select(bindings.c.address).where(bindings.c.asset_id == finding.asset_id))
        addresses = [str(address) for address in bound]
        if not addresses or not all(
            _seen_closed(scan, address, finding.protocol, finding.port, trusted) for address in addresses
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
