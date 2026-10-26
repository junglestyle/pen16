import re
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Connection, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from pen16.db import assets, bindings, expected_services, findings, observations
from pen16.nmap import PARSER_VERSION, Port, Scan

UNEXPECTED_EXPOSURE = "unexpected-exposure"
ASSET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


@dataclass(frozen=True)
class Finding:
    asset_id: str
    protocol: str
    port: int
    vantage: str


def ingest(conn: Connection, scan: Scan, vantage: str, closures: bool = True) -> list[Finding]:
    """Record a scan's observations, open findings for unexpected open ports, and resolve closed ones.

    Returns the findings this scan newly opened or reopened: the ones worth an alert. Run it inside one
    transaction, so the observations and finding changes land together. Re-ingesting the same evidence
    changes nothing. closures=False records everything but resolves nothing, for scans whose negative
    results can't be trusted, such as when the gateway didn't answer.
    """
    opened = []
    for port in scan.ports:
        asset_id = _asset_for(conn, port.address)
        observation_id = _observe(conn, scan, port, asset_id, vantage)
        if observation_id is None or port.state != "open":
            continue
        if _expected(conn, asset_id, port.protocol, port.port, vantage):
            continue
        if _open(conn, asset_id, port, vantage, scan.finished_at, observation_id):
            opened.append(Finding(asset_id, port.protocol, port.port, vantage))
    if closures:
        _close(conn, scan, vantage)
    return opened


def expect(conn: Connection, finding_ids: list[int], reason: str) -> None:
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
            insert(expected_services).values(**row._asdict(), reason=reason).on_conflict_do_nothing()
        )
    conn.execute(
        update(findings)
        .where(findings.c.id.in_(finding_ids), findings.c.status == "open")
        .values(status="resolved", resolved_at=func.now(), resolution=f"expected: {reason}")
    )


def unexpect(conn: Connection, asset_id: str, protocol: str, port: int, vantage: str) -> None:
    """Stop expecting a service. The next scan that sees it open reopens its finding."""
    conn.execute(
        delete(expected_services).where(
            expected_services.c.asset_id == asset_id,
            expected_services.c.protocol == protocol,
            expected_services.c.port == port,
            expected_services.c.vantage == vantage,
        )
    )


def name_asset(conn: Connection, provisional_id: str, asset_id: str) -> None:
    """Give a provisional asset an owner-chosen ID, carrying its history and findings along.

    Only provisional assets can be renamed: they carry no owner decisions that a reused address could
    wrongly inherit.
    """
    if not ASSET_ID.fullmatch(asset_id) or asset_id.startswith("new-"):
        raise ValueError("asset IDs are lowercase letters, digits, and dashes, and don't start with new-")
    provisional = conn.scalar(select(assets.c.provisional).where(assets.c.id == provisional_id))
    if provisional is not True:
        raise ValueError(f"{provisional_id} isn't a provisional asset")
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
            )
        )
        is not None
    )


def _open(
    conn: Connection, asset_id: str, port: Port, vantage: str, observed_at: datetime, observation_id: int
) -> bool:
    key = (
        findings.c.kind == UNEXPECTED_EXPOSURE,
        findings.c.asset_id == asset_id,
        findings.c.protocol == port.protocol,
        findings.c.port == port.port,
        findings.c.vantage == vantage,
    )
    existing = conn.execute(select(findings.c.status, findings.c.resolved_at).where(*key)).first()
    if existing is None:
        conn.execute(
            insert(findings).values(
                kind=UNEXPECTED_EXPOSURE,
                asset_id=asset_id,
                protocol=port.protocol,
                port=port.port,
                vantage=vantage,
                status="open",
                opened_at=observed_at,
                last_observation_id=observation_id,
            )
        )
        return True
    if existing.status == "open":
        conn.execute(update(findings).where(*key).values(last_observation_id=observation_id))
        return False
    if existing.resolved_at is not None and existing.resolved_at >= observed_at:
        return False
    conn.execute(
        update(findings)
        .where(*key)
        .values(status="open", resolved_at=None, resolution=None, last_observation_id=observation_id)
    )
    return True


def _close(conn: Connection, scan: Scan, vantage: str) -> None:
    """Resolve open findings whose port this scan saw closed on every address bound to the asset."""
    last_open = observations.alias("last_open")
    rows = conn.execute(
        select(
            findings.c.id, findings.c.asset_id, findings.c.protocol, findings.c.port, last_open.c.observed_at
        )
        .join(last_open, last_open.c.id == findings.c.last_observation_id)
        .where(
            findings.c.kind == UNEXPECTED_EXPOSURE,
            findings.c.status == "open",
            findings.c.vantage == vantage,
            last_open.c.observed_at < scan.finished_at,
        )
    )
    up = {host.address for host in scan.hosts if host.up}
    for finding in rows.all():
        bound = conn.scalars(select(bindings.c.address).where(bindings.c.asset_id == finding.asset_id))
        addresses = [str(address) for address in bound]
        if not addresses or not all(
            address in up and scan.state(address, finding.protocol, finding.port) == "closed"
            for address in addresses
        ):
            continue
        for address in addresses:
            closed = Port(address, finding.protocol, finding.port, "closed", None, None, None)
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
                status="resolved",
                resolved_at=scan.finished_at,
                resolution="closed",
                last_observation_id=closed_id,
            )
        )
