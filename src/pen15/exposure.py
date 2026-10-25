from dataclasses import dataclass

from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert

from pen15.db import assets, bindings, expected_services, findings, observations
from pen15.nmap import PARSER_VERSION, Port, Scan

UNEXPECTED_EXPOSURE = "unexpected-exposure"


@dataclass(frozen=True)
class Finding:
    asset_id: str
    protocol: str
    port: int
    vantage: str


def ingest(conn: Connection, scan: Scan, vantage: str) -> list[Finding]:
    """Record a scan's observations and open a finding for each unexpected open port.

    Returns the findings this scan opened or refreshed. Run it inside one transaction, so the observations and
    finding changes land together. Re-ingesting the same evidence changes nothing and returns no findings.
    """
    opened = []
    for port in scan.ports:
        asset_id = _asset_for(conn, port.address)
        observation_id = _observe(conn, scan, port, asset_id, vantage)
        if observation_id is None or port.state != "open":
            continue
        if _expected(conn, asset_id, port, vantage):
            continue
        conn.execute(
            insert(findings)
            .values(
                kind=UNEXPECTED_EXPOSURE,
                asset_id=asset_id,
                protocol=port.protocol,
                port=port.port,
                vantage=vantage,
                status="open",
                opened_at=scan.finished_at,
                last_observation_id=observation_id,
            )
            .on_conflict_do_update(
                index_elements=["kind", "asset_id", "protocol", "port", "vantage"],
                set_={"status": "open", "resolved_at": None, "last_observation_id": observation_id},
            )
        )
        opened.append(Finding(asset_id, port.protocol, port.port, vantage))
    return opened


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


def _expected(conn: Connection, asset_id: str, port: Port, vantage: str) -> bool:
    return (
        conn.scalar(
            select(expected_services.c.asset_id).where(
                expected_services.c.asset_id == asset_id,
                expected_services.c.protocol == port.protocol,
                expected_services.c.port == port.port,
                expected_services.c.vantage == vantage,
            )
        )
        is not None
    )
