from pathlib import Path

from sqlalchemy import Connection, func, insert, select

from pen15 import exposure, nmap
from pen15.db import assets, bindings, expected_services, findings, observations
from pen15.exposure import Finding

LAB_SCAN = Path(__file__).parent / "fixtures" / "nmap-lab.xml"


def declare_fileserver(conn: Connection) -> None:
    conn.execute(insert(assets).values(id="fileserver", provisional=False))
    conn.execute(insert(bindings).values(address="192.0.2.10", asset_id="fileserver"))
    conn.execute(
        insert(expected_services),
        [
            {
                "asset_id": "fileserver",
                "protocol": "tcp",
                "port": port,
                "vantage": "internal",
                "reason": "lab",
            }
            for port in (22, 445)
        ],
    )


def open_findings(conn: Connection) -> list[tuple[str, str, int]]:
    rows = conn.execute(
        select(findings.c.asset_id, findings.c.protocol, findings.c.port).where(findings.c.status == "open")
    )
    return [tuple(row) for row in rows]


def test_unexpected_listener_becomes_one_finding(conn: Connection) -> None:
    declare_fileserver(conn)

    opened = exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    assert opened == [Finding("fileserver", "tcp", 8080, "internal")]
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_same_evidence_twice_changes_nothing(conn: Connection) -> None:
    declare_fileserver(conn)
    scan = nmap.read(LAB_SCAN)
    exposure.ingest(conn, scan, vantage="internal")

    assert exposure.ingest(conn, scan, vantage="internal") == []
    assert conn.scalar(select(func.count()).select_from(observations)) == len(scan.ports)
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_unknown_host_gets_a_provisional_asset(conn: Connection) -> None:
    exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    assert conn.scalar(select(assets.c.provisional).where(assets.c.id == "new-192.0.2.10")) is True
    assert sorted(port for _, _, port in open_findings(conn)) == [22, 445, 8080]
