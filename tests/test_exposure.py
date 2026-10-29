from sqlalchemy import func, insert, select

from pen16 import exposure, nmap
from pen16.db import assets, bindings, expected_services, findings, observations
from pen16.exposure import Finding
from tests.conftest import CLOSED_SCAN, LAB_SCAN


def declare_fileserver(conn):
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


def open_findings(conn):
    rows = conn.execute(
        select(findings.c.asset_id, findings.c.protocol, findings.c.port).where(findings.c.status == "open")
    )
    return [tuple(row) for row in rows]


def later(shift=2 * 86400):
    """The lab scan's result, observed later."""
    finished = b'<finished time="1767225612"'
    return nmap.parse(LAB_SCAN.read_bytes().replace(finished, b'<finished time="%d"' % (1767225612 + shift)))


def test_unexpected_listener_becomes_one_finding(conn):
    declare_fileserver(conn)

    opened = exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    assert opened == [Finding("fileserver", "tcp", 8080, "internal")]
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_same_evidence_twice_changes_nothing(conn):
    declare_fileserver(conn)
    scan = nmap.read(LAB_SCAN)
    exposure.ingest(conn, scan, vantage="internal")

    assert exposure.ingest(conn, scan, vantage="internal") == []
    assert conn.scalar(select(func.count()).select_from(observations)) == len(scan.ports)
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_unknown_host_gets_a_provisional_asset(conn):
    exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    assert conn.scalar(select(assets.c.provisional).where(assets.c.id == "new-192.0.2.10")) is True
    assert sorted(port for _, _, port in open_findings(conn)) == [22, 445, 8080]


def test_still_open_next_night_alerts_once(conn):
    declare_fileserver(conn)
    exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    assert exposure.ingest(conn, later(), vantage="internal") == []
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_closed_port_resolves_and_reopening_alerts_again(conn):
    declare_fileserver(conn)
    exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    exposure.ingest(conn, nmap.read(CLOSED_SCAN), vantage="internal")
    assert open_findings(conn) == []
    assert conn.scalar(select(findings.c.resolution)) == "closed"

    reopened = exposure.ingest(conn, later(), vantage="internal")
    assert reopened == [Finding("fileserver", "tcp", 8080, "internal")]


def test_untrusted_negatives_resolve_nothing(conn):
    declare_fileserver(conn)
    exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    exposure.ingest(conn, nmap.read(CLOSED_SCAN), vantage="internal", closures=False)

    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_older_closed_evidence_resolves_nothing(conn):
    declare_fileserver(conn)
    exposure.ingest(conn, later(shift=7 * 86400), vantage="internal")

    exposure.ingest(conn, nmap.read(CLOSED_SCAN), vantage="internal")

    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_expected_service_resolves_and_stays_quiet(conn):
    exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")
    ids = list(conn.scalars(select(findings.c.id).where(findings.c.port.in_([22, 445]))))

    exposure.expect(conn, ids, "file sharing for the LAN")

    assert open_findings(conn) == [("new-192.0.2.10", "tcp", 8080)]
    assert exposure.ingest(conn, later(), vantage="internal") == []


def test_naming_a_device_keeps_its_findings(conn):
    exposure.ingest(conn, nmap.read(LAB_SCAN), vantage="internal")

    exposure.name_asset(conn, "new-192.0.2.10", "fileserver")

    assert sorted(port for asset, _, port in open_findings(conn) if asset == "fileserver") == [22, 445, 8080]
    assert exposure.ingest(conn, later(), vantage="internal") == []
