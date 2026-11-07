import pytest
from sqlalchemy import func, insert, select

from pen16 import exposure, scope, status
from pen16.db import assets, bindings, expected_services, findings, observations
from pen16.exposure import Finding
from tests.conftest import closed, ingest, lab


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


def test_unexpected_listener_becomes_one_finding(conn):
    declare_fileserver(conn)

    opened = ingest(conn, lab())

    assert opened == [Finding("fileserver", "tcp", 8080, "internal")]
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_same_evidence_twice_changes_nothing(conn):
    declare_fileserver(conn)
    scan = lab()
    ingest(conn, scan)

    assert ingest(conn, scan) == []
    assert conn.scalar(select(func.count()).select_from(observations)) == len(scan.ports)
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_unknown_host_gets_a_provisional_asset(conn):
    ingest(conn, lab())

    assert conn.scalar(select(assets.c.provisional).where(assets.c.id == "new-192.0.2.10")) is True
    assert sorted(port for _, _, port in open_findings(conn)) == [22, 445, 8080]


def test_still_open_next_night_alerts_once(conn):
    declare_fileserver(conn)
    ingest(conn, lab())

    assert ingest(conn, lab(shift=2 * 86400)) == []
    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_closed_port_resolves_and_reopening_alerts_again(conn):
    declare_fileserver(conn)
    ingest(conn, lab())

    ingest(conn, closed())
    assert open_findings(conn) == []
    assert conn.scalar(select(findings.c.resolution)) == "closed"

    reopened = ingest(conn, lab(shift=2 * 86400))
    assert reopened == [Finding("fileserver", "tcp", 8080, "internal")]


def test_a_silent_gateway_resolves_nothing_in_its_network(conn):
    declare_fileserver(conn)
    ingest(conn, lab())

    ingest(conn, closed(gateway=False))

    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_another_networks_silent_gateway_doesnt_hold_this_one_back(conn):
    declare_fileserver(conn)
    ingest(conn, lab())
    networks = scope.parse(
        [
            {"name": "lab", "cidr": "192.0.2.0/24", "gateway": "192.0.2.1"},
            {"name": "iot", "cidr": "198.51.100.0/24", "gateway": "198.51.100.1"},
        ],
        [],
    ).networks

    exposure.ingest(conn, closed(), networks, "internal", {})

    assert open_findings(conn) == []


def test_older_closed_evidence_resolves_nothing(conn):
    declare_fileserver(conn)
    ingest(conn, lab(shift=7 * 86400))

    ingest(conn, closed())

    assert open_findings(conn) == [("fileserver", "tcp", 8080)]


def test_expected_service_resolves_and_stays_quiet(conn):
    ingest(conn, lab())
    ids = list(conn.scalars(select(findings.c.id).where(findings.c.port.in_([22, 445]))))

    exposure.expect(conn, ids, "file sharing for the LAN", "owner@example.com")

    assert open_findings(conn) == [("new-192.0.2.10", "tcp", 8080)]
    assert ingest(conn, lab(shift=2 * 86400)) == []


def test_stopping_expecting_a_service_reopens_it_and_keeps_the_old_intent(conn):
    ingest(conn, lab())
    ssh = conn.scalar(select(findings.c.id).where(findings.c.port == 22))
    exposure.expect(conn, [ssh], "admin over ssh", "owner@example.com")

    with pytest.raises(ValueError, match="reason"):
        exposure.unexpect(conn, "new-192.0.2.10", "tcp", 22, "internal", "", "owner@example.com")
    exposure.unexpect(
        conn, "new-192.0.2.10", "tcp", 22, "internal", "moved to the bastion", "owner@example.com"
    )
    reopened = ingest(conn, lab(shift=86400))

    assert Finding("new-192.0.2.10", "tcp", 22, "internal") in reopened
    intent = conn.execute(select(expected_services.c.reason, expected_services.c.end_reason)).all()
    assert [tuple(row) for row in intent] == [("admin over ssh", "moved to the bastion")]


def test_naming_a_device_keeps_its_findings(conn):
    ingest(conn, lab())

    exposure.name_asset(conn, "new-192.0.2.10", "fileserver", "owner@example.com")

    assert sorted(port for asset, _, port in open_findings(conn) if asset == "fileserver") == [22, 445, 8080]
    assert ingest(conn, lab(shift=2 * 86400)) == []


def test_a_name_another_device_has_is_refused(conn):
    conn.execute(insert(assets).values(id="fileserver", provisional=False))
    conn.execute(insert(bindings).values(address="192.0.2.11", asset_id="fileserver"))
    ingest(conn, lab())

    with pytest.raises(ValueError, match="another device"):
        exposure.name_asset(conn, "new-192.0.2.10", "fileserver", "owner@example.com")

    assert (
        conn.scalar(select(bindings.c.asset_id).where(bindings.c.address == "192.0.2.10")) == "new-192.0.2.10"
    )


def test_naming_a_device_after_a_compliance_host_joins_them(conn):
    # A compliance result creates the host as a named asset with no address.
    conn.execute(insert(assets).values(id="fileserver", provisional=False))
    ingest(conn, lab())

    exposure.name_asset(conn, "new-192.0.2.10", "fileserver", "owner@example.com")

    assert conn.scalar(select(bindings.c.asset_id).where(bindings.c.address == "192.0.2.10")) == "fileserver"


def service_changes(conn):
    return [
        (c.port, c.difference, c.before.version if c.before else None, c.now.version)
        for c in status.recent_changes(conn).services
    ]


def exposed_ports(conn):
    return [service.port for service in status.exposed(conn)]


def test_an_expected_service_that_closes_is_removed_once_the_gateway_answers(conn):
    ingest(conn, lab())
    web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))
    # Expected, so no open finding closes it: only the observation can say it's gone.
    exposure.expect(conn, [web_app], "lab tool", "owner@example.com")

    ingest(conn, closed(gateway=False))
    assert 8080 in exposed_ports(conn)
    assert [c[:2] for c in service_changes(conn)] == [(22, "new"), (445, "new"), (8080, "new")]

    ingest(conn, closed())
    assert exposed_ports(conn) == [22, 445]
    assert service_changes(conn)[0] == (8080, "removed", "3.0.1", None)


def test_a_new_version_is_a_change_and_an_unreported_one_isnt(conn):
    ingest(conn, lab())
    ingest(conn, lab(shift=3600, version=b""))
    ingest(conn, lab(shift=7200))
    assert [c[:2] for c in service_changes(conn)] == [(22, "new"), (445, "new"), (8080, "new")]

    ingest(conn, lab(shift=10800, version=b'version="3.0.2"'))

    assert service_changes(conn)[0] == (8080, "changed", "3.0.1", "3.0.2")
