import pytest
from sqlalchemy import func, insert, select

from pen16 import exposure, status, tokens
from pen16.db import (
    DecisionKind,
    TokenKind,
    assets,
    binding_events,
    bindings,
    expected_services,
    finding_events,
    findings,
    observations,
)
from tests.conftest import OWNER_LOGIN, alerts, closed, ingest, lab

ADDRESS = "192.0.2.10"
# A hardware MAC, and its replacement's.
NAS = "00:11:32:00:00:10"
OTHER = "00:11:32:00:00:99"
# Private MACs, which a phone or laptop makes up, and may make up again.
PRIVATE = "02:00:00:00:00:10"
ROTATED = "06:00:00:00:00:10"


def fileserver(conn, mac):
    """The lab host, named fileserver, with ssh and smb expected and its web app's risk accepted."""
    ingest(conn, lab(), {ADDRESS: mac})
    exposure.name_asset(conn, f"new-{ADDRESS}", "fileserver", OWNER_LOGIN)
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
    ids = list(conn.scalars(select(findings.c.id).where(findings.c.port.in_([22, 445]))))
    exposure.resolve(conn, ids, "expected now", OWNER_LOGIN)
    web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))
    exposure.decide(conn, [web_app], DecisionKind.ACCEPTED_RISK, "lab tool", OWNER_LOGIN)
    return web_app


def bound(conn):
    return conn.execute(select(bindings.c.asset_id, func.text(bindings.c.mac))).one()


def open_ports(conn, asset_id):
    return sorted(
        conn.scalars(
            select(findings.c.port).where(findings.c.asset_id == asset_id, findings.c.status == "open")
        )
    )


def test_a_binding_learns_the_first_mac_a_scan_sees(conn):
    ingest(conn, lab())
    assert tuple(bound(conn)) == (f"new-{ADDRESS}", None)

    ingest(conn, lab(shift=3600), {ADDRESS: NAS})

    assert tuple(bound(conn)) == (f"new-{ADDRESS}", NAS)
    assert status.unnamed(conn)[0].took_over_from is None


def test_a_different_hardware_mac_gives_the_address_to_a_new_device(conn):
    web_app = fileserver(conn, NAS)

    opened = ingest(conn, lab(shift=86400), {ADDRESS: OTHER})

    # Nothing fileserver expected or decided applies to the new device: everything it has open is news.
    newcomer = f"new-{ADDRESS}-2"
    assert tuple(bound(conn)) == (newcomer, OTHER)
    assert sorted(f.port for f in opened) == [22, 445, 8080]
    assert {f.asset_id for f in opened} == {newcomer}
    [device] = status.unnamed(conn)
    assert (device.id, device.took_over_from, device.took_over_private) == (newcomer, "fileserver", False)
    assert OTHER in alerts(conn)[-1][1]
    # fileserver's own finding stays open, away from the address: a device that's gone resolves nothing.
    assert conn.scalar(select(findings.c.status).where(findings.c.id == web_app)) == "open"
    exposure.withdraw(conn, status.decided(conn)[0].decision_id, "test")
    [away] = [f for f in status.needs_attention(conn) if f.id == web_app]
    assert away.away
    # Only the device at the address now has anything reachable there.
    assert {service.asset_id for service in status.exposed(conn)} == {newcomer}


def test_a_new_devices_closed_ports_resolve_nothing_of_the_old_ones(conn):
    web_app = fileserver(conn, NAS)

    ingest(conn, closed(), {ADDRESS: OTHER, "192.0.2.1": "00:11:32:00:00:01"})

    assert conn.scalar(select(findings.c.status).where(findings.c.id == web_app)) == "open"
    assert open_ports(conn, f"new-{ADDRESS}-2") == [22, 445]


def test_a_private_mac_that_changed_asks_and_the_same_device_merges_back(conn):
    web_app = fileserver(conn, PRIVATE)
    ingest(conn, lab(shift=86400), {ADDRESS: ROTATED})
    [device] = status.unnamed(conn)
    assert (device.took_over_from, device.took_over_private) == ("fileserver", True)

    exposure.name_asset(conn, device.id, "fileserver", OWNER_LOGIN)

    assert tuple(bound(conn)) == ("fileserver", ROTATED)
    assert conn.scalar(select(assets.c.id).where(assets.c.id == device.id)) is None
    # One finding per service again: the decided web app, and ssh and smb resolved as expected.
    assert open_ports(conn, "fileserver") == [8080]
    assert [f.id for f in status.decided(conn)] == [web_app]
    assert (
        conn.scalar(
            select(func.count()).select_from(observations).where(observations.c.asset_id != "fileserver")
        )
        == 0
    )
    # The next scan with the new MAC is plainly fileserver, and quiet.
    assert ingest(conn, lab(shift=2 * 86400), {ADDRESS: ROTATED}) == []


def test_a_different_device_stays_unnamed_without_the_question(conn):
    fileserver(conn, PRIVATE)
    ingest(conn, lab(shift=86400), {ADDRESS: ROTATED})

    exposure.separate(conn, f"new-{ADDRESS}-2")

    [device] = status.unnamed(conn)
    assert (device.id, device.took_over_from) == (f"new-{ADDRESS}-2", None)


def test_a_retired_devices_address_goes_to_a_new_unnamed_device_and_its_history_stays(conn):
    web_app = fileserver(conn, NAS)
    compliance_token = tokens.create(conn, TokenKind.COMPLIANCE, "fileserver")

    with pytest.raises(ValueError, match="reason"):
        exposure.retire(conn, "fileserver", " ", OWNER_LOGIN)
    exposure.retire(conn, "fileserver", "sold it", OWNER_LOGIN)
    opened = ingest(conn, lab(shift=86400), {ADDRESS: OTHER})

    # The new host at the address is unnamed, with nothing expected or decided: everything is news.
    assert tuple(bound(conn)) == (f"new-{ADDRESS}-2", OTHER)
    assert sorted(f.port for f in opened) == [22, 445, 8080]
    assert status.unnamed(conn)[0].took_over_from is None
    assert [d.id for d in status.devices(conn)] == []
    # fileserver's history is intact, ending with its retirement.
    events = conn.execute(
        select(finding_events.c.change, finding_events.c.reason)
        .where(finding_events.c.finding_id == web_app)
        .order_by(finding_events.c.id)
    ).all()
    assert [tuple(e) for e in events] == [("opened", None), ("resolved", "retired: sold it")]
    assert (
        conn.scalar(
            select(binding_events.c.reason).where(
                binding_events.c.asset_id == "fileserver", binding_events.c.change == "ended"
            )
        )
        == "retired: sold it"
    )
    assert tokens.verify(conn, compliance_token, TokenKind.COMPLIANCE) is None
    with pytest.raises(ValueError, match="retired"):
        exposure.name_asset(conn, f"new-{ADDRESS}-2", "fileserver", OWNER_LOGIN)
