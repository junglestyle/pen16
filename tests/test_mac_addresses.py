import json
import time

import pytest
from sqlalchemy import select

from pen16 import neighbours, status
from pen16.db import mac_sightings
from tests.conftest import OWNER, dashboard, lab_xml, queue, runner_client, upload


def neighbour_table(path, *entries):
    """A pen16-neighbours snapshot. Entries are (address, mac, seconds since confirmed, state)."""
    # A second ahead, so a MAC confirmed "now" isn't truncated to before the job started.
    snapshot = {
        "taken_at": int(time.time()) + 1,
        "neighbours": [
            {"dst": address, "dev": "eth0", "lladdr": mac, "confirmed": ago, "state": [state]}
            for address, mac, ago, state in entries
        ],
    }
    path.write_text(json.dumps(snapshot))


def sightings(engine):
    with engine.connect() as conn:
        return [
            (str(a), str(m)) for a, m in conn.execute(select(mac_sightings.c.address, mac_sightings.c.mac))
        ]


@pytest.fixture
def vendors(tmp_path, monkeypatch):
    """nmap's manufacturer list, with one fictional maker in it."""
    prefixes = tmp_path / "nmap-mac-prefixes"
    prefixes.write_text("# fictional\nACDE48 Example Devices\n")
    monkeypatch.setattr(neighbours, "VENDORS", prefixes)
    neighbours._vendors.cache_clear()
    yield
    neighbours._vendors.cache_clear()


def test_a_scan_records_the_mac_the_host_confirmed_during_it(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    job_id = queue(committed)
    client.post("/runner/v1/jobs/claim")
    neighbour_table(
        tmp_path / "neighbours.json",
        ("192.0.2.10", "02:00:00:00:00:10", 0, "REACHABLE"),
        # Not in this scan's up hosts.
        ("192.0.2.99", "02:00:00:00:00:99", 0, "REACHABLE"),
    )

    assert upload(client, job_id, lab_xml()) == 204

    assert sightings(committed) == [("192.0.2.10", "02:00:00:00:00:10")]


def test_a_scan_that_finds_a_different_mac_gives_the_address_to_a_new_device(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    for shift, mac in ((0, "00:11:32:00:00:10"), (86400, "00:11:32:00:00:99")):
        job_id = queue(committed)
        client.post("/runner/v1/jobs/claim")
        neighbour_table(tmp_path / "neighbours.json", ("192.0.2.10", mac, 0, "REACHABLE"))
        assert upload(client, job_id, lab_xml(shift)) == 204

    with committed.connect() as conn:
        [device] = status.unnamed(conn)
    assert (device.id, device.mac, device.took_over_from) == (
        "new-192.0.2.10-2",
        "00:11:32:00:00:99",
        "new-192.0.2.10",
    )


def test_a_mac_confirmed_before_the_scan_isnt_recorded(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    job_id = queue(committed)
    client.post("/runner/v1/jobs/claim")
    neighbour_table(tmp_path / "neighbours.json", ("192.0.2.10", "02:00:00:00:00:10", 3600, "STALE"))

    assert upload(client, job_id, lab_xml()) == 204

    assert sightings(committed) == []


def test_unusable_entries_and_files_give_no_macs(tmp_path):
    table = tmp_path / "neighbours.json"
    neighbour_table(
        table,
        ("192.0.2.10", "02:00:00:00:00:10", 0, "FAILED"),
        ("192.0.2.11", "not-a-mac", 0, "REACHABLE"),
        ("192.0.2.12", "02:00:00:00:00:12", 0, "REACHABLE"),
    )
    assert set(neighbours.read(table)) == {"192.0.2.12"}

    table.write_text("{")
    assert neighbours.read(table) == {}
    assert neighbours.read(tmp_path / "missing.json") == {}


@pytest.mark.usefixtures("vendors")
def test_vendor_names_the_maker_or_a_private_address():
    assert neighbours.vendor("ac:de:48:00:00:01") == "Example Devices"
    assert neighbours.vendor("02:00:00:00:00:10") == "private address"
    assert neighbours.vendor("00:00:00:00:00:01") is None


def test_the_dashboard_shows_each_address_mac(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    job_id = queue(committed)
    client.post("/runner/v1/jobs/claim")
    neighbour_table(tmp_path / "neighbours.json", ("192.0.2.10", "02:00:00:00:00:10", 0, "REACHABLE"))
    upload(client, job_id, lab_xml())

    with committed.connect() as conn:
        seen = status.dashboard(conn)
    page = dashboard(committed).get("/", headers=OWNER).text

    assert {f.seen.mac for f in seen.needs_attention} == {"02:00:00:00:00:10"}
    assert [device.mac for device in seen.unnamed] == ["02:00:00:00:00:10"]
    assert "02:00:00:00:00:10 · private address" in page
