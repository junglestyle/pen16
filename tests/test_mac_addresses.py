import json
import time

from sqlalchemy import func, insert, select

from pen16 import neighbours
from pen16.db import mac_sightings
from tests.conftest import LAB_SCAN
from tests.test_jobs import queue, runner_client, upload
from tests.test_web import OWNER, dashboard, scanned


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


def test_a_scan_records_the_mac_the_host_confirmed_during_it(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    job_id = queue(committed, lab_scope)
    client.post("/runner/v1/jobs/claim")
    neighbour_table(
        tmp_path / "neighbours.json",
        ("192.0.2.10", "02:00:00:00:00:10", 0, "REACHABLE"),
        # Not in this scan's up hosts.
        ("192.0.2.99", "02:00:00:00:00:99", 0, "REACHABLE"),
    )

    assert upload(client, job_id, LAB_SCAN) == 204

    assert sightings(committed) == [("192.0.2.10", "02:00:00:00:00:10")]


def test_a_mac_confirmed_before_the_scan_isnt_recorded(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    job_id = queue(committed, lab_scope)
    client.post("/runner/v1/jobs/claim")
    neighbour_table(tmp_path / "neighbours.json", ("192.0.2.10", "02:00:00:00:00:10", 3600, "STALE"))

    assert upload(client, job_id, LAB_SCAN) == 204

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


def test_vendor_names_the_maker_or_a_private_address(tmp_path, monkeypatch):
    prefixes = tmp_path / "nmap-mac-prefixes"
    prefixes.write_text("# fictional\nACDE48 Example Devices\n")
    monkeypatch.setattr(neighbours, "VENDORS", prefixes)
    neighbours._vendors.cache_clear()

    assert neighbours.vendor("ac:de:48:00:00:01") == "Example Devices"
    assert neighbours.vendor("02:00:00:00:00:10") == "private address"
    assert neighbours.vendor("00:00:00:00:00:01") is None
    neighbours._vendors.cache_clear()


def test_the_dashboard_shows_each_address_mac(committed, lab_scope):
    scanned(committed)
    with committed.begin() as conn:
        conn.execute(
            insert(mac_sightings).values(
                address="192.0.2.10", mac="02:00:00:00:00:10", confirmed_at=func.now(), evidence_digest="x"
            )
        )

    page = dashboard(committed, lab_scope).get("/", headers=OWNER).text

    # Once under each finding on the device in Needs attention, and once under Unnamed devices.
    assert page.count("02:00:00:00:00:10 · private address") == 4
