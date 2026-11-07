import re
from datetime import timedelta

import pytest
from sqlalchemy import func, select, update

from pen16 import coverage, jobs, runner, status
from pen16.db import Profile, findings, sweep_blocks
from pen16.db import jobs as jobs_table
from pen16.scope import OutOfScopeError
from tests.conftest import (
    LAB,
    OWNER,
    closed_xml,
    dashboard,
    lab_xml,
    open_incidents,
    queue,
    runner_client,
    upload,
)

LAB_HOST = "192.0.2.10"


def without_lab_host(raw):
    """A scan in which the lab host didn't answer and the gateway did."""
    return re.sub(
        rb'<host [^>]*>(?:(?!</host>).)*?addr="192\.0\.2\.10".*?</host>\n', b"", raw, flags=re.DOTALL
    )


def scanned_nightly(engine, client, raw):
    job_id = queue(engine)
    client.post("/runner/v1/jobs/claim")
    assert upload(client, job_id, raw) == 204


def sweep_once(engine, client, raw=None):
    """Queue the next sweep chunk, run it with `raw` as its output, and return what the runner was sent."""
    with engine.begin() as conn:
        assert jobs.queue_sweep(conn, LAB) is not None
    job = client.post("/runner/v1/jobs/claim").json()
    assert upload(client, job["id"], raw or closed_xml()) == 204
    return job


def lab_sweep(engine):
    with engine.connect() as conn:
        return coverage.sweep(conn, "lab", conn.scalar(select(func.now())))


def age_blocks(engine, blocks, days):
    with engine.begin() as conn:
        conn.execute(
            update(sweep_blocks)
            .where(sweep_blocks.c.block.in_(blocks))
            .values(swept_at=func.now() - timedelta(days=days))
        )


def let_pace_pass(engine):
    """Make the last sweep chunk old enough that the next one is due."""
    with engine.begin() as conn:
        conn.execute(
            update(jobs_table)
            .where(jobs_table.c.profile == Profile.SWEEP)
            .values(created_at=func.now() - timedelta(days=7))
        )


def test_a_known_device_that_doesnt_answer_is_unavailable_and_its_findings_stay_open(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    scanned_nightly(committed, client, lab_xml())

    scanned_nightly(committed, client, without_lab_host(closed_xml()))

    with committed.connect() as conn:
        [lab] = status.network_coverage(conn, LAB, conn.scalar(select(func.now())))
        [web_app] = [f for f in status.needs_attention(conn) if f.port == 8080]
        assert conn.scalar(select(findings.c.status).where(findings.c.port == 8080)) == "open"
    assert (lab.latest.gateway_up, lab.latest.hosts_up) == (True, 1)
    assert lab.latest.unavailable == [(LAB_HOST, f"new-{LAB_HOST}")]
    assert web_app.unavailable
    assert "Didn't answer" in dashboard(committed).get("/", headers=OWNER).text


def test_sweep_chunks_cover_every_port_on_pace_and_the_sweep_age_counts_down(
    committed, tmp_path, monkeypatch
):
    # Room for 16 blocks a chunk on the lab's two addresses (the host and its gateway): four chunks a sweep.
    monkeypatch.setattr(coverage, "CHUNK_PAIRS", 2 * coverage.BLOCK * 16)
    client = runner_client(committed, tmp_path)
    scanned_nightly(committed, client, lab_xml())

    first = sweep_once(committed, client)

    assert (first["profile"], first["port_from"], first["port_to"]) == ("sweep", 1, 16 * coverage.BLOCK - 1)
    assert first["targets"] == ["192.0.2.1", LAB_HOST]
    assert lab_sweep(committed).swept == 16
    # The next chunk waits for its turn: a sweep paced to finish inside FRESH, not all at once.
    with committed.begin() as conn:
        assert jobs.queue_sweep(conn, LAB) is None
    for _ in range(3):
        let_pace_pass(committed)
        last = sweep_once(committed, client)
    assert last["port_to"] == 65535
    swept = lab_sweep(committed)
    assert (swept.complete, swept.stale) == (True, False)

    # The least recently swept blocks go next, and sweeping them brings the sweep's age down.
    age_blocks(committed, range(16), 6)
    age_blocks(committed, range(16, 64), 1)
    before = lab_sweep(committed).oldest
    let_pace_pass(committed)
    again = sweep_once(committed, client)
    assert again["port_from"] == 1
    assert lab_sweep(committed).oldest - before > timedelta(days=4)


def test_a_chunk_whose_gateway_didnt_answer_sweeps_nothing(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    scanned_nightly(committed, client, lab_xml())

    sweep_once(committed, client, closed_xml(gateway=False))

    assert lab_sweep(committed).swept == 0


def test_a_sweep_two_periods_behind_alerts_once_and_recovers(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    scanned_nightly(committed, client, lab_xml())
    sweep_once(committed, client)

    def incidents_after_check():
        with committed.begin() as conn:
            coverage.check(conn, LAB)
            return open_incidents(conn)

    # A week and a day: one period missed, which ordinary slippage explains.
    age_blocks(committed, range(coverage.BLOCKS), 8)
    slipped = incidents_after_check()
    age_blocks(committed, range(coverage.BLOCKS), 15)
    behind = incidents_after_check()
    let_pace_pass(committed)
    sweep_once(committed, client)

    assert "sweep:lab" not in slipped
    assert "sweep:lab" in behind
    assert "sweep:lab" not in incidents_after_check()


def test_a_waiting_sweep_chunk_neither_swallows_a_nightly_scan_nor_counts_as_one(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    scanned_nightly(committed, client, lab_xml())
    with committed.connect() as conn:
        nightly_finished = status.health(conn, conn.scalar(select(func.now()))).last_scan

    with committed.begin() as conn:
        chunk = jobs.queue_sweep(conn, LAB)
        nightly = jobs.request(conn, LAB, "owner:test", "test", Profile.NIGHTLY)
        assert jobs.queue_sweep(conn, LAB) is None
    client.post("/runner/v1/jobs/claim")
    assert upload(client, chunk, closed_xml()) == 204

    assert nightly != chunk
    with committed.connect() as conn:
        assert status.health(conn, conn.scalar(select(func.now()))).last_scan == nightly_finished


def test_the_runner_refuses_a_sweep_without_a_proper_port_range():
    job = {"profile": "sweep", "targets": [LAB_HOST], "exclude": ["192.0.2.12/32"], "extra_tcp": []}

    for port_from, port_to in (("1", "1024"), (0, 1024), (1024, 1), (1, 70000), (None, None)):
        with pytest.raises(OutOfScopeError):
            runner._argv(LAB, {**job, "port_from": port_from, "port_to": port_to}, None)
    argv = runner._argv(LAB, {**job, "port_from": 1, "port_to": 1023}, None)
    assert argv[argv.index("-p") + 1] == "T:1-1023"
