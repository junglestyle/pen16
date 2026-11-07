import gzip
import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, update

from pen16 import evidence, jobs, runner, scope, tokens
from pen16.db import TokenKind, findings, schedules
from pen16.db import jobs as jobs_table
from pen16.scope import OutOfScopeError
from tests.conftest import LAB, alerts, closed_xml, lab_xml, open_incidents, queue, runner_client, upload

SERVICES = Path(__file__).parent / "fixtures" / "nmap-services"


def miss_deadlines(engine, client):
    """Claim the queued job and let it miss its deadline, then do the same to its one retry."""
    for _ in range(2):
        assert client.post("/runner/v1/jobs/claim").status_code == 200
        with engine.begin() as conn:
            conn.execute(update(jobs_table).values(deadline_at=func.now() - timedelta(seconds=1)))
            jobs.expire(conn)


def incidents_and_alerts(engine):
    with engine.connect() as conn:
        return open_incidents(conn), alerts(conn)


def test_scan_round_trip_opens_one_alerted_finding(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    job_id = queue(committed)

    job = client.post("/runner/v1/jobs/claim").json()
    assert job["id"] == job_id
    assert job["exclude"] == ["192.0.2.12/32"]
    assert upload(client, job_id, lab_xml()) == 204

    assert len(list(tmp_path.glob("*.xml.gz"))) == 1
    [body] = [body for kind, body in incidents_and_alerts(committed)[1] if kind == "finding"]
    assert "8080/tcp" in body
    with committed.connect() as conn:
        assert conn.scalar(select(jobs_table.c.status)) == "succeeded"


def test_late_or_repeated_upload_is_refused(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    job_id = queue(committed)
    client.post("/runner/v1/jobs/claim")
    upload(client, job_id, lab_xml())

    assert upload(client, job_id, closed_xml()) == 409
    with committed.connect() as conn:
        assert conn.scalar(select(findings.c.status).where(findings.c.port == 8080)) == "open"


def test_silent_gateway_blocks_closure_and_says_so(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    for raw in (lab_xml(), closed_xml(gateway=False)):
        job_id = queue(committed)
        client.post("/runner/v1/jobs/claim")
        upload(client, job_id, raw)

    with committed.connect() as conn:
        assert conn.scalar(select(findings.c.status).where(findings.c.port == 8080)) == "open"
    assert incidents_and_alerts(committed)[0] == ["gateway:lab"]


def test_gateway_up_lets_closed_ports_resolve(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    for raw in (lab_xml(), closed_xml()):
        job_id = queue(committed)
        client.post("/runner/v1/jobs/claim")
        upload(client, job_id, raw)

    with committed.connect() as conn:
        assert conn.scalar(select(findings.c.status).where(findings.c.port == 8080)) == "resolved"


def test_a_requested_scan_retries_once_then_fails_on_the_dashboard(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    queue(committed)

    miss_deadlines(committed, client)

    assert client.post("/runner/v1/jobs/claim").status_code == 204
    with committed.connect() as conn:
        assert conn.scalar(select(jobs_table.c.status)) == "failed"
    assert incidents_and_alerts(committed) == ([], [])


def test_two_failed_nights_alert_once_and_a_good_one_recovers(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    queue(committed, schedule="nightly")
    miss_deadlines(committed, client)
    assert incidents_and_alerts(committed) == ([], [])

    for _ in range(2):
        queue(committed, schedule="nightly")
        miss_deadlines(committed, client)
    assert incidents_and_alerts(committed)[0] == ["schedule:nightly"]

    job_id = queue(committed, schedule="nightly")
    client.post("/runner/v1/jobs/claim")
    upload(client, job_id, closed_xml())

    incidents, sent = incidents_and_alerts(committed)
    assert incidents == []
    assert [kind for kind, _ in sent if kind == "health"] == ["health", "health"]


def test_a_due_schedule_takes_a_waiting_requested_scan_as_its_run(committed):
    requested = queue(committed)
    with committed.begin() as conn:
        conn.execute(update(schedules).values(next_run_at=func.now() - timedelta(days=3)))
        jobs.run_due_schedules(conn, LAB)

    with committed.connect() as conn:
        rows = [tuple(row) for row in conn.execute(select(jobs_table.c.id, jobs_table.c.schedule))]
        assert rows == [(requested, "nightly")]
        # The missed windows don't each queue a scan: the next run is within one period from now.
        assert conn.scalar(
            select(schedules.c.next_run_at.between(func.now(), func.now() + timedelta(hours=24)))
        )


def test_only_a_runner_token_gets_in(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    queue(committed)
    with committed.begin() as conn:
        compliance = tokens.create(conn, TokenKind.COMPLIANCE, "lab-rhel9")

    for authorization in ("Bearer pen16_x_y", f"Bearer {compliance}", ""):
        response = client.post("/runner/v1/jobs/claim", headers={"Authorization": authorization})
        assert response.status_code == 401
    with committed.connect() as conn:
        assert conn.scalar(select(jobs_table.c.status)) == "queued"


def test_a_revoked_runner_token_is_refused_from_the_next_request(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    assert client.post("/runner/v1/jobs/claim").status_code == 204
    token_id = client.headers["Authorization"].split("_")[1]

    with committed.begin() as conn:
        tokens.revoke(conn, token_id)

    assert client.post("/runner/v1/jobs/claim").status_code == 401
    with committed.begin() as conn, pytest.raises(LookupError):
        tokens.revoke(conn, token_id)


def test_hostile_upload_fails_the_attempt(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    job_id = queue(committed)
    client.post("/runner/v1/jobs/claim")

    hostile = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "a">]><nmaprun>&a;</nmaprun>'
    response = client.post(f"/runner/v1/jobs/{job_id}/result", content=gzip.compress(hostile))

    assert response.status_code == 422
    with committed.connect() as conn:
        assert conn.scalar(select(jobs_table.c.status)) == "queued"


def test_an_upload_past_the_limit_is_cut_off_and_fails_the_attempt(committed, tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "MAX_COMPRESSED", 1024)
    client = runner_client(committed, tmp_path)
    job_id = queue(committed)
    client.post("/runner/v1/jobs/claim")

    response = client.post(f"/runner/v1/jobs/{job_id}/result", content=os.urandom(4096))

    assert response.status_code == 413
    assert list(tmp_path.glob("*.gz")) == []
    with committed.connect() as conn:
        assert tuple(conn.execute(select(jobs_table.c.status, jobs_table.c.error)).one()) == (
            "queued",
            "scan output over the upload limit",
        )


def test_a_scan_is_killed_at_its_deadline_or_its_output_limit(monkeypatch):
    with pytest.raises(runner.ScanFailedError, match="deadline"):
        runner.scan([sys.executable, "-c", "import time; time.sleep(10)"], 0.2)

    monkeypatch.setattr(runner, "MAX_EXPANDED", 1024)
    with pytest.raises(runner.ScanFailedError, match="limit"):
        runner.scan([sys.executable, "-c", "import sys; sys.stdout.write('x' * 100_000)"], 10)

    with pytest.raises(runner.ScanFailedError, match="exited 3: no route"):
        runner.scan([sys.executable, "-c", "import sys; sys.stderr.write('no route'); sys.exit(3)"], 10)


def test_runner_refuses_a_job_outside_its_own_scope(committed, tmp_path):
    client = runner_client(committed, tmp_path)
    queue(committed)
    job = client.post("/runner/v1/jobs/claim").json()
    narrower = scope.parse(
        [{"name": "lab", "cidr": "192.0.2.0/24", "gateway": "192.0.2.1"}], ["192.0.2.12/32", "192.0.2.13/32"]
    )

    runner.run_job(client, narrower, job, SERVICES)

    with committed.connect() as conn:
        assert "192.0.2.13/32" in conn.scalar(select(jobs_table.c.error))


def test_scope_rejects_targets_outside_and_dropped_exclusions():
    with pytest.raises(OutOfScopeError):
        LAB.check(["192.0.2.0/23"], ["192.0.2.12/32"])
    with pytest.raises(OutOfScopeError):
        LAB.check(["198.51.100.7/32"], ["192.0.2.12/32"])
    with pytest.raises(OutOfScopeError):
        LAB.check(["192.0.2.0/24"], [])
    LAB.check(["192.0.2.8/29"], ["192.0.2.12/32"])


@pytest.mark.skipif(not Path("/proc/self/ns/net").exists(), reason="needs Linux network namespaces")
def test_runner_waits_for_egress_on_its_current_namespace(tmp_path):
    marker = tmp_path / "ready"
    assert not runner.egress_ready(marker)

    marker.write_text("net:[1]\n")
    assert not runner.egress_ready(marker)

    namespace = Path("/proc/self/ns/net").readlink().as_posix()
    marker.write_text(f"{namespace} 1")
    assert not runner.egress_ready(marker, Path("/proc/self"))

    marker.write_text(runner.stamp(Path("/proc/self")))
    assert runner.egress_ready(marker, Path("/proc/self"))
