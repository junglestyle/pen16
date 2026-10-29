import gzip
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from pen16 import jobs, listener, runner, scope, tokens
from pen16.config import Config
from pen16.db import findings, notifications
from pen16.db import jobs as jobs_table
from pen16.scope import OutOfScopeError
from tests.conftest import CLOSED_SCAN, LAB_SCAN

SERVICES = Path(__file__).parent / "fixtures" / "nmap-services"


def runner_client(engine, scope, evidence):
    app = listener.create(engine, Config(scope=scope, owner_login="", dashboard_url=""), evidence)
    with engine.begin() as conn:
        token = tokens.create(conn, "runner", "lab")
    return TestClient(app, headers={"Authorization": f"Bearer {token}"})


def queue(engine, scope):
    with engine.begin() as conn:
        return jobs.request(conn, scope, "owner:test", "test")


def upload(client, job_id, path):
    response = client.post(f"/runner/v1/jobs/{job_id}/result", content=gzip.compress(path.read_bytes()))
    return int(response.status_code)


def notices(engine):
    with engine.connect() as conn:
        return [tuple(row) for row in conn.execute(select(notifications.c.kind, notifications.c.title))]


def test_scan_round_trip_opens_one_alerted_finding(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    job_id = queue(committed, lab_scope)

    job = client.post("/runner/v1/jobs/claim").json()
    assert job["id"] == job_id
    assert job["exclude"] == ["192.0.2.12/32"]
    assert upload(client, job_id, LAB_SCAN) == 204

    assert len(list(tmp_path.glob("*.xml.gz"))) == 1
    assert ("finding", "3 unexpected service(s)") in notices(committed)
    with committed.connect() as conn:
        assert conn.scalar(select(jobs_table.c.status)) == "succeeded"


def test_late_or_repeated_upload_is_refused(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    job_id = queue(committed, lab_scope)
    client.post("/runner/v1/jobs/claim")
    upload(client, job_id, LAB_SCAN)

    assert upload(client, job_id, CLOSED_SCAN) == 409
    with committed.connect() as conn:
        assert conn.scalar(select(findings.c.status).where(findings.c.port == 8080)) == "open"


def test_silent_gateway_blocks_closure_and_says_so(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    for path in (LAB_SCAN, LAB_SCAN):
        job_id = queue(committed, lab_scope)
        client.post("/runner/v1/jobs/claim")
        upload(client, job_id, path)

    assert ("health", "Gateway didn't answer") in notices(committed)


def test_gateway_up_lets_closed_ports_resolve(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    for path in (LAB_SCAN, CLOSED_SCAN):
        job_id = queue(committed, lab_scope)
        client.post("/runner/v1/jobs/claim")
        upload(client, job_id, path)

    with committed.connect() as conn:
        assert conn.scalar(select(findings.c.status).where(findings.c.port == 8080)) == "resolved"


def test_missed_deadline_retries_once_then_fails_loudly(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    queue(committed, lab_scope)
    for _ in range(2):
        assert client.post("/runner/v1/jobs/claim").status_code == 200
        with committed.begin() as conn:
            conn.execute(update(jobs_table).values(deadline_at=datetime.now(UTC) - timedelta(seconds=1)))
            jobs.expire(conn)

    assert client.post("/runner/v1/jobs/claim").status_code == 204
    assert notices(committed) == [("health", "Scan failed")]


def test_runner_token_is_required(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    queue(committed, lab_scope)

    assert (
        client.post("/runner/v1/jobs/claim", headers={"Authorization": "Bearer pen16_x_y"}).status_code == 401
    )
    assert client.post("/runner/v1/jobs/claim", headers={"Authorization": ""}).status_code == 401


def test_hostile_upload_fails_the_attempt(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    job_id = queue(committed, lab_scope)
    client.post("/runner/v1/jobs/claim")

    hostile = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "a">]><nmaprun>&a;</nmaprun>'
    response = client.post(f"/runner/v1/jobs/{job_id}/result", content=gzip.compress(hostile))

    assert response.status_code == 422
    with committed.connect() as conn:
        assert conn.scalar(select(jobs_table.c.status)) == "queued"


def test_runner_refuses_a_job_outside_its_own_scope(committed, lab_scope, tmp_path):
    client = runner_client(committed, lab_scope, tmp_path)
    queue(committed, lab_scope)
    job = client.post("/runner/v1/jobs/claim").json()
    narrower = scope.parse(
        [{"name": "lab", "cidr": "192.0.2.0/24", "gateway": "192.0.2.1"}], ["192.0.2.12/32", "192.0.2.13/32"]
    )

    runner.run_job(client, narrower, job, SERVICES)

    with committed.connect() as conn:
        assert conn.scalar(select(jobs_table.c.error)) == "exclusion 192.0.2.13/32 is missing"


def test_scope_rejects_targets_outside_and_dropped_exclusions(lab_scope):
    with pytest.raises(OutOfScopeError):
        lab_scope.check(["192.0.2.0/23"], ["192.0.2.12/32"])
    with pytest.raises(OutOfScopeError):
        lab_scope.check(["198.51.100.7/32"], ["192.0.2.12/32"])
    with pytest.raises(OutOfScopeError):
        lab_scope.check(["192.0.2.0/24"], [])
    lab_scope.check(["192.0.2.8/29"], ["192.0.2.12/32"])


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
