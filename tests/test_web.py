from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import insert, select

from pen16 import nmap, web
from pen16.config import Config
from pen16.db import assets, bindings, decisions, expected_services, findings
from tests.conftest import ingest, lab_xml

OWNER = {"Tailscale-User-Login": "owner@example.com"}


def dashboard(engine, scope, evidence_dir=Path("/nonexistent")):
    settings = Config(scope=scope, owner_login="owner@example.com", dashboard_url="")
    return TestClient(web.create(engine, settings, evidence_dir), base_url="https://pen16.example.ts.net")


def scanned(engine, raw=None):
    with engine.begin() as conn:
        ingest(conn, nmap.parse(raw or lab_xml()))


def test_only_the_owner_gets_in(committed, lab_scope):
    client = dashboard(committed, lab_scope)

    assert client.get("/").status_code == 403
    assert client.get("/", headers={"Tailscale-User-Login": "guest@example.com"}).status_code == 403
    assert client.get("/", headers=OWNER).status_code == 200
    # The logo and manifest are the only things served without the owner check.
    assert client.get("/static/manifest.webmanifest").status_code == 200


def test_cross_site_post_is_refused(committed, lab_scope):
    client = dashboard(committed, lab_scope)

    response = client.post("/scan", headers={**OWNER, "Sec-Fetch-Site": "cross-site"})

    assert response.status_code == 403


def test_marking_findings_expected_from_the_dashboard(committed, lab_scope):
    scanned(committed)
    client = dashboard(committed, lab_scope)
    with committed.connect() as conn:
        ssh = conn.scalar(select(findings.c.id).where(findings.c.port == 22))

    response = client.post(
        "/findings/expect",
        data={"finding": [str(ssh)], "reason": "admin over ssh"},
        headers={**OWNER, "Origin": "https://pen16.example.ts.net"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with committed.connect() as conn:
        assert conn.scalar(select(expected_services.c.reason)) == "admin over ssh"
        assert conn.scalar(select(findings.c.status).where(findings.c.id == ssh)) == "resolved"


def test_scan_output_is_escaped(committed, lab_scope):
    scanned(committed, lab_xml().replace(b'product="Werkzeug httpd"', b'product="&lt;script&gt;x"'))
    with committed.begin() as conn:
        conn.execute(
            insert(expected_services).values(
                asset_id="new-192.0.2.10", protocol="tcp", port=22, vantage="internal", reason="<b>ok</b>"
            )
        )

    page = dashboard(committed, lab_scope).get("/", headers=OWNER).text

    assert "<script>" not in page
    assert "&lt;script&gt;x" in page
    assert "<b>ok</b>" not in page


def test_accepting_a_risk_from_the_dashboard(committed, lab_scope):
    with committed.begin() as conn:
        conn.execute(insert(assets).values(id="fileserver", provisional=False))
        conn.execute(insert(bindings).values(address="192.0.2.10", asset_id="fileserver"))
    scanned(committed)
    client = dashboard(committed, lab_scope)
    post = {"headers": {**OWNER, "Origin": "https://pen16.example.ts.net"}, "follow_redirects": False}
    with committed.connect() as conn:
        web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))

    response = client.post(
        "/findings/decide",
        data={"finding": [str(web_app)], "kind": "accepted-risk", "reason": "lab tool"},
        **post,
    )

    assert response.status_code == 303
    page = client.get("/", headers=OWNER).text
    assert "Accepted risks and false positives (1)" in page
    assert "Accepted risk: lab tool" in page

    with committed.connect() as conn:
        decision = conn.scalar(select(decisions.c.id))
    client.post("/decisions/withdraw", data={"decision": str(decision)}, **post)
    page = client.get("/", headers=OWNER).text
    assert "Accepted risks and false positives (0)" in page
    assert "Decision withdrawn: withdrawn by owner@example.com" in page


def test_a_decision_on_an_unnamed_device_is_refused(committed, lab_scope):
    scanned(committed)
    with committed.connect() as conn:
        web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))

    response = dashboard(committed, lab_scope).post(
        "/findings/decide",
        data={"finding": [str(web_app)], "kind": "accepted-risk", "reason": "fine"},
        headers={**OWNER, "Origin": "https://pen16.example.ts.net"},
    )

    assert response.status_code == 400


def test_input_the_services_refuse_is_a_bad_request(committed, lab_scope):
    scanned(committed)
    client = dashboard(committed, lab_scope)
    post = {"headers": {**OWNER, "Origin": "https://pen16.example.ts.net"}, "follow_redirects": False}
    with committed.connect() as conn:
        ssh = conn.scalar(select(findings.c.id).where(findings.c.port == 22))

    blank = client.post("/findings/expect", data={"finding": [str(ssh)], "reason": " "}, **post)
    unknown = client.post(
        "/compliance/waive", data={"asset_id": "nas", "rule_id": "x", "reason": "r"}, **post
    )

    assert (blank.status_code, unknown.status_code) == (400, 400)
