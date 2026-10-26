from fastapi.testclient import TestClient
from sqlalchemy import Engine, insert, select

from pen15 import exposure, nmap, web
from pen15.config import Config
from pen15.db import expected_services, findings
from pen15.scope import Scope
from tests.conftest import LAB_SCAN

OWNER = {"Tailscale-User-Login": "owner@example.com"}


def dashboard(engine: Engine, scope: Scope) -> TestClient:
    settings = Config(scope=scope, owner_login="owner@example.com", dashboard_url="")
    return TestClient(web.create(engine, settings), base_url="https://pen15.example.ts.net")


def scanned(engine: Engine, raw: bytes = LAB_SCAN.read_bytes()) -> None:
    with engine.begin() as conn:
        exposure.ingest(conn, nmap.parse(raw), vantage="internal")


def test_only_the_owner_gets_in(committed: Engine, lab_scope: Scope) -> None:
    client = dashboard(committed, lab_scope)

    assert client.get("/").status_code == 403
    assert client.get("/", headers={"Tailscale-User-Login": "guest@example.com"}).status_code == 403
    assert client.get("/", headers=OWNER).status_code == 200


def test_cross_site_post_is_refused(committed: Engine, lab_scope: Scope) -> None:
    client = dashboard(committed, lab_scope)

    response = client.post("/scan", headers={**OWNER, "Sec-Fetch-Site": "cross-site"})

    assert response.status_code == 403


def test_marking_findings_expected_from_the_dashboard(committed: Engine, lab_scope: Scope) -> None:
    scanned(committed)
    client = dashboard(committed, lab_scope)
    with committed.connect() as conn:
        ssh = conn.scalar(select(findings.c.id).where(findings.c.port == 22))

    response = client.post(
        "/findings/expect",
        data={"finding": [str(ssh)], "reason": "admin over ssh"},
        headers={**OWNER, "Origin": "https://pen15.example.ts.net"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with committed.connect() as conn:
        assert conn.scalar(select(expected_services.c.reason)) == "admin over ssh"
        assert conn.scalar(select(findings.c.status).where(findings.c.id == ssh)) == "resolved"


def test_scan_output_is_escaped(committed: Engine, lab_scope: Scope) -> None:
    scanned(
        committed, LAB_SCAN.read_bytes().replace(b'product="Werkzeug httpd"', b'product="&lt;script&gt;x"')
    )
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
