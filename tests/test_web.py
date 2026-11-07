from sqlalchemy import insert, select

from pen16 import status
from pen16.db import DecisionKind, assets, bindings, expected_services, findings
from tests.conftest import OWNER, SAME_ORIGIN, dashboard, lab_xml, scanned


def post(client, path, data):
    return client.post(path, data=data, headers=SAME_ORIGIN, follow_redirects=False)


def view(engine):
    with engine.connect() as conn:
        return status.dashboard(conn)


def test_only_the_owner_gets_in(committed):
    client = dashboard(committed)

    assert client.get("/").status_code == 403
    assert client.get("/", headers={"Tailscale-User-Login": "guest@example.com"}).status_code == 403
    assert client.get("/", headers=OWNER).status_code == 200
    # The logo and manifest are the only things served without the owner check.
    assert client.get("/static/manifest.webmanifest").status_code == 200


def test_cross_site_post_is_refused(committed):
    client = dashboard(committed)

    cross_site = client.post("/scan", headers={**OWNER, "Sec-Fetch-Site": "cross-site"})
    other_origin = client.post("/scan", headers={**OWNER, "Origin": "https://evil.example.com"})

    assert (cross_site.status_code, other_origin.status_code) == (403, 403)
    assert view(committed).health.latest_job is None


def test_marking_findings_expected_from_the_dashboard(committed):
    scanned(committed)
    client = dashboard(committed)
    with committed.connect() as conn:
        ssh = conn.scalar(select(findings.c.id).where(findings.c.port == 22))

    response = post(client, "/findings/expect", {"finding": [str(ssh)], "reason": "admin over ssh"})

    assert response.status_code == 303
    seen = view(committed)
    assert [(e.port, e.reason) for e in seen.expected] == [(22, "admin over ssh")]
    assert 22 not in [f.port for f in seen.needs_attention]


def test_scan_output_is_escaped(committed):
    scanned(committed, lab_xml().replace(b'product="Werkzeug httpd"', b'product="&lt;script&gt;x"'))
    with committed.begin() as conn:
        conn.execute(
            insert(expected_services).values(
                asset_id="new-192.0.2.10", protocol="tcp", port=22, vantage="internal", reason="<b>ok</b>"
            )
        )

    page = dashboard(committed).get("/", headers=OWNER).text

    assert "<script>" not in page
    assert "&lt;script&gt;x" in page
    assert "<b>ok</b>" not in page


def test_accepting_a_risk_and_withdrawing_it_from_the_dashboard(committed):
    with committed.begin() as conn:
        conn.execute(insert(assets).values(id="fileserver", provisional=False))
        conn.execute(insert(bindings).values(address="192.0.2.10", asset_id="fileserver"))
    scanned(committed)
    client = dashboard(committed)
    with committed.connect() as conn:
        web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))

    response = post(
        client, "/findings/decide", {"finding": [str(web_app)], "kind": "accepted-risk", "reason": "lab tool"}
    )

    assert response.status_code == 303
    [decided] = view(committed).decided
    assert (decided.id, decided.kind, decided.reason) == (web_app, DecisionKind.ACCEPTED_RISK, "lab tool")
    assert client.get("/", headers=OWNER).status_code == 200

    post(client, "/decisions/withdraw", {"decision": str(decided.decision_id)})

    seen = view(committed)
    assert seen.decided == []
    [back] = [f for f in seen.needs_attention if f.id == web_app]
    assert "owner@example.com" in back.withdrawal


def test_input_the_services_refuse_is_a_bad_request(committed):
    scanned(committed)
    client = dashboard(committed)
    with committed.connect() as conn:
        web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))

    unnamed = post(
        client, "/findings/decide", {"finding": [str(web_app)], "kind": "accepted-risk", "reason": "fine"}
    )
    blank = post(client, "/findings/expect", {"finding": [str(web_app)], "reason": " "})
    unknown = post(client, "/compliance/waive", {"asset_id": "nas", "rule_id": "x", "reason": "r"})

    assert (unnamed.status_code, blank.status_code, unknown.status_code) == (400, 400, 400)
    assert [f.id for f in view(committed).needs_attention if f.port == 8080] == [web_app]
