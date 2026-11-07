import gzip

from sqlalchemy import insert, select

from pen16 import evidence, exposure, status
from pen16.db import DecisionKind, assets, bindings, expected_services, findings
from tests.conftest import OWNER, OWNER_LOGIN, SAME_ORIGIN, dashboard, ingest, lab, lab_xml, scanned


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

    assert "<script>x" not in page
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


def test_a_private_mac_change_is_asked_about_and_same_device_rejoins(committed):
    with committed.begin() as conn:
        ingest(conn, lab(), {"192.0.2.10": "02:00:00:00:00:10"})
        exposure.name_asset(conn, "new-192.0.2.10", "fileserver", OWNER_LOGIN)
        ingest(conn, lab(shift=86400), {"192.0.2.10": "06:00:00:00:00:10"})
    client = dashboard(committed)

    page = client.get("/", headers=OWNER).text
    same = post(client, "/assets/name", {"provisional_id": "new-192.0.2.10-2", "asset_id": "fileserver"})

    assert "Is this fileserver?" in page
    assert same.status_code == 303
    seen = view(committed)
    assert seen.unnamed == []
    assert [(d.id, d.addresses) for d in seen.devices] == [
        ("fileserver", [("192.0.2.10", "06:00:00:00:00:10")])
    ]


def test_retiring_a_device_from_the_dashboard(committed):
    with committed.begin() as conn:
        ingest(conn, lab())
        exposure.name_asset(conn, "new-192.0.2.10", "fileserver", OWNER_LOGIN)
    client = dashboard(committed)

    blank = post(client, "/assets/retire", {"asset_id": "fileserver", "reason": " "})
    retired = post(client, "/assets/retire", {"asset_id": "fileserver", "reason": "sold it"})

    assert (blank.status_code, retired.status_code) == (400, 303)
    seen = view(committed)
    assert (seen.devices, seen.needs_attention) == ([], [])


def test_moving_an_address_from_a_devices_page_shows_on_both_pages_and_in_recent_changes(committed):
    with committed.begin() as conn:
        ingest(conn, lab())
        exposure.name_asset(conn, "new-192.0.2.10", "fileserver", OWNER_LOGIN)
        conn.execute(insert(assets).values(id="nas", provisional=False))
    client = dashboard(committed)

    blank = post(client, "/assets/move", {"address": "192.0.2.10", "asset_id": "nas", "reason": " "})
    moved = post(
        client, "/assets/move", {"address": "192.0.2.10", "asset_id": "nas", "reason": "its second NIC"}
    )

    assert blank.status_code == 400
    assert (moved.status_code, moved.headers["location"]) == (303, "/assets/nas")
    for page in ("/assets/fileserver", "/assets/nas", "/changes"):
        assert "its second NIC" in client.get(page, headers=OWNER).text
    assert client.get("/assets/printer", headers=OWNER).status_code == 404


def test_raw_scan_evidence_is_served_only_for_a_recorded_scan(committed, tmp_path):
    scan = lab()
    with committed.begin() as conn:
        ingest(conn, scan)
    unrecorded = "0" * 64
    evidence.store(tmp_path, scan.digest, gzip.compress(lab_xml()))
    evidence.store(tmp_path, unrecorded, gzip.compress(b"<nmaprun/>"))
    client = dashboard(committed, tmp_path)

    served = client.get(f"/evidence/{scan.digest}.xml", headers=OWNER)

    assert (served.status_code, served.content) == (200, lab_xml())
    assert client.get(f"/evidence/{unrecorded}.xml", headers=OWNER).status_code == 404
