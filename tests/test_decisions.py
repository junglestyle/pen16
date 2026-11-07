import pytest
from sqlalchemy import exists, insert, select

from pen16 import exposure
from pen16.db import DecisionKind, assets, bindings, decisions, expected_services, findings
from pen16.exposure import Finding
from tests.conftest import closed, lab


def web_app_open(conn):
    """A named fileserver with ssh and smb expected, and its web app on 8080 open and unexpected."""
    conn.execute(insert(assets).values(id="fileserver", provisional=False))
    conn.execute(insert(bindings).values(address="192.0.2.10", asset_id="fileserver"))
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
    exposure.ingest(conn, lab(), vantage="internal")
    return conn.scalar(select(findings.c.id).where(findings.c.port == 8080))


def needs_attention(conn):
    """Open findings without an active decision, as the dashboard lists them."""
    active = (decisions.c.finding_id == findings.c.id) & decisions.c.withdrawn_at.is_(None)
    return list(
        conn.scalars(select(findings.c.port).where(findings.c.status == "open", ~exists().where(active)))
    )


def test_accepted_risk_leaves_needs_attention_and_stays_quiet(conn):
    web_app = web_app_open(conn)

    exposure.decide(
        conn, [web_app], DecisionKind.ACCEPTED_RISK, "lab tool, tailnet only", "owner@example.com"
    )

    assert needs_attention(conn) == []
    assert exposure.ingest(conn, lab(shift=3600), vantage="internal") == []
    # Closed, then open again with the same service: still decided, no alert.
    exposure.ingest(conn, closed(), vantage="internal")
    assert exposure.ingest(conn, lab(shift=2 * 86400), vantage="internal") == []
    assert needs_attention(conn) == []


def test_a_new_version_brings_the_decision_back_with_the_reason(conn):
    web_app = web_app_open(conn)
    exposure.decide(
        conn, [web_app], DecisionKind.ACCEPTED_RISK, "lab tool, tailnet only", "owner@example.com"
    )

    opened = exposure.ingest(conn, lab(shift=86400, version=b'version="3.1.0"'), vantage="internal")

    assert len(opened) == 1
    assert (opened[0].asset_id, opened[0].port) == ("fileserver", 8080)
    assert "3.0.1" in opened[0].why
    assert "3.1.0" in opened[0].why
    assert needs_attention(conn) == [8080]
    assert "3.1.0" in conn.scalar(select(decisions.c.withdrawal))


def test_a_scan_without_the_version_isnt_a_change(conn):
    web_app = web_app_open(conn)
    exposure.decide(
        conn, [web_app], DecisionKind.FALSE_POSITIVE, "it's the printer's web ui", "owner@example.com"
    )

    assert exposure.ingest(conn, lab(shift=86400, version=b""), vantage="internal") == []
    assert needs_attention(conn) == []


def test_an_unnamed_device_takes_no_decision(conn):
    exposure.ingest(conn, lab(), vantage="internal")
    web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))

    with pytest.raises(ValueError, match=r"new-192\.0\.2\.10"):
        exposure.decide(conn, [web_app], DecisionKind.ACCEPTED_RISK, "fine", "owner@example.com")


def test_withdrawing_a_decision_puts_the_finding_back(conn):
    web_app = web_app_open(conn)
    exposure.decide(conn, [web_app], DecisionKind.ACCEPTED_RISK, "lab tool", "owner@example.com")
    decision = conn.scalar(select(decisions.c.id))

    exposure.withdraw(conn, decision, "withdrawn by owner@example.com")

    assert needs_attention(conn) == [8080]


def test_resolving_by_hand_needs_a_reason_and_can_be_reopened(conn):
    web_app = web_app_open(conn)

    with pytest.raises(ValueError, match="reason"):
        exposure.resolve(conn, [web_app], " ")
    exposure.resolve(conn, [web_app], "unplugged it")
    assert needs_attention(conn) == []
    assert conn.scalar(select(findings.c.resolution)) == "by hand: unplugged it"

    exposure.reopen(conn, web_app)
    assert needs_attention(conn) == [8080]


def test_a_port_resolved_by_hand_but_still_open_comes_back(conn):
    web_app = web_app_open(conn)
    exposure.resolve(conn, [web_app], "thought it was off")

    # The lab fixture is from 2026, before now(), so shift it past the resolution.
    opened = exposure.ingest(conn, lab(shift=10 * 365 * 86400), vantage="internal")

    assert opened == [Finding("fileserver", "tcp", 8080, "internal")]
