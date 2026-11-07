import pytest
from sqlalchemy import insert, select

from pen16 import exposure, status
from pen16.db import DecisionKind, assets, bindings, decisions, expected_services, finding_events, findings
from pen16.exposure import Finding
from tests.conftest import OWNER_LOGIN as OWNER
from tests.conftest import closed, ingest, lab


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
    ingest(conn, lab())
    return conn.scalar(select(findings.c.id).where(findings.c.port == 8080))


def needs_attention(conn):
    """The ports in the dashboard's Needs attention."""
    return [finding.port for finding in status.needs_attention(conn)]


def test_accepted_risk_leaves_needs_attention_and_stays_quiet(conn):
    web_app = web_app_open(conn)

    exposure.decide(
        conn, [web_app], DecisionKind.ACCEPTED_RISK, "lab tool, tailnet only", "owner@example.com"
    )

    assert needs_attention(conn) == []
    assert ingest(conn, lab(shift=3600)) == []
    # Closed, then open again with the same service: still decided, no alert.
    ingest(conn, closed())
    assert ingest(conn, lab(shift=2 * 86400)) == []
    assert needs_attention(conn) == []


def test_a_new_version_brings_the_decision_back_with_the_reason(conn):
    web_app = web_app_open(conn)
    exposure.decide(
        conn, [web_app], DecisionKind.ACCEPTED_RISK, "lab tool, tailnet only", "owner@example.com"
    )

    opened = ingest(conn, lab(shift=86400, version=b'version="3.1.0"'))

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

    assert ingest(conn, lab(shift=86400, version=b"")) == []
    assert needs_attention(conn) == []


def test_an_unnamed_device_takes_no_decision(conn):
    ingest(conn, lab())
    web_app = conn.scalar(select(findings.c.id).where(findings.c.port == 8080))

    with pytest.raises(ValueError, match=r"new-192\.0\.2\.10"):
        exposure.decide(conn, [web_app], DecisionKind.ACCEPTED_RISK, "fine", "owner@example.com")


def test_withdrawing_a_decision_puts_the_finding_back(conn):
    web_app = web_app_open(conn)
    exposure.decide(conn, [web_app], DecisionKind.ACCEPTED_RISK, "lab tool", "owner@example.com")
    decision = conn.scalar(select(decisions.c.id))

    exposure.withdraw(conn, decision, "withdrawn by owner@example.com")

    assert needs_attention(conn) == [8080]


def test_resolving_by_hand_needs_a_reason_and_reopening_keeps_it_in_history(conn):
    web_app = web_app_open(conn)

    with pytest.raises(ValueError, match="reason"):
        exposure.resolve(conn, [web_app], " ", OWNER)
    exposure.resolve(conn, [web_app], "unplugged it", OWNER)
    assert needs_attention(conn) == []

    exposure.reopen(conn, web_app, OWNER)

    assert needs_attention(conn) == [8080]
    history = conn.execute(
        select(finding_events.c.change, finding_events.c.by, finding_events.c.reason)
        .where(finding_events.c.finding_id == web_app)
        .order_by(finding_events.c.id)
    )
    assert [tuple(event) for event in history] == [
        ("opened", "scan", None),
        ("resolved", OWNER, "by hand: unplugged it"),
        ("reopened", OWNER, None),
    ]


def test_a_port_resolved_by_hand_but_still_open_comes_back(conn):
    web_app = web_app_open(conn)
    exposure.resolve(conn, [web_app], "thought it was off", OWNER)

    opened = ingest(conn, lab(shift=86400))

    assert opened == [Finding("fileserver", "tcp", 8080, "internal")]
