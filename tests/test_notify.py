import httpx
from sqlalchemy import select

from pen16 import notify
from pen16.db import notifications


def deliver(engine, status):
    sent = []

    def ntfy(request):
        sent.append(request)
        return httpx.Response(status)

    with engine.begin() as conn:
        notify.enqueue(conn, "finding", "1 unexpected service(s)", "nas 8080/tcp")
    with httpx.Client(transport=httpx.MockTransport(ntfy)) as client:
        notify.deliver_due(engine, client, "https://ntfy.example/topic", "", "https://pen16.example")
        notify.deliver_due(engine, client, "https://ntfy.example/topic", "", "https://pen16.example")
    return sent


def stored(engine):
    with engine.connect() as conn:
        row = conn.execute(select(notifications.c.status, notifications.c.attempts)).one()
    return row.status, row.attempts


def test_alert_is_delivered_once_with_a_dashboard_link(committed):
    sent = deliver(committed, 200)

    assert len(sent) == 1
    assert sent[0].headers["Click"] == "https://pen16.example"
    assert sent[0].content == b"nas 8080/tcp"
    assert stored(committed) == ("delivered", 1)


def test_transient_failure_backs_off_instead_of_hammering(committed):
    assert len(deliver(committed, 503)) == 1
    assert stored(committed) == ("pending", 1)


def test_permanent_failure_stops_and_shows_up(committed):
    deliver(committed, 403)

    assert stored(committed) == ("failed", 1)
