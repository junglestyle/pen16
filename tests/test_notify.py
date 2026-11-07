import httpx
from sqlalchemy import select

from pen16 import notify
from pen16.db import notifications
from tests.conftest import open_incidents


def queue(engine, title="1 unexpected service(s)", body="nas 8080/tcp"):
    with engine.begin() as conn:
        notify.enqueue(conn, "finding", title, body)


def deliver(engine, status):
    sent = []

    def ntfy(request):
        sent.append(request)
        return httpx.Response(status)

    with httpx.Client(transport=httpx.MockTransport(ntfy)) as client:
        notify.deliver_due(engine, client, "https://ntfy.example/topic", "", "https://pen16.example")
        notify.deliver_due(engine, client, "https://ntfy.example/topic", "", "https://pen16.example")
    return sent


def stored(engine):
    with engine.connect() as conn:
        rows = conn.execute(
            select(notifications.c.status, notifications.c.attempts).order_by(notifications.c.id)
        )
        return [tuple(row) for row in rows]


def incidents(engine):
    with engine.connect() as conn:
        return open_incidents(conn)


def test_alert_is_delivered_once_with_a_dashboard_link(committed):
    queue(committed)

    sent = deliver(committed, 200)

    assert len(sent) == 1
    assert sent[0].headers["Click"] == "https://pen16.example"
    assert sent[0].content == b"nas 8080/tcp"
    assert stored(committed) == [("delivered", 1)]


def test_transient_failure_backs_off_instead_of_hammering(committed):
    queue(committed)

    assert len(deliver(committed, 503)) == 1
    assert stored(committed) == [("pending", 1)]


def test_permanent_failure_opens_one_incident_and_resending_clears_it(committed):
    queue(committed)
    deliver(committed, 403)

    assert stored(committed)[0] == ("failed", 1)
    assert incidents(committed) == [notify.DELIVERY]

    with committed.begin() as conn:
        notify.replay_failed(conn)
    deliver(committed, 200)

    assert stored(committed)[0] == ("delivered", 2)
    assert incidents(committed) == []
