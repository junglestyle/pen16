from sqlalchemy import select

from pen16 import backups, worker
from pen16.db import heartbeats
from tests.conftest import LAB, open_incidents


def state(engine):
    with engine.connect() as conn:
        return open_incidents(conn), conn.scalar(select(heartbeats.c.at))


def test_a_failing_task_opens_an_incident_without_stopping_the_rest(committed, monkeypatch):
    def broken(conn):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(backups, "check", broken)
    delivered = []

    worker.tick(committed, LAB, lambda: delivered.append(True))

    incidents, heartbeat = state(committed)
    assert incidents == ["worker:backups"]
    assert delivered == [True]
    assert heartbeat is not None

    monkeypatch.undo()
    worker.tick(committed, LAB, None)

    assert state(committed)[0] == []
