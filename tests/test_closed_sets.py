from sqlalchemy import text

from pen16 import db


def test_each_closed_set_is_exactly_its_check(conn):
    assert db.closed_set_drift(conn) == []


def test_a_closed_set_that_differs_from_its_check_is_caught(conn):
    conn.execute(text("ALTER TABLE jobs DROP CONSTRAINT job_status"))
    conn.execute(text("ALTER TABLE jobs ADD CONSTRAINT job_status CHECK (status IN ('queued', 'running'))"))

    assert db.closed_set_drift(conn) == ["job_status"]
