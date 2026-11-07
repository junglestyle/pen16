import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import ProgrammingError

from pen16.db import compliance_waivers, decisions, expected_services, findings, schedules, tokens
from tests.conftest import as_role


@pytest.mark.parametrize(
    ("role", "statement"),
    [
        ("pen16_listener", select(schedules)),
        ("pen16_listener", delete(expected_services)),
        ("pen16_listener", update(compliance_waivers).values(reason="x")),
        ("pen16_listener", delete(tokens)),
        ("pen16_listener", update(tokens).values(revoked_at=None)),
        ("pen16_listener", update(decisions).values(reason="x")),
        ("pen16_intake", select(findings)),
        ("pen16_intake", update(decisions).values(reason="x")),
        ("pen16_intake", update(compliance_waivers).values(reason="x")),
        ("pen16_intake", update(tokens).values(revoked_at=None, kind="runner")),
    ],
)
def test_the_listener_and_intake_cant_reach_intent_or_each_others_data(engine, role, statement):
    with as_role(engine, role).connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(statement)
