import re

import pytest
from sqlalchemy import text

from pen16.db import (
    FindingStatus,
    JobStatus,
    NotificationKind,
    NotificationStatus,
    ObservationState,
    RuleResult,
    Severity,
    TokenKind,
)

# The migrations hold each CHECK, and they're never edited, so the code's names are checked against the
# database the migrations built, not against db.py.
CLOSED_SETS = [
    ("observation_state", ObservationState),
    ("finding_status", FindingStatus),
    ("job_status", JobStatus),
    ("token_kind", TokenKind),
    ("notification_kind", NotificationKind),
    ("notification_status", NotificationStatus),
    ("compliance_severity", Severity),
    ("compliance_result", RuleResult),
]


@pytest.mark.parametrize(("constraint", "names"), CLOSED_SETS)
def test_each_closed_set_is_exactly_its_check(conn, constraint, names):
    definition = conn.scalar(
        text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :name"),
        {"name": constraint},
    )
    assert definition is not None, constraint
    assert set(re.findall(r"'([^']*)'", definition)) == {str(name) for name in names}
