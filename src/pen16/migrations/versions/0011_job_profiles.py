"""Scan profiles as a closed set, and no cancelled job status until cancellation exists"""

from alembic import op

revision = "0011"
down_revision = "0010"


def upgrade() -> None:
    op.create_check_constraint("schedule_profile", "schedules", "profile IN ('nightly')")
    op.create_check_constraint("job_profile", "jobs", "profile IN ('nightly')")
    op.drop_constraint("job_status", "jobs", type_="check")
    op.create_check_constraint("job_status", "jobs", "status IN ('queued', 'running', 'succeeded', 'failed')")


def downgrade() -> None:
    op.drop_constraint("job_status", "jobs", type_="check")
    op.create_check_constraint(
        "job_status", "jobs", "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')"
    )
    op.drop_constraint("job_profile", "jobs", type_="check")
    op.drop_constraint("schedule_profile", "schedules", type_="check")
