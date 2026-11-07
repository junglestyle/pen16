"""Coverage per scan and network, unavailable devices, and rolling full-range sweeps"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0014"
down_revision = "0013"

PROFILES = "profile IN ('nightly', 'sweep')"


def upgrade() -> None:
    for constraint, table in (("schedule_profile", "schedules"), ("job_profile", "jobs")):
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(constraint, table, PROFILES)
    op.add_column("jobs", sa.Column("network", sa.Text(), nullable=True))
    op.add_column("jobs", sa.Column("port_from", sa.Integer(), nullable=True))
    op.add_column("jobs", sa.Column("port_to", sa.Integer(), nullable=True))
    op.create_table(
        "coverage",
        sa.Column("job_id", sa.BigInteger(), nullable=False),
        sa.Column("network", sa.Text(), nullable=False),
        sa.Column("profile", sa.Text(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("gateway_up", sa.Boolean(), nullable=False),
        sa.Column("hosts_up", sa.Integer(), nullable=False),
        sa.Column("tcp_ports", sa.Integer(), nullable=False),
        sa.Column("udp_ports", sa.Integer(), nullable=False),
        sa.Column("port_from", sa.Integer(), nullable=True),
        sa.Column("port_to", sa.Integer(), nullable=True),
        sa.CheckConstraint(PROFILES, name="coverage_profile"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("job_id", "network"),
    )
    op.create_table(
        "unavailable",
        sa.Column("job_id", sa.BigInteger(), nullable=False),
        sa.Column("network", sa.Text(), nullable=False),
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("job_id", "address"),
    )
    op.create_table(
        "sweep_blocks",
        sa.Column("network", sa.Text(), nullable=False),
        sa.Column("block", sa.Integer(), nullable=False),
        sa.Column("swept_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("job_id", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("network", "block"),
    )


def downgrade() -> None:
    op.drop_table("sweep_blocks")
    op.drop_table("unavailable")
    op.drop_table("coverage")
    # The older schema has no sweep jobs. Their evidence and observations stay; only the job rows go.
    op.execute("DELETE FROM jobs WHERE profile = 'sweep'")
    op.drop_column("jobs", "port_to")
    op.drop_column("jobs", "port_from")
    op.drop_column("jobs", "network")
    for constraint, table in (("schedule_profile", "schedules"), ("job_profile", "jobs")):
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(constraint, table, "profile IN ('nightly')")
