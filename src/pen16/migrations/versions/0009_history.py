"""Change history: finding events, and expected services and waivers that end instead of being deleted"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"

# Each table's natural key, which stops being its primary key and becomes unique among current rows only.
ENDED = {
    "expected_services": (
        "expected_services_current",
        ["asset_id", "protocol", "port", "vantage"],
        "declared_by",
    ),
    "compliance_waivers": ("compliance_waivers_current", ["asset_id", "rule_id"], "waived_by"),
}


def upgrade() -> None:
    op.create_table(
        "finding_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("change", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("by", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("observation_id", sa.BigInteger(), nullable=True),
        sa.CheckConstraint("change IN ('opened', 'resolved', 'reopened')", name="finding_change"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["observation_id"], ["observations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for table, (index, key, author) in ENDED.items():
        op.drop_constraint(f"{table}_pkey", table, type_="primary")
        op.add_column(table, sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False))
        op.create_primary_key(f"{table}_pkey", table, ["id"])
        op.add_column(table, sa.Column(author, sa.Text(), nullable=True))
        op.add_column(table, sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True))
        op.add_column(table, sa.Column("ended_by", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("end_reason", sa.Text(), nullable=True))
        op.create_index(index, table, key, unique=True, postgresql_where=sa.text("ended_at IS NULL"))


def downgrade() -> None:
    for table, (index, key, author) in ENDED.items():
        op.execute(f"DELETE FROM {table} WHERE ended_at IS NOT NULL")  # noqa: S608  # the table names are this file's
        op.drop_index(index, table_name=table)
        for column in ("end_reason", "ended_by", "ended_at", author):
            op.drop_column(table, column)
        op.drop_constraint(f"{table}_pkey", table, type_="primary")
        op.drop_column(table, "id")
        op.create_primary_key(f"{table}_pkey", table, key)
    op.drop_table("finding_events")
