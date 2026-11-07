"""Devices told apart by MAC: each binding's MAC and history, devices that took over an address, retirement"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013"
down_revision = "0012"


def upgrade() -> None:
    op.add_column("bindings", sa.Column("mac", postgresql.MACADDR(), nullable=True))
    op.add_column(
        "bindings",
        sa.Column("bound_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.add_column("assets", sa.Column("took_over_from", sa.Text(), nullable=True))
    op.add_column(
        "assets", sa.Column("took_over_private", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column("assets", sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assets", sa.Column("retired_by", sa.Text(), nullable=True))
    op.add_column("assets", sa.Column("retirement", sa.Text(), nullable=True))
    op.create_table(
        "binding_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.Column("mac", postgresql.MACADDR(), nullable=True),
        sa.Column("change", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("by", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.CheckConstraint("change IN ('bound', 'learned', 'ended')", name="binding_change"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("binding_events")
    for column in ("retirement", "retired_by", "retired_at", "took_over_private", "took_over_from"):
        op.drop_column("assets", column)
    op.drop_column("bindings", "bound_at")
    op.drop_column("bindings", "mac")
