"""Initial schema"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("provisional", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "bindings",
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("address"),
    )
    op.create_table(
        "expected_services",
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.Column("protocol", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("vantage", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("asset_id", "protocol", "port", "vantage"),
    )
    op.create_table(
        "observations",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("protocol", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("service", sa.Text(), nullable=True),
        sa.Column("product", sa.Text(), nullable=True),
        sa.Column("version", sa.Text(), nullable=True),
        sa.Column("vantage", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tool_version", sa.Text(), nullable=False),
        sa.Column("parser_version", sa.Text(), nullable=False),
        sa.Column("evidence_digest", sa.Text(), nullable=False),
        sa.CheckConstraint("state IN ('open', 'closed', 'filtered')", name="observation_state"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_digest", "address", "protocol", "port", "vantage"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.Column("protocol", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("vantage", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observation_id", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("status IN ('open', 'resolved')", name="finding_status"),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.ForeignKeyConstraint(
            ["last_observation_id"],
            ["observations.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kind", "asset_id", "protocol", "port", "vantage"),
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("observations")
    op.drop_table("expected_services")
    op.drop_table("bindings")
    op.drop_table("assets")
