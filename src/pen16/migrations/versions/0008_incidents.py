"""Health incidents, and a retry deadline a replayed notification can move"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("cleared_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "incidents_one_open",
        "incidents",
        ["key"],
        unique=True,
        postgresql_where=sa.text("cleared_at IS NULL"),
    )
    op.add_column(
        "notifications",
        sa.Column(
            "retry_until",
            sa.DateTime(timezone=True),
            server_default=sa.text("now() + interval '24 hours'"),
            nullable=False,
        ),
    )
    op.execute("UPDATE notifications SET retry_until = created_at + interval '24 hours'")


def downgrade() -> None:
    op.drop_column("notifications", "retry_until")
    op.drop_index("incidents_one_open", table_name="incidents")
    op.drop_table("incidents")
