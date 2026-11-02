"""MAC addresses seen at scanned addresses, from the scanner host's neighbour table"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"


def upgrade() -> None:
    op.create_table(
        "mac_sightings",
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("mac", postgresql.MACADDR(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_digest", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("evidence_digest", "address"),
    )


def downgrade() -> None:
    op.drop_table("mac_sightings")
