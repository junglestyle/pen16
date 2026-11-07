"""Indexes for the lookups every scan and dashboard view makes"""

from alembic import op

revision = "0012"
down_revision = "0011"


def upgrade() -> None:
    # The latest observation of each service: the dashboard's exposure view and every finding's last state.
    op.create_index(
        "observations_latest", "observations", ["asset_id", "protocol", "port", "vantage", "observed_at"]
    )
    # Every address bound to an asset, which closing a finding checks.
    op.create_index("bindings_asset", "bindings", ["asset_id"])
    # The newest MAC seen at an address.
    op.create_index("mac_sightings_address", "mac_sightings", ["address", "confirmed_at"])


def downgrade() -> None:
    op.drop_index("mac_sightings_address", table_name="mac_sightings")
    op.drop_index("bindings_asset", table_name="bindings")
    op.drop_index("observations_latest", table_name="observations")
