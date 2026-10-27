import os

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Engine,
    ForeignKey,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET

metadata = MetaData()

assets = Table(
    "assets",
    metadata,
    Column("id", Text, primary_key=True),
    Column("provisional", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

bindings = Table(
    "bindings",
    metadata,
    Column("address", INET, primary_key=True),
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
)

expected_services = Table(
    "expected_services",
    metadata,
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("protocol", Text, nullable=False),
    Column("port", Integer, nullable=False),
    Column("vantage", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    PrimaryKeyConstraint("asset_id", "protocol", "port", "vantage"),
)

observations = Table(
    "observations",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("address", INET, nullable=False),
    Column("protocol", Text, nullable=False),
    Column("port", Integer, nullable=False),
    Column("state", Text, nullable=False),
    Column("service", Text),
    Column("product", Text),
    Column("version", Text),
    Column("vantage", Text, nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("tool_version", Text, nullable=False),
    Column("parser_version", Text, nullable=False),
    Column("evidence_digest", Text, nullable=False),
    CheckConstraint("state IN ('open', 'closed', 'filtered')", name="observation_state"),
    UniqueConstraint("evidence_digest", "address", "protocol", "port", "vantage"),
)

findings = Table(
    "findings",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("protocol", Text, nullable=False),
    Column("port", Integer, nullable=False),
    Column("vantage", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("opened_at", DateTime(timezone=True), nullable=False),
    Column("resolved_at", DateTime(timezone=True)),
    Column("resolution", Text),
    Column("last_observation_id", BigInteger, ForeignKey("observations.id"), nullable=False),
    CheckConstraint("status IN ('open', 'resolved')", name="finding_status"),
    UniqueConstraint("kind", "asset_id", "protocol", "port", "vantage"),
)

schedules = Table(
    "schedules",
    metadata,
    Column("name", Text, primary_key=True),
    Column("profile", Text, nullable=False),
    Column("every_hours", Integer, nullable=False),
    Column("next_run_at", DateTime(timezone=True), nullable=False),
    Column("enabled", Boolean, nullable=False),
)

jobs = Table(
    "jobs",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("schedule", Text, ForeignKey("schedules.name")),
    Column("requester", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("profile", Text, nullable=False),
    Column("targets", ARRAY(Text), nullable=False),
    Column("exclude", ARRAY(Text), nullable=False),
    Column("extra_tcp", ARRAY(Integer), nullable=False),
    Column("status", Text, nullable=False),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("runner", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("started_at", DateTime(timezone=True)),
    Column("deadline_at", DateTime(timezone=True)),
    Column("finished_at", DateTime(timezone=True)),
    Column("error", Text),
    Column("evidence_digest", Text),
    CheckConstraint("status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')", name="job_status"),
)

tokens = Table(
    "tokens",
    metadata,
    Column("id", Text, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("secret_hash", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_used_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    CheckConstraint("kind IN ('runner')", name="token_kind"),
)

notifications = Table(
    "notifications",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("body", Text, nullable=False),
    Column("status", Text, nullable=False, server_default="pending"),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("next_attempt_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("delivered_at", DateTime(timezone=True)),
    Column("last_error", Text),
    CheckConstraint("kind IN ('finding', 'health')", name="notification_kind"),
    CheckConstraint("status IN ('pending', 'delivered', 'failed')", name="notification_status"),
)

# One row per verified backup, written by deploy/pen16-backup through `pen16 backed-up`.
backups = Table(
    "backups",
    metadata,
    Column("id", BigInteger, primary_key=True),
    Column("name", Text, nullable=False, unique=True),
    Column("size_bytes", BigInteger, nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


def database_url() -> str:
    url = os.environ.get("PEN16_DATABASE_URL")
    if not url:
        raise RuntimeError("PEN16_DATABASE_URL is not set")
    return url


def connect() -> Engine:
    return create_engine(database_url())
