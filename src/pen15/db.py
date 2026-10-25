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
from sqlalchemy.dialects.postgresql import INET

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
    Column("last_observation_id", BigInteger, ForeignKey("observations.id"), nullable=False),
    CheckConstraint("status IN ('open', 'resolved')", name="finding_status"),
    UniqueConstraint("kind", "asset_id", "protocol", "port", "vantage"),
)


def database_url() -> str:
    url = os.environ.get("PEN15_DATABASE_URL")
    if not url:
        raise RuntimeError("PEN15_DATABASE_URL is not set")
    return url


def connect() -> Engine:
    return create_engine(database_url())
