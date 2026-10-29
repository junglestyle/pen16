import os
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Engine,
    ForeignKey,
    Identity,
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


class ObservationState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TokenKind(StrEnum):
    RUNNER = "runner"
    COMPLIANCE = "compliance"


class NotificationKind(StrEnum):
    FINDING = "finding"
    HEALTH = "health"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"


def _one_of(column: str, names: type[StrEnum], constraint: str) -> CheckConstraint:
    """The CHECK for a column holding a closed set of names, built from its StrEnum so the two can't drift."""
    listed = ", ".join(f"'{name}'" for name in names)
    return CheckConstraint(f"{column} IN ({listed})", name=constraint)


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
    Column("id", BigInteger, Identity(always=True), primary_key=True),
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
    _one_of("state", ObservationState, "observation_state"),
    UniqueConstraint("evidence_digest", "address", "protocol", "port", "vantage"),
)

findings = Table(
    "findings",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
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
    _one_of("status", FindingStatus, "finding_status"),
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
    Column("id", BigInteger, Identity(always=True), primary_key=True),
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
    _one_of("status", JobStatus, "job_status"),
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
    _one_of("kind", TokenKind, "token_kind"),
)

notifications = Table(
    "notifications",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("kind", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("body", Text, nullable=False),
    Column("status", Text, nullable=False, server_default=NotificationStatus.PENDING),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("next_attempt_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("delivered_at", DateTime(timezone=True)),
    Column("last_error", Text),
    _one_of("kind", NotificationKind, "notification_kind"),
    _one_of("status", NotificationStatus, "notification_status"),
)

# One row per verified backup, written by deploy/pen16-backup through `pen16 backed-up`.
backups = Table(
    "backups",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("name", Text, nullable=False, unique=True),
    Column("size_bytes", BigInteger, nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


# Compliance: one row per OpenSCAP result a host pushed to the intake (FR-14). The ARF and the playbook the
# host generated from it are evidence files named by digest.
compliance_scans = Table(
    "compliance_scans",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("benchmark_id", Text, nullable=False),
    Column("benchmark_version", Text, nullable=False),
    Column("profile_id", Text, nullable=False),
    Column("profile_title", Text, nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=False),
    Column("passed", Integer, nullable=False),
    Column("failed", Integer, nullable=False),
    Column("tool_version", Text, nullable=False),
    Column("parser_version", Text, nullable=False),
    Column("evidence_digest", Text, nullable=False),
    Column("playbook_digest", Text),
    Column("received_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    UniqueConstraint("asset_id", "evidence_digest"),
)

# What a benchmark says about each rule, refreshed from every result that carries it.
compliance_rules = Table(
    "compliance_rules",
    metadata,
    Column("benchmark_id", Text, nullable=False),
    Column("rule_id", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("vuln_id", Text),
    Column("stig_rule_id", Text),
    Column("stig_ids", ARRAY(Text), nullable=False),
    Column("srgs", ARRAY(Text), nullable=False),
    Column("ccis", ARRAY(Text), nullable=False),
    Column("nist", ARRAY(Text), nullable=False),
    Column("rationale", Text, nullable=False),
    PrimaryKeyConstraint("benchmark_id", "rule_id"),
    CheckConstraint("severity IN ('high', 'medium', 'low', 'info', 'unknown')", name="compliance_severity"),
)

compliance_results = Table(
    "compliance_results",
    metadata,
    Column("scan_id", BigInteger, ForeignKey("compliance_scans.id", ondelete="CASCADE"), nullable=False),
    Column("rule_id", Text, nullable=False),
    Column("result", Text, nullable=False),
    PrimaryKeyConstraint("scan_id", "rule_id"),
    CheckConstraint(
        "result IN ('pass', 'fail', 'error', 'unknown', 'notapplicable', 'notchecked', 'informational', "
        "'fixed')",
        name="compliance_result",
    ),
)

# Owner decisions: a rule that fails on purpose on one host. It stays failing; the reason travels with it.
compliance_waivers = Table(
    "compliance_waivers",
    metadata,
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("rule_id", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    PrimaryKeyConstraint("asset_id", "rule_id"),
)

# DISA STIG releases, imported from the manual XCCDF in DISA's zip. A checklist lists every rule of the STIG,
# with the status the matching SCAP rules give it.
stigs = Table(
    "stigs",
    metadata,
    Column("id", Text, primary_key=True),
    Column("title", Text, nullable=False),
    Column("version", Text, nullable=False),
    Column("release", Text, nullable=False),
    Column("target_key", Text, nullable=False),
    Column("imported_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

stig_rules = Table(
    "stig_rules",
    metadata,
    Column("stig_id", Text, ForeignKey("stigs.id"), nullable=False),
    Column("vuln_id", Text, nullable=False),
    Column("rule_id", Text, nullable=False),
    Column("rule_version", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("weight", Text, nullable=False),
    Column("group_title", Text, nullable=False),
    Column("discussion", Text, nullable=False),
    Column("check_content", Text, nullable=False),
    Column("fix_text", Text, nullable=False),
    Column("ccis", ARRAY(Text), nullable=False),
    PrimaryKeyConstraint("stig_id", "vuln_id"),
)


def database_url() -> str:
    url = os.environ.get("PEN16_DATABASE_URL")
    if not url:
        raise SystemExit("PEN16_DATABASE_URL is not set (see examples/pen16.env)")
    return url


def connect() -> Engine:
    return create_engine(database_url())
