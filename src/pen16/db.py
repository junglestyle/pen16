import os
import re
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    Connection,
    DateTime,
    Engine,
    ForeignKey,
    Identity,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, MACADDR

metadata = MetaData()


class ObservationState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


class FindingChange(StrEnum):
    OPENED = "opened"
    RESOLVED = "resolved"
    REOPENED = "reopened"


class BindingChange(StrEnum):
    BOUND = "bound"
    # The binding's first MAC, from the first scan that saw one there.
    LEARNED = "learned"
    ENDED = "ended"


class DecisionKind(StrEnum):
    ACCEPTED_RISK = "accepted-risk"
    FALSE_POSITIVE = "false-positive"

    @property
    def label(self) -> str:
        """How the dashboard and alerts name it."""
        return self.value.replace("-", " ")


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Profile(StrEnum):
    """The fixed scan profiles a job can ask for; the runner builds each one's nmap command itself."""

    NIGHTLY = "nightly"
    # A chunk of a network's rolling full-range TCP sweep: its known addresses, across a range of ports.
    SWEEP = "sweep"


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


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class RuleResult(StrEnum):
    PASS = "pass"  # noqa: S105  # a rule result, not a password
    FAIL = "fail"
    ERROR = "error"
    UNKNOWN = "unknown"
    NOTAPPLICABLE = "notapplicable"
    NOTCHECKED = "notchecked"
    INFORMATIONAL = "informational"
    FIXED = "fixed"


def _one_of(column: str, names: type[StrEnum], constraint: str) -> CheckConstraint:
    """The CHECK for a column holding a closed set of names, built from its StrEnum so the two can't drift. The
    StrEnum rides along in the constraint's info, for closed_set_drift."""
    listed = ", ".join(f"'{name}'" for name in names)
    return CheckConstraint(f"{column} IN ({listed})", name=constraint, info={"names": names})


def closed_set_drift(conn: Connection) -> list[str]:
    """The CHECKs the database has that don't list exactly their StrEnum's names, or that it lacks. Migrations
    are never edited, so this compares the code with what the migrations built."""
    drifted = []
    for table in metadata.sorted_tables:
        for constraint in table.constraints:
            names = constraint.info.get("names")
            if not isinstance(constraint, CheckConstraint) or names is None:
                continue
            definition = conn.scalar(
                text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :name"),
                {"name": constraint.name},
            )
            if definition is None or set(re.findall(r"'([^']*)'", definition)) != {
                str(name) for name in names
            }:
                drifted.append(str(constraint.name))
    return drifted


# A device. Provisional ones are named by the address pen16 first saw them at. A device that took over a bound
# address, because a different MAC answered there, records which asset had it and whether either MAC was a
# private one, which a device can change on its own: then the dashboard asks whether it's the same device.
assets = Table(
    "assets",
    metadata,
    Column("id", Text, primary_key=True),
    Column("provisional", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("took_over_from", Text),
    Column("took_over_private", Boolean, nullable=False, server_default="false"),
    Column("retired_at", DateTime(timezone=True)),
    Column("retired_by", Text),
    Column("retirement", Text),
)

# Which device is at an address now, and the MAC that answered for it, once a scan has seen one.
bindings = Table(
    "bindings",
    metadata,
    Column("address", INET, primary_key=True),
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("mac", MACADDR),
    Column("bound_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Index("bindings_asset", "asset_id"),
)

# Every change to which device is at an address. Asset IDs here outlive the provisional assets they name.
binding_events = Table(
    "binding_events",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("address", INET, nullable=False),
    Column("asset_id", Text, nullable=False),
    Column("mac", MACADDR),
    Column("change", Text, nullable=False),
    Column("at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("by", Text, nullable=False),
    Column("reason", Text),
    _one_of("change", BindingChange, "binding_change"),
)

# Intent: a service the owner expects. Stopping expecting it ends the row with a reason; ended rows stay as history,
# and at most one row per service is current.
expected_services = Table(
    "expected_services",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("protocol", Text, nullable=False),
    Column("port", Integer, nullable=False),
    Column("vantage", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("declared_by", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("ended_at", DateTime(timezone=True)),
    Column("ended_by", Text),
    Column("end_reason", Text),
    Index(
        "expected_services_current",
        "asset_id",
        "protocol",
        "port",
        "vantage",
        unique=True,
        postgresql_where=text("ended_at IS NULL"),
    ),
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
    Index("observations_latest", "asset_id", "protocol", "port", "vantage", "observed_at"),
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

# Every change to a finding's status, by a scan (with the observation that caused it) or by the owner (with
# their reason). The finding row holds only the current state.
finding_events = Table(
    "finding_events",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("finding_id", BigInteger, ForeignKey("findings.id"), nullable=False),
    Column("change", Text, nullable=False),
    Column("at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("by", Text, nullable=False),
    Column("reason", Text),
    Column("observation_id", BigInteger, ForeignKey("observations.id")),
    _one_of("change", FindingChange, "finding_change"),
)

# Which MAC answered at an address during a scan, from the scanner host's neighbour table (pen16.neighbours).
mac_sightings = Table(
    "mac_sightings",
    metadata,
    Column("address", INET, nullable=False),
    Column("mac", MACADDR, nullable=False),
    Column("confirmed_at", DateTime(timezone=True), nullable=False),
    Column("evidence_digest", Text, nullable=False),
    PrimaryKeyConstraint("evidence_digest", "address"),
    Index("mac_sightings_address", "address", "confirmed_at"),
)

# The owner's decision about one finding: its risk is accepted, or it's a false positive. It records the service
# it was decided on, and a scan that sees a materially different one withdraws it. A finding has at most one
# active decision; withdrawn ones stay as its history.
decisions = Table(
    "decisions",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("finding_id", BigInteger, ForeignKey("findings.id"), nullable=False),
    Column("kind", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("decided_by", Text, nullable=False),
    Column("decided_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("service", Text),
    Column("product", Text),
    Column("version", Text),
    Column("withdrawn_at", DateTime(timezone=True)),
    Column("withdrawal", Text),
    _one_of("kind", DecisionKind, "decision_kind"),
    Index("decisions_one_active", "finding_id", unique=True, postgresql_where=text("withdrawn_at IS NULL")),
)

schedules = Table(
    "schedules",
    metadata,
    Column("name", Text, primary_key=True),
    Column("profile", Text, nullable=False),
    Column("every_hours", Integer, nullable=False),
    Column("next_run_at", DateTime(timezone=True), nullable=False),
    Column("enabled", Boolean, nullable=False),
    _one_of("profile", Profile, "schedule_profile"),
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
    # A sweep chunk's network and TCP port range; null for a nightly scan of the whole scope.
    Column("network", Text),
    Column("port_from", Integer),
    Column("port_to", Integer),
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
    _one_of("profile", Profile, "job_profile"),
)

# What a finished job covered in each network it scanned: whether the gateway answered, how many addresses were
# up, and how many ports nmap says it scanned. Coverage is shown apart from the job's status.
coverage = Table(
    "coverage",
    metadata,
    Column("job_id", BigInteger, ForeignKey("jobs.id"), nullable=False),
    Column("network", Text, nullable=False),
    Column("profile", Text, nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("gateway_up", Boolean, nullable=False),
    Column("hosts_up", Integer, nullable=False),
    Column("tcp_ports", Integer, nullable=False),
    Column("udp_ports", Integer, nullable=False),
    Column("port_from", Integer),
    Column("port_to", Integer),
    PrimaryKeyConstraint("job_id", "network"),
    _one_of("profile", Profile, "coverage_profile"),
)

# Known devices a job scanned that didn't answer. Their findings stay open: missing coverage resolves nothing.
unavailable = Table(
    "unavailable",
    metadata,
    Column("job_id", BigInteger, ForeignKey("jobs.id"), nullable=False),
    Column("network", Text, nullable=False),
    Column("address", INET, nullable=False),
    Column("asset_id", Text, nullable=False),
    PrimaryKeyConstraint("job_id", "address"),
)

# When each block of a network's TCP ports was last swept in full, by a chunk whose gateway answered. The oldest
# block's time is the network's sweep age.
sweep_blocks = Table(
    "sweep_blocks",
    metadata,
    Column("network", Text, nullable=False),
    Column("block", Integer, nullable=False),
    Column("swept_at", DateTime(timezone=True), nullable=False),
    Column("job_id", BigInteger, ForeignKey("jobs.id"), nullable=False),
    PrimaryKeyConstraint("network", "block"),
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
    # Delivery retries until then; replaying a failed notification moves it on.
    Column(
        "retry_until",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now() + interval '24 hours'"),
    ),
    Column("delivered_at", DateTime(timezone=True)),
    Column("last_error", Text),
    _one_of("kind", NotificationKind, "notification_kind"),
    _one_of("status", NotificationStatus, "notification_status"),
)

# Something wrong with monitoring itself, such as stale backups or a gateway that didn't answer. A key has at most
# one open incident: opening it alerts once, and clearing it sends one recovery notice. Cleared ones stay as history.
incidents = Table(
    "incidents",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("key", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("detail", Text, nullable=False),
    Column("opened_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("cleared_at", DateTime(timezone=True)),
    Index("incidents_one_open", "key", unique=True, postgresql_where=text("cleared_at IS NULL")),
)

# When each long-running component last finished a round of its work, for the dashboard to tell it's alive.
heartbeats = Table(
    "heartbeats",
    metadata,
    Column("component", Text, primary_key=True),
    Column("at", DateTime(timezone=True), nullable=False, server_default=func.now()),
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
    _one_of("severity", Severity, "compliance_severity"),
)

compliance_results = Table(
    "compliance_results",
    metadata,
    Column("scan_id", BigInteger, ForeignKey("compliance_scans.id", ondelete="CASCADE"), nullable=False),
    Column("rule_id", Text, nullable=False),
    Column("result", Text, nullable=False),
    PrimaryKeyConstraint("scan_id", "rule_id"),
    _one_of("result", RuleResult, "compliance_result"),
)

# Owner decisions: a rule that fails on purpose on one host. It stays failing; the reason travels with it. Removing
# or replacing one ends it with a reason; ended rows stay as history, and at most one per rule and host is current.
compliance_waivers = Table(
    "compliance_waivers",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("asset_id", Text, ForeignKey("assets.id"), nullable=False),
    Column("rule_id", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("waived_by", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("ended_at", DateTime(timezone=True)),
    Column("ended_by", Text),
    Column("end_reason", Text),
    Index(
        "compliance_waivers_current",
        "asset_id",
        "rule_id",
        unique=True,
        postgresql_where=text("ended_at IS NULL"),
    ),
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


def now(conn: Connection) -> datetime:
    """The database's time, the one clock pen16 compares stored times with. The worker, web and listener may run
    on clocks a little off from it, and a row stamped by now() mustn't look like it's from the future."""
    current: datetime = conn.execute(select(func.now())).scalar_one()
    return current
