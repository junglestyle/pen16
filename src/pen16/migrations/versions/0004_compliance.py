"""Compliance results pushed by hosts, their rules, waivers, and imported DISA STIGs"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    op.drop_constraint("token_kind", "tokens", type_="check")
    op.create_check_constraint("token_kind", "tokens", "kind IN ('runner', 'compliance')")
    op.create_table(
        "compliance_rules",
        sa.Column("benchmark_id", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("vuln_id", sa.Text(), nullable=True),
        sa.Column("stig_rule_id", sa.Text(), nullable=True),
        sa.Column("stig_ids", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("srgs", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("ccis", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("nist", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "severity IN ('high', 'medium', 'low', 'info', 'unknown')", name="compliance_severity"
        ),
        sa.PrimaryKeyConstraint("benchmark_id", "rule_id"),
    )
    op.create_table(
        "compliance_scans",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.Column("benchmark_id", sa.Text(), nullable=False),
        sa.Column("benchmark_version", sa.Text(), nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_title", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("passed", sa.Integer(), nullable=False),
        sa.Column("failed", sa.Integer(), nullable=False),
        sa.Column("tool_version", sa.Text(), nullable=False),
        sa.Column("parser_version", sa.Text(), nullable=False),
        sa.Column("evidence_digest", sa.Text(), nullable=False),
        sa.Column("playbook_digest", sa.Text(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "evidence_digest"),
    )
    op.create_table(
        "compliance_waivers",
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("asset_id", "rule_id"),
    )
    op.create_table(
        "compliance_results",
        sa.Column("scan_id", sa.BigInteger(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("result", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "result IN ('pass', 'fail', 'error', 'unknown', 'notapplicable', 'notchecked', 'informational', "
            "'fixed')",
            name="compliance_result",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["compliance_scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id", "rule_id"),
    )
    op.create_table(
        "stigs",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("release", sa.Text(), nullable=False),
        sa.Column("target_key", sa.Text(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "stig_rules",
        sa.Column("stig_id", sa.Text(), nullable=False),
        sa.Column("vuln_id", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("rule_version", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("weight", sa.Text(), nullable=False),
        sa.Column("group_title", sa.Text(), nullable=False),
        sa.Column("discussion", sa.Text(), nullable=False),
        sa.Column("check_content", sa.Text(), nullable=False),
        sa.Column("fix_text", sa.Text(), nullable=False),
        sa.Column("ccis", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["stig_id"],
            ["stigs.id"],
        ),
        sa.PrimaryKeyConstraint("stig_id", "vuln_id"),
    )


def downgrade() -> None:
    op.drop_table("stig_rules")
    op.drop_table("stigs")
    op.drop_table("compliance_results")
    op.drop_table("compliance_waivers")
    op.drop_table("compliance_scans")
    op.drop_table("compliance_rules")
    op.execute("DELETE FROM tokens WHERE kind = 'compliance'")
    op.drop_constraint("token_kind", "tokens", type_="check")
    op.create_check_constraint("token_kind", "tokens", "kind IN ('runner')")
