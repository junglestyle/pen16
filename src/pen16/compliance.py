"""Host compliance: OpenSCAP results hosts push to the intake, waivers, alerts, and STIG checklists."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, case, delete, exists, func, insert, select
from sqlalchemy.dialects.postgresql import insert as upsert

from pen16 import arf, notify
from pen16.arf import FAILING, PASSING, Result
from pen16.db import (
    assets,
    compliance_results,
    compliance_rules,
    compliance_scans,
    compliance_waivers,
    notifications,
    stig_rules,
    stigs,
)

STALE = timedelta(days=10)
SEVERITY_ORDER = case(
    {"high": 0, "medium": 1, "low": 2, "info": 3}, value=compliance_rules.c.severity, else_=4
)
# Names of CKLB statuses, in STIG Viewer's spelling.
OPEN, NOT_A_FINDING, NOT_APPLICABLE, NOT_REVIEWED = "open", "not_a_finding", "not_applicable", "not_reviewed"


class StaleResult(Exception):
    """A result no newer than the latest one already recorded for that host, benchmark and profile."""


@dataclass(frozen=True)
class Recorded:
    scan_id: int
    duplicate: bool


def record(
    conn: Connection, asset_id: str, result: Result, evidence_digest: str, playbook_digest: str | None
) -> Recorded:
    """Record a host's result and queue its alerts in the caller's transaction. Re-sending the same evidence
    is a no-op; an older result than the latest is refused, so a late upload can't roll a host back."""
    conn.execute(upsert(assets).values(id=asset_id, provisional=False).on_conflict_do_nothing())
    existing = conn.scalar(
        select(compliance_scans.c.id).where(
            compliance_scans.c.asset_id == asset_id, compliance_scans.c.evidence_digest == evidence_digest
        )
    )
    if existing is not None:
        return Recorded(existing, duplicate=True)
    previous = conn.execute(
        select(compliance_scans)
        .where(
            compliance_scans.c.asset_id == asset_id,
            compliance_scans.c.benchmark_id == result.benchmark_id,
            compliance_scans.c.profile_id == result.profile_id,
        )
        .order_by(compliance_scans.c.finished_at.desc())
        .limit(1)
    ).first()
    if previous is not None and previous.finished_at >= result.finished_at:
        raise StaleResult(f"{asset_id} already has a result from {previous.finished_at:%Y-%m-%d %H:%M} UTC")
    was_stale = _stale_warned(conn, asset_id)

    for rule in result.rules:
        values = {
            "title": rule.title,
            "severity": rule.severity,
            "vuln_id": rule.vuln_id,
            "stig_rule_id": rule.stig_rule_id,
            "stig_ids": rule.stig_ids,
            "srgs": rule.srgs,
            "ccis": rule.ccis,
            "nist": rule.nist,
            "rationale": rule.rationale,
        }
        conn.execute(
            upsert(compliance_rules)
            .values(benchmark_id=result.benchmark_id, rule_id=rule.id, **values)
            .on_conflict_do_update(index_elements=["benchmark_id", "rule_id"], set_=values)
        )
    scan_id: int = conn.scalar(
        insert(compliance_scans)
        .values(
            asset_id=asset_id,
            benchmark_id=result.benchmark_id,
            benchmark_version=result.benchmark_version,
            profile_id=result.profile_id,
            profile_title=result.profile_title,
            started_at=result.started_at,
            finished_at=result.finished_at,
            passed=result.passed,
            failed=result.failed,
            tool_version=result.tool_version,
            parser_version=arf.PARSER_VERSION,
            evidence_digest=evidence_digest,
            playbook_digest=playbook_digest,
        )
        .returning(compliance_scans.c.id)
    )
    if result.rules:
        conn.execute(
            insert(compliance_results),
            [{"scan_id": scan_id, "rule_id": rule.id, "result": rule.result} for rule in result.rules],
        )

    summary = (
        f"{result.profile_title}: {pass_rate(result.passed, result.failed)} passing, {result.failed} failing."
    )
    if previous is None:
        notify.enqueue(conn, "finding", f"First compliance result from {asset_id}", summary)
    else:
        regressed = _regressions(conn, asset_id, previous.id, scan_id)
        if regressed:
            lines = [f"[{row.severity}] {row.title}" for row in regressed[:10]]
            if len(regressed) > 10:
                lines.append(f"and {len(regressed) - 10} more")
            notify.enqueue(
                conn,
                "finding",
                f"{len(regressed)} compliance regression{'s' if len(regressed) > 1 else ''} on {asset_id}",
                "\n".join([summary, *lines]),
            )
    if was_stale:
        notify.enqueue(conn, "health", f"Compliance results resumed from {asset_id}", summary)
    return Recorded(scan_id, duplicate=False)


def waive(conn: Connection, asset_id: str, rule_id: str, reason: str) -> None:
    """Accept a failing rule on one host. It stays failing, with the reason beside it, and stops alerting."""
    if not reason.strip():
        raise ValueError("a waiver needs a reason")
    conn.execute(
        upsert(compliance_waivers)
        .values(asset_id=asset_id, rule_id=rule_id, reason=reason.strip())
        .on_conflict_do_update(
            index_elements=["asset_id", "rule_id"], set_={"reason": reason.strip(), "created_at": func.now()}
        )
    )


def unwaive(conn: Connection, asset_id: str, rule_id: str) -> None:
    conn.execute(
        delete(compliance_waivers).where(
            compliance_waivers.c.asset_id == asset_id, compliance_waivers.c.rule_id == rule_id
        )
    )


def check(conn: Connection) -> None:
    """Alert once for each host whose newest result is older than STALE."""
    now = datetime.now(UTC)
    for asset_id, last in conn.execute(
        select(compliance_scans.c.asset_id, func.max(compliance_scans.c.received_at)).group_by(
            compliance_scans.c.asset_id
        )
    ):
        if now - last > STALE and not _stale_warned(conn, asset_id, since=last):
            notify.enqueue(
                conn,
                "health",
                _stale_title(asset_id),
                f"The last compliance result from {asset_id} arrived {last:%Y-%m-%d %H:%M} UTC.",
            )


def latest(conn: Connection) -> list[Any]:
    """Each host's newest result per benchmark and profile."""
    newest = (
        select(compliance_scans)
        .distinct(compliance_scans.c.asset_id, compliance_scans.c.benchmark_id, compliance_scans.c.profile_id)
        .order_by(
            compliance_scans.c.asset_id,
            compliance_scans.c.benchmark_id,
            compliance_scans.c.profile_id,
            compliance_scans.c.finished_at.desc(),
        )
        .subquery()
    )
    return list(conn.execute(select(newest).order_by(newest.c.asset_id, newest.c.benchmark_id)).all())


def failing(conn: Connection, scan_id: int) -> list[Any]:
    """A result's failing rules, unwaived first, then worst first, with any waiver's reason."""
    scan = conn.execute(select(compliance_scans).where(compliance_scans.c.id == scan_id)).one()
    return list(
        conn.execute(
            select(
                compliance_results.c.rule_id,
                compliance_results.c.result,
                compliance_rules.c.title,
                compliance_rules.c.severity,
                compliance_rules.c.stig_ids,
                compliance_waivers.c.reason.label("waiver"),
            )
            .join(
                compliance_rules,
                (compliance_rules.c.benchmark_id == scan.benchmark_id)
                & (compliance_rules.c.rule_id == compliance_results.c.rule_id),
            )
            .outerjoin(
                compliance_waivers,
                (compliance_waivers.c.asset_id == scan.asset_id)
                & (compliance_waivers.c.rule_id == compliance_results.c.rule_id),
            )
            .where(compliance_results.c.scan_id == scan_id, compliance_results.c.result.in_(FAILING))
            .order_by(compliance_waivers.c.reason.is_not(None), SEVERITY_ORDER, compliance_rules.c.title)
        ).all()
    )


def matching_stig(conn: Connection, scan_id: int) -> str | None:
    """The imported STIG sharing the most vulnerability IDs with this result, if any."""
    scan = conn.execute(select(compliance_scans).where(compliance_scans.c.id == scan_id)).first()
    if scan is None:
        return None
    stig_id: str | None = conn.scalar(
        select(stig_rules.c.stig_id)
        .join(compliance_rules, compliance_rules.c.vuln_id == stig_rules.c.vuln_id)
        .join(
            compliance_results,
            (compliance_results.c.rule_id == compliance_rules.c.rule_id)
            & (compliance_results.c.scan_id == scan_id),
        )
        .where(compliance_rules.c.benchmark_id == scan.benchmark_id)
        .group_by(stig_rules.c.stig_id)
        .order_by(func.count().desc())
        .limit(1)
    )
    return stig_id


def checklist(conn: Connection, scan_id: int) -> tuple[str, dict[str, Any]]:
    """A STIG Viewer 3 checklist (CKLB) for one result: every rule of the matching STIG, with the status its
    SCAP rules give it, or not reviewed when the content doesn't automate it. Returns a file name and the
    document."""
    scan = conn.execute(select(compliance_scans).where(compliance_scans.c.id == scan_id)).first()
    stig_id = matching_stig(conn, scan_id) if scan is not None else None
    if scan is None or stig_id is None:
        raise LookupError("no imported STIG matches this result")
    stig = conn.execute(select(stigs).where(stigs.c.id == stig_id)).one()
    evaluated: dict[str, list[Any]] = {}
    for row in conn.execute(
        select(
            compliance_rules.c.vuln_id,
            compliance_rules.c.rule_id,
            compliance_rules.c.title,
            compliance_results.c.result,
            compliance_waivers.c.reason.label("waiver"),
        )
        .join(
            compliance_results,
            (compliance_results.c.rule_id == compliance_rules.c.rule_id)
            & (compliance_results.c.scan_id == scan_id),
        )
        .outerjoin(
            compliance_waivers,
            (compliance_waivers.c.asset_id == scan.asset_id)
            & (compliance_waivers.c.rule_id == compliance_rules.c.rule_id),
        )
        .where(compliance_rules.c.benchmark_id == scan.benchmark_id, compliance_rules.c.vuln_id.is_not(None))
        .order_by(compliance_rules.c.rule_id)
    ):
        evaluated.setdefault(row.vuln_id, []).append(row)

    # Deterministic IDs, so the same result always produces the same file.
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"pen16:compliance:{scan_id}")
    stig_uuid = str(uuid.uuid5(namespace, stig.id))
    source = (
        f"Evaluated by {scan.tool_version} at {scan.finished_at:%Y-%m-%d %H:%M} UTC with "
        f"{scan.benchmark_id} {scan.benchmark_version}, profile {scan.profile_id}."
    )
    rules = []
    for rule in conn.execute(
        select(stig_rules).where(stig_rules.c.stig_id == stig.id).order_by(stig_rules.c.vuln_id)
    ):
        found = evaluated.get(rule.vuln_id, [])
        rules.append(
            {
                "uuid": str(uuid.uuid5(namespace, rule.vuln_id)),
                "stig_uuid": stig_uuid,
                "target_key": None,
                "stig_ref": None,
                "group_id": rule.vuln_id,
                "rule_id": rule.rule_id.removesuffix("_rule"),
                "rule_id_src": rule.rule_id,
                "weight": rule.weight,
                "classification": "Unclassified",
                "severity": rule.severity,
                "rule_version": rule.rule_version,
                "group_title": rule.group_title,
                "rule_title": rule.title,
                "fix_text": rule.fix_text,
                "false_positives": "",
                "false_negatives": "",
                "discussion": rule.discussion,
                "check_content": rule.check_content,
                "documentable": "false",
                "mitigations": "",
                "potential_impacts": "",
                "third_party_tools": "",
                "mitigation_control": "",
                "responsibility": "",
                "security_override_guidance": "",
                "ia_controls": "",
                "check_content_ref": {"href": "", "name": "M"},
                "legacy_ids": [],
                "ccis": rule.ccis,
                "group_tree": [{"id": rule.vuln_id, "title": rule.group_title, "description": ""}],
                "status": _status([row.result for row in found]),
                "overrides": {},
                "comments": "\n".join(f"Waived ({row.rule_id}): {row.waiver}" for row in found if row.waiver),
                "finding_details": "\n".join(
                    [source, *(f"{row.result}: {row.title} ({row.rule_id})" for row in found)]
                )
                if found
                else "",
            }
        )
    document = {
        "title": f"{scan.asset_id} - {stig.title}",
        "id": str(namespace),
        "active": False,
        "mode": 2,
        "has_path": True,
        "target_data": {
            "target_type": "Computing",
            "host_name": scan.asset_id,
            "ip_address": "",
            "mac_address": "",
            "fqdn": "",
            "comments": "",
            "role": "None",
            "is_web_database": False,
            "technology_area": "",
            "web_db_site": "",
            "web_db_instance": "",
            "classification": None,
        },
        "stigs": [
            {
                "stig_name": stig.title,
                "display_name": stig.title.removesuffix(" Security Technical Implementation Guide"),
                "stig_id": stig.id,
                "release_info": stig.release,
                "version": stig.version,
                "uuid": stig_uuid,
                "reference_identifier": stig.target_key,
                "size": len(rules),
                "rules": rules,
            }
        ],
        "cklb_version": "1.0",
    }
    return f"{scan.asset_id}-{stig.id}-{scan.finished_at:%Y%m%d}.cklb", document


def _status(results: list[str]) -> str:
    """One vulnerability, many SCAP rules: any failure is open; not a finding only when every rule passed."""
    if not results:
        return NOT_REVIEWED
    if any(result in FAILING for result in results):
        return OPEN
    if all(result in PASSING for result in results):
        return NOT_A_FINDING
    if all(result == "notapplicable" for result in results):
        return NOT_APPLICABLE
    return NOT_REVIEWED


def _regressions(conn: Connection, asset_id: str, previous_id: int, scan_id: int) -> list[Any]:
    before = compliance_results.alias("before")
    now = compliance_results.alias("now")
    scan = select(compliance_scans.c.benchmark_id).where(compliance_scans.c.id == scan_id).scalar_subquery()
    return list(
        conn.execute(
            select(compliance_rules.c.title, compliance_rules.c.severity)
            .select_from(now)
            .join(before, (before.c.rule_id == now.c.rule_id) & (before.c.scan_id == previous_id))
            .join(
                compliance_rules,
                (compliance_rules.c.rule_id == now.c.rule_id) & (compliance_rules.c.benchmark_id == scan),
            )
            .where(
                now.c.scan_id == scan_id,
                now.c.result.in_(FAILING),
                before.c.result.in_(PASSING),
                ~exists().where(
                    compliance_waivers.c.asset_id == asset_id, compliance_waivers.c.rule_id == now.c.rule_id
                ),
            )
            .order_by(SEVERITY_ORDER, compliance_rules.c.title)
        ).all()
    )


def _stale_title(asset_id: str) -> str:
    return f"Compliance results stale from {asset_id}"


def _stale_warned(conn: Connection, asset_id: str, since: datetime | None = None) -> bool:
    """Whether a stale warning went out for this host after its newest result (or after `since`)."""
    if since is None:
        since = conn.scalar(
            select(func.max(compliance_scans.c.received_at)).where(compliance_scans.c.asset_id == asset_id)
        )
        if since is None:
            return False
    return bool(
        conn.scalar(
            select(
                exists().where(
                    notifications.c.kind == "health",
                    notifications.c.title == _stale_title(asset_id),
                    notifications.c.created_at > since,
                )
            )
        )
    )


def pass_rate(passed: int, failed: int) -> str:
    return f"{100 * passed / (passed + failed):.0f}%" if passed + failed else "n/a"
