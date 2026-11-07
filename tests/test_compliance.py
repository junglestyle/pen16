import gzip
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, func, select, update

from pen16 import arf, compliance, intake, status, stig, tokens
from pen16.db import TokenKind, compliance_results, compliance_scans, compliance_waivers
from tests.conftest import (
    DISA_STIG,
    OWNER,
    OWNER_LOGIN,
    SAME_ORIGIN,
    STIG_RESULT,
    alerts,
    dashboard,
    open_incidents,
)

RULE = "xccdf_org.ssgproject.content_rule_"
GPGCHECK = f"{RULE}ensure_gpgcheck_globally_activated"
UMASK = f"{RULE}accounts_umask_etc_bashrc"


def later(raw: bytes = STIG_RESULT.read_bytes(), days: int = 7, **results: str) -> bytes:
    """The fixture, as if it ran `days` later with some rules' results changed."""
    finished = (datetime(2026, 10, 29, 3, 25, 48, tzinfo=UTC) + timedelta(days=days)).isoformat()
    raw = re.sub(rb'end-time="[^"]*"', f'end-time="{finished}"'.encode(), raw)
    for rule, result in results.items():
        raw = re.sub(
            rb'(<rule-result idref="' + f"{RULE}{rule}".encode() + rb'".*?<result>)\w+(</result>)',
            rb"\g<1>" + result.encode() + rb"\g<2>",
            raw,
            flags=re.DOTALL,
        )
    return raw


def recorded(conn: Connection, raw: bytes, host: str = "lab-rhel9") -> compliance.Recorded:
    result = arf.parse(raw)
    return compliance.record(conn, host, result, result.digest, None)


def test_parse_reads_profile_results_and_stig_references() -> None:
    result = arf.parse(STIG_RESULT.read_bytes())

    assert result.benchmark_id == "xccdf_org.ssgproject.content_benchmark_RHEL-9"
    assert result.benchmark_version == "0.1.82"
    assert result.profile_title == "DISA STIG for Red Hat Enterprise Linux 9"
    assert result.tool_version == "redhat:openscap:1.3.9"
    assert (len(result.rules), result.passed, result.failed) == (20, 9, 8)
    crypto = next(rule for rule in result.rules if rule.id == f"{RULE}configure_crypto_policy")
    assert crypto.result == "fail"
    assert crypto.severity == "high"
    assert crypto.vuln_id == "V-258241"
    assert crypto.stig_rule_id == "SV-258241r1184293_rule"
    assert crypto.stig_ids == ["RHEL-09-215105", "RHEL-09-672030"]
    assert "SRG-OS-000396-GPOS-00176" in crypto.srgs
    assert "SC-13" in crypto.nist


def test_first_result_alerts_once_with_the_pass_rate(conn: Connection) -> None:
    recorded(conn, STIG_RESULT.read_bytes())

    [(kind, body)] = alerts(conn)
    assert kind == "finding"
    assert "53%" in body


def test_regression_alerts_with_the_rule_and_a_fix_alone_stays_quiet(conn: Connection) -> None:
    recorded(conn, STIG_RESULT.read_bytes())
    recorded(conn, later(days=7, accounts_umask_etc_bashrc="pass"))
    assert len(alerts(conn)) == 1

    recorded(
        conn, later(days=14, accounts_umask_etc_bashrc="pass", ensure_gpgcheck_globally_activated="fail")
    )

    kind, body = alerts(conn)[-1]
    assert kind == "finding"
    assert "Ensure gpgcheck Enabled In Main dnf Configuration" in body
    assert "umask" not in body.lower()


def test_a_waived_rule_regresses_quietly_and_stays_failing(conn: Connection) -> None:
    recorded(conn, STIG_RESULT.read_bytes())
    compliance.waive(conn, "lab-rhel9", GPGCHECK, "local repo mirror signs nothing", OWNER_LOGIN)

    scan = recorded(conn, later(ensure_gpgcheck_globally_activated="fail"))

    assert len(alerts(conn)) == 1
    waived = [row for row in compliance.failing(conn, scan.scan_id) if row.rule_id == GPGCHECK]
    assert waived[0].waiver == "local repo mirror signs nothing"
    with pytest.raises(ValueError, match="needs a reason"):
        compliance.waive(conn, "lab-rhel9", UMASK, " ", OWNER_LOGIN)


def test_a_removed_waiver_stays_in_history_and_its_rule_alerts_again(conn: Connection) -> None:
    recorded(conn, STIG_RESULT.read_bytes())
    compliance.waive(conn, "lab-rhel9", GPGCHECK, "mirror signs nothing", OWNER_LOGIN)
    compliance.waive(conn, "lab-rhel9", GPGCHECK, "mirror signs nothing yet", OWNER_LOGIN)
    compliance.unwaive(conn, "lab-rhel9", GPGCHECK, "mirror signs now", OWNER_LOGIN)

    recorded(conn, later(ensure_gpgcheck_globally_activated="fail"))

    assert alerts(conn)[-1][0] == "finding"
    assert len(alerts(conn)) == 2
    history = conn.execute(
        select(compliance_waivers.c.reason, compliance_waivers.c.end_reason).order_by(compliance_waivers.c.id)
    )
    assert [tuple(row) for row in history] == [
        ("mirror signs nothing", "replaced by a new waiver"),
        ("mirror signs nothing yet", "mirror signs now"),
    ]


def test_failing_lists_unwaived_worst_first(conn: Connection) -> None:
    scan = recorded(conn, STIG_RESULT.read_bytes())
    compliance.waive(conn, "lab-rhel9", f"{RULE}configure_crypto_policy", "FIPS breaks the lab", OWNER_LOGIN)

    rows = compliance.failing(conn, scan.scan_id)

    assert len(rows) == 8
    assert rows[0].severity == "high"
    assert rows[0].waiver is None
    assert rows[-1].rule_id == f"{RULE}configure_crypto_policy"


def test_duplicate_is_a_no_op_and_an_older_result_is_refused(conn: Connection) -> None:
    newer = recorded(conn, later(days=7))

    assert recorded(conn, later(days=7)) == compliance.Recorded(newer.scan_id, duplicate=True)
    with pytest.raises(compliance.StaleResultError):
        recorded(conn, STIG_RESULT.read_bytes())
    assert conn.scalar(select(func.count()).select_from(compliance_scans)) == 1


def test_a_silent_host_alerts_once_then_recovers(conn: Connection) -> None:
    recorded(conn, STIG_RESULT.read_bytes())
    conn.execute(update(compliance_scans).values(received_at=func.now() - timedelta(days=11)))

    compliance.check(conn)
    compliance.check(conn)
    assert open_incidents(conn) == ["compliance-stale:lab-rhel9"]

    recorded(conn, later())

    assert open_incidents(conn) == []
    assert [kind for kind, _ in alerts(conn)] == ["finding", "health", "health"]


def checklist(conn: Connection, scan_id: int) -> dict[str, Any]:
    stig.load(conn, stig.parse(DISA_STIG.read_bytes()))
    name, document = compliance.checklist(conn, scan_id)
    assert name == "lab-rhel9-RHEL_9_STIG-20261029.cklb"
    return {rule["group_id"]: rule for rule in document["stigs"][0]["rules"]}


def test_checklist_lists_every_stig_rule_with_its_scap_status(conn: Connection) -> None:
    scan = recorded(conn, STIG_RESULT.read_bytes())
    compliance.waive(conn, "lab-rhel9", f"{RULE}rootfiles_configured", "image default", OWNER_LOGIN)

    rules = checklist(conn, scan.scan_id)

    assert len(rules) == 21
    assert rules["V-258234"]["status"] == "not_a_finding"
    assert rules["V-258234"]["rule_version"] == "RHEL-09-215100"
    assert rules["V-258234"]["ccis"]
    # Two SCAP rules check V-257889; both fail, so it's open and both show in the details.
    shared = rules["V-257889"]
    assert shared["status"] == "open"
    assert "rootfiles_configured" in shared["finding_details"]
    assert "file_permission_user_init_files_root" in shared["finding_details"]
    assert shared["comments"] == f"Waived ({RULE}rootfiles_configured): image default"
    # The content doesn't automate these, so they're left for a person.
    assert rules["V-257777"]["status"] == "not_reviewed"
    assert rules["V-257985"]["status"] == "not_applicable"


def test_no_checklist_without_a_matching_stig(conn: Connection) -> None:
    scan = recorded(conn, STIG_RESULT.read_bytes())

    with pytest.raises(LookupError):
        compliance.checklist(conn, scan.scan_id)


def intake_client(engine: Engine, evidence: Path) -> tuple[TestClient, dict[str, str]]:
    with engine.begin() as conn:
        token = tokens.create(conn, TokenKind.COMPLIANCE, "lab-rhel9")
    return TestClient(intake.create(engine, evidence)), {"Authorization": f"Bearer {token}"}


def upload(client: TestClient, headers: dict[str, str], raw: bytes, playbook: bytes | None = None) -> Any:
    files = {"result": ("arf.xml.gz", gzip.compress(raw))}
    if playbook is not None:
        files["playbook"] = ("fix.yml.gz", gzip.compress(playbook))
    return client.post("/compliance/v1/results", files=files, headers=headers)


def test_intake_takes_a_result_for_the_tokens_host_only(committed: Engine, tmp_path: Path) -> None:
    client, headers = intake_client(committed, tmp_path)
    with committed.begin() as conn:
        runner = tokens.create(conn, TokenKind.RUNNER, "lab-rhel9")

    assert upload(client, {}, STIG_RESULT.read_bytes()).status_code == 401
    assert upload(client, {"Authorization": f"Bearer {runner}"}, STIG_RESULT.read_bytes()).status_code == 401
    first = upload(client, headers, STIG_RESULT.read_bytes(), b"- hosts: all\n  tasks: []\n")
    again = upload(client, headers, STIG_RESULT.read_bytes())
    older = upload(client, headers, later(days=-1))

    assert first.status_code == 201
    assert first.json() == {"result": first.json()["result"], "passed": 9, "failed": 8}
    assert again.status_code == 200
    assert older.status_code == 409
    # Evidence is stored before the database decides, as for a runner; the refused one is never referenced.
    assert len(list(tmp_path.glob("*.xml.gz"))) == 2
    assert len(list(tmp_path.glob("*.yml.gz"))) == 1
    with committed.connect() as conn:
        assert conn.scalar(select(compliance_scans.c.asset_id)) == "lab-rhel9"
        assert conn.scalar(select(func.count()).select_from(compliance_results)) == 20


@pytest.mark.parametrize(
    "body",
    [
        b"not gzip",
        gzip.compress(b"<nmaprun/>"),
        gzip.compress(b'<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>'),
        gzip.compress(
            b'<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"/>'
        ),
    ],
)
def test_intake_refuses_what_isnt_a_result(committed: Engine, tmp_path: Path, body: bytes) -> None:
    client, headers = intake_client(committed, tmp_path)

    response = client.post("/compliance/v1/results", files={"result": ("arf.xml.gz", body)}, headers=headers)

    assert response.status_code == 422
    assert list(tmp_path.iterdir()) == []


PLAYBOOK = b"- hosts: all\n  tasks: []\n"


@pytest.fixture
def uploaded(committed: Engine, tmp_path: Path) -> int:
    """The fixture's result, sent through the intake with a playbook, and its DISA STIG imported."""
    client, headers = intake_client(committed, tmp_path)
    scan_id: int = upload(client, headers, STIG_RESULT.read_bytes(), PLAYBOOK).json()["result"]
    with committed.begin() as conn:
        stig.load(conn, stig.parse(DISA_STIG.read_bytes()))
    return scan_id


def test_the_dashboard_shows_a_hosts_result_and_takes_a_waiver(committed: Engine, uploaded: int) -> None:
    owner = dashboard(committed)

    waived = owner.post(
        "/compliance/waive",
        data={"asset_id": "lab-rhel9", "rule_id": UMASK, "reason": "set by the container image"},
        headers=SAME_ORIGIN,
        follow_redirects=False,
    )

    assert waived.status_code == 303
    with committed.connect() as conn:
        [host] = status.dashboard(conn).compliance
    assert (host.result.scan_id, host.rate, host.checklist, host.result.has_playbook) == (
        uploaded,
        "53%",
        True,
        True,
    )
    assert [rule.waiver for rule in host.failing if rule.rule_id == UMASK] == ["set by the container image"]
    assert "Configure System Cryptography Policy" in owner.get("/", headers=OWNER).text


def test_the_owner_downloads_the_checklist_and_playbook(
    committed: Engine, uploaded: int, tmp_path: Path
) -> None:
    owner = dashboard(committed, tmp_path)

    cklb = owner.get(f"/compliance/{uploaded}/checklist.cklb", headers=OWNER)
    playbook = owner.get(f"/compliance/{uploaded}/playbook.yml", headers=OWNER)

    assert cklb.json()["stigs"][0]["stig_id"] == "RHEL_9_STIG"
    assert "attachment" in cklb.headers["content-disposition"]
    assert playbook.content == PLAYBOOK
    assert owner.get(f"/compliance/{uploaded}/checklist.cklb").status_code == 403
    assert owner.get(f"/compliance/{uploaded}/playbook.yml").status_code == 403
    assert owner.get(f"/compliance/{uploaded + 1}/playbook.yml", headers=OWNER).status_code == 404
