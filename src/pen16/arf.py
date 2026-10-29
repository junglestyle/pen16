"""Read an OpenSCAP result: an ARF (asset reporting format) report from `oscap xccdf eval --results-arf`."""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from defusedxml import ElementTree

from pen16.db import RuleResult, Severity

PARSER_VERSION = "1"

ARF = "{http://scap.nist.gov/schema/asset-reporting-format/1.1}"
XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"

# Outcomes that count toward the pass rate. "notselected" rules weren't in the profile, so they aren't kept.
PASSING = (RuleResult.PASS, RuleResult.FIXED)
FAILING = (RuleResult.FAIL, RuleResult.ERROR)


@dataclass(frozen=True)
class Rule:
    id: str
    result: RuleResult
    title: str
    severity: Severity
    rationale: str
    vuln_id: str | None
    stig_rule_id: str | None
    stig_ids: list[str]
    srgs: list[str]
    ccis: list[str]
    nist: list[str]


@dataclass(frozen=True)
class Result:
    benchmark_id: str
    benchmark_version: str
    profile_id: str
    profile_title: str
    started_at: datetime
    finished_at: datetime
    tool_version: str
    digest: str
    rules: list[Rule]

    @property
    def passed(self) -> int:
        return sum(rule.result in PASSING for rule in self.rules)

    @property
    def failed(self) -> int:
        return sum(rule.result in FAILING for rule in self.rules)


def parse(raw: bytes) -> Result:
    """Parse one ARF report. Entities and external references are refused by defusedxml."""
    root = ElementTree.fromstring(raw)
    if root.tag != f"{ARF}asset-report-collection":
        raise ValueError("not an ARF report")
    test = root.find(f".//{XCCDF}TestResult")
    if test is None:
        raise ValueError("ARF report has no XCCDF TestResult")
    benchmark_ref = _child(test, "benchmark")
    benchmark_id = benchmark_ref.get("id", "") if benchmark_ref is not None else ""
    benchmark = next(
        (b for b in root.iter(f"{XCCDF}Benchmark") if b.get("id") == benchmark_id),
        root.find(f".//{XCCDF}Benchmark"),
    )
    if benchmark is None:
        raise ValueError("ARF report doesn't include its benchmark")
    profile = _child(test, "profile")
    profile_id = profile.get("idref", "") if profile is not None else ""
    labels = {ref.get("href", ""): _text(ref) for ref in benchmark.findall(f"{XCCDF}reference")}
    definitions = {rule.get("id"): rule for rule in benchmark.iter(f"{XCCDF}Rule")}

    rules = []
    for outcome in test.findall(f"{XCCDF}rule-result"):
        result = _text(_child(outcome, "result"))
        if result == "notselected":
            continue
        rule_id = outcome.get("idref", "")
        definition = definitions.get(rule_id)
        severity = (definition.get("severity") if definition is not None else None) or outcome.get(
            "severity", "unknown"
        )
        known = severity in Severity.__members__.values()
        rules.append(
            _rule(
                rule_id,
                RuleResult(result),
                Severity(severity) if known else Severity.UNKNOWN,
                definition,
                labels,
            )
        )
    return Result(
        benchmark_id=benchmark.get("id", benchmark_id),
        benchmark_version=_text(_child(benchmark, "version")),
        profile_id=profile_id,
        profile_title=_profile_title(root, profile_id),
        started_at=datetime.fromisoformat(test.get("start-time", "")),
        finished_at=datetime.fromisoformat(test.get("end-time", "")),
        tool_version=test.get("test-system", "").removeprefix("cpe:/a:"),
        digest=hashlib.sha256(raw).hexdigest(),
        rules=rules,
    )


def _rule(
    rule_id: str, result: RuleResult, severity: Severity, definition: Any, labels: dict[str, str]
) -> Rule:
    """Sort a rule's references by what the benchmark says each source is: SSG labels its reference hrefs."""
    found: dict[str, list[str]] = {"stigid": [], "stigref": [], "vuln": [], "srg": [], "cci": [], "nist": []}
    for ref in definition.findall(f"{XCCDF}reference") if definition is not None else []:
        text = _text(ref)
        label = labels.get(ref.get("href", ""), "")
        if label == "stigref_vulnerability_id":
            found["vuln"].append(text)
        elif label == "stigref":
            found["stigref"].append(text)
        elif label == "stigid":
            found["stigid"].append(text)
        elif text.startswith("SRG-"):
            found["srg"].append(text)
        elif label == "disa" or text.startswith("CCI-"):
            found["cci"].append(text)
        elif label == "nist":
            found["nist"].append(text)
    return Rule(
        id=rule_id,
        result=result,
        title=_text(_child(definition, "title")) or rule_id,
        severity=severity,
        rationale=_text(_child(definition, "rationale")),
        vuln_id=found["vuln"][0] if found["vuln"] else None,
        stig_rule_id=found["stigref"][0] if found["stigref"] else None,
        stig_ids=found["stigid"],
        srgs=found["srg"],
        ccis=found["cci"],
        nist=found["nist"],
    )


def _profile_title(root: Any, profile_id: str) -> str:
    """Profiles live in the benchmark, or in a tailoring file when the host customized one."""
    for profile in root.iter(f"{XCCDF}Profile"):
        if profile.get("id") == profile_id:
            return _text(_child(profile, "title")) or profile_id
    return profile_id


def _child(element: Any, name: str) -> Any:
    return element.find(f"{XCCDF}{name}") if element is not None else None


def _text(element: Any) -> str:
    return " ".join("".join(element.itertext()).split()) if element is not None else ""
