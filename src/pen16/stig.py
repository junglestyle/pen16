"""DISA STIG benchmarks: the manual XCCDF in a STIG zip from cyber.mil, the source of a checklist's rules."""

import re
from dataclasses import dataclass
from typing import Any

from defusedxml import ElementTree
from sqlalchemy import Connection, delete, insert
from sqlalchemy.dialects.postgresql import insert as upsert

from pen16.db import stig_rules, stigs

XCCDF = "{http://checklists.nist.gov/xccdf/1.1}"
DC = "{http://purl.org/dc/elements/1.1/}"


@dataclass(frozen=True)
class StigRule:
    vuln_id: str
    rule_id: str
    rule_version: str
    title: str
    severity: str
    weight: str
    group_title: str
    discussion: str
    check_content: str
    fix_text: str
    ccis: list[str]


@dataclass(frozen=True)
class Stig:
    id: str
    title: str
    version: str
    release: str
    target_key: str
    rules: list[StigRule]


def parse(raw: bytes) -> Stig:
    root = ElementTree.fromstring(raw)
    if root.tag != f"{XCCDF}Benchmark":
        raise ValueError("not a DISA STIG benchmark (XCCDF 1.1)")
    rules = []
    target_key = ""
    for group in root.findall(f"{XCCDF}Group"):
        rule = group.find(f"{XCCDF}Rule")
        if rule is None:
            continue
        reference = rule.find(f"{XCCDF}reference/{DC}identifier")
        target_key = target_key or _text(reference)
        description = _text(rule.find(f"{XCCDF}description"))
        rules.append(
            StigRule(
                vuln_id=group.get("id", ""),
                rule_id=rule.get("id", ""),
                rule_version=_text(rule.find(f"{XCCDF}version")),
                title=_text(rule.find(f"{XCCDF}title")),
                severity=rule.get("severity", "medium"),
                weight=rule.get("weight", "10.0"),
                group_title=_text(group.find(f"{XCCDF}title")),
                discussion=_tag(description, "VulnDiscussion"),
                check_content=_text(rule.find(f"{XCCDF}check/{XCCDF}check-content")),
                fix_text=_text(rule.find(f"{XCCDF}fixtext")),
                ccis=[
                    _text(ident)
                    for ident in rule.findall(f"{XCCDF}ident")
                    if ident.get("system", "").endswith("/cci")
                ],
            )
        )
    release = next(
        (_text(p) for p in root.findall(f"{XCCDF}plain-text") if p.get("id") == "release-info"), ""
    )
    return Stig(
        id=root.get("id", ""),
        title=_text(root.find(f"{XCCDF}title")),
        version=_text(root.find(f"{XCCDF}version")),
        release=release,
        target_key=target_key,
        rules=rules,
    )


def load(conn: Connection, stig: Stig) -> None:
    """Make this release the STIG's current one. A new release replaces the old one's rules."""
    values = {
        "title": stig.title,
        "version": stig.version,
        "release": stig.release,
        "target_key": stig.target_key,
    }
    conn.execute(
        upsert(stigs).values(id=stig.id, **values).on_conflict_do_update(index_elements=["id"], set_=values)
    )
    conn.execute(delete(stig_rules).where(stig_rules.c.stig_id == stig.id))
    if stig.rules:
        conn.execute(insert(stig_rules), [{"stig_id": stig.id, **rule.__dict__} for rule in stig.rules])


def _tag(description: str, name: str) -> str:
    """DISA packs fields into the description as escaped pseudo-XML, such as <VulnDiscussion>."""
    match = re.search(rf"<{name}>(.*?)</{name}>", description, re.DOTALL)
    return match.group(1).strip() if match else ""


def _text(element: Any) -> str:
    return "".join(element.itertext()).strip() if element is not None else ""
