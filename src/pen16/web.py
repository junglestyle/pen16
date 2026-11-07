"""The owner dashboard. tailscale serve puts it on the tailnet and names the visitor in a header."""

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import ColumnElement, Connection, Engine, ScalarSelect, Text, cast, exists, func, select

from pen16 import backups, compliance, config, db, evidence, exposure, jobs, neighbours, notify
from pen16.config import Config
from pen16.db import (
    DecisionKind,
    FindingStatus,
    JobStatus,
    NotificationStatus,
    ObservationState,
    RuleResult,
    Severity,
    TokenKind,
    assets,
    bindings,
    compliance_scans,
    decisions,
    expected_services,
    findings,
    incidents,
    mac_sightings,
    notifications,
    observations,
    schedules,
    tokens,
)

STALE = timedelta(hours=48)
templates = Jinja2Templates(directory=str(files("pen16") / "templates"))
# The template compares states by name, not by quoted string.
templates.env.globals.update(
    DecisionKind=DecisionKind,
    FindingStatus=FindingStatus,
    JobStatus=JobStatus,
    RuleResult=RuleResult,
    Severity=Severity,
    vendor=neighbours.vendor,
)


def create(engine: Engine, settings: Config, evidence_dir: Path) -> FastAPI:
    def owner(request: Request) -> str:
        """Allow only the configured Tailscale login. The web port is bound to localhost for tailscale serve,
        so these headers can't come from anywhere else on the network."""
        login = request.headers.get("Tailscale-User-Login", "")
        if not settings.owner_login or login != settings.owner_login:
            raise HTTPException(403, "owner only")
        if request.method == "POST" and not _same_origin(request):
            raise HTTPException(403, "cross-site form post")
        return login

    Owner = Annotated[str, Depends(owner)]  # noqa: N806  # a type alias, named like one
    app = FastAPI(title="pen16", docs_url=None, redoc_url=None, openapi_url=None)
    # The logo and the web app manifest, for a browser tab or a phone's home screen. They hold nothing about the
    # network, so they skip the owner check; everything else needs it.
    app.mount("/static", StaticFiles(directory=str(files("pen16") / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, login: Owner) -> HTMLResponse:
        with engine.connect() as conn:
            context = _dashboard(conn)
        return templates.TemplateResponse(request, "dashboard.html", {"owner": login, **context})

    @app.post("/scan")
    def scan_now(login: Owner) -> RedirectResponse:
        with engine.begin() as conn:
            jobs.request(conn, settings.scope, f"owner:{login}", "requested from the dashboard")
        return _back()

    @app.post("/findings/expect")
    def expect(
        login: Owner, finding: Annotated[list[int], Form()], reason: Annotated[str, Form()]
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.expect(conn, finding, reason, login)
        return _back()

    @app.post("/findings/decide")
    def decide(
        login: Owner,
        finding: Annotated[list[int], Form()],
        kind: Annotated[DecisionKind, Form()],
        reason: Annotated[str, Form()],
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.decide(conn, finding, kind, reason, login)
        return _back()

    @app.post("/findings/resolve")
    def resolve(
        login: Owner, finding: Annotated[list[int], Form()], reason: Annotated[str, Form()]
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.resolve(conn, finding, reason, login)
        return _back()

    @app.post("/findings/reopen")
    def reopen(login: Owner, finding: Annotated[int, Form()]) -> RedirectResponse:
        with engine.begin() as conn:
            exposure.reopen(conn, finding, login)
        return _back()

    @app.post("/decisions/withdraw")
    def withdraw(login: Owner, decision: Annotated[int, Form()]) -> RedirectResponse:
        with engine.begin() as conn:
            exposure.withdraw(conn, decision, f"withdrawn by {login}")
        return _back()

    @app.post("/expected/remove")
    def unexpect(
        login: Owner,
        asset_id: Annotated[str, Form()],
        protocol: Annotated[str, Form()],
        port: Annotated[int, Form()],
        vantage: Annotated[str, Form()],
        reason: Annotated[str, Form()],
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.unexpect(conn, asset_id, protocol, port, vantage, reason, login)
        return _back()

    @app.post("/assets/name")
    def name_asset(
        _login: Owner, provisional_id: Annotated[str, Form()], asset_id: Annotated[str, Form()]
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.name_asset(conn, provisional_id, asset_id)
        return _back()

    @app.post("/compliance/waive")
    def waive(
        login: Owner,
        asset_id: Annotated[str, Form()],
        rule_id: Annotated[str, Form()],
        reason: Annotated[str, Form()],
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            compliance.waive(conn, asset_id, rule_id, reason, login)
        return _back("#compliance")

    @app.post("/compliance/unwaive")
    def unwaive(
        login: Owner,
        asset_id: Annotated[str, Form()],
        rule_id: Annotated[str, Form()],
        reason: Annotated[str, Form()],
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            compliance.unwaive(conn, asset_id, rule_id, reason, login)
        return _back("#compliance")

    @app.post("/alerts/replay")
    def replay(_login: Owner) -> RedirectResponse:
        with engine.begin() as conn:
            notify.replay_failed(conn)
        return _back()

    @app.get("/compliance/{scan_id}/checklist.cklb")
    def checklist(_login: Owner, scan_id: int) -> Response:
        try:
            with engine.connect() as conn:
                name, document = compliance.checklist(conn, scan_id)
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        return Response(
            json.dumps(document, indent=2), media_type="application/json", headers=_download(name)
        )

    @app.get("/compliance/{scan_id}/playbook.yml")
    def playbook(_login: Owner, scan_id: int) -> Response:
        with engine.connect() as conn:
            scan = conn.execute(select(compliance_scans).where(compliance_scans.c.id == scan_id)).first()
        if scan is None or scan.playbook_digest is None:
            raise HTTPException(404, "no playbook for this result")
        name = f"{scan.asset_id}-remediation-{scan.finished_at:%Y%m%d}.yml"
        return Response(
            evidence.read(evidence_dir, scan.playbook_digest, ".yml.gz"),
            media_type="text/plain; charset=utf-8",
            headers=_download(name),
        )

    return app


def _dashboard(conn: Connection) -> dict[str, Any]:
    now = db.now(conn)
    last_success = conn.scalar(
        select(func.max(db.jobs.c.finished_at)).where(db.jobs.c.status == JobStatus.SUCCEEDED)
    )
    latest = conn.execute(select(db.jobs).order_by(db.jobs.c.id.desc()).limit(1)).first()
    seen = observations.alias("seen")
    service = (
        seen.c.address,
        _mac(seen.c.address).label("mac"),
        seen.c.service,
        seen.c.product,
        seen.c.version,
        seen.c.observed_at,
    )
    active = (decisions.c.finding_id == findings.c.id) & decisions.c.withdrawn_at.is_(None)
    # The latest withdrawn decision, shown on a finding that's back in Needs attention.
    withdrawn = (
        select(decisions.c.withdrawal)
        .where(decisions.c.finding_id == findings.c.id, decisions.c.withdrawn_at.is_not(None))
        .order_by(decisions.c.withdrawn_at.desc())
        .limit(1)
        .scalar_subquery()
    )
    open_findings = conn.execute(
        select(findings, *service, withdrawn.label("withdrawal"))
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .where(findings.c.status == FindingStatus.OPEN, ~exists().where(active))
        .order_by(findings.c.opened_at.desc())
    ).all()
    decided = conn.execute(
        select(
            findings,
            *service,
            decisions.c.id.label("decision_id"),
            decisions.c.kind.label("decision_kind"),
            decisions.c.reason,
            decisions.c.decided_at,
        )
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .join(decisions, active)
        .order_by(findings.c.asset_id, findings.c.protocol, findings.c.port)
    ).all()
    resolved = conn.execute(
        select(findings, *service)
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .where(findings.c.status == FindingStatus.RESOLVED)
        .order_by(findings.c.resolved_at.desc())
        .limit(20)
    ).all()
    latest_state = (
        select(observations)
        .distinct(
            observations.c.asset_id, observations.c.protocol, observations.c.port, observations.c.vantage
        )
        .order_by(
            observations.c.asset_id,
            observations.c.protocol,
            observations.c.port,
            observations.c.vantage,
            observations.c.observed_at.desc(),
        )
        .subquery()
    )
    expected = expected_services.alias("expected")
    exposed = conn.execute(
        select(latest_state, expected.c.reason)
        .outerjoin(
            expected,
            (expected.c.asset_id == latest_state.c.asset_id)
            & (expected.c.protocol == latest_state.c.protocol)
            & (expected.c.port == latest_state.c.port)
            & (expected.c.vantage == latest_state.c.vantage)
            & expected.c.ended_at.is_(None),
        )
        .where(latest_state.c.state == ObservationState.OPEN)
        .order_by(latest_state.c.asset_id, latest_state.c.protocol, latest_state.c.port)
    ).all()
    last_backup = backups.latest(conn)
    results = compliance.latest(conn)
    return {
        "compliance": [
            {
                "scan": scan,
                "rate": compliance.pass_rate(scan.passed, scan.failed),
                "stale": now - scan.received_at > compliance.STALE,
                "failing": compliance.failing(conn, scan.id),
                "checklist": compliance.matching_stig(conn, scan.id) is not None,
            }
            for scan in results
        ],
        "now": now,
        "last_backup": last_backup,
        "backup_stale": last_backup is None or now - last_backup > backups.STALE,
        "last_success": last_success,
        "stale": last_success is None or now - last_success > STALE,
        "latest": latest,
        "next_run": conn.scalar(select(func.min(schedules.c.next_run_at)).where(schedules.c.enabled)),
        "runner_seen": conn.scalar(
            select(func.max(tokens.c.last_used_at)).where(tokens.c.kind == TokenKind.RUNNER)
        ),
        "pending": _count(conn, notifications.c.status == NotificationStatus.PENDING),
        "failed": _count(conn, notifications.c.status == NotificationStatus.FAILED),
        "incidents": conn.execute(
            select(incidents).where(incidents.c.cleared_at.is_(None)).order_by(incidents.c.opened_at)
        ).all(),
        "findings": open_findings,
        "decided": decided,
        "resolved": resolved,
        "exposed": exposed,
        "expected": conn.execute(
            select(expected_services)
            .where(expected_services.c.ended_at.is_(None))
            .order_by(expected_services.c.asset_id)
        ).all(),
        # A provisional asset is one address, so one row each.
        "provisional": conn.execute(
            select(
                assets.c.id,
                func.host(bindings.c.address).label("address"),
                _mac(bindings.c.address).label("mac"),
            )
            .join(bindings, bindings.c.asset_id == assets.c.id)
            .where(assets.c.provisional)
            .order_by(bindings.c.address)
        ).all(),
    }


def _mac(address: ColumnElement[Any]) -> ScalarSelect[str]:
    """The MAC most recently seen at an address, if any scan saw one."""
    return (
        select(cast(mac_sightings.c.mac, Text))
        .where(mac_sightings.c.address == address)
        .order_by(mac_sightings.c.confirmed_at.desc())
        .limit(1)
        .scalar_subquery()
    )


def _count(conn: Connection, condition: ColumnElement[bool]) -> int:
    return int(conn.scalar(select(func.count()).select_from(notifications).where(condition)) or 0)


@contextmanager
def _refusing() -> Iterator[None]:
    """The services raise ValueError when the owner's input can't be taken, such as a missing reason: a 400."""
    try:
        yield
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


def _same_origin(request: Request) -> bool:
    if request.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin":
        return False
    origin = request.headers.get("Origin")
    return origin is None or urlsplit(origin).netloc == request.headers.get("Host")


def _back(anchor: str = "") -> RedirectResponse:
    return RedirectResponse(f"/{anchor}", status_code=303)


def _download(name: str) -> dict[str, str]:
    return {"Content-Disposition": f'attachment; filename="{name}"'}


def app() -> FastAPI:
    return create(
        db.connect(), config.load(), Path(os.environ.get("PEN16_EVIDENCE_DIR", "/var/lib/pen16/evidence"))
    )
