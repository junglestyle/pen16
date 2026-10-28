"""The owner dashboard. tailscale serve puts it on the tailnet and names the visitor in a header."""

from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import ColumnElement, Connection, Engine, func, select

from pen16 import backups, config, db, exposure, jobs
from pen16.config import Config
from pen16.db import (
    FindingStatus,
    JobStatus,
    NotificationStatus,
    ObservationState,
    TokenKind,
    assets,
    bindings,
    expected_services,
    findings,
    notifications,
    observations,
    schedules,
    tokens,
)

STALE = timedelta(hours=48)
templates = Jinja2Templates(directory=str(files("pen16") / "templates"))


def create(engine: Engine, settings: Config) -> FastAPI:
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
        _login: Owner, finding: Annotated[list[int], Form()], reason: Annotated[str, Form()]
    ) -> RedirectResponse:
        with engine.begin() as conn:
            exposure.expect(conn, finding, reason)
        return _back()

    @app.post("/expected/remove")
    def unexpect(
        _login: Owner,
        asset_id: Annotated[str, Form()],
        protocol: Annotated[str, Form()],
        port: Annotated[int, Form()],
        vantage: Annotated[str, Form()],
    ) -> RedirectResponse:
        with engine.begin() as conn:
            exposure.unexpect(conn, asset_id, protocol, port, vantage)
        return _back()

    @app.post("/assets/name")
    def name_asset(
        _login: Owner, provisional_id: Annotated[str, Form()], asset_id: Annotated[str, Form()]
    ) -> RedirectResponse:
        try:
            with engine.begin() as conn:
                exposure.name_asset(conn, provisional_id, asset_id)
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
        return _back()

    return app


def _dashboard(conn: Connection) -> dict[str, Any]:
    now = datetime.now(UTC)
    last_success = conn.scalar(
        select(func.max(db.jobs.c.finished_at)).where(db.jobs.c.status == JobStatus.SUCCEEDED)
    )
    latest = conn.execute(select(db.jobs).order_by(db.jobs.c.id.desc()).limit(1)).first()
    seen = observations.alias("seen")
    open_findings = conn.execute(
        select(findings, seen.c.address, seen.c.service, seen.c.product, seen.c.version, seen.c.observed_at)
        .join(seen, seen.c.id == findings.c.last_observation_id)
        .where(findings.c.status == FindingStatus.OPEN)
        .order_by(findings.c.opened_at.desc())
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
            & (expected.c.vantage == latest_state.c.vantage),
        )
        .where(latest_state.c.state == ObservationState.OPEN)
        .order_by(latest_state.c.asset_id, latest_state.c.protocol, latest_state.c.port)
    ).all()
    last_backup = backups.latest(conn)
    return {
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
        "findings": open_findings,
        "exposed": exposed,
        "expected": conn.execute(select(expected_services).order_by(expected_services.c.asset_id)).all(),
        "provisional": conn.execute(
            select(assets.c.id, func.string_agg(func.host(bindings.c.address), ", ").label("addresses"))
            .join(bindings, bindings.c.asset_id == assets.c.id)
            .where(assets.c.provisional)
            .group_by(assets.c.id)
            .order_by(assets.c.id)
        ).all(),
    }


def _count(conn: Connection, condition: ColumnElement[bool]) -> int:
    return int(conn.scalar(select(func.count()).select_from(notifications).where(condition)) or 0)


def _same_origin(request: Request) -> bool:
    if request.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin":
        return False
    origin = request.headers.get("Origin")
    return origin is None or urlsplit(origin).netloc == request.headers.get("Host")


def _back() -> RedirectResponse:
    return RedirectResponse("/", status_code=303)


def app() -> FastAPI:
    return create(db.connect(), config.load())
