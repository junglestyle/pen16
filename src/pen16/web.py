"""The owner dashboard. tailscale serve puts it on the tailnet and names the visitor in a header."""

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Engine

from pen16 import compliance, config, db, evidence, exposure, jobs, neighbours, notify, status
from pen16.config import Config
from pen16.db import DecisionKind, JobStatus, Profile, RuleResult, Severity

templates = Jinja2Templates(directory=str(files("pen16") / "templates"))
# The template compares states by name, not by quoted string.
templates.env.globals.update(
    DecisionKind=DecisionKind,
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
            view = status.dashboard(conn)
        return templates.TemplateResponse(request, "dashboard.html", {"owner": login, "d": view})

    @app.post("/scan")
    def scan_now(login: Owner) -> RedirectResponse:
        with engine.begin() as conn:
            jobs.request(
                conn, settings.scope, f"owner:{login}", "requested from the dashboard", Profile.NIGHTLY
            )
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
        try:
            with engine.connect() as conn:
                name, digest = compliance.playbook(conn, scan_id)
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        return Response(
            evidence.read(evidence_dir, digest, ".yml.gz"),
            media_type="text/plain; charset=utf-8",
            headers=_download(name),
        )

    return app


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
