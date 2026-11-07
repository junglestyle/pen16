"""The owner dashboard. tailscale serve puts it on the tailnet and names the visitor in a header."""

import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import StrictUndefined
from sqlalchemy import Engine, exists, select

from pen16 import compliance, config, db, evidence, exposure, jobs, neighbours, notify, status
from pen16.config import Config
from pen16.db import (
    BindingChange,
    DecisionKind,
    FindingStatus,
    JobStatus,
    ObservationState,
    Profile,
    RuleResult,
    Severity,
    observations,
)


def _asset_url(asset_id: str) -> str:
    return f"/assets/{quote(asset_id, safe='')}"


templates = Jinja2Templates(directory=str(files("pen16") / "templates"))
# A field a record doesn't have is a bug, not an empty cell.
templates.env.undefined = StrictUndefined
# The template compares states by name, not by quoted string.
templates.env.globals.update(
    BindingChange=BindingChange,
    DecisionKind=DecisionKind,
    Difference=status.Difference,
    FindingStatus=FindingStatus,
    JobStatus=JobStatus,
    ObservationState=ObservationState,
    RuleResult=RuleResult,
    Severity=Severity,
    asset_url=_asset_url,
    vendor=neighbours.vendor,
)
# An evidence file's name: its SHA-256.
DIGEST = re.compile(r"[0-9a-f]{64}")


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

    @app.get("/assets/{asset_id}", response_class=HTMLResponse)
    def asset_page(request: Request, login: Owner, asset_id: str) -> HTMLResponse:
        with engine.connect() as conn:
            device = status.asset(conn, asset_id)
            if device is None:
                raise HTTPException(404, f"there's no device {asset_id!r}")
            others = [d.id for d in status.devices(conn) if d.id != asset_id]
        return templates.TemplateResponse(
            request, "asset.html", {"owner": login, "a": device, "others": others}
        )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_page(request: Request, login: Owner, finding_id: int) -> HTMLResponse:
        with engine.connect() as conn:
            found = status.finding(conn, finding_id)
        if found is None:
            raise HTTPException(404, f"there's no finding {finding_id}")
        return templates.TemplateResponse(request, "finding.html", {"owner": login, "f": found})

    @app.get("/changes", response_class=HTMLResponse)
    def changes_page(request: Request, login: Owner) -> HTMLResponse:
        with engine.connect() as conn:
            changes = status.recent_changes(conn)
        return templates.TemplateResponse(request, "changes.html", {"owner": login, "c": changes})

    @app.get("/evidence/{digest}.xml")
    def raw_scan(_login: Owner, digest: str) -> Response:
        """A scan's nmap XML, as the runner sent it. Only digests an observation names are served."""
        with engine.connect() as conn:
            known = DIGEST.fullmatch(digest) and conn.scalar(
                select(exists().where(observations.c.evidence_digest == digest))
            )
        if not known:
            raise HTTPException(404, "no such scan")
        try:
            raw = evidence.read(evidence_dir, digest)
        except FileNotFoundError as error:
            raise HTTPException(404, "this scan's raw evidence is no longer kept") from error
        return Response(raw, media_type="application/xml", headers=_download(f"{digest}.xml"))

    # The device forms are on the dashboard and on the device's own page. One posted from the device's page
    # sends `back` with that page's URL and returns there; any other value returns to the dashboard.
    @app.post("/assets/name")
    def name_asset(
        login: Owner,
        provisional_id: Annotated[str, Form()],
        asset_id: Annotated[str, Form()],
        back: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.name_asset(conn, provisional_id, asset_id, login)
        # The device's page is under its new name now.
        return _back(_asset_url(asset_id) if back == _asset_url(provisional_id) else "/#devices")

    @app.post("/assets/separate")
    def separate(
        _login: Owner, provisional_id: Annotated[str, Form()], back: Annotated[str, Form()] = ""
    ) -> RedirectResponse:
        with engine.begin() as conn:
            exposure.separate(conn, provisional_id)
        return _back(_returning(back, _asset_url(provisional_id)))

    @app.post("/assets/retire")
    def retire(
        login: Owner,
        asset_id: Annotated[str, Form()],
        reason: Annotated[str, Form()],
        back: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.retire(conn, asset_id, reason, login)
        return _back(_returning(back, _asset_url(asset_id)))

    @app.post("/assets/move")
    def move(
        login: Owner,
        address: Annotated[str, Form()],
        asset_id: Annotated[str, Form()],
        reason: Annotated[str, Form()],
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            exposure.move(conn, address, asset_id, reason, login)
        return _back(_asset_url(asset_id))

    @app.post("/compliance/waive")
    def waive(
        login: Owner,
        asset_id: Annotated[str, Form()],
        rule_id: Annotated[str, Form()],
        reason: Annotated[str, Form()],
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            compliance.waive(conn, asset_id, rule_id, reason, login)
        return _back("/#compliance")

    @app.post("/compliance/unwaive")
    def unwaive(
        login: Owner,
        asset_id: Annotated[str, Form()],
        rule_id: Annotated[str, Form()],
        reason: Annotated[str, Form()],
    ) -> RedirectResponse:
        with _refusing(), engine.begin() as conn:
            compliance.unwaive(conn, asset_id, rule_id, reason, login)
        return _back("/#compliance")

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

    @app.get("/compliance/{scan_id}/playbook-without-waived.yml")
    def playbook_without_waived(_login: Owner, scan_id: int) -> Response:
        try:
            with engine.connect() as conn:
                name, digest = compliance.playbook(conn, scan_id)
                waived = [rule.rule_id for rule in compliance.failing(conn, scan_id) if rule.waiver]
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        try:
            cut = compliance.without_waived(evidence.read(evidence_dir, digest, ".yml.gz").decode(), waived)
        except ValueError as error:
            raise HTTPException(
                422,
                f"can't take the waived rules' tasks out ({error}): download the full playbook and skip them "
                "with --skip-tags",
            ) from error
        return Response(
            cut,
            media_type="text/plain; charset=utf-8",
            headers=_download(name.removesuffix(".yml") + "-without-waived.yml"),
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


def _back(to: str = "/") -> RedirectResponse:
    return RedirectResponse(to, status_code=303)


def _returning(back: str, page: str) -> str:
    """`page` if the form came from it, else the dashboard's devices."""
    return page if back == page else "/#devices"


def _download(name: str) -> dict[str, str]:
    return {"Content-Disposition": f'attachment; filename="{name}"'}


def app() -> FastAPI:
    return create(
        db.connect(), config.load(), Path(os.environ.get("PEN16_EVIDENCE_DIR", "/var/lib/pen16/evidence"))
    )
