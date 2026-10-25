"""The runner listener: the only API a runner can reach. It hands out jobs and takes their results."""

import logging
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import Engine

from pen15 import config, db, evidence, jobs, nmap, tokens
from pen15.config import Config

log = logging.getLogger(__name__)


class Failure(BaseModel):
    error: str


def create(engine: Engine, settings: Config, evidence_dir: Path) -> FastAPI:
    app = FastAPI(title="pen15 runner listener", docs_url=None, redoc_url=None)

    def runner(authorization: Annotated[str, Header()] = "") -> str:
        scheme, _, presented = authorization.partition(" ")
        with engine.begin() as conn:
            runner_id = tokens.verify(conn, presented, "runner") if scheme.lower() == "bearer" else None
        if runner_id is None:
            raise HTTPException(401, "runner token required")
        return runner_id

    Runner = Annotated[str, Depends(runner)]

    @app.post("/runner/v1/jobs/claim", response_model=None)
    def claim(runner_id: Runner) -> dict[str, Any] | Response:
        with engine.begin() as conn:
            job = jobs.claim(conn, runner_id)
        if job is None:
            return Response(status_code=204)
        log.info("runner %s claimed job %s", runner_id, job.id)
        return {
            "id": job.id,
            "profile": job.profile,
            "targets": job.targets,
            "exclude": job.exclude,
            "extra_tcp": job.extra_tcp,
            "deadline_at": job.deadline_at.isoformat(),
        }

    @app.post("/runner/v1/jobs/{job_id}/result", status_code=204)
    async def result(job_id: int, request: Request, runner_id: Runner) -> None:
        compressed = await request.body()
        try:
            raw = evidence.expand(compressed)
            scan = nmap.parse(raw)
        except Exception as error:
            # Hostile or broken output is the runner's failure, not ours: record it and retry the job.
            log.warning("job %s: unusable upload: %s", job_id, type(error).__name__)
            _fail(engine, job_id, runner_id, f"unusable scan output: {type(error).__name__}")
            raise HTTPException(422, "unusable scan output") from error
        evidence.store(evidence_dir, raw, compressed)
        try:
            with engine.begin() as conn:
                opened = jobs.complete(conn, job_id, runner_id, scan, settings.scope)
        except jobs.StaleJob as error:
            raise HTTPException(409, str(error)) from error
        log.info("job %s succeeded: %s hosts, %s new findings", job_id, len(scan.hosts), len(opened))

    @app.post("/runner/v1/jobs/{job_id}/failure", status_code=204)
    def failure(job_id: int, body: Failure, runner_id: Runner) -> None:
        _fail(engine, job_id, runner_id, body.error[:500])

    return app


def _fail(engine: Engine, job_id: int, runner_id: str, error: str) -> None:
    try:
        with engine.begin() as conn:
            jobs.fail(conn, job_id, runner_id, error)
    except jobs.StaleJob as stale:
        raise HTTPException(409, str(stale)) from stale


def app() -> FastAPI:
    return create(
        db.connect(), config.load(), Path(os.environ.get("PEN15_EVIDENCE_DIR", "/var/lib/pen15/evidence"))
    )
