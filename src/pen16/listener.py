"""The runner listener: the only API a runner can reach. It hands out jobs and takes their results."""

import logging
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy import Engine

from pen16 import config, db, evidence, jobs, neighbours, nmap, tokens
from pen16.config import Config
from pen16.db import TokenKind

log = logging.getLogger(__name__)


class Failure(BaseModel):
    error: str


def create(engine: Engine, settings: Config, evidence_dir: Path, neighbours_file: Path) -> FastAPI:
    app = FastAPI(title="pen16 runner listener", docs_url=None, redoc_url=None)

    def runner(authorization: Annotated[str, Header()] = "") -> str:
        scheme, _, presented = authorization.partition(" ")
        with engine.begin() as conn:
            runner_id = (
                tokens.verify(conn, presented, TokenKind.RUNNER) if scheme.lower() == "bearer" else None
            )
        if runner_id is None:
            raise HTTPException(401, "runner token required")
        return runner_id

    Runner = Annotated[str, Depends(runner)]  # noqa: N806  # a type alias, named like one

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
        """Receive the gzipped XML here, on the event loop, and stop reading at the upload limit. Parsing,
        storing and recording are blocking work, so they run in a worker thread."""
        try:
            compressed = await evidence.receive(request.stream())
        except evidence.TooLargeError as error:
            await run_in_threadpool(_fail, engine, job_id, runner_id, "scan output over the upload limit")
            raise HTTPException(413, "scan output over the upload limit") from error
        await run_in_threadpool(
            _record, engine, settings, evidence_dir, neighbours_file, job_id, runner_id, compressed
        )

    @app.post("/runner/v1/jobs/{job_id}/failure", status_code=204)
    def failure(job_id: int, body: Failure, runner_id: Runner) -> None:
        _fail(engine, job_id, runner_id, body.error[:500])

    return app


def _record(
    engine: Engine,
    settings: Config,
    evidence_dir: Path,
    neighbours_file: Path,
    job_id: int,
    runner_id: str,
    compressed: bytes,
) -> None:
    try:
        scan = nmap.parse(evidence.expand(compressed))
    except Exception as error:
        # Hostile or broken output is the runner's failure, not ours: record it and retry the job.
        log.warning("job %s: unusable upload: %s", job_id, type(error).__name__)
        _fail(engine, job_id, runner_id, f"unusable scan output: {type(error).__name__}")
        raise HTTPException(422, "unusable scan output") from error
    evidence.store(evidence_dir, scan.digest, compressed)
    seen = neighbours.read(neighbours_file)
    try:
        with engine.begin() as conn:
            opened = jobs.complete(conn, job_id, runner_id, scan, settings.scope, seen)
    except jobs.StaleJobError as error:
        raise HTTPException(409, str(error)) from error
    log.info("job %s succeeded: %s hosts, %s new findings", job_id, len(scan.hosts), len(opened))


def _fail(engine: Engine, job_id: int, runner_id: str, error: str) -> None:
    try:
        with engine.begin() as conn:
            jobs.fail(conn, job_id, runner_id, error)
    except jobs.StaleJobError as stale:
        raise HTTPException(409, str(stale)) from stale


def app() -> FastAPI:
    return create(
        db.connect(),
        config.load(),
        Path(os.environ.get("PEN16_EVIDENCE_DIR", "/var/lib/pen16/evidence")),
        neighbours.path(),
    )
