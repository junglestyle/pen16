"""The compliance intake: the only thing a scanned host can reach. It takes the host's OpenSCAP result and the
remediation playbook the host generated from it, and nothing else."""

import hashlib
import logging
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response, UploadFile
from sqlalchemy import Engine

from pen16 import arf, compliance, db, evidence, tokens
from pen16.db import TokenKind

log = logging.getLogger(__name__)


def create(engine: Engine, evidence_dir: Path) -> FastAPI:
    app = FastAPI(title="pen16 compliance intake", docs_url=None, redoc_url=None)

    def host(authorization: Annotated[str, Header()] = "") -> str:
        """The host a compliance token speaks for. A token can only ever upload for its own host."""
        scheme, _, presented = authorization.partition(" ")
        with engine.begin() as conn:
            token_id = tokens.verify(conn, presented, TokenKind.COMPLIANCE) if scheme.lower() == "bearer" else None
            if token_id is None:
                raise HTTPException(401, "compliance token required")
            return tokens.name(conn, token_id)

    Host = Annotated[str, Depends(host)]

    @app.post("/compliance/v1/results", status_code=201)
    async def upload(
        asset_id: Host, response: Response, result: UploadFile, playbook: UploadFile | None = None
    ) -> dict[str, Any]:
        """Take one gzipped ARF and, optionally, the gzipped playbook `oscap xccdf generate fix` made."""
        try:
            compressed = await result.read()
            raw = evidence.expand(compressed)
            parsed = arf.parse(raw)
            fix = None
            if playbook is not None:
                fix_compressed = await playbook.read()
                fix = (evidence.expand(fix_compressed), fix_compressed)
        except Exception as error:
            log.warning("%s: unusable compliance upload: %s", asset_id, type(error).__name__)
            raise HTTPException(422, "unusable compliance result") from error
        evidence.store(evidence_dir, raw, compressed)
        playbook_digest = None
        if fix is not None:
            evidence.store(evidence_dir, *fix, suffix=".yml.gz")
            playbook_digest = hashlib.sha256(fix[0]).hexdigest()
        try:
            with engine.begin() as conn:
                recorded = compliance.record(conn, asset_id, parsed, parsed.digest, playbook_digest)
        except compliance.StaleResult as error:
            raise HTTPException(409, str(error)) from error
        if recorded.duplicate:
            response.status_code = 200
        log.info(
            "%s: compliance result %s, %s passed, %s failed",
            asset_id,
            recorded.scan_id,
            parsed.passed,
            parsed.failed,
        )
        return {"result": recorded.scan_id, "passed": parsed.passed, "failed": parsed.failed}

    return app


def app() -> FastAPI:
    return create(db.connect(), Path(os.environ.get("PEN16_EVIDENCE_DIR", "/var/lib/pen16/evidence")))
