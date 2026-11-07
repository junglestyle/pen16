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
            token_id = (
                tokens.verify(conn, presented, TokenKind.COMPLIANCE) if scheme.lower() == "bearer" else None
            )
            if token_id is None:
                raise HTTPException(401, "compliance token required")
            return tokens.name(conn, token_id)

    Host = Annotated[str, Depends(host)]  # noqa: N806  # a type alias, named like one

    @app.post("/compliance/v1/results", status_code=201)
    def upload(
        asset_id: Host, response: Response, result: UploadFile, playbook: UploadFile | None = None
    ) -> dict[str, Any]:
        """Take one gzipped ARF and, optionally, the gzipped playbook `oscap xccdf generate fix` made. The upload
        is already spooled to a size-capped /tmp; reading stops at the upload limit."""
        try:
            compressed = _bounded(result)
            parsed = arf.parse(evidence.expand(compressed))
            fix = None
            if playbook is not None:
                fix_compressed = _bounded(playbook)
                fix = (hashlib.sha256(evidence.expand(fix_compressed)).hexdigest(), fix_compressed)
        except Exception as error:
            log.warning("%s: unusable compliance upload: %s", asset_id, type(error).__name__)
            raise HTTPException(422, "unusable compliance result") from error
        evidence.store(evidence_dir, parsed.digest, compressed)
        playbook_digest = None
        if fix is not None:
            playbook_digest, fix_compressed = fix
            evidence.store(evidence_dir, playbook_digest, fix_compressed, suffix=".yml.gz")
        try:
            with engine.begin() as conn:
                recorded = compliance.record(conn, asset_id, parsed, parsed.digest, playbook_digest)
        except compliance.StaleResultError as error:
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


def _bounded(upload: UploadFile) -> bytes:
    data = upload.file.read(evidence.MAX_COMPRESSED + 1)
    if len(data) > evidence.MAX_COMPRESSED:
        raise evidence.TooLargeError(f"upload is larger than {evidence.MAX_COMPRESSED} bytes")
    return data


def app() -> FastAPI:
    return create(db.connect(), Path(os.environ.get("PEN16_EVIDENCE_DIR", "/var/lib/pen16/evidence")))
