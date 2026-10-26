"""The scanner runner: claims jobs from the listener, runs nmap, and uploads the XML.

It holds no database credentials. It runs nothing until the host has loaded the egress policy into its
network namespace and stamped that namespace into the egress marker (see deploy/pen16-egress).
"""

import gzip
import logging
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from pen16 import config, profiles
from pen16.evidence import MAX_EXPANDED
from pen16.scope import OutOfScope, Scope

log = logging.getLogger(__name__)

IDLE = 30
WAIT_FOR_EGRESS = 5


def egress_ready(marker: Path, process: Path = Path("/proc/1")) -> bool:
    """True once the host has applied egress policy to this container's current network namespace.

    The host stamps the namespace ID and the start time of the container's first process. A restarted
    container starts without the policy, and the kernel can reuse namespace IDs, so the start time is
    what keeps a stale marker from counting.
    """
    try:
        return marker.read_text().strip() == stamp(process)
    except OSError:
        return False


def stamp(process: Path) -> str:
    """The same value pen16-egress writes: the namespace ID, then the start time in clock ticks since boot."""
    fields = (process / "stat").read_text().rpartition(")")[2].split()
    return f"{os.readlink(process / 'ns' / 'net')} {fields[19]}"


def run_forever() -> None:
    scope = config.load().scope
    url = os.environ["PEN16_LISTENER_URL"]
    token = Path(os.environ.get("PEN16_RUNNER_TOKEN_FILE", "/etc/pen16/runner.token")).read_text().strip()
    marker = Path(os.environ.get("PEN16_EGRESS_MARKER", "/run/pen16-egress/ready"))
    with httpx.Client(base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=30) as client:
        waiting = False
        while True:
            if not egress_ready(marker):
                if not waiting:
                    log.warning("waiting for the host to apply egress policy")
                waiting = True
                time.sleep(WAIT_FOR_EGRESS)
                continue
            waiting = False
            response = client.post("/runner/v1/jobs/claim")
            response.raise_for_status()
            if response.status_code == 204:
                time.sleep(IDLE)
                continue
            run_job(client, scope, response.json(), profiles.NMAP_SERVICES)


def run_job(client: httpx.Client, scope: Scope, job: dict[str, Any], services: Path) -> None:
    job_id = job["id"]
    log.info("running job %s", job_id)
    try:
        if job["profile"] != "nightly":
            raise OutOfScope(f"unknown profile {job['profile']!r}")
        scope.check(job["targets"], job["exclude"])
        argv = profiles.nightly_argv(job["targets"], job["exclude"], job["extra_tcp"], services)
        deadline = datetime.fromisoformat(job["deadline_at"])
        xml = scan(argv, (deadline - datetime.now(UTC)).total_seconds())
    except (OutOfScope, ScanFailed) as error:
        log.warning("job %s failed: %s", job_id, error)
        client.post(f"/runner/v1/jobs/{job_id}/failure", json={"error": str(error)})
        return
    client.post(f"/runner/v1/jobs/{job_id}/result", content=gzip.compress(xml)).raise_for_status()
    log.info("job %s uploaded", job_id)


class ScanFailed(Exception):
    pass


def scan(argv: list[str], timeout: float) -> bytes:
    """Run nmap with a fixed argument list, no shell, a deadline, and bounded output."""
    if timeout <= 0:
        raise ScanFailed("deadline already passed")
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, check=False, shell=False)  # noqa: S603
    except subprocess.TimeoutExpired as error:
        raise ScanFailed("nmap ran past the job deadline") from error
    if done.returncode != 0:
        raise ScanFailed(f"nmap exited {done.returncode}: {done.stderr.decode(errors='replace')[-300:]}")
    if len(done.stdout) > MAX_EXPANDED:
        raise ScanFailed("nmap output is over the upload limit")
    return done.stdout
