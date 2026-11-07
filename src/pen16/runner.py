"""The scanner runner: claims jobs from the listener, runs nmap, and uploads the XML.

It holds no database credentials. It runs nothing until the host has loaded the egress policy into its
network namespace and stamped that namespace into the egress marker (see deploy/pen16-egress).
"""

import gzip
import logging
import os
import signal
import subprocess
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

import httpx

from pen16 import config, profiles
from pen16.db import Profile
from pen16.evidence import MAX_COMPRESSED, MAX_EXPANDED
from pen16.scope import OutOfScopeError, Scope

log = logging.getLogger(__name__)

IDLE = 30
WAIT_FOR_EGRESS = 5
CHUNK = 64 * 1024
# How much of nmap's stderr a failed job reports.
ERROR_TAIL = 300


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
    return f"{(process / 'ns' / 'net').readlink()} {fields[19]}"


def run_forever() -> None:
    stop = threading.Event()
    # SIGTERM stops claiming. A scan in progress runs until compose's stop timeout kills the container, and
    # the listener retries that job when this runner next claims.
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    scope = config.load().scope
    url = os.environ.get("PEN16_LISTENER_URL")
    if not url:
        raise SystemExit("PEN16_LISTENER_URL is not set (deploy/compose.yaml sets it for the runner)")
    token = Path(os.environ.get("PEN16_RUNNER_TOKEN_FILE", "/etc/pen16/runner.token")).read_text().strip()
    marker = Path(os.environ.get("PEN16_EGRESS_MARKER", "/run/pen16-egress/ready"))
    with httpx.Client(base_url=url, headers={"Authorization": f"Bearer {token}"}, timeout=30) as client:
        waiting = False
        while not stop.is_set():
            if not egress_ready(marker):
                if not waiting:
                    log.warning("waiting for the host to apply egress policy")
                waiting = True
                stop.wait(WAIT_FOR_EGRESS)
                continue
            waiting = False
            response = client.post("/runner/v1/jobs/claim")
            response.raise_for_status()
            if response.status_code == 204:
                stop.wait(IDLE)
                continue
            run_job(client, scope, response.json(), profiles.NMAP_SERVICES)


def run_job(client: httpx.Client, scope: Scope, job: dict[str, Any], services: Path) -> None:
    job_id = job["id"]
    log.info("running job %s", job_id)
    try:
        compressed = _scanned(scope, job, services)
    except (OutOfScopeError, ScanFailedError) as error:
        log.warning("job %s failed: %s", job_id, error)
        reported = client.post(f"/runner/v1/jobs/{job_id}/failure", json={"error": str(error)})
        if reported.is_error:
            log.warning("job %s: the listener refused its failure: HTTP %s", job_id, reported.status_code)
        return
    client.post(f"/runner/v1/jobs/{job_id}/result", content=compressed).raise_for_status()
    log.info("job %s uploaded", job_id)


def _scanned(scope: Scope, job: dict[str, Any], services: Path) -> bytes:
    """The job's scan output, gzipped for upload. Raises OutOfScopeError or ScanFailedError."""
    deadline = datetime.fromisoformat(job["deadline_at"])
    compressed = gzip.compress(
        scan(_argv(scope, job, services), (deadline - datetime.now(UTC)).total_seconds())
    )
    if len(compressed) > MAX_COMPRESSED:
        raise ScanFailedError("nmap output is over the upload limit")
    return compressed


def _argv(scope: Scope, job: dict[str, Any], services: Path) -> list[str]:
    """The fixed nmap command for the job's profile, or OutOfScopeError if the job asks for anything else."""
    scope.check(job["targets"], job["exclude"])
    if job["profile"] == Profile.NIGHTLY:
        return profiles.nightly_argv(job["targets"], job["exclude"], job["extra_tcp"], services)
    if job["profile"] == Profile.SWEEP:
        port_from, port_to = job.get("port_from"), job.get("port_to")
        if not (isinstance(port_from, int) and isinstance(port_to, int)):
            raise OutOfScopeError("a sweep needs a whole-number port range")
        try:
            return profiles.sweep_argv(job["targets"], job["exclude"], port_from, port_to)
        except ValueError as error:
            raise OutOfScopeError(str(error)) from error
    raise OutOfScopeError(f"unknown profile {job['profile']!r}")


class ScanFailedError(Exception):
    """nmap couldn't produce a usable result for the job: the job fails, and the listener may retry it."""


def scan(argv: list[str], timeout: float) -> bytes:
    """Run nmap with a fixed argument list and no shell, killing it at the deadline or as soon as its output
    passes the upload limit, so neither its runtime nor this process's memory can grow without bound."""
    if timeout <= 0:
        raise ScanFailedError("deadline already passed")
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False) as nmap:
        stdout, stderr = nmap.stdout, nmap.stderr
        if stdout is None or stderr is None:
            raise RuntimeError("nmap's output isn't piped")
        expired = threading.Event()

        def expire() -> None:
            expired.set()
            nmap.kill()

        timer = threading.Timer(timeout, expire)
        errors = bytearray()
        drain = threading.Thread(target=_tail, args=(stderr, errors), daemon=True)
        timer.start()
        drain.start()
        output = bytearray()
        try:
            while chunk := stdout.read(CHUNK):
                output += chunk
                if len(output) > MAX_EXPANDED:
                    nmap.kill()
                    raise ScanFailedError("nmap output is over the upload limit")
            returncode = nmap.wait()
        finally:
            timer.cancel()
            drain.join()
    if expired.is_set():
        raise ScanFailedError("nmap ran past the job deadline")
    if returncode != 0:
        raise ScanFailedError(f"nmap exited {returncode}: {errors.decode(errors='replace')}")
    return bytes(output)


def _tail(stream: IO[bytes], kept: bytearray) -> None:
    """Read a stream to its end, keeping its last ERROR_TAIL bytes."""
    while chunk := stream.read(CHUNK):
        kept += chunk
        del kept[:-ERROR_TAIL]
