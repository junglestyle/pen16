"""What each scan covered, which known devices didn't answer, and the rolling full-range TCP sweep.

A sweep covers a network's 65,535 TCP ports in BLOCKS blocks, a few at a time on the network's known addresses,
in chunks that fit a job's deadline at the runner's probe rate. The worker queues the stalest blocks next, paced so
a full sweep finishes inside FRESH. A chunk counts only if the network's gateway answered: without it, a closed
port can't be told from a network that was down.
"""

import ipaddress
import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Row, Text, cast, func, select
from sqlalchemy.dialects.postgresql import insert

from pen16 import db, notify, profiles
from pen16.db import Profile, bindings, coverage, jobs, sweep_blocks, unavailable
from pen16.nmap import Scan
from pen16.scope import Network, Scope

BLOCK = 1024
BLOCKS = 64
# How old a network's least recently swept block may get.
FRESH = timedelta(days=7)
# Pace sweeps to finish in this share of FRESH, leaving room for failed chunks and nightly scans.
PACE = 0.8
# Address-port pairs one chunk may scan: a quarter-hour at the probe ceiling, at two probes a port, inside the
# half-hour job deadline.
CHUNK_PAIRS = profiles.MAX_RATE * 15 * 60 // 2


def block_ports(block: int) -> tuple[int, int]:
    """The first and last TCP port of a block. Port 0 isn't scanned."""
    return max(1, block * BLOCK), min(65535, (block + 1) * BLOCK - 1)


@dataclass(frozen=True)
class Chunk:
    network: str
    targets: list[str]
    port_from: int
    port_to: int


def next_chunk(conn: Connection, scope: Scope, now: datetime) -> Chunk | None:
    """The next sweep chunk due, for the network whose sweep is stalest, or None while every network is on pace."""
    due = []
    for network in scope.networks:
        targets = sorted({str(network.gateway)} | {a for a, _ in known(conn, network, scope)}, key=_ip)
        per_chunk = max(1, min(BLOCKS, CHUNK_PAIRS // (len(targets) * BLOCK)))
        last = conn.scalar(
            select(func.max(jobs.c.created_at)).where(
                jobs.c.profile == Profile.SWEEP, jobs.c.network == network.name
            )
        )
        if last is not None and now - last < FRESH * PACE / math.ceil(BLOCKS / per_chunk):
            continue
        swept = _swept(conn, network.name)
        # Never-swept blocks first, lowest first; then the least recently swept.
        start = min(range(BLOCKS), key=lambda b: (b in swept, swept.get(b, now), b))
        end = min(BLOCKS - 1, start + per_chunk - 1)
        stalest = swept.get(start)
        due.append((stalest is not None, stalest or now, Chunk(network.name, targets, *_span(start, end))))
    if not due:
        return None
    return min(due, key=lambda d: (d[0], d[1]))[2]


def record(conn: Connection, job: Row[Any], scan: Scan, scope: Scope) -> None:
    """Record what a finished job covered in each network it scanned, the known devices that didn't answer, and
    for a sweep chunk whose gateway answered, the blocks it swept."""
    up = scan.up()
    for network in scope.networks:
        if job.profile == Profile.SWEEP and job.network != network.name:
            continue
        gateway_up = str(network.gateway) in up
        conn.execute(
            insert(coverage).values(
                job_id=job.id,
                network=network.name,
                profile=job.profile,
                gateway_up=gateway_up,
                hosts_up=sum(1 for address in up if _ip(address) in network.cidr),
                tcp_ports=scan.scanned.get("tcp", 0),
                udp_ports=scan.scanned.get("udp", 0),
                port_from=job.port_from,
                port_to=job.port_to,
            )
        )
        targeted = set(job.targets) if job.profile == Profile.SWEEP else None
        missing = [
            {"job_id": job.id, "network": network.name, "address": address, "asset_id": asset_id}
            for address, asset_id in known(conn, network, scope)
            if address not in up and (targeted is None or address in targeted)
        ]
        if missing:
            conn.execute(insert(unavailable).values(missing))
        if job.profile == Profile.SWEEP and gateway_up:
            covered = [
                b
                for b in range(BLOCKS)
                if job.port_from <= block_ports(b)[0] <= block_ports(b)[1] <= job.port_to
            ]
            if covered:
                rows = [
                    {"network": network.name, "block": b, "swept_at": func.now(), "job_id": job.id}
                    for b in covered
                ]
                statement = insert(sweep_blocks).values(rows)
                conn.execute(
                    statement.on_conflict_do_update(
                        index_elements=["network", "block"],
                        set_={"swept_at": statement.excluded.swept_at, "job_id": statement.excluded.job_id},
                    )
                )


@dataclass(frozen=True)
class Sweep:
    """How far a network's rolling sweep has got: blocks ever swept, and the age of the least recently swept one
    once every block has been swept at least once."""

    network: str
    swept: int
    oldest: datetime | None
    stale: bool

    @property
    def complete(self) -> bool:
        return self.swept == BLOCKS


def sweep(conn: Connection, network: str, now: datetime) -> Sweep:
    swept = _swept(conn, network)
    oldest = min(swept.values()) if len(swept) == BLOCKS else None
    if oldest is not None:
        stale = now - oldest > FRESH
    else:
        # Not yet swept in full: stale once its first chunk is older than a whole sweep should take.
        first = conn.scalar(
            select(func.min(jobs.c.created_at)).where(
                jobs.c.profile == Profile.SWEEP, jobs.c.network == network
            )
        )
        stale = first is not None and now - first > FRESH
    return Sweep(network, len(swept), oldest, stale)


def check(conn: Connection, scope: Scope) -> None:
    """Open one incident per network whose full sweep has gone stale, and clear it once the sweep is fresh."""
    now = db.now(conn)
    for network in scope.networks:
        key = f"sweep:{network.name}"
        if sweep(conn, network.name, now).stale:
            notify.raise_incident(
                conn,
                key,
                f"Full sweeps of {network.name} are behind",
                f"Part of {network.cidr}'s TCP ports hasn't been swept in {FRESH.days} days: sweep jobs are failing "
                "or never get a turn.",
            )
        else:
            notify.clear_incident(
                conn,
                key,
                f"Full sweeps of {network.name} caught up",
                f"All of {network.cidr} swept within {FRESH.days} days.",
            )


def known(conn: Connection, network: Network, scope: Scope) -> list[tuple[str, str]]:
    """The bound addresses in a network, with their devices, leaving out excluded ones."""
    rows = conn.execute(
        select(cast(func.host(bindings.c.address), Text).label("address"), bindings.c.asset_id).order_by(
            bindings.c.address
        )
    )
    return [
        (row.address, row.asset_id)
        for row in rows
        if _ip(row.address) in network.cidr
        and not any(_ip(row.address) in excluded for excluded in scope.exclude)
    ]


def _swept(conn: Connection, network: str) -> dict[int, datetime]:
    rows: Iterable[Row[Any]] = conn.execute(
        select(sweep_blocks.c.block, sweep_blocks.c.swept_at).where(sweep_blocks.c.network == network)
    )
    return {row.block: row.swept_at for row in rows}


def _span(start: int, end: int) -> tuple[int, int]:
    return block_ports(start)[0], block_ports(end)[1]


def _ip(address: str) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(address)
