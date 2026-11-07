"""MAC addresses the scanner host learned while forwarding the runner's traffic.

The runner reaches targets through the host's NAT, so nmap never sees a target's MAC. The host's kernel does: to
deliver a packet to an address on its own segment, it resolves that address's MAC and keeps it in its neighbour
table. deploy/pen16-neighbours writes that table to a file whenever it changes, and the listener reads it when a
scan result arrives. Only addresses on the scanner host's own segment have one; a routed network's are behind its
router.
"""

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path

log = logging.getLogger(__name__)

MAX_BYTES = 4 * 1024 * 1024
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
# Entries the kernel never resolved, or gave up on, hold no usable MAC.
UNRESOLVED = {"FAILED", "INCOMPLETE", "NOARP"}
# nmap's list of manufacturer prefixes, in the image with nmap.
VENDORS = Path("/usr/share/nmap/nmap-mac-prefixes")


@dataclass(frozen=True)
class Neighbour:
    mac: str
    confirmed_at: datetime


def path() -> Path:
    return Path(os.environ.get("PEN16_NEIGHBOURS", "/run/pen16-neighbours/neighbours.json"))


def read(file: Path) -> dict[str, Neighbour]:
    """Each IPv4 address's MAC and when the kernel last confirmed it. Empty when there's no usable snapshot:
    a scan records no MACs then, but nothing else changes."""
    try:
        if file.stat().st_size > MAX_BYTES:
            log.warning("%s is over %s bytes; recording no MACs", file, MAX_BYTES)
            return {}
        snapshot = json.loads(file.read_bytes())
        taken_at = datetime.fromtimestamp(int(snapshot["taken_at"]), UTC)
        entries = snapshot["neighbours"]
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, KeyError, TypeError) as error:
        log.warning("%s is unusable (%s); recording no MACs", file, type(error).__name__)
        return {}
    found = {}
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or UNRESOLVED & set(entry.get("state", [])):
            continue
        mac = str(entry.get("lladdr", "")).lower()
        confirmed = entry.get("confirmed")
        if not MAC.fullmatch(mac) or not isinstance(confirmed, int) or "." not in str(entry.get("dst", "")):
            continue
        found[str(entry["dst"])] = Neighbour(mac, taken_at - timedelta(seconds=confirmed))
    return found


def is_private(mac: str) -> bool:
    """A locally administered MAC: one a phone or laptop made up for privacy, and may make up again."""
    return bool(int(mac[:2], 16) & 0b10)


def vendor(mac: str) -> str | None:
    """Who made the device, from the MAC's prefix. A private MAC names no manufacturer."""
    if is_private(mac):
        return "private address"
    return _vendors().get(mac.replace(":", "")[:6].upper())


@cache
def _vendors() -> dict[str, str]:
    try:
        lines = VENDORS.read_text(errors="replace").splitlines()
    except OSError:
        return {}
    return {line[:6]: line[7:].strip() for line in lines if len(line) > 7 and not line.startswith("#")}
