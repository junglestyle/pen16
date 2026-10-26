import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

PARSER_VERSION = "2"
MAX_XML_BYTES = 250 * 1024 * 1024

# open|filtered is what UDP reports for silence. pen16 can't tell it from a drop, so it stays filtered.
STATES = {
    "open": "open",
    "closed": "closed",
    "filtered": "filtered",
    "open|filtered": "filtered",
    "closed|filtered": "filtered",
}


@dataclass(frozen=True)
class Port:
    address: str
    protocol: str
    port: int
    state: str
    service: str | None
    product: str | None
    version: str | None


@dataclass(frozen=True)
class Host:
    address: str
    up: bool
    # Ports nmap folded into <extraports>, as (protocol, port) -> state. Closed ports usually land here.
    unlisted: dict[tuple[str, int], str]


@dataclass(frozen=True)
class Scan:
    nmap_version: str
    finished_at: datetime
    digest: str
    ports: list[Port]
    hosts: list[Host]

    def state(self, address: str, protocol: str, port: int) -> str | None:
        """What this scan saw on one port, or None when it didn't cover it."""
        for listed in self.ports:
            if (listed.address, listed.protocol, listed.port) == (address, protocol, port):
                return listed.state
        for host in self.hosts:
            if host.address == address:
                return host.unlisted.get((protocol, port))
        return None


def read(path: Path) -> Scan:
    if path.stat().st_size > MAX_XML_BYTES:
        raise ValueError(f"{path} is larger than {MAX_XML_BYTES} bytes")
    return parse(path.read_bytes())


def parse(raw: bytes) -> Scan:
    root = ElementTree.fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError(f"expected nmaprun, got {root.tag}")
    finished = root.find("runstats/finished")
    if finished is None:
        raise ValueError("scan has no runstats/finished: nmap didn't complete")

    ports = []
    hosts = []
    for host in root.iter("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue
        status = host.find("status")
        hosts.append(
            Host(
                address=address.attrib["addr"],
                up=status is not None and status.get("state") == "up",
                unlisted=_unlisted(host),
            )
        )
        for port in host.iter("port"):
            state = port.find("state")
            service = port.find("service")
            if state is None:
                raise ValueError(f"port {port.get('portid')} on {address.get('addr')} has no state")
            ports.append(
                Port(
                    address=address.attrib["addr"],
                    protocol=port.attrib["protocol"],
                    port=int(port.attrib["portid"]),
                    state=STATES[state.attrib["state"]],
                    service=None if service is None else service.get("name"),
                    product=None if service is None else service.get("product"),
                    version=None if service is None else service.get("version"),
                )
            )

    return Scan(
        nmap_version=root.attrib["version"],
        finished_at=datetime.fromtimestamp(int(finished.attrib["time"]), UTC),
        digest=hashlib.sha256(raw).hexdigest(),
        ports=ports,
        hosts=hosts,
    )


def _unlisted(host: Any) -> dict[tuple[str, int], str]:
    unlisted = {}
    for extra in host.iter("extraports"):
        state = STATES[extra.attrib["state"]]
        # nmap 7.92+ names the folded ports; without that, coverage is unknown and nothing gets closed.
        for reasons in extra.iter("extrareasons"):
            protocol = reasons.get("proto")
            for port in _expand(reasons.get("ports", "")):
                if protocol:
                    unlisted[(protocol, port)] = state
    return unlisted


def _expand(ports: str) -> list[int]:
    expanded: list[int] = []
    for part in filter(None, ports.split(",")):
        first, _, last = part.partition("-")
        expanded.extend(range(int(first), int(last or first) + 1))
    return expanded
