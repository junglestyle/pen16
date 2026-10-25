import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from defusedxml import ElementTree

PARSER_VERSION = "1"
MAX_XML_BYTES = 250 * 1024 * 1024

# open|filtered is what UDP reports for silence. pen15 can't tell it from a drop, so it stays filtered.
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
class Scan:
    nmap_version: str
    finished_at: datetime
    digest: str
    ports: list[Port]


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
    for host in root.iter("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue
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
    )
