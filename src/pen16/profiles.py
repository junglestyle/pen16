from pathlib import Path

NMAP = "/usr/bin/nmap"
NMAP_SERVICES = Path("/usr/share/nmap/nmap-services")

# Where home devices leak over UDP: DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, IKE, SSDP, mDNS, memcached.
NIGHTLY_UDP = [53, 67, 69, 123, 137, 161, 500, 1900, 5353, 11211]
TOP_TCP = 1000
# Internal probe rate, under the 500 packets/s ceiling the host egress policy enforces on the runner's interface.
MAX_RATE = 400


def nightly_argv(targets: list[str], exclude: list[str], extra_tcp: list[int], services: Path) -> list[str]:
    """nmap arguments for the nightly internal scan: top TCP ports plus declared/observed ones, and fixed UDP.

    Arguments are fixed here. Jobs only carry targets, exclusions, and extra port numbers.
    """
    tcp = sorted(set(top_tcp(services, TOP_TCP)) | {port for port in extra_tcp if 0 < port < 65536})
    ports = "T:" + ",".join(map(str, tcp)) + ",U:" + ",".join(map(str, NIGHTLY_UDP))
    argv = [NMAP, "-n", "-sS", "-sU", "-sV", "--version-light", "-T4", "--max-retries", "2"]
    argv += ["--max-rate", str(MAX_RATE), "--host-timeout", "10m", "-p", ports, "-oX", "-"]
    if exclude:
        argv += ["--exclude", ",".join(exclude)]
    return [*argv, "--", *targets]


def sweep_argv(targets: list[str], exclude: list[str], port_from: int, port_to: int) -> list[str]:
    """nmap arguments for one chunk of a rolling full-range sweep: a range of TCP ports on known addresses.

    Light version detection, as nightly does, so an open port found here is named the way the nightly scan names
    it, and a decision on it isn't withdrawn over a guess from nmap's port table. It only probes open ports.
    """
    if not 0 < port_from <= port_to < 65536:
        raise ValueError(f"port range {port_from}-{port_to} is outside 1-65535")
    argv = [NMAP, "-n", "-sS", "-sV", "--version-light", "-T4", "--max-retries", "1"]
    argv += [
        "--max-rate",
        str(MAX_RATE),
        "--host-timeout",
        "20m",
        "-p",
        f"T:{port_from}-{port_to}",
        "-oX",
        "-",
    ]
    if exclude:
        argv += ["--exclude", ",".join(exclude)]
    return [*argv, "--", *targets]


def top_tcp(services: Path, count: int) -> list[int]:
    """The ports nmap's --top-ports would pick, read from its own frequency table."""
    ranked = []
    for line in services.read_text().splitlines():
        fields = line.split()
        if len(fields) < 3 or line.startswith("#"):
            continue
        port, _, protocol = fields[1].partition("/")
        if protocol == "tcp":
            ranked.append((-float(fields[2]), int(port)))
    # nmap breaks frequency ties by file order, which is port order.
    ranked.sort()
    return [port for _, port in ranked[:count]]
