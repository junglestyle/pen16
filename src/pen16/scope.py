import ipaddress
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


class OutOfScope(ValueError):
    pass


@dataclass(frozen=True)
class Network:
    name: str
    cidr: IPv4Network
    gateway: IPv4Address


@dataclass(frozen=True)
class Scope:
    networks: list[Network]
    exclude: list[IPv4Network]

    def check(self, targets: list[str], exclude: list[str]) -> None:
        """Raise OutOfScope unless every target sits inside a scope network and every exclusion is kept.

        The worker runs this before dispatch and the runner again before nmap starts. The host egress
        policy is the boundary that doesn't depend on either.
        """
        if not targets:
            raise OutOfScope("no targets")
        for target in targets:
            network = _network(target)
            if not any(network.subnet_of(allowed.cidr) for allowed in self.networks):
                raise OutOfScope(f"{target} is outside every scope network")
        kept = {_network(excluded) for excluded in exclude}
        for excluded in self.exclude:
            if excluded not in kept:
                raise OutOfScope(f"exclusion {excluded} is missing")


def parse(networks: list[dict[str, str]], exclude: list[str]) -> Scope:
    return Scope(
        networks=[
            Network(
                name=network["name"],
                cidr=_network(network["cidr"]),
                gateway=IPv4Address(network["gateway"]),
            )
            for network in networks
        ],
        exclude=[_network(excluded) for excluded in exclude],
    )


def _network(value: str) -> IPv4Network:
    try:
        return ipaddress.IPv4Network(value, strict=True)
    except ValueError as error:
        raise OutOfScope(f"{value!r} is not an IPv4 address or network") from error
