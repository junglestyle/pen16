import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from pen15 import scope
from pen15.scope import Scope


@dataclass(frozen=True)
class Config:
    """Deployment-owned settings, rendered by the deployment repository. The dashboard can't change them."""

    scope: Scope
    owner_login: str
    dashboard_url: str


def load() -> Config:
    path = Path(os.environ.get("PEN15_CONFIG", "/etc/pen15/pen15.toml"))
    with path.open("rb") as file:
        raw = tomllib.load(file)
    return Config(
        scope=scope.parse(raw["networks"], raw.get("exclude", [])),
        owner_login=raw.get("owner_login", ""),
        dashboard_url=raw.get("dashboard_url", ""),
    )
