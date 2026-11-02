import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from pen16 import scope
from pen16.scope import Scope


@dataclass(frozen=True)
class Config:
    """Deployment-owned settings, rendered by the deployment repository. The dashboard can't change them."""

    scope: Scope
    owner_login: str
    dashboard_url: str


def load() -> Config:
    path = Path(os.environ.get("PEN16_CONFIG", "/etc/pen16/pen16.toml"))
    try:
        with path.open("rb") as file:
            raw = tomllib.load(file)
    except FileNotFoundError:
        raise SystemExit(f"{str(path)!r} doesn't exist: set PEN16_CONFIG (see examples/pen16.toml)") from None
    except tomllib.TOMLDecodeError as error:
        raise SystemExit(f"{str(path)!r} isn't valid TOML: {error}") from None
    if "networks" not in raw:
        raise SystemExit(f"{str(path)!r} has no networks (see examples/pen16.toml)")
    return Config(
        scope=scope.parse(raw["networks"], raw.get("exclude", [])),
        owner_login=raw.get("owner_login", ""),
        dashboard_url=raw.get("dashboard_url", ""),
    )
