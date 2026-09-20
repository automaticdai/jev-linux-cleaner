"""The scan surface, loaded from YAML."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import Scope

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config" / "roots.yaml"


@dataclass(frozen=True)
class Root:
    path: str
    scope: Scope
    max_depth: int


def _expand(raw: str, home: str) -> str:
    if raw.startswith("~"):
        raw = home + raw[1:]
    return os.path.normpath(os.path.expandvars(raw))


def load_roots(
    path: str | None = None,
    scopes: tuple[str, ...] = ("user",),
    home: str | None = None,
) -> list[Root]:
    """Roots for the requested scopes that actually exist on this machine."""
    home = home or os.path.expanduser("~")
    config_path = Path(path) if path else DEFAULT_CONFIG
    data = yaml.safe_load(config_path.read_text()) or {}

    roots: list[Root] = []
    for scope in scopes:
        for entry in data.get(scope, []) or []:
            expanded = _expand(entry["path"], home)
            if os.path.isdir(expanded):
                roots.append(Root(path=expanded, scope=scope, max_depth=int(entry.get("max_depth", 1))))
    return roots
