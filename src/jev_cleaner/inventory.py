"""What software is installed, so a directory can be called orphaned."""

from __future__ import annotations

import logging
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)

Runner = Callable[[list[str]], str]

_SPLIT = re.compile(r"[-_.\s]+")


@dataclass(frozen=True)
class Inventory:
    names: frozenset[str]

    def related(self, directory_name: str, limit: int = 6) -> list[str]:
        """Installed names plausibly connected to a directory name.

        Code does this matching, not the model: handing the model a full package
        list would bury the judgment in irrelevant detail.
        """
        needle = directory_name.lower().lstrip(".")
        tokens = {t for t in _SPLIT.split(needle) if len(t) > 3}
        hits = set()
        for name in self.names:
            low = name.lower()
            if needle and (needle in low or low in needle):
                hits.add(name)
                continue
            if any(t in low for t in tokens):
                hits.add(name)
        return sorted(hits)[:limit]


def _run(runner: Runner, cmd: list[str]) -> str:
    try:
        return runner(cmd)
    except Exception as exc:  # noqa: BLE001 - a missing tool is normal
        log.debug("inventory source unavailable (%s): %s", cmd[0], exc)
        return ""


def _default_runner(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True).stdout


def collect(runner: Runner | None = None) -> Inventory:
    runner = runner or _default_runner
    names: set[str] = set()

    dpkg = _run(runner, ["dpkg-query", "-f", "${Package}\n", "-W"])
    names.update(line.strip() for line in dpkg.splitlines() if line.strip())

    snap = _run(runner, ["snap", "list"])
    for line in snap.splitlines()[1:]:
        if line.strip():
            names.add(line.split()[0])

    docker = _run(runner, ["docker", "image", "ls", "--format", "{{.Repository}}"])
    names.update(line.strip() for line in docker.splitlines() if line.strip() and line.strip() != "<none>")

    names.update(path_executables())

    return Inventory(names=frozenset(names))


def path_executables() -> set[str]:
    """Commands on $PATH.

    dpkg alone is not an inventory of installed software: uv, playwright and
    huggingface arrive through pip and npm and appear in no package database.
    Without this, every one of their cache directories looks orphaned.
    """
    found: set[str] = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    if not entry.name.startswith(".") and entry.is_file(follow_symlinks=True):
                        found.add(entry.name)
        except OSError:
            continue
    return found
