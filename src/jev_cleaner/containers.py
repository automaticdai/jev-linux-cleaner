"""The container layer.

Unlike the filesystem, this is closed-world: docker tells us exactly what a
dangling image or a stopped container is, and what removing one costs. There is
no semantic judgment to make, so these rows are not sent to Jev.
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable

from .models import CandidateGroup, Verdict

log = logging.getLogger(__name__)

Runner = Callable[[list[str]], str]

_SIZE = re.compile(r"([\d.]+)\s*([KMGT]?i?B)", re.IGNORECASE)
_UNITS = {
    "b": 1,
    "kb": 1000, "mb": 1000 ** 2, "gb": 1000 ** 3, "tb": 1000 ** 4,
    "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4,
}

PRUNE_COMMANDS = {
    "docker://dangling-images": "docker image prune -f",
    "docker://stopped-containers": "docker container prune -f",
    "docker://build-cache": "docker builder prune -f",
}


def parse_docker_size(text: str) -> int:
    """Docker's human sizes to bytes. The first number wins: `12.3kB (virtual 40MB)`."""
    match = _SIZE.search(text)
    if not match:
        return 0
    value, unit = match.group(1), match.group(2).lower()
    return int(float(value) * _UNITS.get(unit, 1))


def _default_runner(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True).stdout


def _run(runner: Runner, cmd: list[str]) -> str:
    try:
        return runner(cmd)
    except Exception as exc:  # noqa: BLE001 - no docker is a normal state
        log.debug("docker unavailable (%s): %s", " ".join(cmd[:2]), exc)
        return ""


def _row(path: str, size: int, count: int, why: str) -> Verdict:
    group = CandidateGroup(path=path, scope="container", size_bytes=size, file_count=count,
                           newest_mtime=0.0, oldest_mtime=0.0, extensions={},
                           sample_names=[], subdirs=[])
    return Verdict(group=group, tier="clean", why=why, judgment=None, baseline="clean")


def container_verdicts(runner: Runner | None = None) -> list[Verdict]:
    """Reclaimable container space. Empty when docker is absent or has nothing to drop."""
    runner = runner or _default_runner
    rows: list[Verdict] = []

    images = _run(runner, ["docker", "image", "ls", "--filter", "dangling=true",
                           "--format", "{{.ID}}\t{{.Size}}"]).strip()
    if images:
        lines = [line for line in images.splitlines() if line.strip()]
        total = sum(parse_docker_size(line.split("\t")[-1]) for line in lines)
        rows.append(_row("docker://dangling-images", total, len(lines),
                         "untagged images no container references"))

    containers = _run(runner, ["docker", "ps", "-a", "--filter", "status=exited",
                               "--format", "{{.ID}}\t{{.Size}}\t{{.Names}}"]).strip()
    if containers:
        lines = [line for line in containers.splitlines() if line.strip()]
        total = sum(parse_docker_size(line.split("\t")[1]) for line in lines)
        rows.append(_row("docker://stopped-containers", total, len(lines),
                         "exited containers and their writable layers"))

    cache = _run(runner, ["docker", "builder", "du"]).strip()
    if cache:
        total = sum(parse_docker_size(line.split("\t")[-1]) for line in cache.splitlines() if line.strip())
        if total:
            rows.append(_row("docker://build-cache", total, 1, "build cache, rebuilt on the next build"))

    return rows
