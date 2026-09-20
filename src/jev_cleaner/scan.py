"""Scan orchestration: in-process for user roots, a sudo subprocess for system roots."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from collections.abc import Callable

from . import probe
from .models import ScanRecord, record_from_dict
from .roots import Root

log = logging.getLogger(__name__)

Runner = Callable[[list[str]], str]

MANIFEST_FILES = ("package.json", "metadata.json", "manifest.json", "CACHEDIR.TAG", "README.md", "README")


def sudo_command(roots: list[Root], interactive: bool = False) -> list[str]:
    """The exact command used for privileged scanning. Read-only by construction.

    `-n` keeps sudo from blocking on a password prompt in a script. When there
    is a terminal to prompt on, we drop it and let the user type their password:
    the previous behaviour skipped system scanning with only a log line, which
    is what sent one user to `sudo jev-cleaner` instead.
    """
    max_depth = max((r.max_depth for r in roots), default=1)
    prefix = ["sudo"] if interactive else ["sudo", "-n"]
    return [
        *prefix, sys.executable, "-m", "jev_cleaner.probe",
        "--scope", "system",
        "--max-depth", str(max_depth),
        "--roots", *[r.path for r in roots],
    ]


def _default_runner(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"probe exited {result.returncode}")
    return result.stdout


def scan(
    roots: list[Root],
    runner: Runner | None = None,
    interactive: bool | None = None,
) -> list[ScanRecord]:
    """Walk every root. A failure in one scope never discards another scope's results."""
    records: list[ScanRecord] = []

    for root in [r for r in roots if r.scope != "system"]:
        for raw in probe.walk(root.path, scope=root.scope, max_depth=root.max_depth):
            records.append(record_from_dict(raw))

    system_roots = [r for r in roots if r.scope == "system"]
    if system_roots:
        run = runner or _default_runner
        may_prompt = sys.stdin.isatty() if interactive is None else interactive
        try:
            output = run(sudo_command(system_roots))
        except Exception as exc:  # noqa: BLE001
            output = None
            if may_prompt:
                log.info("sudo needs a password for the read-only system probe")
                try:
                    output = run(sudo_command(system_roots, interactive=True))
                except Exception as retry_exc:  # noqa: BLE001
                    log.warning("system scan skipped: %s", retry_exc)
            else:
                log.warning("system scan skipped: %s", exc)
        if output:
            records.extend(record_from_dict(raw) for raw in json.loads(output))

    return records


def read_manifest(directory: str) -> str | None:
    """The first manifest-ish file in a directory, as text. Read-only, best effort."""
    for name in MANIFEST_FILES:
        candidate = os.path.join(directory, name)
        try:
            if os.path.isfile(candidate):
                with open(candidate, encoding="utf-8", errors="replace") as handle:
                    return handle.read(4000)
        except OSError:
            continue
    return None
