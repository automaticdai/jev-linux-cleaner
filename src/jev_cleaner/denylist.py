"""The safety floor. Enforced in code, before any request is built."""

from __future__ import annotations

import os
from collections.abc import Callable

from .models import CandidateGroup

RECENT_SECONDS = 15 * 60

SYSTEM_ROOTS = ("/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/dev", "/proc", "/sys", "/run", "/opt")
SYSTEM_EXCEPTIONS = ("/var/cache", "/var/log", "/var/tmp", "/tmp", "/var/lib/snapd/snaps")
SECRET_DIRS = (".ssh", ".gnupg", ".password-store", ".local/share/keyrings", ".pki", ".aws", ".kube")
CONTENT_DIRS = ("Documents", "Desktop", "Pictures", "Videos", "Music", "OneDrive", "Nextcloud")


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _has_git_above(path: str) -> bool:
    current = path
    while current not in ("/", ""):
        if os.path.isdir(os.path.join(current, ".git")):
            return True
        current = os.path.dirname(current)
    return False


def deny_reason(
    group: CandidateGroup,
    now: float,
    home: str,
    protect: tuple[str, ...] = (),
    git_check: Callable[[str], bool] | None = None,
) -> str | None:
    """Why this group must never be judged or recommended, or None if it may be."""
    path = os.path.normpath(group.path)

    for prefix in protect:
        if _under(path, prefix):
            return "listed under protect"

    if not any(_under(path, allowed) for allowed in SYSTEM_EXCEPTIONS):
        for prefix in SYSTEM_ROOTS:
            if _under(path, prefix):
                return "protected system location"
        if path == "/":
            return "protected system location"

    for secret in SECRET_DIRS:
        if _under(path, os.path.join(home, secret)):
            return "credentials or keys"

    for content in CONTENT_DIRS:
        if _under(path, os.path.join(home, content)):
            return "user content"

    if now - group.newest_mtime < RECENT_SECONDS:
        return "modified in the last 15 minutes"

    if (git_check or _has_git_above)(path):
        return "inside a git working tree"

    return None


def partition(
    groups: list[CandidateGroup],
    now: float,
    home: str,
    protect: tuple[str, ...] = (),
    git_check: Callable[[str], bool] | None = None,
) -> tuple[list[CandidateGroup], list[tuple[CandidateGroup, str]]]:
    allowed: list[CandidateGroup] = []
    denied: list[tuple[CandidateGroup, str]] = []
    for group in groups:
        reason = deny_reason(group, now, home, protect, git_check)
        (denied.append((group, reason)) if reason else allowed.append(group))
    return allowed, denied
