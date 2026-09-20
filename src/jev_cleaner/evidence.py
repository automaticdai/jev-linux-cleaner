"""Turn a flat scan into candidate groups, then into the state Jev sees."""

from __future__ import annotations

import os

from .models import CandidateGroup, ScanRecord
from .roots import Root

LARGE_BYTES = 500 * 1024 ** 2
DOMINANCE = 0.6
CAP = 400
MANIFEST_EXCERPT_CHARS = 2000

CONVENTIONS = {
    "/.cache/": "inside ~/.cache, which by XDG convention holds data an application can regenerate",
    "/.config/": "inside ~/.config, which by XDG convention holds settings the user chose",
    "/.local/share/": "inside ~/.local/share, which by XDG convention holds an application's durable data",
    "/.local/state/": "inside ~/.local/state, which by XDG convention holds state that persists between runs, such as logs and history",
    "/var/log": "inside /var/log, the system log directory",
    "/var/cache": "inside /var/cache, which holds data the system can fetch or rebuild again",
    "/var/tmp": "inside /var/tmp, for temporary files that survive a reboot",
    "/tmp": "inside /tmp, for temporary files cleared on reboot",
}


def group_records(
    records: list[ScanRecord],
    roots: list[Root],
    large_bytes: int = LARGE_BYTES,
    dominance: float = DOMINANCE,
    cap: int = CAP,
) -> list[CandidateGroup]:
    """One group per immediate child of a root, split deeper only when it pays."""
    by_path = {r.path: r for r in records}
    root_paths = {r.path for r in roots}

    # Children come from the records themselves, never from record.subdirs: the
    # probe truncates that list, and a truncated list silently hides whatever
    # sorts after the cut. That is how a 5.8 GB cache goes unreported.
    by_parent: dict[str, list[ScanRecord]] = {}
    for record in records:
        by_parent.setdefault(os.path.dirname(record.path), []).append(record)

    def children_of(record: ScanRecord) -> list[ScanRecord]:
        return sorted(by_parent.get(record.path, []), key=lambda r: r.path)

    def resolve(record: ScanRecord) -> list[ScanRecord]:
        kids = children_of(record)
        if not kids or record.size_bytes < large_bytes:
            return [record]
        biggest = max(kid.size_bytes for kid in kids)
        if biggest >= record.size_bytes * dominance:
            return [record]
        resolved: list[ScanRecord] = []
        for kid in kids:
            resolved.extend(resolve(kid))
        return resolved

    selected: list[ScanRecord] = []
    for path in sorted(root_paths):
        root_record = by_path.get(path)
        if root_record is None:
            continue
        for child in children_of(root_record):
            selected.extend(resolve(child))

    groups = [
        CandidateGroup(**{
            "path": r.path, "scope": r.scope, "size_bytes": r.size_bytes,
            "file_count": r.file_count, "newest_mtime": r.newest_mtime,
            "oldest_mtime": r.oldest_mtime, "extensions": r.extensions,
            "sample_names": r.sample_names, "subdirs": r.subdirs,
        })
        for r in selected
        if r.size_bytes > 0
    ]
    groups.sort(key=lambda g: -g.size_bytes)
    return groups[:cap]


def humanize_size(n: int) -> str:
    for unit, step in (("TB", 1024 ** 4), ("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= step:
            return f"{n / step:.1f} {unit}"
    return f"{n} bytes"


def size_bucket(n: int) -> str:
    if n >= 1024 ** 3:
        return "very large, over 1 GB"
    if n >= 100 * 1024 ** 2:
        return "large, hundreds of megabytes"
    if n >= 1024 ** 2:
        return "small, a few megabytes"
    return "tiny, under a megabyte"


def age_phrase(mtime: float, now: float) -> str:
    days = (now - mtime) / 86400.0
    if days < 1:
        return "today"
    if days < 7:
        return "within the last week"
    if days < 31:
        return "within the last month"
    if days < 93:
        return "one to three months ago"
    if days < 186:
        return "three to six months ago"
    if days < 366:
        return "over six months ago"
    return "over a year ago"


def location_convention(path: str) -> str:
    for marker, text in CONVENTIONS.items():
        if marker in path or path.startswith(marker.rstrip("/")):
            return text
    return "outside the standard cache and configuration locations"


def build_state(group: CandidateGroup, inventory, now: float, distribution: str = "Ubuntu 24.04") -> dict:
    """The full state for one group. Numbers and dates are already words."""
    name = os.path.basename(group.path)
    extensions = [
        f"{ext or 'no extension'} ({count:,} files)"
        for ext, count in list(group.extensions.items())[:5]
    ]
    return {
        "directory": {
            "path": group.path,
            "name": name,
            "location_convention": location_convention(group.path),
            "size": humanize_size(group.size_bytes),
            "size_bucket": size_bucket(group.size_bytes),
            "file_count": f"about {group.file_count:,} files",
            "last_modified": age_phrase(group.newest_mtime, now),
            "oldest_content": age_phrase(group.oldest_mtime, now),
            "top_extensions": extensions,
            "subdirectories": group.subdirs[:10],
            "sample_names": group.sample_names[:10],
        },
        "system": {
            "distribution": distribution,
            "possibly_related_installed_software": inventory.related(name),
            "inventory_is_complete": True,
        },
    }


def build_escalated_state(
    group: CandidateGroup,
    inventory,
    now: float,
    children: list[CandidateGroup],
    manifest_text: str | None,
    distribution: str = "Ubuntu 24.04",
) -> dict:
    """The first state plus the evidence a second look can add."""
    state = build_state(group, inventory, now=now, distribution=distribution)
    state["directory"]["subdirectory_detail"] = [
        {
            "name": os.path.basename(child.path),
            "size": humanize_size(child.size_bytes),
            "sample_names": child.sample_names[:5],
        }
        for child in children[:10]
    ]
    if manifest_text:
        state["directory"]["manifest_excerpt"] = manifest_text[:MANIFEST_EXCERPT_CHARS]
    return state
