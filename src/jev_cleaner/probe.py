"""Read-only directory walker. This is the module that runs under sudo.

Standard library only, by rule. It reads metadata, writes JSON to stdout and
exits. It contains no deletion code, no network code, and reads no secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

SAMPLE_LIMIT = 10
SUBDIR_LIMIT = 20


def _accumulate(path: str, sample_limit: int) -> dict:
    size = 0
    files = 0
    newest = 0.0
    oldest = float("inf")
    extensions: dict[str, int] = {}
    samples: list[str] = []
    unreadable = False

    try:
        root_dev = os.stat(path).st_dev
    except OSError:
        root_dev = None
        unreadable = True

    for dirpath, dirnames, filenames in os.walk(path, followlinks=False, onerror=lambda _e: None):
        try:
            if root_dev is not None and os.stat(dirpath).st_dev != root_dev:
                dirnames[:] = []
                continue
        except OSError:
            unreadable = True
            continue
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                unreadable = True
                continue
            if os.path.islink(full):
                continue
            files += 1
            size += st.st_size
            newest = max(newest, st.st_mtime)
            oldest = min(oldest, st.st_mtime)
            ext = os.path.splitext(name)[1].lower()
            extensions[ext] = extensions.get(ext, 0) + 1
            if len(samples) < sample_limit:
                samples.append(os.path.relpath(full, path))

    if not os.access(path, os.R_OK):
        unreadable = True
    return {
        "size_bytes": size,
        "file_count": files,
        "newest_mtime": newest,
        "oldest_mtime": 0.0 if oldest == float("inf") else oldest,
        "extensions": dict(sorted(extensions.items(), key=lambda kv: -kv[1])[:8]),
        "sample_names": samples,
        "unreadable": unreadable,
    }


def _children(path: str) -> list[str]:
    try:
        with os.scandir(path) as it:
            return sorted(e.name for e in it if e.is_dir(follow_symlinks=False))
    except OSError:
        return []


def walk(root: str, scope: str, max_depth: int = 2, sample_limit: int = SAMPLE_LIMIT) -> list[dict]:
    """One record per directory from `root` down to `max_depth` levels below it."""
    records: list[dict] = []
    frontier = [(root, 0)]
    while frontier:
        path, depth = frontier.pop(0)
        if os.path.islink(path) or not os.path.isdir(path):
            continue
        stats = _accumulate(path, sample_limit)
        subdirs = _children(path)
        records.append({
            "path": path,
            "scope": scope,
            "subdirs": subdirs[:SUBDIR_LIMIT],
            **stats,
        })
        if depth < max_depth:
            frontier.extend((os.path.join(path, name), depth + 1) for name in subdirs)
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only directory probe. Prints JSON.")
    parser.add_argument("--roots", nargs="+", required=True)
    parser.add_argument("--scope", default="system")
    parser.add_argument("--max-depth", type=int, default=2)
    args = parser.parse_args(argv)

    out: list[dict] = []
    for root in args.roots:
        out.extend(walk(root, scope=args.scope, max_depth=args.max_depth))
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
