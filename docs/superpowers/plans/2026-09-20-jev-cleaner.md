# jev-cleaner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Linux disk cleaner that scans home and system locations, asks Jev seven atomic questions about every candidate directory, and reports what is safe to reclaim — without deleting anything.

**Architecture:** A one-directional pipeline of small modules: `scan` (the only Linux-dependent part) emits JSON; `evidence` rolls it into directory-level candidate groups and turns every number and timestamp into words; `denylist` drops protected paths before any network call; `judge` asks Jev one batched request per group; `policy` turns raw answers into tiers as a pure function; `report` renders. Privileged system reads happen in `probe.py`, a stdlib-only read-only walker run under `sudo` as a subprocess, so the main process never runs as root.

**Tech Stack:** Python 3.12, `typesafe-sdk` 0.7.0 (Jev / System One), PyYAML, Rich, pytest.

**Spec:** `docs/superpowers/specs/2026-09-20-jev-cleaner-design.md` — read it before Task 1. Sections 4–7 of the spec are normative for Tasks 7, 10, 11 and 12.

## Global Constraints

- Python `>=3.12`. Target platform Ubuntu 24.04 (developed on WSL2).
- Package lives in `src/jev_cleaner/`; import name `jev_cleaner`; console script `jev-cleaner`.
- Runtime dependencies are exactly: `typesafe-sdk>=0.7.0`, `pyyaml>=6.0`, `rich>=13.0`. Dev adds `pytest>=8.0`.
- `probe.py` imports **standard library only**. No third-party import may ever appear in that file — it is the module that runs under `sudo`.
- v1 never deletes, moves, or writes to any scanned path. The only files the tool writes are under `runs/` and a `plan.sh` it does not execute.
- No arithmetic or date comparison is ever asked of Jev. `evidence.py` converts every byte count and mtime to words before the state is built.
- Every module except `scan.py`, `probe.py`, `inventory.py`, `judge.py` and `cli.py` is pure: no I/O, no clock, no network.
- Model is addressed as `jev-1.13.0` (pinned, not the `jev-latest` alias) so stored thresholds stay meaningful. The answering model ID is recorded in every run.
- The API key comes from `TYPESAFE_API_KEY` in the environment. It is never written to a run artifact and never passed to the probe subprocess.
- Tests never hit the network. `judge.py` is tested against recorded cassettes only.
- Commit after every task.

---

### Task 1: Project scaffold and core types

**Files:**
- Create: `pyproject.toml`
- Create: `src/jev_cleaner/__init__.py`
- Create: `src/jev_cleaner/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ScanRecord`, `CandidateGroup`, `Judgment`, `Verdict`, `Scope`; helpers `to_dict(obj) -> dict`, `record_from_dict(d) -> ScanRecord`. Every later task uses these.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from jev_cleaner.models import CandidateGroup, ScanRecord, record_from_dict, to_dict


def make_record(**over) -> ScanRecord:
    base = dict(
        path="/home/u/.cache/uv",
        scope="user",
        size_bytes=6_227_020_800,
        file_count=120_000,
        newest_mtime=1_758_000_000.0,
        oldest_mtime=1_726_000_000.0,
        extensions={".whl": 900, "": 400},
        sample_names=["archive-v0/abc", "sdists-v7/x"],
        subdirs=["archive-v0", "sdists-v7"],
    )
    base.update(over)
    return ScanRecord(**base)


def test_scan_record_round_trips_through_json_shaped_dict():
    record = make_record()
    restored = record_from_dict(to_dict(record))
    assert restored == record


def test_candidate_group_is_hashable_and_ordered_by_size():
    small = CandidateGroup(**{**to_dict(make_record()), "size_bytes": 10})
    large = CandidateGroup(**to_dict(make_record()))
    assert sorted([small, large], key=lambda g: -g.size_bytes)[0] is large
    assert {small, large}  # frozen dataclasses are hashable
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner'`

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
[project]
name = "jev-cleaner"
version = "0.1.0"
description = "A Linux disk cleaner that judges unknown leftovers with Jev"
requires-python = ">=3.12"
dependencies = ["typesafe-sdk>=0.7.0", "pyyaml>=6.0", "rich>=13.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
jev-cleaner = "jev_cleaner.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-m 'not eval'"
markers = ["eval: agreement against hand-labelled fixtures; opt-in, may call the API"]
```

```python
# src/jev_cleaner/__init__.py
"""jev-cleaner: a Linux disk cleaner that judges unknown leftovers with Jev."""

__version__ = "0.1.0"
```

```python
# src/jev_cleaner/models.py
"""Core value types. Every one is frozen: nothing downstream mutates a scan."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Scope = Literal["user", "system", "container"]
Tier = Literal["clean", "costly", "orphan", "review", "keep", "denied"]


@dataclass(frozen=True)
class ScanRecord:
    """One directory as the walker saw it. Sizes and counts include descendants."""

    path: str
    scope: Scope
    size_bytes: int
    file_count: int
    newest_mtime: float
    oldest_mtime: float
    extensions: dict[str, int] = field(hash=False)
    sample_names: list[str] = field(hash=False)
    subdirs: list[str] = field(hash=False)

    def __hash__(self) -> int:
        return hash((self.path, self.scope, self.size_bytes))


@dataclass(frozen=True)
class CandidateGroup(ScanRecord):
    """A ScanRecord chosen as a unit of judgment."""


@dataclass(frozen=True)
class Judgment:
    """Raw Jev answers for one group. No policy applied."""

    content_kind: str
    content_kind_confidence: float
    content_kind_probabilities: dict[str, float] = field(hash=False)
    loss_if_deleted: float = 0.0
    loss_confidence: float = 0.0
    breaks_if_deleted: float = 0.0
    recreated_automatically: float = 0.0
    orphaned: float = 0.0
    holds_credentials: float = 0.0
    privacy_traces: float = 0.0
    model: str = "jev-1.13.0"
    escalated: bool = False

    def __hash__(self) -> int:
        return hash((self.content_kind, self.loss_if_deleted, self.model))


@dataclass(frozen=True)
class Verdict:
    """A group, its judgment, and the tier policy assigned."""

    group: CandidateGroup
    tier: Tier
    why: str
    judgment: Judgment | None = None
    baseline: str | None = None


def to_dict(obj: Any) -> dict:
    """Dataclass to a plain JSON-serializable dict."""
    return asdict(obj)


def record_from_dict(data: dict) -> ScanRecord:
    fields = {
        "path", "scope", "size_bytes", "file_count",
        "newest_mtime", "oldest_mtime", "extensions", "sample_names", "subdirs",
    }
    return ScanRecord(**{k: v for k, v in data.items() if k in fields})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pip install -e ".[dev]" && python -m pytest tests/test_models.py -v`
Expected: PASS, 2 tests

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/jev_cleaner/__init__.py src/jev_cleaner/models.py tests/test_models.py
git commit -m "feat: project scaffold and core value types"
```

---

### Task 2: The privileged probe

`probe.py` is the only code that runs as root. It walks directories read-only and prints JSON. Keep it boring and keep it stdlib.

**Files:**
- Create: `src/jev_cleaner/probe.py`
- Test: `tests/test_probe.py`

**Interfaces:**
- Consumes: nothing (must not import `jev_cleaner.models` — it stays importable with no package installed).
- Produces: `walk(root: str, scope: str, max_depth: int = 2, sample_limit: int = 10) -> list[dict]`, and a `__main__` entry accepting `--roots PATH [PATH ...] --scope NAME --max-depth N` that prints a JSON list to stdout. Each dict has the ScanRecord field names from Task 1.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_probe.py
import json
import os
import subprocess
import sys

from jev_cleaner.probe import walk


def build_tree(tmp_path):
    (tmp_path / "app" / "sub").mkdir(parents=True)
    (tmp_path / "app" / "a.whl").write_bytes(b"x" * 100)
    (tmp_path / "app" / "sub" / "b.whl").write_bytes(b"y" * 50)
    (tmp_path / "app" / "sub" / "c.txt").write_bytes(b"z" * 10)
    os.symlink(tmp_path / "app", tmp_path / "link-to-app")
    return tmp_path


def test_walk_rolls_descendants_into_one_record(tmp_path):
    build_tree(tmp_path)
    records = {r["path"]: r for r in walk(str(tmp_path), scope="user", max_depth=1)}
    app = records[str(tmp_path / "app")]
    assert app["size_bytes"] == 160
    assert app["file_count"] == 3
    assert app["extensions"][".whl"] == 2
    assert app["subdirs"] == ["sub"]
    assert app["scope"] == "user"


def test_walk_does_not_follow_symlinks(tmp_path):
    build_tree(tmp_path)
    paths = [r["path"] for r in walk(str(tmp_path), scope="user", max_depth=1)]
    assert str(tmp_path / "link-to-app") not in paths


def test_walk_survives_an_unreadable_directory(tmp_path):
    build_tree(tmp_path)
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "secret").write_bytes(b"s")
    os.chmod(locked, 0o000)
    try:
        records = {r["path"]: r for r in walk(str(tmp_path), scope="user", max_depth=1)}
        assert records[str(locked)]["size_bytes"] == 0
        assert records[str(locked)]["unreadable"] is True
    finally:
        os.chmod(locked, 0o755)


def test_module_entry_point_prints_json(tmp_path):
    build_tree(tmp_path)
    out = subprocess.run(
        [sys.executable, "-m", "jev_cleaner.probe", "--roots", str(tmp_path),
         "--scope", "system", "--max-depth", "1"],
        capture_output=True, text=True, check=True,
    )
    payload = json.loads(out.stdout)
    assert any(r["path"].endswith("/app") for r in payload)
    assert all(r["scope"] == "system" for r in payload)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_probe.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.probe'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/probe.py
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

    for dirpath, dirnames, filenames in os.walk(path, followlinks=False, onerror=lambda _e: None):
        try:
            if os.stat(dirpath).st_dev != os.stat(path).st_dev:
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_probe.py -v`
Expected: PASS, 4 tests

- [ ] **Step 5: Verify the stdlib-only rule holds**

Run: `grep -nE '^\s*(import|from)\s+' src/jev_cleaner/probe.py`
Expected: only `argparse`, `json`, `os`, `sys`, and `from __future__ import annotations`. If anything else appears, remove it before committing.

- [ ] **Step 6: Commit**

```bash
git add src/jev_cleaner/probe.py tests/test_probe.py
git commit -m "feat: read-only privileged probe"
```

---

### Task 3: Scan roots configuration

**Files:**
- Create: `config/roots.yaml`
- Create: `src/jev_cleaner/roots.py`
- Test: `tests/test_roots.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Root` dataclass (`path: str`, `scope: Scope`, `max_depth: int`), `load_roots(path: str | None = None, scopes: tuple[str, ...] = ("user",), home: str | None = None) -> list[Root]`. `~` and `$HOME` in the YAML expand against `home`. Missing paths are dropped.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_roots.py
from jev_cleaner.roots import load_roots


def test_loads_only_requested_scopes_and_expands_home(tmp_path):
    (tmp_path / ".cache").mkdir()
    cfg = tmp_path / "roots.yaml"
    cfg.write_text(
        "user:\n"
        "  - path: ~/.cache\n"
        "    max_depth: 1\n"
        "system:\n"
        "  - path: /var/cache/apt/archives\n"
        "    max_depth: 0\n"
    )
    roots = load_roots(str(cfg), scopes=("user",), home=str(tmp_path))
    assert [(r.path, r.scope, r.max_depth) for r in roots] == [
        (str(tmp_path / ".cache"), "user", 1)
    ]


def test_drops_roots_that_do_not_exist(tmp_path):
    cfg = tmp_path / "roots.yaml"
    cfg.write_text("user:\n  - path: ~/.nope\n    max_depth: 1\n")
    assert load_roots(str(cfg), scopes=("user",), home=str(tmp_path)) == []


def test_default_config_ships_with_the_package():
    roots_by_scope = {r.scope for r in load_roots(scopes=("user", "system"), home="/nonexistent-home")}
    assert roots_by_scope <= {"user", "system"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_roots.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.roots'`

- [ ] **Step 3: Write minimal implementation**

```yaml
# config/roots.yaml
# The scan surface. Editing this file widens or narrows the scan.
# max_depth is how many levels below the root the walker descends.
user:
  - {path: ~/.cache, max_depth: 1}
  - {path: ~/.local/share, max_depth: 1}
  - {path: ~/.local/state, max_depth: 1}
  - {path: ~/.config, max_depth: 1}
  - {path: ~/.npm, max_depth: 1}
  - {path: ~/.cargo/registry, max_depth: 1}
  - {path: ~/go/pkg/mod/cache, max_depth: 1}
  - {path: ~/.nv, max_depth: 1}
system:
  - {path: /var/cache/apt/archives, max_depth: 0}
  - {path: /var/log, max_depth: 1}
  - {path: /var/tmp, max_depth: 1}
  - {path: /tmp, max_depth: 1}
  - {path: /var/lib/snapd/snaps, max_depth: 0}
  - {path: /var/cache/snapd, max_depth: 0}
```

```python
# src/jev_cleaner/roots.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_roots.py -v`
Expected: PASS, 3 tests

- [ ] **Step 5: Commit**

```bash
git add config/roots.yaml src/jev_cleaner/roots.py tests/test_roots.py
git commit -m "feat: scan roots configuration"
```

---

### Task 4: Scan orchestration

**Files:**
- Create: `src/jev_cleaner/scan.py`
- Test: `tests/test_scan.py`

**Interfaces:**
- Consumes: `Root`/`load_roots` (Task 3), `probe.walk` (Task 2), `ScanRecord`/`record_from_dict` (Task 1).
- Produces: `scan(roots: list[Root], runner: Runner | None = None) -> list[ScanRecord]` and `Runner = Callable[[list[str]], str]`. User-scope roots are walked in-process; system-scope roots go through `sudo python -m jev_cleaner.probe`. The runner is injectable so tests never call sudo.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scan.py
import json

from jev_cleaner.roots import Root
from jev_cleaner.scan import scan, sudo_command


def test_user_scope_is_walked_in_process(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "f.bin").write_bytes(b"x" * 10)
    records = scan([Root(str(tmp_path), "user", 1)])
    assert {r.path for r in records} == {str(tmp_path), str(tmp_path / "app")}
    assert all(r.scope == "user" for r in records)


def test_system_scope_goes_through_the_injected_runner(tmp_path):
    calls: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> str:
        calls.append(cmd)
        return json.dumps([{
            "path": "/var/log", "scope": "system", "size_bytes": 4096, "file_count": 7,
            "newest_mtime": 1.0, "oldest_mtime": 0.5, "extensions": {".log": 7},
            "sample_names": ["syslog"], "subdirs": [],
        }])

    records = scan([Root("/var/log", "system", 1)], runner=fake_runner)
    assert [r.path for r in records] == ["/var/log"]
    assert records[0].scope == "system"
    assert calls[0][:2] == ["sudo", "-n"]
    assert "jev_cleaner.probe" in calls[0]


def test_sudo_command_passes_roots_and_depth():
    cmd = sudo_command([Root("/var/log", "system", 3)])
    assert "--roots" in cmd and "/var/log" in cmd
    assert cmd[cmd.index("--max-depth") + 1] == "3"


def test_a_failing_system_probe_does_not_lose_user_results(tmp_path):
    (tmp_path / "app").mkdir()

    def angry_runner(cmd: list[str]) -> str:
        raise RuntimeError("sudo: a password is required")

    records = scan(
        [Root(str(tmp_path), "user", 1), Root("/var/log", "system", 1)],
        runner=angry_runner,
    )
    assert {r.path for r in records} == {str(tmp_path), str(tmp_path / "app")}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_scan.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.scan'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/scan.py
"""Scan orchestration: in-process for user roots, a sudo subprocess for system roots."""

from __future__ import annotations

import logging
import subprocess
import sys
from collections.abc import Callable

from . import probe
from .models import ScanRecord, record_from_dict
from .roots import Root

log = logging.getLogger(__name__)

Runner = Callable[[list[str]], str]


def sudo_command(roots: list[Root]) -> list[str]:
    """The exact command used for privileged scanning. Read-only by construction."""
    max_depth = max((r.max_depth for r in roots), default=1)
    return [
        "sudo", "-n", sys.executable, "-m", "jev_cleaner.probe",
        "--scope", "system",
        "--max-depth", str(max_depth),
        "--roots", *[r.path for r in roots],
    ]


def _default_runner(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"probe exited {result.returncode}")
    return result.stdout


def scan(roots: list[Root], runner: Runner | None = None) -> list[ScanRecord]:
    """Walk every root. A failure in one scope never discards another scope's results."""
    import json

    records: list[ScanRecord] = []

    for root in [r for r in roots if r.scope != "system"]:
        for raw in probe.walk(root.path, scope=root.scope, max_depth=root.max_depth):
            records.append(record_from_dict(raw))

    system_roots = [r for r in roots if r.scope == "system"]
    if system_roots:
        try:
            output = (runner or _default_runner)(sudo_command(system_roots))
            records.extend(record_from_dict(raw) for raw in json.loads(output))
        except Exception as exc:  # noqa: BLE001 - a scope failure is reported, not fatal
            log.warning("system scan skipped: %s", exc)

    return records
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_scan.py -v`
Expected: PASS, 4 tests

- [ ] **Step 5: Capture a real fixture from this machine**

Run:
```bash
mkdir -p tests/fixtures
python - <<'PY'
import json
from jev_cleaner.models import to_dict
from jev_cleaner.roots import load_roots
from jev_cleaner.scan import scan
records = scan(load_roots(scopes=("user",)))
json.dump([to_dict(r) for r in records], open("tests/fixtures/scan-ubuntu-2404.json", "w"), indent=1)
print(len(records), "records")
PY
```
Expected: a few hundred records. This fixture drives every later test. It contains real path names from this machine, so read it once before committing and confirm you are willing to publish it (the repo is public); delete any row you are not.

- [ ] **Step 6: Commit**

```bash
git add src/jev_cleaner/scan.py tests/test_scan.py tests/fixtures/scan-ubuntu-2404.json
git commit -m "feat: scan orchestration with privilege-separated system scope"
```

---

### Task 5: Installed-software inventory

**Files:**
- Create: `src/jev_cleaner/inventory.py`
- Test: `tests/test_inventory.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Inventory` dataclass with `names: frozenset[str]` and `related(directory_name: str, limit: int = 6) -> list[str]`; `collect(runner: Callable[[list[str]], str] | None = None) -> Inventory`. `related` is the code-side fuzzy match that keeps the full package list out of the state.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_inventory.py
from jev_cleaner.inventory import Inventory, collect


def test_related_matches_on_substring_in_either_direction():
    inv = Inventory(names=frozenset({"python3-playwright", "firefox", "docker-ce", "libreoffice-calc"}))
    assert inv.related("ms-playwright") == ["python3-playwright"]
    assert inv.related("firefox") == ["firefox"]
    assert inv.related("libreoffice") == ["libreoffice-calc"]


def test_related_returns_empty_for_software_that_is_gone():
    inv = Inventory(names=frozenset({"firefox"}))
    assert inv.related("some-abandoned-tool") == []


def test_related_is_capped():
    inv = Inventory(names=frozenset(f"python3-mod{i}" for i in range(50)))
    assert len(inv.related("python3", limit=6)) == 6


def test_collect_parses_dpkg_and_snap_output():
    outputs = {
        "dpkg-query": "firefox\nsnapd\npython3.12\n",
        "snap": "Name    Version\ncore22  20240101\n",
        "docker": "",
    }

    def fake_runner(cmd: list[str]) -> str:
        return outputs.get(cmd[0], "")

    inv = collect(runner=fake_runner)
    assert {"firefox", "python3.12", "core22"} <= inv.names


def test_collect_tolerates_a_missing_package_manager():
    def broken_runner(cmd: list[str]) -> str:
        raise FileNotFoundError(cmd[0])

    assert collect(runner=broken_runner).names == frozenset()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_inventory.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.inventory'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/inventory.py
"""What software is installed, so a directory can be called orphaned."""

from __future__ import annotations

import logging
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

    return Inventory(names=frozenset(names))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_inventory.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add src/jev_cleaner/inventory.py tests/test_inventory.py
git commit -m "feat: installed-software inventory with code-side fuzzy matching"
```

---

### Task 6: Grouping records into candidates

Spec section 3.3. One group per immediate child of a root; split one level deeper only when a group is over 500 MB and no single subdirectory holds more than 60% of its bytes; cap at 400 groups, largest first.

**Files:**
- Create: `src/jev_cleaner/evidence.py`
- Test: `tests/test_grouping.py`

**Interfaces:**
- Consumes: `ScanRecord`, `CandidateGroup` (Task 1), `Root` (Task 3).
- Produces: `group_records(records: list[ScanRecord], roots: list[Root], large_bytes: int = 500 * 1024**2, dominance: float = 0.6, cap: int = 400) -> list[CandidateGroup]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_grouping.py
from jev_cleaner.evidence import group_records
from jev_cleaner.models import ScanRecord
from jev_cleaner.roots import Root

MB = 1024 ** 2


def rec(path, size, subdirs=(), scope="user"):
    return ScanRecord(
        path=path, scope=scope, size_bytes=size, file_count=max(size // 1000, 1),
        newest_mtime=1_758_000_000.0, oldest_mtime=1_726_000_000.0,
        extensions={".bin": 1}, sample_names=["f.bin"], subdirs=list(subdirs),
    )


def test_immediate_children_of_a_root_become_groups_and_the_root_does_not():
    records = [
        rec("/h/.cache", 300 * MB, subdirs=["a", "b"]),
        rec("/h/.cache/a", 200 * MB),
        rec("/h/.cache/b", 100 * MB),
    ]
    groups = group_records(records, [Root("/h/.cache", "user", 1)])
    assert [g.path for g in groups] == ["/h/.cache/a", "/h/.cache/b"]


def test_a_large_heterogeneous_group_is_split_one_level_deeper():
    records = [
        rec("/h/.cache", 1200 * MB, subdirs=["big"]),
        rec("/h/.cache/big", 1200 * MB, subdirs=["x", "y", "z"]),
        rec("/h/.cache/big/x", 400 * MB),
        rec("/h/.cache/big/y", 400 * MB),
        rec("/h/.cache/big/z", 400 * MB),
    ]
    groups = group_records(records, [Root("/h/.cache", "user", 2)])
    assert [g.path for g in groups] == ["/h/.cache/big/x", "/h/.cache/big/y", "/h/.cache/big/z"]


def test_a_large_but_dominated_group_is_kept_whole():
    records = [
        rec("/h/.cache", 1000 * MB, subdirs=["big"]),
        rec("/h/.cache/big", 1000 * MB, subdirs=["x", "y"]),
        rec("/h/.cache/big/x", 950 * MB),
        rec("/h/.cache/big/y", 50 * MB),
    ]
    groups = group_records(records, [Root("/h/.cache", "user", 2)])
    assert [g.path for g in groups] == ["/h/.cache/big"]


def test_groups_are_capped_largest_first():
    records = [rec("/h/.cache", 100 * MB, subdirs=[str(i) for i in range(10)])]
    records += [rec(f"/h/.cache/{i}", i * MB) for i in range(10)]
    groups = group_records(records, [Root("/h/.cache", "user", 1)], cap=3)
    assert [g.path for g in groups] == ["/h/.cache/9", "/h/.cache/8", "/h/.cache/7"]


def test_empty_directories_are_dropped():
    records = [rec("/h/.cache", 0, subdirs=["empty"]), rec("/h/.cache/empty", 0)]
    assert group_records(records, [Root("/h/.cache", "user", 1)]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_grouping.py -v`
Expected: FAIL with `ImportError: cannot import name 'group_records'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/evidence.py
"""Turn a flat scan into candidate groups, then into the state Jev sees."""

from __future__ import annotations

import os

from .models import CandidateGroup, ScanRecord
from .roots import Root

LARGE_BYTES = 500 * 1024 ** 2
DOMINANCE = 0.6
CAP = 400


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

    def children_of(record: ScanRecord) -> list[ScanRecord]:
        found = [by_path.get(os.path.join(record.path, name)) for name in record.subdirs]
        return [c for c in found if c is not None]

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_grouping.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add src/jev_cleaner/evidence.py tests/test_grouping.py
git commit -m "feat: roll scan records into candidate groups"
```

---

### Task 7: Building the state Jev sees

Spec section 4. Every number and timestamp becomes words here, because `jev-1.13` is unreliable at counting, numeric comparison and date ordering.

**Files:**
- Modify: `src/jev_cleaner/evidence.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: `CandidateGroup` (Task 1), `Inventory` (Task 5).
- Produces: `humanize_size(n: int) -> str`, `size_bucket(n: int) -> str`, `age_phrase(mtime: float, now: float) -> str`, `location_convention(path: str) -> str`, `build_state(group: CandidateGroup, inventory: Inventory, now: float, distribution: str = "Ubuntu 24.04") -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_state.py
from jev_cleaner.evidence import age_phrase, build_state, humanize_size, location_convention, size_bucket
from jev_cleaner.inventory import Inventory
from jev_cleaner.models import CandidateGroup

DAY = 86400.0
NOW = 1_758_000_000.0
GB = 1024 ** 3


def group(path="/home/u/.cache/ms-playwright", size=2 * GB, newest=NOW - 3 * DAY, oldest=NOW - 240 * DAY):
    return CandidateGroup(
        path=path, scope="user", size_bytes=size, file_count=12_000,
        newest_mtime=newest, oldest_mtime=oldest,
        extensions={".so": 3100, ".pak": 210, "": 900},
        sample_names=["chromium-1140/chrome-linux/chrome", ".links"],
        subdirs=["chromium-1140", "firefox-1450"],
    )


def test_sizes_become_words():
    assert humanize_size(2 * GB) == "2.0 GB"
    assert humanize_size(500) == "500 bytes"
    assert size_bucket(2 * GB) == "very large, over 1 GB"
    assert size_bucket(5 * 1024 ** 2) == "small, a few megabytes"


def test_ages_become_phrases_never_dates():
    assert age_phrase(NOW - 2 * DAY, NOW) == "within the last week"
    assert age_phrase(NOW - 400 * DAY, NOW) == "over a year ago"
    assert age_phrase(NOW - 45 * DAY, NOW) == "one to three months ago"


def test_location_convention_explains_xdg():
    assert "regenerate" in location_convention("/home/u/.cache/foo")
    assert "settings" in location_convention("/home/u/.config/foo")
    assert location_convention("/var/log/nginx") != ""


def test_state_contains_only_words_for_numbers_and_only_related_packages():
    inv = Inventory(names=frozenset({"python3-playwright", "firefox", "nginx"}))
    state = build_state(group(), inv, now=NOW)
    assert state["directory"]["size"] == "2.0 GB"
    assert state["directory"]["last_modified"] == "within the last week"
    assert state["directory"]["oldest_content"] == "over six months ago"
    assert state["directory"]["file_count"] == "about 12,000 files"
    assert state["directory"]["top_extensions"][0] == ".so (3,100 files)"
    assert state["system"]["possibly_related_installed_software"] == ["python3-playwright"]
    assert "nginx" not in str(state)


def test_state_reports_when_no_related_software_is_installed():
    state = build_state(group(path="/home/u/.config/abandoned-tool"), Inventory(frozenset({"firefox"})), now=NOW)
    assert state["system"]["possibly_related_installed_software"] == []
    assert state["system"]["inventory_is_complete"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_state.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_state'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/jev_cleaner/evidence.py`:

```python
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
```

`inventory_is_complete` is sent so the model can read an empty match list as evidence of absence rather than as missing data — which is what `orphaned` turns on.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_state.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add src/jev_cleaner/evidence.py tests/test_state.py
git commit -m "feat: build Jev state with words in place of numbers and dates"
```

---

### Task 8: The safety floor

Spec section 6. Denied groups never reach Jev and can never be recommended.

**Files:**
- Create: `src/jev_cleaner/denylist.py`
- Test: `tests/test_denylist.py`

**Interfaces:**
- Consumes: `CandidateGroup` (Task 1).
- Produces: `DenyReason` (str alias), `deny_reason(group: CandidateGroup, now: float, home: str, protect: tuple[str, ...] = (), git_check: Callable[[str], bool] | None = None) -> str | None`, and `partition(groups, now, home, protect=(), git_check=None) -> tuple[list[CandidateGroup], list[tuple[CandidateGroup, str]]]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_denylist.py
from jev_cleaner.denylist import deny_reason, partition
from jev_cleaner.models import CandidateGroup

NOW = 1_758_000_000.0
HOME = "/home/u"


def g(path, newest=NOW - 86400.0):
    return CandidateGroup(
        path=path, scope="user", size_bytes=1024, file_count=1,
        newest_mtime=newest, oldest_mtime=newest,
        extensions={}, sample_names=[], subdirs=[],
    )


def test_system_roots_are_denied():
    assert deny_reason(g("/etc/nginx"), NOW, HOME) == "protected system location"
    assert deny_reason(g("/boot/grub"), NOW, HOME) == "protected system location"
    assert deny_reason(g("/usr/lib/python3"), NOW, HOME) == "protected system location"


def test_listed_system_caches_are_allowed_through():
    assert deny_reason(g("/var/cache/apt/archives"), NOW, HOME) is None
    assert deny_reason(g("/var/log/nginx"), NOW, HOME) is None


def test_secrets_and_user_content_are_denied():
    assert deny_reason(g(f"{HOME}/.ssh"), NOW, HOME) == "credentials or keys"
    assert deny_reason(g(f"{HOME}/.gnupg/private-keys"), NOW, HOME) == "credentials or keys"
    assert deny_reason(g(f"{HOME}/Documents/taxes"), NOW, HOME) == "user content"


def test_recently_modified_groups_are_denied():
    assert deny_reason(g(f"{HOME}/.cache/live", newest=NOW - 60), NOW, HOME) == "modified in the last 15 minutes"


def test_a_git_working_tree_is_denied():
    def git_check(path: str) -> bool:
        return path.startswith(f"{HOME}/src/project")

    assert deny_reason(g(f"{HOME}/src/project/build"), NOW, HOME, git_check=git_check) == "inside a git working tree"


def test_user_protect_list_is_honoured():
    assert deny_reason(g(f"{HOME}/.cache/keepme"), NOW, HOME, protect=(f"{HOME}/.cache/keepme",)) == "listed under protect"


def test_partition_splits_allowed_from_denied():
    allowed, denied = partition([g(f"{HOME}/.cache/ok"), g("/etc/x")], NOW, HOME)
    assert [x.path for x in allowed] == [f"{HOME}/.cache/ok"]
    assert denied[0][1] == "protected system location"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_denylist.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.denylist'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/denylist.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_denylist.py -v`
Expected: PASS, 7 tests

- [ ] **Step 5: Check the floor against the real fixture**

Run:
```bash
python - <<'PY'
import json, time
from jev_cleaner.denylist import partition
from jev_cleaner.evidence import group_records
from jev_cleaner.models import CandidateGroup, record_from_dict
from jev_cleaner.roots import load_roots
records = [record_from_dict(d) for d in json.load(open("tests/fixtures/scan-ubuntu-2404.json"))]
groups = group_records(records, load_roots(scopes=("user",)))
allowed, denied = partition(groups, time.time(), home=__import__("os").path.expanduser("~"))
print(len(allowed), "allowed,", len(denied), "denied")
for g, why in denied[:20]:
    print(" ", why, g.path)
PY
```
Expected: `~/.ssh`, `~/.gnupg` and any git tree appear in the denied list. If something you would never delete appears in `allowed`, add it to the floor and add a test for it before moving on.

- [ ] **Step 6: Commit**

```bash
git add src/jev_cleaner/denylist.py tests/test_denylist.py
git commit -m "feat: enforce the safety floor before any request"
```

---

### Task 9: The rule baseline

Not a gate. `rules.py` produces the comparison column that shows where Jev and a conventional rule list disagree.

**Files:**
- Create: `src/jev_cleaner/rules.py`
- Test: `tests/test_rules.py`

**Interfaces:**
- Consumes: `CandidateGroup` (Task 1).
- Produces: `baseline_tier(group: CandidateGroup) -> str | None` returning `"clean"`, `"keep"` or `None` for "no rule covers this".

- [ ] **Step 1: Write the failing test**

```python
# tests/test_rules.py
from jev_cleaner.models import CandidateGroup
from jev_cleaner.rules import baseline_tier


def g(path):
    return CandidateGroup(
        path=path, scope="user", size_bytes=1024, file_count=1,
        newest_mtime=0.0, oldest_mtime=0.0, extensions={}, sample_names=[], subdirs=[],
    )


def test_known_throwaway_paths_are_clean():
    assert baseline_tier(g("/home/u/.cache/thumbnails")) == "clean"
    assert baseline_tier(g("/home/u/.cache/mesa_shader_cache")) == "clean"
    assert baseline_tier(g("/var/cache/apt/archives")) == "clean"
    assert baseline_tier(g("/tmp/whatever")) == "clean"


def test_known_valuable_paths_are_keep():
    assert baseline_tier(g("/home/u/.local/share/keyrings")) == "keep"
    assert baseline_tier(g("/home/u/.config/gnupg")) == "keep"


def test_an_unknown_path_has_no_baseline():
    assert baseline_tier(g("/home/u/.cache/some-tool-released-last-month")) is None
    assert baseline_tier(g("/home/u/.cache/uv")) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_rules.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.rules'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/rules.py
"""A conventional rule list, kept only as a baseline to compare Jev against.

Nothing in the pipeline is gated on these verdicts. The point of the column is
the disagreements: they are where the open-world judgment either earns its place
or exposes a problem.
"""

from __future__ import annotations

import os

from .models import CandidateGroup

CLEAN_NAMES = frozenset({
    "thumbnails", "mesa_shader_cache", "mesa_shader_cache_db", "fontconfig",
    "pip", "node-gyp", "vscode-ripgrep", "tracker3", "gstreamer-1.0",
})
CLEAN_PREFIXES = ("/tmp", "/var/tmp", "/var/cache/apt/archives", "/var/cache/snapd")
KEEP_NAMES = frozenset({"keyrings", "gnupg", "ssh", "password-store", "chromium", "gnome-keyring"})


def baseline_tier(group: CandidateGroup) -> str | None:
    """`clean`, `keep`, or None when no rule covers this path."""
    path = os.path.normpath(group.path)
    name = os.path.basename(path)

    if name in KEEP_NAMES:
        return "keep"
    if name in CLEAN_NAMES:
        return "clean"
    for prefix in CLEAN_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return "clean"
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_rules.py -v`
Expected: PASS, 3 tests

- [ ] **Step 5: Commit**

```bash
git add src/jev_cleaner/rules.py tests/test_rules.py
git commit -m "feat: rule baseline for comparison against Jev"
```

---

### Task 10: The question battery

Spec section 5, verbatim. This file is the contract with the model; its wording is normative and changing it invalidates stored thresholds.

**Files:**
- Create: `src/jev_cleaner/questions.py`
- Test: `tests/test_questions.py`

**Interfaces:**
- Consumes: `typesafe_sdk` types.
- Produces: `BATTERY_VERSION: str`, `battery() -> dict[str, Choice | Score | Noul]`, `CONTENT_KINDS: tuple[str, ...]`, `LOSS_LEVELS: tuple[str, ...]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_questions.py
from jev_cleaner.questions import BATTERY_VERSION, CONTENT_KINDS, LOSS_LEVELS, battery


def test_battery_has_every_question_from_the_spec():
    assert set(battery()) == {
        "content_kind", "loss_if_deleted", "breaks_if_deleted",
        "recreated_automatically", "orphaned", "holds_credentials", "privacy_traces",
    }


def test_content_kind_offers_an_unclear_option():
    assert "unclear" in CONTENT_KINDS
    assert len(CONTENT_KINDS) == 8


def test_loss_levels_are_ordered_and_self_contained():
    assert len(LOSS_LEVELS) == 5
    assert LOSS_LEVELS[0].startswith("Nothing noticeable")
    assert "cannot obtain again" in LOSS_LEVELS[4]
    assert all(len(level) > 40 for level in LOSS_LEVELS)


def test_every_question_names_the_directory_by_state_path():
    for qid, question in battery().items():
        assert "`directory.path`" in question.instructions, qid


def test_battery_version_is_pinned():
    assert BATTERY_VERSION == "1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_questions.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.questions'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/questions.py
"""The seven questions asked about every candidate directory.

The wording here is the contract with the model. Thresholds in policy.yaml were
tuned against this wording and this model version; changing either invalidates
them. Bump BATTERY_VERSION when you change a question, so cached answers from an
older wording are not reused.
"""

from __future__ import annotations

from typesafe_sdk import Choice, Noul, Score

BATTERY_VERSION = "1"

CONTENT_KIND_CRITERIA: dict[str, str] = {
    "regenerable_cache": "Data the program rebuilds or re-downloads by itself the next time it runs.",
    "downloaded_artifacts": "Packages, binaries, browsers or model files fetched over the network, restored only by downloading them again.",
    "build_output": "Compiled objects or build artifacts produced from source code that still exists elsewhere.",
    "transient_runtime_state": "Logs, crash dumps, sockets, pid files and temporary working files.",
    "application_settings": "Configuration and preferences the user set up.",
    "user_content": "Documents, saves, notes, keys or other material the user created or cannot obtain again.",
    "installed_program_files": "The program itself rather than its data.",
    "unclear": "The evidence does not identify what is stored here.",
}
CONTENT_KINDS: tuple[str, ...] = tuple(CONTENT_KIND_CRITERIA)

LOSS_LEVELS: tuple[str, ...] = (
    "Nothing noticeable. The program rebuilds it silently and the user never sees a difference.",
    "A slower next run. The program re-downloads or regenerates the data on its own, costing time or bandwidth but requiring no action from the user.",
    "The user must run a command to restore it, such as re-installing a component or re-downloading a model.",
    "Session or personalization is lost: the user is signed out, or history, preferences and customizations disappear.",
    "Data the user created, or cannot obtain again, is destroyed.",
)


def battery() -> dict[str, Choice | Score | Noul]:
    """All seven questions, asked together against one directory's state."""
    return {
        "content_kind": Choice(
            instructions="What is stored in the directory `directory.path`?",
            criteria=CONTENT_KIND_CRITERIA,
        ),
        "loss_if_deleted": Score(
            instructions=(
                "What does the user lose if the directory `directory.path` is deleted "
                "while the software that uses it stays installed?"
            ),
            criteria=list(LOSS_LEVELS),
        ),
        "breaks_if_deleted": Noul(
            instructions=(
                "Deleting the directory `directory.path` while the software remains installed "
                "would leave that software broken or unable to start until it is reinstalled or repaired."
            ),
        ),
        "recreated_automatically": Noul(
            instructions=(
                "The next time the software runs, it recreates the contents of `directory.path` "
                "by itself, without the user running any command."
            ),
        ),
        "orphaned": Noul(
            instructions=(
                "The directory `directory.path` belongs to software that is no longer installed "
                "on this system."
            ),
            criteria={
                "yes": "Nothing in `system.possibly_related_installed_software` is the software that owns this directory, and `system.inventory_is_complete` is true.",
                "no": "`system.possibly_related_installed_software` includes the software that owns this directory, or the directory belongs to the operating system itself.",
            },
        ),
        "holds_credentials": Noul(
            instructions=(
                "The directory `directory.path` holds login sessions, cookies, tokens or keys, "
                "so deleting it would sign the user out or require re-authentication."
            ),
        ),
        "privacy_traces": Noul(
            instructions=(
                "The directory `directory.path` holds a record of what the user did: "
                "browsing history, search terms, opened files or command history."
            ),
        ),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_questions.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add src/jev_cleaner/questions.py tests/test_questions.py
git commit -m "feat: the seven-question battery"
```

---

### Task 11: The Jev client

**Files:**
- Create: `src/jev_cleaner/judge.py`
- Test: `tests/test_judge.py`
- Create: `tests/fixtures/answers/playwright.json`

**Interfaces:**
- Consumes: `CandidateGroup` (Task 1), `build_state` (Task 7), `battery`/`BATTERY_VERSION` (Task 10), `Judgment` (Task 1).
- Produces: `judgment_from_response(response, escalated: bool = False) -> Judgment`, `cache_key(state: dict) -> str`, `AnswerCache` (with `get(key) -> Judgment | None` and `put(key, judgment)`), `async judge_groups(states: dict[str, dict], client, cache: AnswerCache | None = None, concurrency: int = 8, model: str = "jev-1.13.0") -> dict[str, Judgment]` keyed by group path.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_judge.py
import asyncio
import json
import types

import pytest

from jev_cleaner.judge import AnswerCache, cache_key, judge_groups, judgment_from_response


class FakeAnswer(dict):
    def __getattr__(self, name):
        return self[name]


def fake_response(kind="downloaded_artifacts", loss=3.1, model="jev-1.13.0"):
    return types.SimpleNamespace(
        model=model,
        choices={"content_kind": FakeAnswer(choice=kind, confidence=0.82,
                                            probabilities={kind: 0.82, "regenerable_cache": 0.18})},
        scores={"loss_if_deleted": FakeAnswer(score=loss, confidence=0.71,
                                              probabilities={"1": 0.1, "3": 0.7})},
        nouls={
            "breaks_if_deleted": FakeAnswer(noul=0.12),
            "recreated_automatically": FakeAnswer(noul=0.21),
            "orphaned": FakeAnswer(noul=0.05),
            "holds_credentials": FakeAnswer(noul=0.02),
            "privacy_traces": FakeAnswer(noul=0.03),
        },
    )


def test_judgment_is_read_off_the_response():
    judgment = judgment_from_response(fake_response())
    assert judgment.content_kind == "downloaded_artifacts"
    assert judgment.content_kind_confidence == 0.82
    assert judgment.loss_if_deleted == 3.1
    assert judgment.breaks_if_deleted == 0.12
    assert judgment.model == "jev-1.13.0"
    assert judgment.escalated is False


def test_cache_key_changes_with_the_state_and_the_battery_version():
    a = cache_key({"directory": {"path": "/x", "size": "1.0 GB"}})
    b = cache_key({"directory": {"path": "/x", "size": "2.0 GB"}})
    assert a != b
    assert cache_key({"directory": {"path": "/x", "size": "1.0 GB"}}) == a


def test_cache_round_trips_through_disk(tmp_path):
    cache = AnswerCache(tmp_path / "cache.json")
    judgment = judgment_from_response(fake_response())
    cache.put("k", judgment)
    assert AnswerCache(tmp_path / "cache.json").get("k") == judgment


def test_judge_groups_asks_once_per_group_and_uses_the_cache(tmp_path):
    calls: list[dict] = []

    class FakeClient:
        async def system_one(self, state, questions, model=None):
            calls.append(state)
            return fake_response()

    states = {"/a": {"directory": {"path": "/a"}}, "/b": {"directory": {"path": "/b"}}}
    cache = AnswerCache(tmp_path / "cache.json")

    first = asyncio.run(judge_groups(states, FakeClient(), cache=cache))
    assert set(first) == {"/a", "/b"}
    assert len(calls) == 2

    second = asyncio.run(judge_groups(states, FakeClient(), cache=cache))
    assert second == first


def test_one_failing_group_does_not_sink_the_run(tmp_path):
    class FlakyClient:
        async def system_one(self, state, questions, model=None):
            if state["directory"]["path"] == "/bad":
                raise RuntimeError("429 rate limited")
            return fake_response()

    states = {"/good": {"directory": {"path": "/good"}}, "/bad": {"directory": {"path": "/bad"}}}
    result = asyncio.run(judge_groups(states, FlakyClient(), cache=AnswerCache(tmp_path / "c.json")))
    assert set(result) == {"/good"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_judge.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.judge'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/judge.py
"""The only module that talks to the network."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import asdict
from pathlib import Path

from .models import Judgment
from .questions import BATTERY_VERSION, battery

log = logging.getLogger(__name__)

DEFAULT_MODEL = "jev-1.13.0"


def cache_key(state: dict) -> str:
    """Stable over the state and the battery wording; changes when either does."""
    blob = json.dumps(state, sort_keys=True) + "|" + BATTERY_VERSION
    return hashlib.sha256(blob.encode()).hexdigest()


class AnswerCache:
    """A judgment cache on disk, so a re-scan of an unchanged machine is free."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._data: dict[str, dict] = {}
        if self.path.exists():
            self._data = json.loads(self.path.read_text())

    def get(self, key: str) -> Judgment | None:
        raw = self._data.get(key)
        return Judgment(**raw) if raw else None

    def put(self, key: str, judgment: Judgment) -> None:
        self._data[key] = asdict(judgment)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data))


def judgment_from_response(response, escalated: bool = False) -> Judgment:
    kind = response.choices["content_kind"]
    loss = response.scores["loss_if_deleted"]
    nouls = response.nouls
    return Judgment(
        content_kind=kind.choice,
        content_kind_confidence=kind.confidence,
        content_kind_probabilities=dict(kind.probabilities),
        loss_if_deleted=loss.score,
        loss_confidence=loss.confidence,
        breaks_if_deleted=nouls["breaks_if_deleted"].noul,
        recreated_automatically=nouls["recreated_automatically"].noul,
        orphaned=nouls["orphaned"].noul,
        holds_credentials=nouls["holds_credentials"].noul,
        privacy_traces=nouls["privacy_traces"].noul,
        model=getattr(response, "model", DEFAULT_MODEL),
        escalated=escalated,
    )


async def judge_groups(
    states: dict[str, dict],
    client,
    cache: AnswerCache | None = None,
    concurrency: int = 8,
    model: str = DEFAULT_MODEL,
) -> dict[str, Judgment]:
    """One request per group, all seven questions in each. Failures are skipped."""
    questions = battery()
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, Judgment] = {}

    async def one(path: str, state: dict) -> None:
        key = cache_key(state)
        if cache is not None:
            hit = cache.get(key)
            if hit is not None:
                results[path] = hit
                return
        async with semaphore:
            try:
                response = await client.system_one(state=state, questions=questions, model=model)
            except Exception as exc:  # noqa: BLE001 - one group failing is not the run failing
                log.warning("no judgment for %s: %s", path, exc)
                return
        judgment = judgment_from_response(response)
        results[path] = judgment
        if cache is not None:
            cache.put(key, judgment)

    await asyncio.gather(*(one(path, state) for path, state in states.items()))
    return results
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_judge.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Record one real cassette**

Requires `TYPESAFE_API_KEY`. Run:
```bash
mkdir -p tests/fixtures/answers
python - <<'PY'
import asyncio, json, os, time
from dataclasses import asdict
from typesafe_sdk import AsyncTypeSafeClient
from jev_cleaner.evidence import build_state
from jev_cleaner.inventory import collect
from jev_cleaner.judge import judgment_from_response
from jev_cleaner.models import CandidateGroup
from jev_cleaner.questions import battery

group = CandidateGroup(
    path=os.path.expanduser("~/.cache/ms-playwright"), scope="user",
    size_bytes=2 * 1024**3, file_count=12000, newest_mtime=time.time() - 3 * 86400,
    oldest_mtime=time.time() - 240 * 86400,
    extensions={".so": 3100, ".pak": 210}, sample_names=["chromium-1140/chrome-linux/chrome"],
    subdirs=["chromium-1140", "firefox-1450"],
)
state = build_state(group, collect(), now=time.time())

async def main():
    async with AsyncTypeSafeClient() as client:
        r = await client.system_one(state=state, questions=battery(), model="jev-1.13.0")
    json.dump({"state": state, "judgment": asdict(judgment_from_response(r))},
              open("tests/fixtures/answers/playwright.json", "w"), indent=1)
    print(asdict(judgment_from_response(r)))

asyncio.run(main())
PY
```
Expected: `content_kind` is `downloaded_artifacts` and `loss_if_deleted` is near 3. If it comes back `regenerable_cache` with loss near 1, the battery is mis-wording the question — fix section 5.2 wording in the spec and this file together, bump `BATTERY_VERSION`, and re-record.

- [ ] **Step 6: Commit**

```bash
git add src/jev_cleaner/judge.py tests/test_judge.py tests/fixtures/answers/playwright.json
git commit -m "feat: Jev client with batched battery and on-disk answer cache"
```

---

### Task 12: Policy and tiering

Spec section 7. Pure function, table-driven test, one case per boundary.

**Files:**
- Create: `src/jev_cleaner/policy.py`
- Create: `config/policy.yaml`
- Test: `tests/test_policy.py`

**Interfaces:**
- Consumes: `Judgment`, `CandidateGroup`, `Verdict` (Task 1), `baseline_tier` (Task 9).
- Produces: `Thresholds` dataclass, `load_thresholds(path: str | None = None) -> Thresholds`, `tier_for(judgment: Judgment, t: Thresholds) -> tuple[str, str]` returning `(tier, why)`, `verdicts(groups, judgments, denied, t) -> list[Verdict]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_policy.py
import pytest

from jev_cleaner.models import CandidateGroup, Judgment
from jev_cleaner.policy import Thresholds, load_thresholds, tier_for, verdicts

T = Thresholds()


def j(**over) -> Judgment:
    base = dict(
        content_kind="regenerable_cache", content_kind_confidence=0.9,
        content_kind_probabilities={"regenerable_cache": 0.9},
        loss_if_deleted=1.0, loss_confidence=0.9, breaks_if_deleted=0.05,
        recreated_automatically=0.95, orphaned=0.02, holds_credentials=0.01,
        privacy_traces=0.01,
    )
    base.update(over)
    return Judgment(**base)


@pytest.mark.parametrize("judgment,expected", [
    (j(), "clean"),
    (j(content_kind="build_output"), "clean"),
    (j(content_kind="transient_runtime_state"), "clean"),
    (j(content_kind="downloaded_artifacts", loss_if_deleted=3.1), "costly"),
    (j(loss_if_deleted=3.0), "costly"),
    (j(loss_if_deleted=2.0), "clean"),
    (j(loss_if_deleted=2.01), "costly"),
    (j(loss_if_deleted=4.0), "keep"),
    (j(content_kind="user_content"), "keep"),
    (j(content_kind="application_settings"), "keep"),
    (j(content_kind="installed_program_files"), "keep"),
    (j(breaks_if_deleted=0.6), "keep"),
    (j(content_kind="unclear", content_kind_confidence=0.9), "review"),
    (j(content_kind_confidence=0.45), "review"),
    (j(loss_confidence=0.4), "review"),
    (j(content_kind_confidence=0.6), "review"),
    (j(orphaned=0.85), "orphan"),
    (j(orphaned=0.85, content_kind="user_content"), "keep"),
    (j(holds_credentials=0.5), "costly"),
])
def test_tiering_boundaries(judgment, expected):
    assert tier_for(judgment, T)[0] == expected


def test_why_names_the_deciding_judgment():
    assert "loss" in tier_for(j(loss_if_deleted=4.2), T)[1]
    assert "confidence" in tier_for(j(content_kind_confidence=0.3), T)[1]


def test_denied_groups_become_denied_verdicts_with_no_judgment():
    group = CandidateGroup(path="/etc/x", scope="system", size_bytes=1, file_count=1,
                           newest_mtime=0.0, oldest_mtime=0.0, extensions={}, sample_names=[], subdirs=[])
    out = verdicts([], {}, [(group, "protected system location")], T)
    assert out[0].tier == "denied"
    assert out[0].judgment is None
    assert out[0].why == "protected system location"


def test_a_group_with_no_judgment_lands_in_review():
    group = CandidateGroup(path="/h/.cache/x", scope="user", size_bytes=10, file_count=1,
                           newest_mtime=0.0, oldest_mtime=0.0, extensions={}, sample_names=[], subdirs=[])
    out = verdicts([group], {}, [], T)
    assert out[0].tier == "review"
    assert "no judgment" in out[0].why


def test_thresholds_load_from_yaml(tmp_path):
    cfg = tmp_path / "policy.yaml"
    cfg.write_text("clean_max_loss: 1.5\nconfidence_floor: 0.6\n")
    t = load_thresholds(str(cfg))
    assert t.clean_max_loss == 1.5
    assert t.confidence_floor == 0.6
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_policy.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.policy'`

- [ ] **Step 3: Write minimal implementation**

```yaml
# config/policy.yaml
# Thresholds tuned against jev-1.13.0 and battery version 1.
# Changing either invalidates these; re-run `pytest -m eval` after any edit.
confidence_floor: 0.5        # below this the model is telling you it does not know
clean_min_confidence: 0.7
clean_max_loss: 2.0
clean_max_breaks: 0.15
clean_max_credentials: 0.10
costly_max_loss: 4.0
keep_min_loss: 4.0
keep_min_breaks: 0.5
orphan_min: 0.8
```

```python
# src/jev_cleaner/policy.py
"""Raw judgments to tiers. Pure, and the only place risk tolerance is encoded.

Because this runs on stored judgments, changing a threshold re-tiers a whole
past run with no new requests.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path

import yaml

from .models import CandidateGroup, Judgment, Verdict
from .rules import baseline_tier

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config" / "policy.yaml"

CLEANABLE_KINDS = frozenset({"regenerable_cache", "build_output", "transient_runtime_state"})
KEEP_KINDS = frozenset({"user_content", "application_settings", "installed_program_files"})


@dataclass(frozen=True)
class Thresholds:
    confidence_floor: float = 0.5
    clean_min_confidence: float = 0.7
    clean_max_loss: float = 2.0
    clean_max_breaks: float = 0.15
    clean_max_credentials: float = 0.10
    costly_max_loss: float = 4.0
    keep_min_loss: float = 4.0
    keep_min_breaks: float = 0.5
    orphan_min: float = 0.8


def load_thresholds(path: str | None = None) -> Thresholds:
    config_path = Path(path) if path else DEFAULT_CONFIG
    data = yaml.safe_load(config_path.read_text()) or {}
    known = {f.name for f in fields(Thresholds)}
    return Thresholds(**{k: float(v) for k, v in data.items() if k in known})


def tier_for(judgment: Judgment, t: Thresholds) -> tuple[str, str]:
    """The most conservative tier that matches wins: keep, review, orphan, costly, clean."""
    if judgment.content_kind in KEEP_KINDS:
        return "keep", f"content is {judgment.content_kind.replace('_', ' ')}"
    if judgment.loss_if_deleted >= t.keep_min_loss:
        return "keep", f"loss level {judgment.loss_if_deleted:.1f}: user data would be destroyed"
    if judgment.breaks_if_deleted > t.keep_min_breaks:
        return "keep", f"would break the installed software (p={judgment.breaks_if_deleted:.2f})"

    if judgment.content_kind == "unclear":
        return "review", "the evidence does not identify what is stored here"
    if judgment.content_kind_confidence < t.confidence_floor:
        return "review", f"low confidence on content ({judgment.content_kind_confidence:.2f})"
    if judgment.loss_confidence < t.confidence_floor:
        return "review", f"low confidence on loss ({judgment.loss_confidence:.2f})"

    if judgment.orphaned >= t.orphan_min:
        return "orphan", f"owning software appears to be gone (p={judgment.orphaned:.2f})"

    clean = (
        judgment.content_kind in CLEANABLE_KINDS
        and judgment.content_kind_confidence >= t.clean_min_confidence
        and judgment.loss_if_deleted <= t.clean_max_loss
        and judgment.breaks_if_deleted <= t.clean_max_breaks
        and judgment.holds_credentials <= t.clean_max_credentials
    )
    if clean:
        return "clean", f"{judgment.content_kind.replace('_', ' ')}, loss level {judgment.loss_if_deleted:.1f}"

    if judgment.holds_credentials > t.clean_max_credentials:
        return "costly", f"deleting it would sign you out (p={judgment.holds_credentials:.2f})"
    if judgment.content_kind == "downloaded_artifacts":
        return "costly", f"re-downloading it costs time, loss level {judgment.loss_if_deleted:.1f}"
    if judgment.loss_if_deleted > t.clean_max_loss:
        return "costly", f"loss level {judgment.loss_if_deleted:.1f}: restoring it takes a command"
    return "review", f"{judgment.content_kind.replace('_', ' ')} below the clean bar"


def verdicts(
    groups: list[CandidateGroup],
    judgments: dict[str, Judgment],
    denied: list[tuple[CandidateGroup, str]],
    t: Thresholds,
) -> list[Verdict]:
    out: list[Verdict] = []
    for group in groups:
        judgment = judgments.get(group.path)
        if judgment is None:
            out.append(Verdict(group=group, tier="review", why="no judgment was returned for this directory",
                               judgment=None, baseline=baseline_tier(group)))
            continue
        tier, why = tier_for(judgment, t)
        out.append(Verdict(group=group, tier=tier, why=why, judgment=judgment, baseline=baseline_tier(group)))
    for group, reason in denied:
        out.append(Verdict(group=group, tier="denied", why=reason, judgment=None, baseline=baseline_tier(group)))
    out.sort(key=lambda v: -v.group.size_bytes)
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_policy.py -v`
Expected: PASS, 24 tests

- [ ] **Step 5: Commit**

```bash
git add src/jev_cleaner/policy.py config/policy.yaml tests/test_policy.py
git commit -m "feat: pure policy layer turning judgments into tiers"
```

---

### Task 13: Report, run artifact, and plan.sh

Spec section 8.

**Files:**
- Create: `src/jev_cleaner/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `Verdict` (Task 1), `Thresholds` (Task 12).
- Produces: `render_table(verdicts, console=None) -> None`, `run_document(verdicts, thresholds, model, started_at, finished_at, usage=None) -> dict`, `write_run(document, directory) -> Path`, `load_run(path) -> dict`, `verdicts_from_run(document) -> list[Verdict]`, `render_plan(verdicts) -> str`, `disagreements(verdicts) -> list[Verdict]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report.py
import json

from jev_cleaner.models import CandidateGroup, Judgment, Verdict
from jev_cleaner.policy import Thresholds
from jev_cleaner.report import (
    disagreements, load_run, render_plan, render_table, run_document, verdicts_from_run, write_run,
)

GB = 1024 ** 3


def verdict(path="/h/.cache/uv", tier="costly", size=6 * GB, baseline=None, why="re-downloading it costs time"):
    group = CandidateGroup(path=path, scope="user", size_bytes=size, file_count=100,
                           newest_mtime=1.0, oldest_mtime=0.0, extensions={".whl": 10},
                           sample_names=["a"], subdirs=[])
    judgment = Judgment(content_kind="downloaded_artifacts", content_kind_confidence=0.8,
                        content_kind_probabilities={"downloaded_artifacts": 0.8}, loss_if_deleted=2.4,
                        loss_confidence=0.7, breaks_if_deleted=0.05, recreated_automatically=0.9,
                        orphaned=0.02, holds_credentials=0.01, privacy_traces=0.01)
    return Verdict(group=group, tier=tier, why=why, judgment=judgment, baseline=baseline)


def test_plan_has_live_lines_only_for_clean(tmp_path):
    plan = render_plan([verdict(tier="clean", path="/h/.cache/mesa"), verdict(tier="costly", path="/h/.cache/uv")])
    assert "rm -rf '/h/.cache/mesa'" in plan
    assert "# rm -rf '/h/.cache/uv'" in plan
    assert plan.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in plan


def test_plan_never_emits_a_denied_path():
    plan = render_plan([Verdict(group=verdict().group, tier="denied", why="protected system location")])
    assert "rm -rf" not in plan.replace("# rm -rf", "")


def test_run_document_round_trips(tmp_path):
    doc = run_document([verdict()], Thresholds(), model="jev-1.13.0", started_at=1.0, finished_at=2.0)
    path = write_run(doc, tmp_path)
    reloaded = load_run(path)
    assert reloaded["model"] == "jev-1.13.0"
    assert reloaded["thresholds"]["clean_max_loss"] == 2.0
    restored = verdicts_from_run(reloaded)
    assert restored[0].group.path == "/h/.cache/uv"
    assert restored[0].judgment.content_kind == "downloaded_artifacts"


def test_run_document_never_contains_the_api_key(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-secret-value")
    doc = run_document([verdict()], Thresholds(), model="jev-1.13.0", started_at=1.0, finished_at=2.0)
    assert "sk-secret-value" not in json.dumps(doc)


def test_disagreements_lists_only_rows_where_the_baseline_differs():
    rows = [verdict(tier="clean", baseline="keep"), verdict(tier="clean", baseline="clean"), verdict(tier="clean", baseline=None)]
    assert len(disagreements(rows)) == 1


def test_render_table_prints_every_tier_with_totals(capsys):
    render_table([verdict(tier="clean"), verdict(tier="keep", path="/h/.config/x", size=1024)])
    out = capsys.readouterr().out
    assert "clean" in out and "keep" in out
    assert "6.0 GB" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.report'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/report.py
"""Rendering: the terminal table, the run artifact, and the plan script."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .evidence import humanize_size
from .models import CandidateGroup, Judgment, Verdict
from .policy import Thresholds

TIER_ORDER = ("clean", "costly", "orphan", "review", "keep", "denied")
TIER_STYLE = {"clean": "green", "costly": "yellow", "orphan": "magenta",
              "review": "cyan", "keep": "blue", "denied": "dim"}


def render_table(verdicts: list[Verdict], console: Console | None = None) -> None:
    console = console or Console()
    for tier in TIER_ORDER:
        rows = [v for v in verdicts if v.tier == tier]
        if not rows:
            continue
        total = sum(v.group.size_bytes for v in rows)
        table = Table(title=f"{tier}  ({len(rows)} directories, {humanize_size(total)})",
                      title_style=TIER_STYLE[tier], title_justify="left")
        table.add_column("size", justify="right")
        table.add_column("path")
        table.add_column("kind")
        table.add_column("why")
        table.add_column("rules")
        for v in rows:
            kind = v.judgment.content_kind.replace("_", " ") if v.judgment else "-"
            if v.baseline is None:
                agree = "-"
            else:
                agree = "=" if v.baseline == v.tier else f"!={v.baseline}"
            table.add_row(humanize_size(v.group.size_bytes), v.group.path, kind, v.why, agree)
        console.print(table)
        console.print()


def run_document(
    verdicts: list[Verdict],
    thresholds: Thresholds,
    model: str,
    started_at: float,
    finished_at: float,
    usage: dict | None = None,
) -> dict:
    """Everything needed to re-tier this run later without calling the API."""
    return {
        "schema": 1,
        "created": datetime.now(tz=timezone.utc).isoformat(),
        "model": model,
        "thresholds": asdict(thresholds),
        "started_at": started_at,
        "finished_at": finished_at,
        "usage": usage or {},
        "verdicts": [
            {
                "group": asdict(v.group),
                "tier": v.tier,
                "why": v.why,
                "baseline": v.baseline,
                "judgment": asdict(v.judgment) if v.judgment else None,
            }
            for v in verdicts
        ],
    }


def write_run(document: dict, directory: Path | str) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "run.json"
    path.write_text(json.dumps(document, indent=1))
    return path


def load_run(path: Path | str) -> dict:
    return json.loads(Path(path).read_text())


def verdicts_from_run(document: dict) -> list[Verdict]:
    out: list[Verdict] = []
    for row in document["verdicts"]:
        judgment = Judgment(**row["judgment"]) if row["judgment"] else None
        out.append(Verdict(group=CandidateGroup(**row["group"]), tier=row["tier"],
                           why=row["why"], judgment=judgment, baseline=row["baseline"]))
    return out


def render_plan(verdicts: list[Verdict]) -> str:
    """A script the tool writes and never runs. Only `clean` rows are live."""
    lines = [
        "#!/usr/bin/env bash",
        "# Written by jev-cleaner. Nothing here has been executed.",
        "# Read every line before running it. Commented lines are deliberate.",
        "set -euo pipefail",
        "",
    ]
    for tier in TIER_ORDER:
        rows = [v for v in verdicts if v.tier == tier]
        if not rows:
            continue
        total = sum(v.group.size_bytes for v in rows)
        lines.append(f"# ---- {tier}: {len(rows)} directories, {humanize_size(total)} ----")
        for v in rows:
            command = f"rm -rf '{v.group.path}'"
            if tier == "clean":
                lines.append(f"{command}  # {v.why}")
            else:
                lines.append(f"# {command}  # {v.why}")
        lines.append("")
    return "\n".join(lines)


def disagreements(verdicts: list[Verdict]) -> list[Verdict]:
    return [v for v in verdicts if v.baseline is not None and v.baseline != v.tier]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_report.py -v`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add src/jev_cleaner/report.py tests/test_report.py
git commit -m "feat: terminal report, run artifact, and unexecuted plan.sh"
```

---

### Task 14: The CLI

**Files:**
- Create: `src/jev_cleaner/cli.py`
- Test: `tests/test_cli.py`
- Create: `README.md`

**Interfaces:**
- Consumes: every module above.
- Produces: `main(argv: list[str] | None = None) -> int` with subcommands `scan`, `report`, `explain`, `plan`, `disagree`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import json

from jev_cleaner.cli import main
from jev_cleaner.models import CandidateGroup, Judgment, Verdict
from jev_cleaner.policy import Thresholds
from jev_cleaner.report import run_document, write_run


def a_run(tmp_path):
    group = CandidateGroup(path="/h/.cache/uv", scope="user", size_bytes=6 * 1024 ** 3, file_count=10,
                           newest_mtime=1.0, oldest_mtime=0.0, extensions={}, sample_names=[], subdirs=[])
    judgment = Judgment(content_kind="downloaded_artifacts", content_kind_confidence=0.8,
                        content_kind_probabilities={"downloaded_artifacts": 0.8}, loss_if_deleted=2.4,
                        loss_confidence=0.7, breaks_if_deleted=0.05, recreated_automatically=0.9,
                        orphaned=0.02, holds_credentials=0.01, privacy_traces=0.01)
    verdict = Verdict(group=group, tier="costly", why="re-downloading costs time", judgment=judgment, baseline="clean")
    directory = tmp_path / "runs" / "2026-09-20T00-00-00"
    write_run(run_document([verdict], Thresholds(), "jev-1.13.0", 1.0, 2.0), directory)
    return directory


def test_report_renders_a_stored_run_without_network(tmp_path, capsys):
    directory = a_run(tmp_path)
    # json format, because a Rich table wraps long paths at the console width
    assert main(["report", "--run", str(directory), "--format", "json"]) == 0
    assert "/h/.cache/uv" in capsys.readouterr().out


def test_report_retiers_under_changed_thresholds(tmp_path, capsys):
    directory = a_run(tmp_path)
    policy = tmp_path / "policy.yaml"
    policy.write_text("clean_max_loss: 3.0\nclean_min_confidence: 0.7\n")
    main(["report", "--run", str(directory), "--policy", str(policy)])
    out = capsys.readouterr().out
    assert "costly" in out or "clean" in out


def test_plan_writes_a_script_and_does_not_run_it(tmp_path):
    directory = a_run(tmp_path)
    target = tmp_path / "plan.sh"
    assert main(["plan", "--run", str(directory), "--out", str(target)]) == 0
    text = target.read_text()
    assert "# rm -rf '/h/.cache/uv'" in text
    assert (tmp_path / "h").exists() is False


def test_disagree_lists_baseline_conflicts(tmp_path, capsys):
    directory = a_run(tmp_path)
    assert main(["disagree", "--run", str(directory)]) == 0
    assert "clean" in capsys.readouterr().out


def test_explain_prints_every_probability(tmp_path, capsys):
    directory = a_run(tmp_path)
    assert main(["explain", "/h/.cache/uv", "--run", str(directory)]) == 0
    out = capsys.readouterr().out
    assert "content_kind" in out and "holds_credentials" in out


def test_unknown_run_is_an_error_not_a_traceback(tmp_path, capsys):
    assert main(["report", "--run", str(tmp_path / "nope")]) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.cli'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/cli.py
"""Command line. v1 reads, judges and reports. It never deletes."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from . import report as report_module
from .denylist import partition
from .evidence import build_state, group_records
from .inventory import collect
from .judge import DEFAULT_MODEL, AnswerCache, judge_groups
from .models import Verdict
from .policy import load_thresholds, tier_for, verdicts
from .roots import load_roots
from .scan import scan

console = Console()


def _latest_run(base: Path) -> Path | None:
    runs = sorted(p for p in base.glob("*") if (p / "run.json").exists())
    return runs[-1] if runs else None


def _resolve_run(value: str, base: Path) -> Path | None:
    if value == "latest":
        return _latest_run(base)
    path = Path(value)
    return path if (path / "run.json").exists() else None


def _load(value: str, base: Path):
    directory = _resolve_run(value, base)
    if directory is None:
        console.print(f"[red]no run found at {value}[/red]")
        return None
    return report_module.load_run(directory / "run.json")


def cmd_scan(args) -> int:
    scopes = ("system",) if args.system_only else (("user", "system") if args.system else ("user",))
    roots = load_roots(args.roots, scopes=scopes)
    if not roots:
        console.print("[red]no scan roots exist on this machine[/red]")
        return 1

    started = time.time()
    console.print(f"scanning {len(roots)} roots ({', '.join(scopes)}) ...")
    records = scan(roots)
    groups = group_records(records, roots)
    allowed, denied = partition(groups, time.time(), home=os.path.expanduser("~"),
                                protect=tuple(args.protect or ()))
    console.print(f"{len(groups)} candidate directories, {len(denied)} held back by the safety floor")

    inventory = collect()
    now = time.time()
    states = {g.path: build_state(g, inventory, now=now) for g in allowed}

    if args.dry_run:
        console.print(json.dumps(next(iter(states.values()), {}), indent=1))
        return 0

    from typesafe_sdk import AsyncTypeSafeClient

    async def run() -> dict:
        async with AsyncTypeSafeClient() as client:
            return await judge_groups(states, client, cache=AnswerCache(Path(args.cache)),
                                      concurrency=args.concurrency, model=args.model)

    judgments = asyncio.run(run())
    console.print(f"{len(judgments)} directories judged")

    thresholds = load_thresholds(args.policy)
    rows = verdicts(allowed, judgments, denied, thresholds)
    document = report_module.run_document(rows, thresholds, model=args.model,
                                          started_at=started, finished_at=time.time())
    stamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    path = report_module.write_run(document, Path(args.runs) / stamp)
    report_module.render_table(rows, console)
    console.print(f"run written to {path}")
    return 0


def cmd_report(args) -> int:
    document = _load(args.run, Path(args.runs))
    if document is None:
        return 1
    rows = report_module.verdicts_from_run(document)
    if args.policy:
        thresholds = load_thresholds(args.policy)
        retiered: list[Verdict] = []
        for row in rows:
            if row.judgment is None:
                retiered.append(row)
                continue
            tier, why = tier_for(row.judgment, thresholds)
            retiered.append(Verdict(group=row.group, tier=tier, why=why,
                                    judgment=row.judgment, baseline=row.baseline))
        rows = retiered
    if args.tier:
        rows = [r for r in rows if r.tier == args.tier]
    if args.format == "json":
        print(json.dumps([{**asdict(r.group), "tier": r.tier, "why": r.why} for r in rows], indent=1))
    else:
        report_module.render_table(rows, console)
    return 0


def cmd_plan(args) -> int:
    document = _load(args.run, Path(args.runs))
    if document is None:
        return 1
    text = report_module.render_plan(report_module.verdicts_from_run(document))
    Path(args.out).write_text(text)
    console.print(f"[yellow]plan written to {args.out} and NOT executed. Read it before running it.[/yellow]")
    return 0


def cmd_disagree(args) -> int:
    document = _load(args.run, Path(args.runs))
    if document is None:
        return 1
    rows = report_module.disagreements(report_module.verdicts_from_run(document))
    if not rows:
        console.print("no disagreements between Jev and the rule baseline")
        return 0
    report_module.render_table(rows, console)
    return 0


def cmd_explain(args) -> int:
    document = _load(args.run, Path(args.runs))
    if document is None:
        return 1
    for row in report_module.verdicts_from_run(document):
        if row.group.path == args.path:
            console.print(f"[bold]{row.group.path}[/bold]  {row.tier}: {row.why}")
            console.print(json.dumps(asdict(row.judgment) if row.judgment else {}, indent=1))
            return 0
    console.print(f"[red]{args.path} is not in this run[/red]")
    return 1


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(prog="jev-cleaner", description="Report reclaimable disk space. Deletes nothing.")
    parser.add_argument("--runs", default="runs", help="directory holding run artifacts")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="walk, judge and write a run")
    s.add_argument("--system", action="store_true", help="also scan system locations through sudo")
    s.add_argument("--system-only", action="store_true")
    s.add_argument("--roots", default=None)
    s.add_argument("--policy", default=None)
    s.add_argument("--protect", nargs="*", default=[])
    s.add_argument("--cache", default=".jev-cache.json")
    s.add_argument("--concurrency", type=int, default=8)
    s.add_argument("--model", default=DEFAULT_MODEL)
    s.add_argument("--dry-run", action="store_true", help="print one state and make no requests")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="render or re-tier a stored run; makes no requests")
    r.add_argument("--run", default="latest")
    r.add_argument("--tier", default=None)
    r.add_argument("--policy", default=None)
    r.add_argument("--format", choices=("table", "json"), default="table")
    r.set_defaults(func=cmd_report)

    p = sub.add_parser("plan", help="write plan.sh; never executes it")
    p.add_argument("--run", default="latest")
    p.add_argument("--out", default="plan.sh")
    p.set_defaults(func=cmd_plan)

    d = sub.add_parser("disagree", help="rows where Jev and the rule baseline differ")
    d.add_argument("--run", default="latest")
    d.set_defaults(func=cmd_disagree)

    e = sub.add_parser("explain", help="every probability for one directory")
    e.add_argument("path")
    e.add_argument("--run", default="latest")
    e.set_defaults(func=cmd_explain)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS, 6 tests

- [ ] **Step 5: Run the real thing end to end**

Run: `jev-cleaner scan --dry-run` (no API calls, prints one state — check it reads sensibly), then `jev-cleaner scan` with `TYPESAFE_API_KEY` set, then `jev-cleaner disagree`.
Expected: a tiered table where `~/.cache/uv` is `costly`, `~/.cache/mesa_shader_cache` is `clean`, and `~/.ssh` never appears outside `denied`. If `~/.cache/ms-playwright` lands in `clean`, stop and fix the battery or thresholds before continuing — that is the failure this tool exists to prevent.

- [ ] **Step 6: Write the README**

```markdown
# jev-cleaner

A Linux disk cleaner that judges the leftovers no rule list covers.

Rule-based cleaners only know the paths someone put in a list. jev-cleaner
enumerates candidate directories, hands each one to [Jev](https://docs.typesafe.ai)
as a small set of typed questions, and reports what it found. Four directories
in one `~/.cache` illustrate why that matters:

| Directory | Size | What deletion costs |
| --- | --- | --- |
| `uv` | 5.8 GB | a slower next resolve, automatic |
| `ms-playwright` | 2.0 GB | broken until you run `playwright install` |
| `huggingface` | 469 MB | a long model re-download, automatic |
| `mesa_shader_cache` | 2.5 MB | nothing noticeable |

`rm -rf ~/.cache` treats all four the same. jev-cleaner does not.

## It never deletes

v1 removes nothing. It writes a report, a run artifact, and a `plan.sh` that it
does not execute. You read the script and run it yourself.

## Install

```bash
pip install -e .
export TYPESAFE_API_KEY=...   # from https://console.typesafe.ai/
```

## Use

```bash
jev-cleaner scan                  # walk your home, judge, write a run
jev-cleaner scan --system         # also scan system locations, through sudo
jev-cleaner scan --dry-run        # print one state, make no API calls
jev-cleaner report --tier clean   # render a stored run; no network
jev-cleaner report --policy my.yaml   # re-tier a stored run under new thresholds
jev-cleaner explain ~/.cache/uv   # every probability behind one verdict
jev-cleaner plan                  # write plan.sh (never executed)
jev-cleaner disagree              # rows where Jev and the rule baseline differ
```

A full scan is roughly one million input tokens, about four cents.

## The safety floor

These are dropped in code before anything is sent or judged, and can never be
recommended: `/etc`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib`, `/dev`, `/proc`,
`/sys`, `/run`, `/opt`; `~/.ssh`, `~/.gnupg`, `~/.password-store`, keyrings,
`~/.aws`, `~/.kube`; `~/Documents`, `~/Desktop`, `~/Pictures`, `~/Videos`,
`~/Music`; anything with a `.git` above it; anything modified in the last 15
minutes; anything you list under `--protect`. Symlinks are never followed and
mount boundaries are never crossed.

Privileged scanning runs `jev_cleaner/probe.py` under `sudo`: a stdlib-only,
read-only walker that prints JSON and exits. The main process never runs as root.

## Design

- Spec: `docs/superpowers/specs/2026-09-20-jev-cleaner-design.md`
- Plan: `docs/superpowers/plans/2026-09-20-jev-cleaner.md`
- Agreement against hand labels: see `pytest -m eval` (record the number here)
```

- [ ] **Step 7: Commit**

```bash
git add src/jev_cleaner/cli.py tests/test_cli.py README.md
git commit -m "feat: command line with scan, report, plan, disagree and explain"
```

---

### Task 15: The escalation pass

Spec section 5.5. When the first battery cannot tell what a large directory holds, build a richer state and ask again. This is the one legitimate second request: the second state cannot be constructed until the first answer exists.

**Files:**
- Modify: `src/jev_cleaner/evidence.py`
- Modify: `src/jev_cleaner/judge.py`
- Modify: `src/jev_cleaner/scan.py`
- Modify: `src/jev_cleaner/cli.py`
- Test: `tests/test_escalation.py`

**Interfaces:**
- Consumes: `build_state` (Task 7), `judge_groups`/`Judgment` (Task 11), `CandidateGroup` (Task 1).
- Produces: `evidence.build_escalated_state(group, inventory, now, children: list[CandidateGroup], manifest_text: str | None, distribution: str = "Ubuntu 24.04") -> dict`; `judge.select_for_escalation(judgments: dict[str, Judgment], groups: list[CandidateGroup], large_bytes: int = 500 * 1024**2, confidence_floor: float = 0.5, cap: int = 25) -> list[CandidateGroup]`; `judge.judge_groups(..., mark_escalated: bool = False)`; `scan.read_manifest(directory: str) -> str | None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_escalation.py
import asyncio
import types

from jev_cleaner.evidence import build_escalated_state
from jev_cleaner.inventory import Inventory
from jev_cleaner.judge import AnswerCache, judge_groups, select_for_escalation
from jev_cleaner.models import CandidateGroup, Judgment
from jev_cleaner.scan import read_manifest

MB = 1024 ** 2
NOW = 1_758_000_000.0


def g(path, size):
    return CandidateGroup(path=path, scope="user", size_bytes=size, file_count=10,
                          newest_mtime=NOW - 86400, oldest_mtime=NOW - 86400,
                          extensions={".bin": 3}, sample_names=["a.bin"], subdirs=["x"])


def j(kind="regenerable_cache", confidence=0.9):
    return Judgment(content_kind=kind, content_kind_confidence=confidence,
                    content_kind_probabilities={kind: confidence}, loss_if_deleted=1.0,
                    loss_confidence=0.9, breaks_if_deleted=0.0, recreated_automatically=0.9,
                    orphaned=0.0, holds_credentials=0.0, privacy_traces=0.0)


def test_only_large_uncertain_groups_are_escalated():
    groups = [g("/h/.cache/big-unclear", 900 * MB), g("/h/.cache/small-unclear", 2 * MB),
              g("/h/.cache/big-confident", 900 * MB)]
    judgments = {"/h/.cache/big-unclear": j(kind="unclear"),
                 "/h/.cache/small-unclear": j(kind="unclear"),
                 "/h/.cache/big-confident": j()}
    assert [x.path for x in select_for_escalation(judgments, groups)] == ["/h/.cache/big-unclear"]


def test_low_confidence_also_escalates():
    groups = [g("/h/.cache/vague", 900 * MB)]
    judgments = {"/h/.cache/vague": j(confidence=0.31)}
    assert [x.path for x in select_for_escalation(judgments, groups)] == ["/h/.cache/vague"]


def test_escalation_is_capped_largest_first():
    groups = [g(f"/h/.cache/u{i}", (600 + i) * MB) for i in range(10)]
    judgments = {x.path: j(kind="unclear") for x in groups}
    picked = select_for_escalation(judgments, groups, cap=3)
    assert [x.path for x in picked] == ["/h/.cache/u9", "/h/.cache/u8", "/h/.cache/u7"]


def test_a_group_with_no_judgment_is_not_escalated():
    groups = [g("/h/.cache/missing", 900 * MB)]
    assert select_for_escalation({}, groups) == []


def test_escalated_state_adds_subdirectory_detail_and_a_manifest():
    state = build_escalated_state(
        g("/h/.cache/mystery", 900 * MB), Inventory(frozenset()), now=NOW,
        children=[g("/h/.cache/mystery/one", 400 * MB), g("/h/.cache/mystery/two", 500 * MB)],
        manifest_text='{"name": "mystery-tool", "version": "2.1"}',
    )
    detail = state["directory"]["subdirectory_detail"]
    assert [d["name"] for d in detail] == ["one", "two"]
    assert detail[0]["size"] == "400.0 MB"
    assert "mystery-tool" in state["directory"]["manifest_excerpt"]
    assert state["directory"]["path"] == "/h/.cache/mystery"


def test_manifest_excerpt_is_truncated():
    state = build_escalated_state(g("/h/.cache/m", MB), Inventory(frozenset()), now=NOW,
                                  children=[], manifest_text="x" * 9000)
    assert len(state["directory"]["manifest_excerpt"]) == 2000


def test_escalated_state_omits_the_manifest_field_when_there_is_none():
    state = build_escalated_state(g("/h/.cache/m", MB), Inventory(frozenset()), now=NOW,
                                  children=[], manifest_text=None)
    assert "manifest_excerpt" not in state["directory"]


def test_read_manifest_finds_a_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "thing"}')
    assert "thing" in read_manifest(str(tmp_path))


def test_read_manifest_returns_none_when_there_is_nothing_to_read(tmp_path):
    assert read_manifest(str(tmp_path)) is None


def test_escalated_judgments_are_marked(tmp_path):
    class FakeClient:
        async def system_one(self, state, questions, model=None):
            return types.SimpleNamespace(
                model="jev-1.13.0",
                choices={"content_kind": types.SimpleNamespace(
                    choice="build_output", confidence=0.88, probabilities={"build_output": 0.88})},
                scores={"loss_if_deleted": types.SimpleNamespace(score=1.2, confidence=0.8, probabilities={})},
                nouls={k: types.SimpleNamespace(noul=0.0) for k in
                       ("breaks_if_deleted", "recreated_automatically", "orphaned",
                        "holds_credentials", "privacy_traces")},
            )

    result = asyncio.run(judge_groups({"/h/x": {"directory": {"path": "/h/x"}}}, FakeClient(),
                                      cache=AnswerCache(tmp_path / "c.json"), mark_escalated=True))
    assert result["/h/x"].escalated is True
    assert result["/h/x"].content_kind == "build_output"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_escalation.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_escalated_state'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/jev_cleaner/evidence.py`:

```python
MANIFEST_EXCERPT_CHARS = 2000


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
```

Append to `src/jev_cleaner/scan.py`:

```python
MANIFEST_FILES = ("package.json", "metadata.json", "manifest.json", "CACHEDIR.TAG", "README.md", "README")


def read_manifest(directory: str) -> str | None:
    """The first manifest-ish file in a directory, as text. Read-only, best effort."""
    import os

    for name in MANIFEST_FILES:
        candidate = os.path.join(directory, name)
        try:
            if os.path.isfile(candidate):
                return open(candidate, encoding="utf-8", errors="replace").read(4000)
        except OSError:
            continue
    return None
```

In `src/jev_cleaner/judge.py`, add the selector and the `mark_escalated` flag:

```python
ESCALATION_CAP = 25
ESCALATION_MIN_BYTES = 500 * 1024 ** 2


def select_for_escalation(
    judgments: dict[str, Judgment],
    groups: list[CandidateGroup],
    large_bytes: int = ESCALATION_MIN_BYTES,
    confidence_floor: float = 0.5,
    cap: int = ESCALATION_CAP,
) -> list[CandidateGroup]:
    """Large directories the first pass could not identify. Largest first, capped."""
    picked = []
    for group in groups:
        judgment = judgments.get(group.path)
        if judgment is None or group.size_bytes < large_bytes:
            continue
        if judgment.content_kind == "unclear" or judgment.content_kind_confidence < confidence_floor:
            picked.append(group)
    picked.sort(key=lambda g: -g.size_bytes)
    return picked[:cap]
```

Add the import `from .models import CandidateGroup, Judgment` at the top of `judge.py`, then change the signature and the two places a judgment is produced:

```python
async def judge_groups(
    states: dict[str, dict],
    client,
    cache: AnswerCache | None = None,
    concurrency: int = 8,
    model: str = DEFAULT_MODEL,
    mark_escalated: bool = False,
) -> dict[str, Judgment]:
```

and inside `one()`, replace the judgment line with:

```python
        judgment = judgment_from_response(response, escalated=mark_escalated)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_escalation.py tests/test_judge.py -v`
Expected: PASS, 15 tests (10 new, 5 from Task 11 still green)

- [ ] **Step 5: Wire escalation into `cmd_scan`**

In `src/jev_cleaner/cli.py`, after `judgments = asyncio.run(run())`, insert:

```python
    from .judge import select_for_escalation
    from .scan import read_manifest

    escalating = select_for_escalation(judgments, allowed)
    if escalating:
        console.print(f"re-asking about {len(escalating)} directories the first pass could not identify")
        by_parent = {g.path: [c for c in allowed if os.path.dirname(c.path) == g.path] for g in escalating}
        deeper = {
            g.path: build_escalated_state(g, inventory, now=now, children=by_parent[g.path],
                                          manifest_text=read_manifest(g.path))
            for g in escalating
        }

        async def run_escalation() -> dict:
            async with AsyncTypeSafeClient() as client:
                return await judge_groups(deeper, client, cache=AnswerCache(Path(args.cache)),
                                          concurrency=args.concurrency, model=args.model,
                                          mark_escalated=True)

        judgments.update(asyncio.run(run_escalation()))
```

and add `build_escalated_state` to the `from .evidence import ...` line.

- [ ] **Step 6: Run the suite**

Run: `python -m pytest -v`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/jev_cleaner/evidence.py src/jev_cleaner/judge.py src/jev_cleaner/scan.py src/jev_cleaner/cli.py tests/test_escalation.py
git commit -m "feat: escalation pass for large directories the first battery cannot identify"
```

---

### Task 16: Container scope

Spec section 2 puts the container layer in v1 scope. It is handled differently from the filesystem on purpose: what a dangling image or a stopped container is, and what deleting one costs, is closed-world and fully known from `docker` itself. There is no semantic judgment to make, so Jev is not asked. These rows are enumerated, given fixed verdicts, and reported alongside the judged ones. Note this deviation from section 5, which describes the battery as running on every group.

**Files:**
- Create: `src/jev_cleaner/containers.py`
- Modify: `src/jev_cleaner/report.py`
- Modify: `src/jev_cleaner/cli.py`
- Test: `tests/test_containers.py`

**Interfaces:**
- Consumes: `CandidateGroup`, `Verdict` (Task 1).
- Produces: `parse_docker_size(text: str) -> int`, `container_verdicts(runner: Callable[[list[str]], str] | None = None) -> list[Verdict]`. Paths are synthetic (`docker://dangling-images`, `docker://stopped-containers`, `docker://build-cache`) and carry `scope="container"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_containers.py
from jev_cleaner.containers import container_verdicts, parse_docker_size
from jev_cleaner.report import render_plan


def test_docker_sizes_parse_to_bytes():
    assert parse_docker_size("1.5GB") == 1_500_000_000
    assert parse_docker_size("200MB") == 200_000_000
    assert parse_docker_size("1.5GiB") == int(1.5 * 1024 ** 3)
    assert parse_docker_size("0B") == 0
    assert parse_docker_size("12.3kB (virtual 40MB)") == 12_300


def test_dangling_images_and_stopped_containers_become_verdicts():
    outputs = {
        ("docker", "image"): "sha256:aaa\t1.5GB\nsha256:bbb\t500MB\n",
        ("docker", "ps"): "c1\t12.3kB (virtual 40MB)\tolds\n",
        ("docker", "builder"): "Build Cache\t8\t3\t2.1GB\t2.1GB\n",
    }

    def fake_runner(cmd):
        return outputs[(cmd[0], cmd[1])]

    rows = {v.group.path: v for v in container_verdicts(runner=fake_runner)}
    assert rows["docker://dangling-images"].group.size_bytes == 2_000_000_000
    assert rows["docker://dangling-images"].group.file_count == 2
    assert rows["docker://dangling-images"].tier == "clean"
    assert rows["docker://stopped-containers"].group.size_bytes == 12_300
    assert rows["docker://build-cache"].group.size_bytes == 2_100_000_000
    assert all(v.judgment is None for v in rows.values())
    assert all(v.group.scope == "container" for v in rows.values())


def test_nothing_reclaimable_produces_no_rows():
    def empty_runner(cmd):
        return ""

    assert container_verdicts(runner=empty_runner) == []


def test_docker_absent_is_not_an_error():
    def no_docker(cmd):
        raise FileNotFoundError("docker")

    assert container_verdicts(runner=no_docker) == []


def test_plan_uses_docker_prune_not_rm_for_container_rows():
    def fake_runner(cmd):
        return "sha256:aaa\t1.5GB\n" if cmd[1] == "image" else ""

    plan = render_plan(container_verdicts(runner=fake_runner))
    assert "docker image prune -f" in plan
    assert "rm -rf 'docker://" not in plan
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_containers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jev_cleaner.containers'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/jev_cleaner/containers.py
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
```

In `src/jev_cleaner/report.py`, import the prune table and make `render_plan` emit the right command:

```python
from .containers import PRUNE_COMMANDS
```

and inside `render_plan`, replace the command line with:

```python
            command = PRUNE_COMMANDS.get(v.group.path, f"rm -rf '{v.group.path}'")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_containers.py tests/test_report.py -v`
Expected: PASS, 10 tests

- [ ] **Step 5: Wire it into `cmd_scan`**

Add `--containers` to the `scan` subparser:

```python
    s.add_argument("--containers", action="store_true", help="also report reclaimable docker space")
```

and in `cmd_scan`, before building the run document:

```python
    if args.containers:
        from .containers import container_verdicts
        rows = rows + container_verdicts()
        rows.sort(key=lambda v: -v.group.size_bytes)
```

- [ ] **Step 6: Run it for real**

Run: `jev-cleaner scan --containers --dry-run` then `docker system df` and compare the totals.
Expected: the reported dangling-image and build-cache figures are in the same ballpark as `docker system df`. They will not match exactly, because `docker system df` counts shared layers differently; if they differ by more than a factor of two, fix the parser before continuing.

- [ ] **Step 7: Commit**

```bash
git add src/jev_cleaner/containers.py src/jev_cleaner/report.py src/jev_cleaner/cli.py tests/test_containers.py
git commit -m "feat: report reclaimable container space"
```

---

### Task 17: The evaluation harness

The number that decides whether a v2 is ever allowed to delete.

**Files:**
- Create: `tests/fixtures/labels.json`
- Create: `tests/test_eval.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything.
- Produces: an opt-in `pytest -m eval` run reporting per-tier agreement against hand labels.

- [ ] **Step 1: Write the label file**

List your own candidates first, so the labels are yours and not the tool's:

```bash
python -c "
import json,os
from jev_cleaner.evidence import group_records, humanize_size
from jev_cleaner.models import record_from_dict
from jev_cleaner.roots import load_roots
recs=[record_from_dict(d) for d in json.load(open('tests/fixtures/scan-ubuntu-2404.json'))]
for g in group_records(recs, load_roots(scopes=('user',)))[:30]:
    print(humanize_size(g.size_bytes).rjust(10), g.path)
"
```

Create `tests/fixtures/labels.json` with those 30 directories and the tier you believe each deserves. Label them **before** looking at what the tool said. Start from this shape and fill it from your own `~/.cache`, `~/.local/share` and `~/.config`:

```json
[
  {"path": "~/.cache/mesa_shader_cache", "expected": "clean", "note": "GPU shader cache, rebuilt on demand"},
  {"path": "~/.cache/uv", "expected": "costly", "note": "python wheel cache, large refetch"},
  {"path": "~/.cache/ms-playwright", "expected": "costly", "note": "needs playwright install to restore"},
  {"path": "~/.cache/huggingface", "expected": "costly", "note": "model weights, slow redownload"},
  {"path": "~/.cache/node-gyp", "expected": "clean", "note": "header cache, refetched automatically"},
  {"path": "~/.config/gnupg", "expected": "denied", "note": "keys, must never be offered"},
  {"path": "~/.local/share/Trash", "expected": "clean", "note": "already discarded by the user"}
]
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_eval.py
"""Opt-in agreement check: `pytest -m eval`. Uses the recorded run, not the API."""

import json
import os
from pathlib import Path

import pytest

from jev_cleaner.report import load_run, verdicts_from_run

LABELS = Path(__file__).parent / "fixtures" / "labels.json"
RUN = Path("runs")


def _latest_run() -> Path | None:
    runs = sorted(p for p in RUN.glob("*") if (p / "run.json").exists())
    return runs[-1] if runs else None


@pytest.mark.eval
def test_agreement_with_hand_labels():
    run_dir = _latest_run()
    if run_dir is None:
        pytest.skip("no run yet; run `jev-cleaner scan` first")

    labels = {os.path.expanduser(row["path"]): row for row in json.loads(LABELS.read_text())}
    by_path = {v.group.path: v for v in verdicts_from_run(load_run(run_dir / "run.json"))}

    scored = [(p, labels[p]["expected"], by_path[p].tier, by_path[p].why)
              for p in labels if p in by_path]
    if not scored:
        pytest.skip("no labelled directory appears in the latest run")

    mismatches = [(p, want, got, why) for p, want, got, why in scored if want != got]
    agreement = 1 - len(mismatches) / len(scored)

    print(f"\nagreement: {agreement:.0%} over {len(scored)} labelled directories")
    for path, want, got, why in mismatches:
        print(f"  want {want:<7} got {got:<7} {path}  ({why})")

    unsafe = [m for m in mismatches if m[1] in ("keep", "denied") and m[2] in ("clean", "costly")]
    assert not unsafe, f"directories labelled keep/denied were offered for deletion: {unsafe}"
    assert agreement >= 0.8, f"agreement {agreement:.0%} is below the 80% bar"
```

- [ ] **Step 3: Run it and watch it skip, then run it for real**

Run: `python -m pytest tests/test_eval.py -v -m eval`
Expected: SKIP with "no run yet". Then run `jev-cleaner scan`, run the eval again, and read the mismatch list.

- [ ] **Step 4: Act on what the mismatches say**

The `unsafe` assertion is the one that matters: anything you labelled `keep` or `denied` that the tool offered for deletion is a defect, not a tuning problem. Fix it in the safety floor (Task 8) or the battery wording (Task 10) — not by relabelling. Record the final agreement number in the README.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/labels.json tests/test_eval.py README.md
git commit -m "test: hand-labelled evaluation harness"
```

- [ ] **Step 6: Run the whole suite and push**

```bash
python -m pytest -v
git push
```
Expected: all non-eval tests pass.
