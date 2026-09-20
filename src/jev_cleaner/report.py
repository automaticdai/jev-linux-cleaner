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
