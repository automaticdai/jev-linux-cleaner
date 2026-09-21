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
from .evidence import build_escalated_state, build_state, group_records
from .inventory import collect
from .judge import DEFAULT_MODEL, AnswerCache, judge_groups, select_for_escalation
from .models import Verdict
from .policy import load_thresholds, tier_for, verdicts
from .roots import load_roots
from .scan import read_manifest, scan

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
        console.print_json(json.dumps(next(iter(states.values()), {})))
        return 0

    from typesafe_sdk import AsyncTypeSafeClient

    async def run() -> dict:
        async with AsyncTypeSafeClient() as client:
            return await judge_groups(states, client, cache=AnswerCache(Path(args.cache)),
                                      concurrency=args.concurrency, model=args.model)

    judgments = asyncio.run(run())
    console.print(f"{len(judgments)} directories judged")

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

    thresholds = load_thresholds(args.policy)
    rows = verdicts(allowed, judgments, denied, thresholds, now=time.time())

    if args.containers:
        from .containers import container_verdicts
        rows = rows + container_verdicts()
        rows.sort(key=lambda v: -v.group.size_bytes)

    document = report_module.run_document(rows, thresholds, model=args.model,
                                          started_at=started, finished_at=time.time())
    stamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    path = report_module.write_run(document, Path(args.runs) / stamp)
    report_module.render_table(rows, console)
    console.print(f"run written to {path}")
    console.print("[yellow]nothing was deleted. `jev-cleaner plan` writes a script for you to review.[/yellow]")
    return 0


def cmd_report(args) -> int:
    document = _load(args.run, Path(args.runs))
    if document is None:
        return 1
    rows = report_module.verdicts_from_run(document)
    # Re-tier with the current policy by default. The tiers frozen into a run
    # are a snapshot of whichever thresholds were in force when it was taken,
    # and reading them back is how a policy fix goes unnoticed.
    if not args.as_recorded:
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
    target = os.path.expanduser(args.path).rstrip("/")
    for row in report_module.verdicts_from_run(document):
        if row.group.path == target:
            console.print(f"[bold]{row.group.path}[/bold]  {row.tier}: {row.why}")
            print(json.dumps(asdict(row.judgment) if row.judgment else {}, indent=1))
            return 0
    console.print(f"[red]{args.path} is not in this run[/red]")
    return 1


def refuse_if_root() -> bool:
    """jev-cleaner must not be run under sudo.

    Two things go wrong at once. The API key and the network client end up in a
    root process, which is the opposite of what probe.py exists for. And sudo
    resets HOME, so every ~ root resolves under /root and the scan silently
    reports on the wrong account: a real run went from 59 candidate directories
    to 14 without saying anything was amiss.
    """
    if os.geteuid() != 0:
        return False
    console.print("[red]jev-cleaner must not be run with sudo.[/red]\n")
    console.print("It escalates on its own, only for the read-only probe, and only with --system.")
    console.print("Run it as yourself; it will ask for your password when it needs the probe:\n")
    console.print("  [bold]jev-cleaner scan --system --containers[/bold]\n")
    console.print("Under sudo, HOME becomes /root, so the scan would cover root's home and not yours.")
    return True


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    if refuse_if_root():
        return 2
    parser = argparse.ArgumentParser(prog="jev-cleaner", description="Report reclaimable disk space. Deletes nothing.")
    parser.add_argument("--runs", default="runs", help="directory holding run artifacts")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="walk, judge and write a run")
    s.add_argument("--system", action="store_true", help="also scan system locations through sudo")
    s.add_argument("--system-only", action="store_true")
    s.add_argument("--containers", action="store_true", help="also report reclaimable docker space")
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
    r.add_argument("--policy", default=None, help="policy file to re-tier with (default: the shipped one)")
    r.add_argument("--as-recorded", action="store_true",
                   help="show the tiers as they were when the run was taken, without re-tiering")
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
