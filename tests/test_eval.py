"""Opt-in agreement check: `pytest -m eval`. Reads the stored run, not the API."""

import json
import os
from pathlib import Path

import pytest

from jev_cleaner.report import load_run, verdicts_from_run

LABELS = Path(__file__).parent / "fixtures" / "labels.json"
RUNS = Path("runs")
OFFERED = {"clean", "costly"}
AGREEMENT_BAR = 0.8


def _latest_run() -> Path | None:
    runs = sorted(p for p in RUNS.glob("*") if (p / "run.json").exists())
    return runs[-1] if runs else None


@pytest.mark.eval
def test_agreement_with_hand_labels():
    run_dir = _latest_run()
    if run_dir is None:
        pytest.skip("no run yet; run `jev-cleaner scan` first")

    labels = {os.path.expanduser(row["path"]): row for row in json.loads(LABELS.read_text())}
    by_path = {v.group.path: v for v in verdicts_from_run(load_run(run_dir / "run.json"))}

    # A floor-denied row was never judged, so it is not evidence about the
    # model either way. Report it, but do not score it.
    held_back = [(p, by_path[p].why) for p in labels
                 if p in by_path and by_path[p].tier == "denied"]
    scored = [(p, labels[p]["expected"], by_path[p].tier, by_path[p].why)
              for p in labels if p in by_path and by_path[p].tier != "denied"]
    if not scored:
        pytest.skip("no labelled directory appears in the latest run")

    for path, why in sorted(held_back):
        print(f"  held back by the floor, not judged: {path} ({why})")

    mismatches = [(p, want, got, why) for p, want, got, why in scored if want != got]
    agreement = 1 - len(mismatches) / len(scored)

    print(f"\nagreement: {agreement:.0%} over {len(scored)} labelled directories")
    for path, want, got, why in sorted(mismatches):
        print(f"  want {want:<7} got {got:<7} {path}  ({why})")

    # The one that is a defect rather than a tuning question: something the user
    # said to keep, offered for deletion. Fix the floor or the battery, never
    # the label.
    unsafe = [(p, want, got) for p, want, got, _ in mismatches if want == "keep" and got in OFFERED]
    assert not unsafe, f"directories labelled keep were offered for deletion: {unsafe}"
    assert agreement >= AGREEMENT_BAR, f"agreement {agreement:.0%} is below the {AGREEMENT_BAR:.0%} bar"
