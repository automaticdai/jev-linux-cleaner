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
                        holds_installed_payload=0.3, fails_until_reinstall=0.2,
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
