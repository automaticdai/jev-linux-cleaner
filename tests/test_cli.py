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
                        holds_installed_payload=0.3, fails_until_reinstall=0.2,
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


def test_running_as_root_is_refused(monkeypatch, capsys):
    """sudo puts the API key in a root process and resets HOME to /root, so the
    scan silently covers the wrong account."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert main(["scan"]) == 2
    out = capsys.readouterr().out
    assert "must not be run with sudo" in out
    assert "/root" in out


def test_a_normal_user_is_not_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    directory = a_run(tmp_path)
    assert main(["report", "--run", str(directory), "--format", "json"]) == 0
