import pytest

from jev_cleaner.models import CandidateGroup, Judgment
from jev_cleaner.policy import Thresholds, load_thresholds, tier_for, verdicts

T = Thresholds()
NOW = 1_758_000_000.0
DAY = 86400.0


def j(**over) -> Judgment:
    base = dict(
        content_kind="regenerable_cache", content_kind_confidence=0.9,
        content_kind_probabilities={"regenerable_cache": 0.9},
        loss_if_deleted=1.0, loss_confidence=0.9, breaks_if_deleted=0.05,
        recreated_automatically=0.95, holds_installed_payload=0.05,
        fails_until_reinstall=0.05, orphaned=0.02, holds_credentials=0.01,
        privacy_traces=0.01,
    )
    base.update(over)
    return Judgment(**base)


@pytest.mark.parametrize("judgment,expected", [
    (j(), "clean"),
    (j(content_kind="build_output"), "clean"),
    (j(content_kind="transient_runtime_state"), "clean"),
    (j(content_kind="downloaded_artifacts"), "costly"),
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
    # the two questions that carry restore effort, since the Score cannot
    (j(holds_installed_payload=0.6), "costly"),
    (j(holds_installed_payload=0.59), "clean"),
    (j(fails_until_reinstall=0.5), "costly"),
    (j(fails_until_reinstall=0.49), "clean"),
])
def test_tiering_boundaries(judgment, expected):
    assert tier_for(judgment, T)[0] == expected


def test_an_install_payload_outranks_a_confident_cache_reading():
    """ms-playwright reads as a cache and is 2 GB of browsers you must reinstall."""
    verdict, why = tier_for(j(content_kind="regenerable_cache", content_kind_confidence=0.95,
                              holds_installed_payload=0.81), T)
    assert verdict == "costly"
    assert "installed payload" in why


def test_why_names_the_deciding_judgment():
    assert "loss" in tier_for(j(loss_if_deleted=4.2), T)[1]
    assert "confidence" in tier_for(j(content_kind_confidence=0.3), T)[1]


def group(path="/h/.cache/x", size=10, newest=NOW - 400 * DAY):
    return CandidateGroup(path=path, scope="user", size_bytes=size, file_count=1,
                          newest_mtime=newest, oldest_mtime=newest,
                          extensions={}, sample_names=[], subdirs=[])


def test_denied_groups_become_denied_verdicts_with_no_judgment():
    out = verdicts([], {}, [(group("/etc/x"), "protected system location")], T, now=NOW)
    assert out[0].tier == "denied"
    assert out[0].judgment is None
    assert out[0].why == "protected system location"


def test_a_group_with_no_judgment_lands_in_review():
    out = verdicts([group()], {}, [], T, now=NOW)
    assert out[0].tier == "review"
    assert "no judgment" in out[0].why


def test_an_orphan_verdict_is_vetoed_when_the_directory_is_still_being_written():
    g = group(newest=NOW - 3 * DAY)
    out = verdicts([g], {g.path: j(orphaned=0.95)}, [], T, now=NOW)
    assert out[0].tier != "orphan"
    assert "still in use" in out[0].why


def test_an_idle_orphan_survives_the_veto():
    g = group(newest=NOW - 400 * DAY)
    out = verdicts([g], {g.path: j(orphaned=0.95)}, [], T, now=NOW)
    assert out[0].tier == "orphan"


def test_thresholds_load_from_yaml(tmp_path):
    cfg = tmp_path / "policy.yaml"
    cfg.write_text("clean_max_loss: 1.5\nconfidence_floor: 0.6\n")
    t = load_thresholds(str(cfg))
    assert t.clean_max_loss == 1.5
    assert t.confidence_floor == 0.6


def test_shipped_policy_file_parses():
    t = load_thresholds()
    assert t.costly_min_payload == 0.6
    assert t.orphan_idle_days == 30.0
