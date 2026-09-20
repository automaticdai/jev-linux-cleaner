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
                    holds_installed_payload=0.0, fails_until_reinstall=0.0,
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
                       ("breaks_if_deleted", "recreated_automatically", "holds_installed_payload",
                        "fails_until_reinstall", "orphaned", "holds_credentials", "privacy_traces")},
            )

    result = asyncio.run(judge_groups({"/h/x": {"directory": {"path": "/h/x"}}}, FakeClient(),
                                      cache=AnswerCache(tmp_path / "c.json"), mark_escalated=True))
    assert result["/h/x"].escalated is True
    assert result["/h/x"].content_kind == "build_output"
