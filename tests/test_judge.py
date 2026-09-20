import asyncio
import types

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
            "holds_installed_payload": FakeAnswer(noul=0.77),
            "fails_until_reinstall": FakeAnswer(noul=0.44),
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
    assert judgment.holds_installed_payload == 0.77
    assert judgment.fails_until_reinstall == 0.44
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
