"""The only module that talks to the network."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import asdict
from pathlib import Path

from .models import CandidateGroup, Judgment
from .questions import BATTERY_VERSION, battery

log = logging.getLogger(__name__)

DEFAULT_MODEL = "jev-1.13.0"
ESCALATION_CAP = 25
ESCALATION_MIN_BYTES = 500 * 1024 ** 2


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
        holds_installed_payload=nouls["holds_installed_payload"].noul,
        fails_until_reinstall=nouls["fails_until_reinstall"].noul,
        orphaned=nouls["orphaned"].noul,
        holds_credentials=nouls["holds_credentials"].noul,
        privacy_traces=nouls["privacy_traces"].noul,
        model=getattr(response, "model", DEFAULT_MODEL),
        escalated=escalated,
    )


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


async def judge_groups(
    states: dict[str, dict],
    client,
    cache: AnswerCache | None = None,
    concurrency: int = 8,
    model: str = DEFAULT_MODEL,
    mark_escalated: bool = False,
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
        judgment = judgment_from_response(response, escalated=mark_escalated)
        results[path] = judgment
        if cache is not None:
            cache.put(key, judgment)

    await asyncio.gather(*(one(path, state) for path, state in states.items()))
    return results
