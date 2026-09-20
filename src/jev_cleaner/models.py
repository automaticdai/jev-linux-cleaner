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
