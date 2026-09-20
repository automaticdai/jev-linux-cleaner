"""Raw judgments to tiers. Pure, and the only place risk tolerance is encoded.

Because this runs on stored judgments, changing a threshold re-tiers a whole
past run with no new requests.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path

import yaml

from .models import CandidateGroup, Judgment, Verdict
from .rules import baseline_tier

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config" / "policy.yaml"

CLEANABLE_KINDS = frozenset({"regenerable_cache", "build_output", "transient_runtime_state"})
KEEP_KINDS = frozenset({"user_content", "application_settings", "installed_program_files"})


@dataclass(frozen=True)
class Thresholds:
    confidence_floor: float = 0.5
    clean_min_confidence: float = 0.7
    clean_max_loss: float = 2.0
    clean_max_breaks: float = 0.15
    clean_max_credentials: float = 0.10
    costly_min_payload: float = 0.6
    costly_min_fails: float = 0.5
    keep_min_loss: float = 4.0
    keep_min_breaks: float = 0.5
    orphan_min: float = 0.8
    orphan_idle_days: float = 30.0


def load_thresholds(path: str | None = None) -> Thresholds:
    config_path = Path(path) if path else DEFAULT_CONFIG
    data = yaml.safe_load(config_path.read_text()) or {}
    known = {f.name for f in fields(Thresholds)}
    return Thresholds(**{k: float(v) for k, v in data.items() if k in known})


def _needs_user_action(judgment: Judgment, t: Thresholds) -> bool:
    """Would getting this back take a command from the user?

    The loss Score cannot answer this: it rates a shader cache and 2 GB of
    browser binaries the same. These two Nouls ask what is in the directory
    rather than what would happen, and separate them cleanly.
    """
    return (
        judgment.holds_installed_payload >= t.costly_min_payload
        or judgment.fails_until_reinstall >= t.costly_min_fails
    )


def tier_for(judgment: Judgment, t: Thresholds) -> tuple[str, str]:
    """The most conservative tier that matches wins: keep, review, orphan, costly, clean."""
    if judgment.content_kind in KEEP_KINDS:
        return "keep", f"content is {judgment.content_kind.replace('_', ' ')}"
    if judgment.loss_if_deleted >= t.keep_min_loss:
        return "keep", f"loss level {judgment.loss_if_deleted:.1f}: user data would be destroyed"
    if judgment.breaks_if_deleted > t.keep_min_breaks:
        return "keep", f"would break the installed software (p={judgment.breaks_if_deleted:.2f})"

    if judgment.content_kind == "unclear":
        return "review", "the evidence does not identify what is stored here"
    if judgment.content_kind_confidence < t.confidence_floor:
        return "review", f"low confidence on content ({judgment.content_kind_confidence:.2f})"
    if judgment.loss_confidence < t.confidence_floor:
        return "review", f"low confidence on loss ({judgment.loss_confidence:.2f})"

    if judgment.orphaned >= t.orphan_min:
        return "orphan", f"owning software appears to be gone (p={judgment.orphaned:.2f})"

    if judgment.holds_installed_payload >= t.costly_min_payload:
        return "costly", f"installed payload, not generated data (p={judgment.holds_installed_payload:.2f})"
    if judgment.fails_until_reinstall >= t.costly_min_fails:
        return "costly", f"deleting it means reinstalling something (p={judgment.fails_until_reinstall:.2f})"
    if judgment.holds_credentials > t.clean_max_credentials:
        return "costly", f"deleting it would sign you out (p={judgment.holds_credentials:.2f})"
    if judgment.content_kind == "downloaded_artifacts":
        return "costly", "downloaded artifacts: re-fetching them costs time and bandwidth"

    clean = (
        judgment.content_kind in CLEANABLE_KINDS
        and judgment.content_kind_confidence >= t.clean_min_confidence
        and judgment.loss_if_deleted <= t.clean_max_loss
        and judgment.breaks_if_deleted <= t.clean_max_breaks
    )
    if clean:
        return "clean", f"{judgment.content_kind.replace('_', ' ')}, the program rebuilds it"

    if judgment.loss_if_deleted > t.clean_max_loss:
        return "costly", f"loss level {judgment.loss_if_deleted:.1f}: restoring it takes a command"
    return "review", f"{judgment.content_kind.replace('_', ' ')} below the clean bar"


def verdicts(
    groups: list[CandidateGroup],
    judgments: dict[str, Judgment],
    denied: list[tuple[CandidateGroup, str]],
    t: Thresholds,
    now: float,
) -> list[Verdict]:
    out: list[Verdict] = []
    for group in groups:
        judgment = judgments.get(group.path)
        if judgment is None:
            out.append(Verdict(group=group, tier="review", why="no judgment was returned for this directory",
                               judgment=None, baseline=baseline_tier(group)))
            continue
        tier, why = tier_for(judgment, t)
        # Code owns recency, not the model: a directory written to this month is
        # in use, whatever the inventory suggests about its owner.
        idle_days = (now - group.newest_mtime) / 86400.0
        if tier == "orphan" and idle_days < t.orphan_idle_days:
            tier, why = tier_for(
                Judgment(**{**judgment.__dict__, "orphaned": 0.0}), t
            )
            why = f"{why} (still in use: modified {idle_days:.0f} days ago)"
        out.append(Verdict(group=group, tier=tier, why=why, judgment=judgment, baseline=baseline_tier(group)))
    for group, reason in denied:
        out.append(Verdict(group=group, tier="denied", why=reason, judgment=None, baseline=baseline_tier(group)))
    out.sort(key=lambda v: -v.group.size_bytes)
    return out
