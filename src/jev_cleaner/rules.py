"""A conventional rule list, kept only as a baseline to compare Jev against.

Nothing in the pipeline is gated on these verdicts. The point of the column is
the disagreements: they are where the open-world judgment either earns its place
or exposes a problem.
"""

from __future__ import annotations

import os

from .models import CandidateGroup

CLEAN_NAMES = frozenset({
    "thumbnails", "mesa_shader_cache", "mesa_shader_cache_db", "fontconfig",
    "pip", "node-gyp", "vscode-ripgrep", "tracker3", "gstreamer-1.0",
})
CLEAN_PREFIXES = ("/tmp", "/var/tmp", "/var/cache/apt/archives", "/var/cache/snapd")
KEEP_NAMES = frozenset({"keyrings", "gnupg", "ssh", "password-store", "chromium", "gnome-keyring"})


def baseline_tier(group: CandidateGroup) -> str | None:
    """`clean`, `keep`, or None when no rule covers this path."""
    path = os.path.normpath(group.path)
    name = os.path.basename(path)

    if name in KEEP_NAMES:
        return "keep"
    if name in CLEAN_NAMES:
        return "clean"
    for prefix in CLEAN_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return "clean"
    return None
