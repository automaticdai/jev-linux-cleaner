"""Capture a scan of this machine as a test fixture.

The output names real directories on your machine, so it is gitignored. Every
test that uses it skips when it is absent; run this to enable them.

    python scripts/capture_scan.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jev_cleaner.models import to_dict
from jev_cleaner.roots import load_roots
from jev_cleaner.scan import scan

TARGET = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "scan-ubuntu-2404.json"


def main() -> int:
    roots = load_roots(scopes=("user",))
    if not roots:
        print("no user scan roots exist on this machine", file=sys.stderr)
        return 1
    records = scan(roots)
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(json.dumps([to_dict(r) for r in records], indent=1))
    print(f"{len(records)} records from {len(roots)} roots -> {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
