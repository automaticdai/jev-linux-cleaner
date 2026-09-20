import json
import os
import subprocess
import sys

from jev_cleaner.probe import walk


def build_tree(tmp_path):
    (tmp_path / "app" / "sub").mkdir(parents=True)
    (tmp_path / "app" / "a.whl").write_bytes(b"x" * 100)
    (tmp_path / "app" / "sub" / "b.whl").write_bytes(b"y" * 50)
    (tmp_path / "app" / "sub" / "c.txt").write_bytes(b"z" * 10)
    os.symlink(tmp_path / "app", tmp_path / "link-to-app")
    return tmp_path


def test_walk_rolls_descendants_into_one_record(tmp_path):
    build_tree(tmp_path)
    records = {r["path"]: r for r in walk(str(tmp_path), scope="user", max_depth=1)}
    app = records[str(tmp_path / "app")]
    assert app["size_bytes"] == 160
    assert app["file_count"] == 3
    assert app["extensions"][".whl"] == 2
    assert app["subdirs"] == ["sub"]
    assert app["scope"] == "user"


def test_walk_does_not_follow_symlinks(tmp_path):
    build_tree(tmp_path)
    paths = [r["path"] for r in walk(str(tmp_path), scope="user", max_depth=1)]
    assert str(tmp_path / "link-to-app") not in paths


def test_walk_survives_an_unreadable_directory(tmp_path):
    build_tree(tmp_path)
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "secret").write_bytes(b"s")
    os.chmod(locked, 0o000)
    try:
        records = {r["path"]: r for r in walk(str(tmp_path), scope="user", max_depth=1)}
        assert records[str(locked)]["size_bytes"] == 0
        assert records[str(locked)]["unreadable"] is True
    finally:
        os.chmod(locked, 0o755)


def test_module_entry_point_prints_json(tmp_path):
    build_tree(tmp_path)
    out = subprocess.run(
        [sys.executable, "-m", "jev_cleaner.probe", "--roots", str(tmp_path),
         "--scope", "system", "--max-depth", "1"],
        capture_output=True, text=True, check=True,
    )
    payload = json.loads(out.stdout)
    assert any(r["path"].endswith("/app") for r in payload)
    assert all(r["scope"] == "system" for r in payload)
