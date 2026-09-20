import json

from jev_cleaner.roots import Root
from jev_cleaner.scan import scan, sudo_command


def test_user_scope_is_walked_in_process(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "f.bin").write_bytes(b"x" * 10)
    records = scan([Root(str(tmp_path), "user", 1)])
    assert {r.path for r in records} == {str(tmp_path), str(tmp_path / "app")}
    assert all(r.scope == "user" for r in records)


def test_system_scope_goes_through_the_injected_runner(tmp_path):
    calls: list[list[str]] = []

    def fake_runner(cmd: list[str]) -> str:
        calls.append(cmd)
        return json.dumps([{
            "path": "/var/log", "scope": "system", "size_bytes": 4096, "file_count": 7,
            "newest_mtime": 1.0, "oldest_mtime": 0.5, "extensions": {".log": 7},
            "sample_names": ["syslog"], "subdirs": [],
        }])

    records = scan([Root("/var/log", "system", 1)], runner=fake_runner)
    assert [r.path for r in records] == ["/var/log"]
    assert records[0].scope == "system"
    assert calls[0][:2] == ["sudo", "-n"]
    assert "jev_cleaner.probe" in calls[0]


def test_sudo_command_passes_roots_and_depth():
    cmd = sudo_command([Root("/var/log", "system", 3)])
    assert "--roots" in cmd and "/var/log" in cmd
    assert cmd[cmd.index("--max-depth") + 1] == "3"


def test_a_failing_system_probe_does_not_lose_user_results(tmp_path):
    (tmp_path / "app").mkdir()

    def angry_runner(cmd: list[str]) -> str:
        raise RuntimeError("sudo: a password is required")

    records = scan(
        [Root(str(tmp_path), "user", 1), Root("/var/log", "system", 1)],
        runner=angry_runner,
    )
    assert {r.path for r in records} == {str(tmp_path), str(tmp_path / "app")}
