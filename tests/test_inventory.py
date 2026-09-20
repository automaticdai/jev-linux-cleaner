from jev_cleaner.inventory import Inventory, collect


def test_related_matches_on_substring_in_either_direction():
    inv = Inventory(names=frozenset({"python3-playwright", "firefox", "docker-ce", "libreoffice-calc"}))
    assert inv.related("ms-playwright") == ["python3-playwright"]
    assert inv.related("firefox") == ["firefox"]
    assert inv.related("libreoffice") == ["libreoffice-calc"]


def test_related_returns_empty_for_software_that_is_gone():
    inv = Inventory(names=frozenset({"firefox"}))
    assert inv.related("some-abandoned-tool") == []


def test_related_is_capped():
    inv = Inventory(names=frozenset(f"python3-mod{i}" for i in range(50)))
    assert len(inv.related("python3", limit=6)) == 6


def test_collect_parses_dpkg_and_snap_output():
    outputs = {
        "dpkg-query": "firefox\nsnapd\npython3.12\n",
        "snap": "Name    Version\ncore22  20240101\n",
        "docker": "",
    }

    def fake_runner(cmd: list[str]) -> str:
        return outputs.get(cmd[0], "")

    inv = collect(runner=fake_runner)
    assert {"firefox", "python3.12", "core22"} <= inv.names


def test_collect_tolerates_a_missing_package_manager(monkeypatch):
    monkeypatch.setenv("PATH", "")

    def broken_runner(cmd: list[str]) -> str:
        raise FileNotFoundError(cmd[0])

    assert collect(runner=broken_runner).names == frozenset()


def test_path_executables_are_part_of_the_inventory(tmp_path, monkeypatch):
    """Regression: with dpkg alone, uv and playwright looked uninstalled, and
    every cache directory they own was judged orphaned."""
    (tmp_path / "uv").write_text("#!/bin/sh\n")
    (tmp_path / "uv").chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    def no_packages(cmd: list[str]) -> str:
        return ""

    assert "uv" in collect(runner=no_packages).names
