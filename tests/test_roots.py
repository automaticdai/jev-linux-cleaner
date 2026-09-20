from jev_cleaner.roots import load_roots


def test_loads_only_requested_scopes_and_expands_home(tmp_path):
    (tmp_path / ".cache").mkdir()
    cfg = tmp_path / "roots.yaml"
    cfg.write_text(
        "user:\n"
        "  - path: ~/.cache\n"
        "    max_depth: 1\n"
        "system:\n"
        "  - path: /var/cache/apt/archives\n"
        "    max_depth: 0\n"
    )
    roots = load_roots(str(cfg), scopes=("user",), home=str(tmp_path))
    assert [(r.path, r.scope, r.max_depth) for r in roots] == [
        (str(tmp_path / ".cache"), "user", 1)
    ]


def test_drops_roots_that_do_not_exist(tmp_path):
    cfg = tmp_path / "roots.yaml"
    cfg.write_text("user:\n  - path: ~/.nope\n    max_depth: 1\n")
    assert load_roots(str(cfg), scopes=("user",), home=str(tmp_path)) == []


def test_default_config_ships_with_the_package():
    roots_by_scope = {r.scope for r in load_roots(scopes=("user", "system"), home="/nonexistent-home")}
    assert roots_by_scope <= {"user", "system"}
