from jev_cleaner.models import CandidateGroup
from jev_cleaner.rules import baseline_tier


def g(path):
    return CandidateGroup(
        path=path, scope="user", size_bytes=1024, file_count=1,
        newest_mtime=0.0, oldest_mtime=0.0, extensions={}, sample_names=[], subdirs=[],
    )


def test_known_throwaway_paths_are_clean():
    assert baseline_tier(g("/home/u/.cache/thumbnails")) == "clean"
    assert baseline_tier(g("/home/u/.cache/mesa_shader_cache")) == "clean"
    assert baseline_tier(g("/var/cache/apt/archives")) == "clean"
    assert baseline_tier(g("/tmp/whatever")) == "clean"


def test_known_valuable_paths_are_keep():
    assert baseline_tier(g("/home/u/.local/share/keyrings")) == "keep"
    assert baseline_tier(g("/home/u/.config/gnupg")) == "keep"


def test_an_unknown_path_has_no_baseline():
    assert baseline_tier(g("/home/u/.cache/some-tool-released-last-month")) is None
    assert baseline_tier(g("/home/u/.cache/uv")) is None
