from jev_cleaner.evidence import age_phrase, build_state, humanize_size, location_convention, size_bucket
from jev_cleaner.inventory import Inventory
from jev_cleaner.models import CandidateGroup

DAY = 86400.0
NOW = 1_758_000_000.0
GB = 1024 ** 3


def group(path="/home/u/.cache/ms-playwright", size=2 * GB, newest=NOW - 3 * DAY, oldest=NOW - 240 * DAY):
    return CandidateGroup(
        path=path, scope="user", size_bytes=size, file_count=12_000,
        newest_mtime=newest, oldest_mtime=oldest,
        extensions={".so": 3100, ".pak": 210, "": 900},
        sample_names=["chromium-1140/chrome-linux/chrome", ".links"],
        subdirs=["chromium-1140", "firefox-1450"],
    )


def test_sizes_become_words():
    assert humanize_size(2 * GB) == "2.0 GB"
    assert humanize_size(500) == "500 bytes"
    assert size_bucket(2 * GB) == "very large, over 1 GB"
    assert size_bucket(5 * 1024 ** 2) == "small, a few megabytes"


def test_ages_become_phrases_never_dates():
    assert age_phrase(NOW - 2 * DAY, NOW) == "within the last week"
    assert age_phrase(NOW - 400 * DAY, NOW) == "over a year ago"
    assert age_phrase(NOW - 45 * DAY, NOW) == "one to three months ago"


def test_location_convention_states_the_location_without_prejudging_it():
    """Regression: saying ~/.cache holds regenerable data made the model adopt
    that conclusion over the evidence, rating a 2 GB browser download costless."""
    cache = location_convention("/home/u/.cache/foo")
    assert "~/.cache" in cache
    assert "do not always follow" in cache
    assert "regenerable" not in cache
    assert "configuration" in location_convention("/home/u/.config/foo")
    assert location_convention("/var/log/nginx") != ""


def test_state_contains_only_words_for_numbers_and_only_related_packages():
    inv = Inventory(names=frozenset({"python3-playwright", "firefox", "nginx"}))
    state = build_state(group(), inv, now=NOW)
    assert state["directory"]["size"] == "2.0 GB"
    assert state["directory"]["last_modified"] == "within the last week"
    assert state["directory"]["oldest_content"] == "over six months ago"
    assert state["directory"]["file_count"] == "about 12,000 files"
    assert state["directory"]["top_extensions"][0] == ".so (3,100 files)"
    assert state["system"]["possibly_related_installed_software"] == ["python3-playwright"]
    assert "nginx" not in str(state)


def test_state_reports_when_no_related_software_is_installed():
    state = build_state(group(path="/home/u/.config/abandoned-tool"), Inventory(frozenset({"firefox"})), now=NOW)
    assert state["system"]["possibly_related_installed_software"] == []
    assert "not by itself proof" in state["system"]["inventory_covers"]
