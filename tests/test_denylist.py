from jev_cleaner.denylist import deny_reason, partition
from jev_cleaner.models import CandidateGroup

NOW = 1_758_000_000.0
HOME = "/home/u"


def g(path, newest=NOW - 86400.0):
    return CandidateGroup(
        path=path, scope="user", size_bytes=1024, file_count=1,
        newest_mtime=newest, oldest_mtime=newest,
        extensions={}, sample_names=[], subdirs=[],
    )


def test_system_roots_are_denied():
    assert deny_reason(g("/etc/nginx"), NOW, HOME) == "protected system location"
    assert deny_reason(g("/boot/grub"), NOW, HOME) == "protected system location"
    assert deny_reason(g("/usr/lib/python3"), NOW, HOME) == "protected system location"


def test_listed_system_caches_are_allowed_through():
    assert deny_reason(g("/var/cache/apt/archives"), NOW, HOME) is None
    assert deny_reason(g("/var/log/nginx"), NOW, HOME) is None


def test_secrets_and_user_content_are_denied():
    assert deny_reason(g(f"{HOME}/.ssh"), NOW, HOME) == "credentials or keys"
    assert deny_reason(g(f"{HOME}/.gnupg/private-keys"), NOW, HOME) == "credentials or keys"
    assert deny_reason(g(f"{HOME}/Documents/taxes"), NOW, HOME) == "user content"


def test_recently_modified_groups_are_denied():
    assert deny_reason(g(f"{HOME}/.cache/live", newest=NOW - 60), NOW, HOME) == "modified in the last 15 minutes"


def test_a_git_working_tree_is_denied():
    def git_check(path: str) -> bool:
        return path.startswith(f"{HOME}/src/project")

    assert deny_reason(g(f"{HOME}/src/project/build"), NOW, HOME, git_check=git_check) == "inside a git working tree"


def test_user_protect_list_is_honoured():
    assert deny_reason(g(f"{HOME}/.cache/keepme"), NOW, HOME, protect=(f"{HOME}/.cache/keepme",)) == "listed under protect"


def test_partition_splits_allowed_from_denied():
    allowed, denied = partition([g(f"{HOME}/.cache/ok"), g("/etc/x")], NOW, HOME)
    assert [x.path for x in allowed] == [f"{HOME}/.cache/ok"]
    assert denied[0][1] == "protected system location"
