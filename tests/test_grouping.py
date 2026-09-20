from jev_cleaner.evidence import group_records
from jev_cleaner.models import ScanRecord
from jev_cleaner.roots import Root

MB = 1024 ** 2


def rec(path, size, subdirs=(), scope="user"):
    return ScanRecord(
        path=path, scope=scope, size_bytes=size, file_count=max(size // 1000, 1),
        newest_mtime=1_758_000_000.0, oldest_mtime=1_726_000_000.0,
        extensions={".bin": 1}, sample_names=["f.bin"], subdirs=list(subdirs),
    )


def test_immediate_children_of_a_root_become_groups_and_the_root_does_not():
    records = [
        rec("/h/.cache", 300 * MB, subdirs=["a", "b"]),
        rec("/h/.cache/a", 200 * MB),
        rec("/h/.cache/b", 100 * MB),
    ]
    groups = group_records(records, [Root("/h/.cache", "user", 1)])
    assert [g.path for g in groups] == ["/h/.cache/a", "/h/.cache/b"]


def test_a_large_heterogeneous_group_is_split_one_level_deeper():
    records = [
        rec("/h/.cache", 1200 * MB, subdirs=["big"]),
        rec("/h/.cache/big", 1200 * MB, subdirs=["x", "y", "z"]),
        rec("/h/.cache/big/x", 400 * MB),
        rec("/h/.cache/big/y", 400 * MB),
        rec("/h/.cache/big/z", 400 * MB),
    ]
    groups = group_records(records, [Root("/h/.cache", "user", 2)])
    assert [g.path for g in groups] == ["/h/.cache/big/x", "/h/.cache/big/y", "/h/.cache/big/z"]


def test_a_large_but_dominated_group_is_kept_whole():
    records = [
        rec("/h/.cache", 1000 * MB, subdirs=["big"]),
        rec("/h/.cache/big", 1000 * MB, subdirs=["x", "y"]),
        rec("/h/.cache/big/x", 950 * MB),
        rec("/h/.cache/big/y", 50 * MB),
    ]
    groups = group_records(records, [Root("/h/.cache", "user", 2)])
    assert [g.path for g in groups] == ["/h/.cache/big"]


def test_groups_are_capped_largest_first():
    records = [rec("/h/.cache", 100 * MB, subdirs=[str(i) for i in range(10)])]
    records += [rec(f"/h/.cache/{i}", i * MB) for i in range(10)]
    groups = group_records(records, [Root("/h/.cache", "user", 1)], cap=3)
    assert [g.path for g in groups] == ["/h/.cache/9", "/h/.cache/8", "/h/.cache/7"]


def test_empty_directories_are_dropped():
    records = [rec("/h/.cache", 0, subdirs=["empty"]), rec("/h/.cache/empty", 0)]
    assert group_records(records, [Root("/h/.cache", "user", 1)]) == []
