from jev_cleaner.models import CandidateGroup, ScanRecord, record_from_dict, to_dict


def make_record(**over) -> ScanRecord:
    base = dict(
        path="/home/u/.cache/uv",
        scope="user",
        size_bytes=6_227_020_800,
        file_count=120_000,
        newest_mtime=1_758_000_000.0,
        oldest_mtime=1_726_000_000.0,
        extensions={".whl": 900, "": 400},
        sample_names=["archive-v0/abc", "sdists-v7/x"],
        subdirs=["archive-v0", "sdists-v7"],
    )
    base.update(over)
    return ScanRecord(**base)


def test_scan_record_round_trips_through_json_shaped_dict():
    record = make_record()
    restored = record_from_dict(to_dict(record))
    assert restored == record


def test_candidate_group_is_hashable_and_ordered_by_size():
    small = CandidateGroup(**{**to_dict(make_record()), "size_bytes": 10})
    large = CandidateGroup(**to_dict(make_record()))
    assert sorted([small, large], key=lambda g: -g.size_bytes)[0] is large
    assert {small, large}  # frozen dataclasses are hashable
