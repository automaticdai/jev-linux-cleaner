from jev_cleaner.questions import BATTERY_VERSION, CONTENT_KINDS, LOSS_LEVELS, battery


def test_battery_has_every_question_from_the_spec():
    assert set(battery()) == {
        "content_kind", "loss_if_deleted", "breaks_if_deleted",
        "recreated_automatically", "orphaned", "holds_credentials", "privacy_traces",
    }


def test_content_kind_offers_an_unclear_option():
    assert "unclear" in CONTENT_KINDS
    assert len(CONTENT_KINDS) == 8


def test_loss_levels_are_ordered_and_self_contained():
    assert len(LOSS_LEVELS) == 5
    assert LOSS_LEVELS[0].startswith("Nothing noticeable")
    assert "cannot obtain again" in LOSS_LEVELS[4]
    assert all(len(level) > 40 for level in LOSS_LEVELS)


def test_every_question_names_the_directory_by_state_path():
    for qid, question in battery().items():
        assert "`directory.path`" in question.instructions, qid


def test_battery_version_is_pinned():
    assert BATTERY_VERSION == "1"
