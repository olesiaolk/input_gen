from strategies import LEGACY_STRATEGY_ALIASES, is_truthy, load_enabled_strategies, normalize_strategy_name


class DummyStrategy:
    pass


def test_normalize_strategy_name_removes_case_and_punctuation():
    assert normalize_strategy_name(" ROT-13 ") == "rot13"
    assert normalize_strategy_name("Prompt Injection") == "promptinjection"


def test_legacy_aliases_cover_known_old_names():
    assert LEGACY_STRATEGY_ALIASES["CharacterStream"] == ["LinguisticConfusion"]
    assert "GoalRedirection" in LEGACY_STRATEGY_ALIASES["EmotionalManipulation"]
    assert "ContextPoisoning" in LEGACY_STRATEGY_ALIASES["SemanticManipulation"]


def test_is_truthy_handles_common_disabled_values():
    for value in ["false", "0", "no", "f", ""]:
        assert is_truthy(value) is False

    for value in ["true", "1", "yes", "anything"]:
        assert is_truthy(value) is True


def test_load_enabled_strategies_filters_and_normalizes(tmp_path):
    csv_file = tmp_path / "strategies.csv"
    csv_file.write_text(
        "enabled,strategy_name\n"
        "True,ROT-13\n"
        "False,Base64\n"
        "True,Unknown\n",
        encoding="utf-8",
    )
    rot13 = DummyStrategy()
    base64 = DummyStrategy()

    active, skipped = load_enabled_strategies(csv_file, {"ROT13": rot13, "Base64": base64})

    assert active == [rot13]
    assert skipped == 2
