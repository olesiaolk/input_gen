import os

import pytest

from config import get_env_int, load_environment, require_openai_api_key


def test_get_env_int_uses_default_for_missing(monkeypatch):
    monkeypatch.delenv("MAX_GOLDENS", raising=False)

    assert get_env_int("MAX_GOLDENS", 3) == 3


def test_get_env_int_uses_default_for_invalid(monkeypatch):
    monkeypatch.setenv("MAX_GOLDENS", "many")

    assert get_env_int("MAX_GOLDENS", 3) == 3


def test_load_environment_does_not_override_existing_env(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_MODEL=from-file\n", encoding="utf-8")
    monkeypatch.setenv("OPENAI_MODEL", "from-env")

    load_environment(env_file)

    assert os.environ["OPENAI_MODEL"] == "from-env"


def test_require_openai_api_key_rejects_missing_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY is not set"):
        require_openai_api_key()
