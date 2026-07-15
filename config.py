import logging
import os
from dataclasses import dataclass

from dotenv import load_dotenv

DEFAULT_ENV_FILE = ".env"
DEFAULT_TARGET_PURPOSE = "A helpful AI assistant"
DEFAULT_OPENAI_RETRIES = 3

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Config:
    target_model: str
    target_purpose: str
    max_goldens: int
    openai_retries: int


def load_environment(env_file=DEFAULT_ENV_FILE):
    load_dotenv(env_file, override=False)


def get_env_int(name, default):
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default

    try:
        return int(raw_value)
    except ValueError:
        logger.warning("Invalid integer in %s=%r. Using default=%s.", name, raw_value, default)
        return default


def get_env_str(name, default=""):
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    value = raw_value.strip()
    return value if value else default


def require_openai_api_key():
    if not os.getenv("OPENAI_API_KEY", "").strip():
        raise RuntimeError("OPENAI_API_KEY is not set. Add it to .env.")


def load_config():
    return Config(
        target_model=get_env_str("OPENAI_MODEL"),
        target_purpose=get_env_str("TARGET_PURPOSE", DEFAULT_TARGET_PURPOSE),
        max_goldens=get_env_int("MAX_GOLDENS", 1),
        openai_retries=max(1, get_env_int("OPENAI_MAX_RETRIES", DEFAULT_OPENAI_RETRIES)),
    )
