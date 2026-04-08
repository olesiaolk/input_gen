import argparse
import os
import csv
import pandas as pd
import logging
import inspect
import importlib.util
import importlib
import pkgutil
import re
import time
from datetime import datetime

# --- DEEPTEAM IMPORTS ---
DEEPTEAM_IMPORT_ERROR = None
try:
    from deepteam.vulnerabilities import (
        PIILeakage, Bias, GraphicContent,
        PersonalSafety, Toxicity, IllegalActivity, Misinformation
    )

    # Імпортуємо всі можливі стратегії.
    # Якщо якоїсь із них немає у вашій версії deepteam, просто закоментуйте її тут.
    from deepteam.attacks.single_turn import (
        Base64, Leetspeak, ROT13, GrayBox, PromptInjection, Roleplay
    )
except Exception as e:
    DEEPTEAM_IMPORT_ERROR = e

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)
EXPECTED_DEEPTEAM_VERSION = "1.0.5"
DEFAULT_ENV_FILE = ".env"
DEFAULT_TARGET_PURPOSE = "A helpful AI assistant"
DEFAULT_OPENAI_RETRIES = 3


def _load_dotenv(filepath=DEFAULT_ENV_FILE):
    if not os.path.exists(filepath):
        return

    try:
        with open(filepath, "r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as e:
        logger.warning("Failed to load %s: %s", filepath, e)


def _get_env_int(name, default):
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default

    try:
        return int(raw_value)
    except ValueError:
        logger.warning("Invalid integer in %s=%r. Using default=%s.", name, raw_value, default)
        return default


def _get_env_str(name, default=""):
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    value = raw_value.strip()
    return value if value else default


def _stringify_error(error):
    return f"{error.__class__.__name__}: {error}".strip()


def _is_openai_error(error):
    error_type = error.__class__.__name__.lower()
    error_module = error.__class__.__module__.lower()
    error_text = str(error).lower()
    return any(
        marker in f"{error_module} {error_type} {error_text}"
        for marker in ["openai", "rate limit", "api connection", "timeout", "server error"]
    )


def _call_with_supported_kwargs(callable_obj, **candidate_kwargs):
    try:
        signature = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return callable_obj()

    supported_kwargs = {
        key: value
        for key, value in candidate_kwargs.items()
        if value is not None and key in signature.parameters
    }
    return callable_obj(**supported_kwargs)


_load_dotenv()


def _import_strategy_class(name):
    """
    Safely import a strategy class from deepteam attacks modules.
    Returns class object or None when strategy is unavailable.
    """
    module_candidates = ["deepteam.attacks.single_turn", "deepteam.attacks"]
    for module_name in module_candidates:
        try:
            module = importlib.import_module(module_name)
            strategy_cls = getattr(module, name, None)
            if strategy_cls is not None:
                return strategy_cls
        except Exception:
            continue

    # Fallback: scan all deepteam.attacks submodules for the class.
    try:
        attacks_pkg = importlib.import_module("deepteam.attacks")
        for mod_info in pkgutil.walk_packages(attacks_pkg.__path__, attacks_pkg.__name__ + "."):
            module_name = mod_info.name
            try:
                module = importlib.import_module(module_name)
            except Exception:
                continue
            strategy_cls = getattr(module, name, None)
            if strategy_cls is not None:
                return strategy_cls
    except Exception:
        pass

    return None


def _normalize_strategy_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name or "").strip().lower())


LEGACY_STRATEGY_ALIASES = {
    # Legacy names from older configs mapped to deepteam==1.0.5 strategies.
    "CharacterStream": ["LinguisticConfusion"],
    "EmotionalManipulation": ["GoalRedirection"],
    "SemanticManipulation": ["ContextPoisoning"],
    "Multilingual": ["Multilingual", "LanguageSwitch", "MultiLanguage", "MultilingualObfuscation"],
}


class AttackGenerator:
    def __init__(self, vuln_file, strat_file, plugins_file=None):
        if DEEPTEAM_IMPORT_ERROR is not None:
            raise RuntimeError(
                f"deepteam is required to run generation: {DEEPTEAM_IMPORT_ERROR}"
            ) from DEEPTEAM_IMPORT_ERROR
        try:
            import deepteam  # local import to keep startup tolerant for --help
            actual_version = getattr(deepteam, "__version__", "unknown")
            if actual_version != EXPECTED_DEEPTEAM_VERSION:
                logger.warning(
                    "Expected deepteam==%s, found %s. Strategy compatibility may differ.",
                    EXPECTED_DEEPTEAM_VERSION,
                    actual_version,
                )
        except Exception:
            logger.warning("Could not verify deepteam version.")

        self.vuln_file = vuln_file
        self.strat_file = strat_file
        self.target_model = _get_env_str("OPENAI_MODEL")
        self.target_purpose = _get_env_str("TARGET_PURPOSE", DEFAULT_TARGET_PURPOSE)
        self.max_goldens = _get_env_int("MAX_GOLDENS", 1)
        self.openai_retries = max(1, _get_env_int("OPENAI_MAX_RETRIES", DEFAULT_OPENAI_RETRIES))

        # 1. Реєстр вразливостей
        self.vuln_registry = {
            "PIILeakage": PIILeakage,
            "Bias": Bias,
            "GraphicContent": GraphicContent,
            "PersonalSafety": PersonalSafety,
            "Toxicity": Toxicity,
            "IllegalActivity": IllegalActivity,
            "Misinformation": Misinformation
        }

        if plugins_file:
            self._load_plugins(plugins_file)

        # 2. Реєстр стратегій
        self.strategies_map = {
            "Base64": Base64(),
            "Leetspeak": Leetspeak(),
            "ROT13": ROT13(),
            "GrayBox": GrayBox(),
            "PromptInjection": PromptInjection(),
            "Roleplay": Roleplay(role="System Tester", persona="System Tester")
        }

        # Динамічно додаємо додаткові стратегії: кожну окремо, щоб відсутність однієї
        # не ламала імпорт інших.
        optional_strategy_names = [
            "CharacterStream",
            "EmotionalManipulation",
            "SemanticManipulation",
            "Multilingual",
        ]
        for strategy_name in optional_strategy_names:
            strategy_cls = _import_strategy_class(strategy_name)
            if strategy_cls is None:
                for alias in LEGACY_STRATEGY_ALIASES.get(strategy_name, []):
                    strategy_cls = _import_strategy_class(alias)
                    if strategy_cls is not None:
                        logger.info(f"Mapped legacy strategy '{strategy_name}' to '{alias}'")
                        break
            if strategy_cls is None:
                continue
            try:
                self.strategies_map[strategy_name] = strategy_cls()
            except Exception as e:
                logger.debug(f"Failed to initialize strategy '{strategy_name}': {e}")

        # Normalized alias map allows robust CSV naming (e.g. ROT13 vs Rot13).
        self.strategy_aliases = {
            _normalize_strategy_name(name): name for name in self.strategies_map
        }

        # 3. Завантажуємо тільки УВІМКНЕНІ стратегії
        self.strategies = self._load_strategies()
        self._setup_output()

    def _load_plugins(self, filepath):
        if not os.path.exists(filepath): return
        spec = importlib.util.spec_from_file_location("custom_attacks", filepath)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from deepteam.vulnerabilities import CustomVulnerability
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, CustomVulnerability) and obj is not CustomVulnerability:
                self.vuln_registry[name] = obj
                logger.info(f"🔌 Custom Attack Registered: {name}")

    def _load_strategies(self):
        """Читає strategies.csv і фільтрує за колонкою enabled"""
        active = []
        if os.path.exists(self.strat_file):
            try:
                df = pd.read_csv(self.strat_file).fillna("")
                for idx, row in df.iterrows():
                    # Перевіряємо чи стратегія увімкнена
                    is_enabled = str(row.get("enabled", "True")).strip().lower()
                    if is_enabled in ["false", "0", "no", "f", ""]:
                        continue

                    raw_name = row.get("strategy_name")
                    canonical_name = self.strategy_aliases.get(_normalize_strategy_name(raw_name))
                    if canonical_name in self.strategies_map:
                        active.append(self.strategies_map[canonical_name])
                    else:
                        logger.warning(f"Strategy '{raw_name}' not mapped or not supported by current deepteam version.")
            except Exception as e:
                logger.error(f"Error reading strategies: {e}")

        if not active:
            logger.warning("No active strategies found! Using Base only.")

        return active

    def _setup_output(self):
        os.makedirs("output_data", exist_ok=True)
        self.output_csv = f"output_data/generated_inputs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(self.output_csv, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(
                ["risk_factor", "type", "strategy", "is_transformed", "generated_input", "error"]
            )

    def _apply_runtime_config(self, obj):
        for attr_name, value in {
            "model": self.target_model,
            "purpose": self.target_purpose,
            "target_purpose": self.target_purpose,
            "max_goldens": self.max_goldens,
        }.items():
            if value is None:
                continue
            try:
                setattr(obj, attr_name, value)
            except Exception:
                continue

    def _create_vulnerability_instance(self, vuln_class):
        vuln_instance = _call_with_supported_kwargs(
            vuln_class,
            model=self.target_model,
            purpose=self.target_purpose,
            target_purpose=self.target_purpose,
            max_goldens=self.max_goldens,
        )
        self._apply_runtime_config(vuln_instance)
        return vuln_instance

    def _simulate_attacks(self, vuln_instance, attacks_per_risk):
        return _call_with_supported_kwargs(
            vuln_instance.simulate_attacks,
            attacks_per_vulnerability_type=attacks_per_risk,
            max_goldens=attacks_per_risk,
            purpose=self.target_purpose,
            target_purpose=self.target_purpose,
            model=self.target_model,
        )

    def _run_with_retries(self, operation, context):
        last_error = None
        for attempt in range(1, self.openai_retries + 1):
            try:
                return operation(), None
            except Exception as e:
                last_error = e
                if not _is_openai_error(e) or attempt == self.openai_retries:
                    break
                logger.warning(
                    "OpenAI error during %s. Retry %s/%s: %s",
                    context,
                    attempt,
                    self.openai_retries,
                    e,
                )
                time.sleep(min(attempt, 3))

        return None, _stringify_error(last_error)

    def _write_result_row(self, writer, risk, vuln_type, strategy, is_transformed, generated_input="", error=""):
        writer.writerow([risk, vuln_type, strategy, str(bool(is_transformed)).lower(), generated_input, error])

    def run(self, attacks_per_risk=1):
        try:
            df = pd.read_csv(self.vuln_file).fillna("")
        except Exception as e:
            logger.error(f"Failed to read CSV: {e}")
            return

        with open(self.output_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            for idx, row in df.iterrows():
                # Перевіряємо чи вразливість увімкнена
                is_enabled = str(row.get("enabled", "True")).strip().lower()
                if is_enabled in ["false", "0", "no", "f", ""]:
                    continue

                vuln_type = row.get("type")
                risk = row.get("risk_factor", "General")

                VulnClass = self.vuln_registry.get(vuln_type)
                if not VulnClass:
                    logger.warning(f"Unknown vulnerability type: {vuln_type}. Skipping.")
                    continue

                logger.info(f"⏳ Generating inputs for: {vuln_type}")

                try:
                    vuln_instance = self._create_vulnerability_instance(VulnClass)
                    attacks, error_message = self._run_with_retries(
                        lambda: self._simulate_attacks(vuln_instance, attacks_per_risk),
                        f"attack generation for {vuln_type}",
                    )

                    if error_message:
                        self._write_result_row(writer, risk, vuln_type, "Base", False, error=error_message)
                        logger.error(f"Error processing {vuln_type}: {error_message}")
                        continue

                    for case in attacks:
                        base_input = case.input

                        # Original input окремим рядком (Base), без дублювання в окремій колонці
                        self._write_result_row(writer, risk, vuln_type, "Base", False, generated_input=base_input)

                        # Застосовуємо тільки УВІМКНЕНІ стратегії
                        for strat in self.strategies:
                            try:
                                enhanced, error_message = self._run_with_retries(
                                    lambda strat=strat, base_input=base_input: strat.enhance(base_input),
                                    f"strategy {strat.__class__.__name__} for {vuln_type}",
                                )
                                if error_message:
                                    self._write_result_row(
                                        writer,
                                        risk,
                                        vuln_type,
                                        strat.__class__.__name__,
                                        True,
                                        error=error_message,
                                    )
                                    logger.debug(
                                        "Enhance failed for %s: %s",
                                        strat.__class__.__name__,
                                        error_message,
                                    )
                                    continue

                                self._write_result_row(
                                    writer,
                                    risk,
                                    vuln_type,
                                    strat.__class__.__name__,
                                    True,
                                    generated_input=enhanced,
                                )
                            except Exception as e:
                                error_message = _stringify_error(e)
                                self._write_result_row(
                                    writer,
                                    risk,
                                    vuln_type,
                                    strat.__class__.__name__,
                                    True,
                                    error=error_message,
                                )
                                logger.debug(f"Enhance failed for {strat.__class__.__name__}: {error_message}")

                except Exception as e:
                    error_message = _stringify_error(e)
                    self._write_result_row(writer, risk, vuln_type, "Base", False, error=error_message)
                    logger.error(f"Error processing {vuln_type}: {error_message}")

        logger.info(f"🏁 Generation finished. Saved to {self.output_csv}")


if __name__ == "__main__":
    default_vuln_file = os.path.join("data", "vulnerabilities.csv")
    default_strat_file = os.path.join("data", "strategies.csv")
    default_count = _get_env_int("MAX_GOLDENS", 1)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--vuln_file',
        default=default_vuln_file,
        help=f"Path to vulnerabilities CSV (default: {default_vuln_file})"
    )
    parser.add_argument(
        '--strat_file',
        default=default_strat_file,
        help=f"Path to strategies CSV (default: {default_strat_file})"
    )
    parser.add_argument('--plugins', required=False, help="Path to my_custom_attacks.py")
    parser.add_argument(
        '--count',
        type=int,
        default=default_count,
        help=f"Number of base inputs per risk (default from MAX_GOLDENS or {default_count})"
    )
    args = parser.parse_args()

    if not os.path.exists(args.vuln_file):
        parser.error(f"--vuln_file not found: {args.vuln_file}")
    if not os.path.exists(args.strat_file):
        parser.error(f"--strat_file not found: {args.strat_file}")

    gen = AttackGenerator(args.vuln_file, args.strat_file, args.plugins)
    gen.run(attacks_per_risk=args.count)
