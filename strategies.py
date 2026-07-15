import importlib
import logging
import pkgutil
import re

import pandas as pd

logger = logging.getLogger(__name__)

LEGACY_STRATEGY_ALIASES = {
    "CharacterStream": ["LinguisticConfusion"],
    "EmotionalManipulation": ["GoalRedirection"],
    "SemanticManipulation": ["ContextPoisoning"],
    "Multilingual": ["Multilingual", "LanguageSwitch", "MultiLanguage", "MultilingualObfuscation"],
}


def normalize_strategy_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name or "").strip().lower())


def is_truthy(value):
    text = str(value).strip().lower()
    if text == "":
        return False
    return text not in {"false", "0", "no", "f"}


def import_strategy_class(name):
    module_candidates = ["deepteam.attacks.single_turn", "deepteam.attacks"]
    for module_name in module_candidates:
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            logger.debug("Could not import strategy module %s: %s", module_name, exc)
            continue

        strategy_cls = getattr(module, name, None)
        if strategy_cls is not None:
            return strategy_cls

    try:
        attacks_pkg = importlib.import_module("deepteam.attacks")
    except ImportError as exc:
        logger.debug("Could not scan deepteam.attacks for %s: %s", name, exc)
        return None

    package_path = getattr(attacks_pkg, "__path__", None)
    if package_path is None:
        logger.debug("deepteam.attacks has no package path; cannot scan for %s.", name)
        return None

    for mod_info in pkgutil.walk_packages(package_path, attacks_pkg.__name__ + "."):
        module_name = mod_info.name
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            logger.debug("Could not import strategy submodule %s: %s", module_name, exc)
            continue
        except Exception as exc:
            logger.debug("Skipping strategy submodule %s after import error: %s", module_name, exc)
            continue

        strategy_cls = getattr(module, name, None)
        if strategy_cls is not None:
            return strategy_cls

    return None


def build_strategy_map(base_strategy_classes):
    strategies_map = {
        "Base64": base_strategy_classes["Base64"](),
        "Leetspeak": base_strategy_classes["Leetspeak"](),
        "ROT13": base_strategy_classes["ROT13"](),
        "GrayBox": base_strategy_classes["GrayBox"](),
        "PromptInjection": base_strategy_classes["PromptInjection"](),
        "Roleplay": base_strategy_classes["Roleplay"](role="System Tester", persona="System Tester"),
    }

    for strategy_name in LEGACY_STRATEGY_ALIASES:
        strategy_cls = import_strategy_class(strategy_name)
        if strategy_cls is None:
            for alias in LEGACY_STRATEGY_ALIASES[strategy_name]:
                strategy_cls = import_strategy_class(alias)
                if strategy_cls is not None:
                    logger.info("Mapped legacy strategy '%s' to '%s'", strategy_name, alias)
                    break
        if strategy_cls is None:
            continue
        try:
            strategies_map[strategy_name] = strategy_cls()
        except Exception as exc:
            logger.debug("Failed to initialize strategy '%s': %s", strategy_name, exc)

    return strategies_map


def load_enabled_strategies(strat_file, strategies_map):
    active = []
    skipped = 0
    aliases = {normalize_strategy_name(name): name for name in strategies_map}

    try:
        df = pd.read_csv(strat_file).fillna("")
    except (OSError, pd.errors.ParserError) as exc:
        logger.error("Error reading strategies from %s: %s", strat_file, exc)
        return active, skipped

    for _, row in df.iterrows():
        if not is_truthy(row.get("enabled", "True")):
            skipped += 1
            continue

        raw_name = row.get("strategy_name")
        canonical_name = aliases.get(normalize_strategy_name(raw_name))
        if canonical_name in strategies_map:
            active.append(strategies_map[canonical_name])
        else:
            skipped += 1
            logger.warning(
                "Strategy '%s' is not mapped or not supported by the current deepteam version.",
                raw_name,
            )

    if not active:
        logger.warning("No active strategies found. Using base attacks only.")

    return active, skipped
