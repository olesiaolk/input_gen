import importlib.util
import inspect
import logging
import os

import pandas as pd

from strategies import is_truthy

logger = logging.getLogger(__name__)


def build_vulnerability_registry(vulnerability_classes):
    return {
        "PIILeakage": vulnerability_classes["PIILeakage"],
        "Bias": vulnerability_classes["Bias"],
        "GraphicContent": vulnerability_classes["GraphicContent"],
        "PersonalSafety": vulnerability_classes["PersonalSafety"],
        "Toxicity": vulnerability_classes["Toxicity"],
        "IllegalActivity": vulnerability_classes["IllegalActivity"],
        "Misinformation": vulnerability_classes["Misinformation"],
    }


def load_plugins(filepath, registry):
    if not filepath:
        return
    if not os.path.exists(filepath):
        logger.warning("Plugin file not found: %s", filepath)
        return

    spec = importlib.util.spec_from_file_location("custom_attacks", filepath)
    if spec is None or spec.loader is None:
        logger.warning("Could not load plugin spec from %s", filepath)
        return

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        logger.error("Failed to load plugin file %s: %s", filepath, exc)
        raise

    from deepteam.vulnerabilities import CustomVulnerability

    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, CustomVulnerability) and obj is not CustomVulnerability:
            registry[name] = obj
            logger.info("Custom vulnerability registered: %s", name)


def load_enabled_vulnerabilities(vuln_file):
    try:
        df = pd.read_csv(vuln_file).fillna("")
    except (OSError, pd.errors.ParserError) as exc:
        raise RuntimeError(f"Failed to read vulnerabilities CSV {vuln_file}: {exc}") from exc

    return [row for _, row in df.iterrows() if is_truthy(row.get("enabled", "True"))]
