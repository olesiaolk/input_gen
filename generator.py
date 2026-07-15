import csv
import inspect
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime

from config import Config
from strategies import build_strategy_map, load_enabled_strategies
from vulnerabilities import build_vulnerability_registry, load_enabled_vulnerabilities, load_plugins

logger = logging.getLogger(__name__)

EXPECTED_DEEPTEAM_VERSION = "1.0.5"
OUTPUT_COLUMNS = ["risk_factor", "type", "strategy", "is_transformed", "generated_input", "error"]


@dataclass
class RunSummary:
    generated_inputs: int = 0
    errors: int = 0
    skipped_strategies: int = 0
    empty_vulnerabilities: int = 0


def stringify_error(error):
    return f"{error.__class__.__name__}: {error}".strip()


def is_openai_error(error):
    error_type = error.__class__.__name__.lower()
    error_module = error.__class__.__module__.lower()
    error_text = str(error).lower()
    return any(
        marker in f"{error_module} {error_type} {error_text}"
        for marker in ["openai", "rate limit", "api connection", "timeout", "server error"]
    )


def call_with_supported_kwargs(callable_obj, **candidate_kwargs):
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


class AttackGenerator:
    def __init__(self, vuln_file, strat_file, plugins_file=None, config=None):
        imports = _load_deepteam_imports()
        self._verify_deepteam_version()

        self.vuln_file = vuln_file
        self.strat_file = strat_file
        self.config = config or Config("", "A helpful AI assistant", 1, 3)

        self.vuln_registry = build_vulnerability_registry(imports["vulnerability_classes"])
        load_plugins(plugins_file, self.vuln_registry)

        self.strategies_map = build_strategy_map(imports["strategy_classes"])
        self.strategies, skipped = load_enabled_strategies(self.strat_file, self.strategies_map)
        self.summary = RunSummary(skipped_strategies=skipped)
        self._setup_output()

    def _verify_deepteam_version(self):
        try:
            import deepteam
        except ImportError as exc:
            raise RuntimeError(f"deepteam is required to run generation: {exc}") from exc

        actual_version = getattr(deepteam, "__version__", "unknown")
        if actual_version != EXPECTED_DEEPTEAM_VERSION:
            logger.warning(
                "Expected deepteam==%s, found %s. Strategy compatibility may differ.",
                EXPECTED_DEEPTEAM_VERSION,
                actual_version,
            )

    def _setup_output(self):
        os.makedirs("output_data", exist_ok=True)
        self.output_csv = f"output_data/generated_inputs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(self.output_csv, "w", newline="", encoding="utf-8") as output_file:
            csv.writer(output_file).writerow(OUTPUT_COLUMNS)

    def _apply_runtime_config(self, obj):
        for attr_name, value in {
            "model": self.config.target_model,
            "purpose": self.config.target_purpose,
            "target_purpose": self.config.target_purpose,
            "max_goldens": self.config.max_goldens,
        }.items():
            if value is None:
                continue
            try:
                setattr(obj, attr_name, value)
            except (AttributeError, TypeError, ValueError) as exc:
                logger.debug("Could not set %s on %s: %s", attr_name, obj.__class__.__name__, exc)

    def _create_vulnerability_instance(self, vuln_class):
        vuln_instance = call_with_supported_kwargs(
            vuln_class,
            model=self.config.target_model,
            purpose=self.config.target_purpose,
            target_purpose=self.config.target_purpose,
            max_goldens=self.config.max_goldens,
        )
        self._apply_runtime_config(vuln_instance)
        return vuln_instance

    def _simulate_attacks(self, vuln_instance, attacks_per_risk):
        return call_with_supported_kwargs(
            vuln_instance.simulate_attacks,
            attacks_per_vulnerability_type=attacks_per_risk,
            max_goldens=attacks_per_risk,
            purpose=self.config.target_purpose,
            target_purpose=self.config.target_purpose,
            model=self.config.target_model,
        )

    def _run_with_retries(self, operation, context):
        last_error = None
        for attempt in range(1, self.config.openai_retries + 1):
            try:
                return operation(), None
            except Exception as exc:
                last_error = exc
                if not is_openai_error(exc) or attempt == self.config.openai_retries:
                    break
                logger.warning(
                    "OpenAI error during %s. Retry %s/%s: %s",
                    context,
                    attempt,
                    self.config.openai_retries,
                    exc,
                )
                time.sleep(min(attempt, 3))

        return None, stringify_error(last_error)

    def _write_result_row(self, writer, risk, vuln_type, strategy, is_transformed, generated_input="", error=""):
        writer.writerow([risk, vuln_type, strategy, str(bool(is_transformed)).lower(), generated_input, error])
        if generated_input:
            self.summary.generated_inputs += 1
        if error:
            self.summary.errors += 1

    def run(self, attacks_per_risk=1):
        try:
            vulnerabilities = load_enabled_vulnerabilities(self.vuln_file)
        except RuntimeError as exc:
            logger.error("%s", exc)
            return self.summary

        with open(self.output_csv, "a", newline="", encoding="utf-8") as output_file:
            writer = csv.writer(output_file)

            for row in vulnerabilities:
                vuln_type = row.get("type")
                risk = row.get("risk_factor", "General")

                vuln_class = self.vuln_registry.get(vuln_type)
                if not vuln_class:
                    logger.warning("Unknown vulnerability type: %s. Skipping.", vuln_type)
                    continue

                logger.info("Generating inputs for: %s", vuln_type)
                self._process_vulnerability(writer, risk, vuln_type, vuln_class, attacks_per_risk)

        logger.info(
            "Summary: generated_inputs=%s, errors=%s, skipped_strategies=%s, empty_vulnerabilities=%s",
            self.summary.generated_inputs,
            self.summary.errors,
            self.summary.skipped_strategies,
            self.summary.empty_vulnerabilities,
        )
        logger.info("Generation finished. Saved to %s", self.output_csv)
        return self.summary

    def _process_vulnerability(self, writer, risk, vuln_type, vuln_class, attacks_per_risk):
        try:
            vuln_instance = self._create_vulnerability_instance(vuln_class)
            attacks, error_message = self._run_with_retries(
                lambda: self._simulate_attacks(vuln_instance, attacks_per_risk),
                f"attack generation for {vuln_type}",
            )

            if error_message:
                self._write_result_row(writer, risk, vuln_type, "Base", False, error=error_message)
                logger.error("Error processing %s: %s", vuln_type, error_message)
                return

            if not attacks:
                self.summary.empty_vulnerabilities += 1
                logger.warning("No attacks generated for vulnerability %s.", vuln_type)
                return

            for case in attacks:
                base_input = case.input
                self._write_result_row(writer, risk, vuln_type, "Base", False, generated_input=base_input)
                self._apply_strategies(writer, risk, vuln_type, base_input)

        except Exception as exc:
            error_message = stringify_error(exc)
            self._write_result_row(writer, risk, vuln_type, "Base", False, error=error_message)
            logger.error("Error processing %s: %s", vuln_type, error_message)

    def _apply_strategies(self, writer, risk, vuln_type, base_input):
        for strategy in self.strategies:
            strategy_name = strategy.__class__.__name__
            enhanced, error_message = self._run_with_retries(
                lambda strategy=strategy, base_input=base_input: strategy.enhance(base_input),
                f"strategy {strategy_name} for {vuln_type}",
            )
            if error_message:
                self._write_result_row(writer, risk, vuln_type, strategy_name, True, error=error_message)
                logger.debug("Enhance failed for %s: %s", strategy_name, error_message)
                continue

            self._write_result_row(writer, risk, vuln_type, strategy_name, True, generated_input=enhanced)


def _load_deepteam_imports():
    try:
        from deepteam.attacks.single_turn import Base64, GrayBox, Leetspeak, PromptInjection, ROT13, Roleplay
        from deepteam.vulnerabilities import (
            Bias,
            GraphicContent,
            IllegalActivity,
            Misinformation,
            PIILeakage,
            PersonalSafety,
            Toxicity,
        )
    except ImportError as exc:
        raise RuntimeError(f"deepteam is required to run generation: {exc}") from exc

    return {
        "strategy_classes": {
            "Base64": Base64,
            "Leetspeak": Leetspeak,
            "ROT13": ROT13,
            "GrayBox": GrayBox,
            "PromptInjection": PromptInjection,
            "Roleplay": Roleplay,
        },
        "vulnerability_classes": {
            "PIILeakage": PIILeakage,
            "Bias": Bias,
            "GraphicContent": GraphicContent,
            "PersonalSafety": PersonalSafety,
            "Toxicity": Toxicity,
            "IllegalActivity": IllegalActivity,
            "Misinformation": Misinformation,
        },
    }
