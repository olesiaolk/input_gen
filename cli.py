import argparse
import logging
import os
import sys

from config import get_env_int, load_config, load_environment, require_openai_api_key
from generator import AttackGenerator


def build_parser(default_count):
    default_vuln_file = os.path.join("data", "vulnerabilities.csv")
    default_strat_file = os.path.join("data", "strategies.csv")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--vuln_file",
        default=default_vuln_file,
        help=f"Path to vulnerabilities CSV (default: {default_vuln_file})",
    )
    parser.add_argument(
        "--strat_file",
        default=default_strat_file,
        help=f"Path to strategies CSV (default: {default_strat_file})",
    )
    parser.add_argument("--plugins", required=False, help="Path to my_custom_attacks.py")
    parser.add_argument(
        "--count",
        type=int,
        default=default_count,
        help=f"Number of base inputs per risk (default from MAX_GOLDENS or {default_count})",
    )
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logger = logging.getLogger(__name__)

    load_environment()
    parser = build_parser(default_count=get_env_int("MAX_GOLDENS", 1))
    args = parser.parse_args(argv)

    if not os.path.exists(args.vuln_file):
        parser.error(f"--vuln_file not found: {args.vuln_file}")
    if not os.path.exists(args.strat_file):
        parser.error(f"--strat_file not found: {args.strat_file}")

    try:
        require_openai_api_key()
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1

    generator = AttackGenerator(args.vuln_file, args.strat_file, args.plugins, config=load_config())
    generator.run(attacks_per_risk=args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
