"""
execution/run.py
-----------------
CLI entry point for the red-teaming pipeline.

Usage:
    # From the project root with the venv active:
    python -m execution.run --config execution/pipeline_config.yaml

    # Dry run (no API calls):
    python -m execution.run --config execution/pipeline_config.yaml --dry-run

    # Skip the attacker mutation step (send seed prompts directly):
    python -m execution.run --config execution/pipeline_config.yaml --skip-attacker

    # Override the target model at the command line:
    python -m execution.run --config execution/pipeline_config.yaml --target gpt-4o

    # Verbose logging:
    python -m execution.run --config execution/pipeline_config.yaml -v
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Allow running as `python execution/run.py` from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env before importing any connector that reads env vars.
try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except ImportError:
    pass  # python-dotenv is optional; env vars can be set in the shell

from execution.pipeline import PipelineRunner
from execution.pipeline_config import PipelineConfig


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Finance red-teaming pipeline: seeds → attacker LLM → target → results DB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--config", "-c",
        default="execution/pipeline_config.yaml",
        help="Path to the pipeline YAML config (default: execution/pipeline_config.yaml).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Build prompts and log everything, but skip API calls.",
    )
    p.add_argument(
        "--skip-attacker",
        action="store_true",
        help="Send seed prompts directly to the target without mutation.",
    )
    p.add_argument(
        "--target",
        metavar="MODEL",
        help="Override the target_model from the config (e.g. gpt-4o, gemini-2.5-flash).",
    )
    p.add_argument(
        "--attacker",
        metavar="MODEL",
        help="Override the attacker_model from the config.",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return p.parse_args()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy third-party loggers unless verbose.
    if not verbose:
        for noisy in ("httpx", "openai", "anthropic", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


async def _main() -> None:
    args = _parse_args()
    _setup_logging(args.verbose)
    log = logging.getLogger(__name__)

    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        log.error(
            "Config file not found: %s\n"
            "Copy execution/pipeline_config.example.yaml → %s and edit it.",
            config_path, config_path,
        )
        sys.exit(1)

    cfg = PipelineConfig.from_yaml(config_path)

    # Apply CLI overrides
    if args.dry_run:
        cfg.dry_run = True
    if args.skip_attacker:
        cfg.skip_attacker = True
    if args.target:
        cfg.target_model = args.target
    if args.attacker:
        cfg.attacker_model = args.attacker

    log.info(
        "Config loaded | seeds=%s | mutations=%s | attacker=%s | target=%s",
        cfg.seed_filters,
        cfg.mutations,
        cfg.attacker_model,
        cfg.target_model,
    )

    runner = PipelineRunner(cfg)
    summary = await runner.run()

    # Exit with non-zero if there were target errors (useful in CI).
    if summary.target_calls_err > 0 and summary.target_calls_ok == 0:
        log.error("All target calls failed. Check API keys and model availability.")
        sys.exit(2)


if __name__ == "__main__":
    asyncio.run(_main())
