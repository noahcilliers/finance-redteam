"""
execution/deepteam_run.py
--------------------------
DeepTeam-powered entry point for the red-teaming pipeline.

This is the replacement for `execution/run.py`'s MutationPromptBuilder +
AttackerClient path. DeepTeam handles variant synthesis (no attacker-refusal
issues), while everything downstream — connectors, AttackResult, SQLite,
JSONL — stays the same.

Flow:
  1. Load PipelineConfig from YAML.
  2. Load + filter YAML seeds via SeedLoader (same as the existing pipeline).
  3. For each seed, build a DeepTeam CustomVulnerability.
  4. Build a single async model_callback that proxies to our target connector.
  5. Call `red_team(...)` — DeepTeam synthesises variants, sends them to the
     callback, evaluates with its default judge.
  6. Convert each RTTestCase back to an AttackResult and persist it.

Usage:
  python -m execution.deepteam_run --config execution/pipeline_config.yaml

The existing run.py is untouched so the custom mutation path remains
available for comparison.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as a module from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env before importing anything that reads API keys.
try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except ImportError:
    pass

from data.database import init_db, save_result
from data.models import AttackResult
from execution.connectors import get_connector
from execution.deepteam_bridge import (
    build_target_callback,
    seed_to_custom_vulnerability,
    testcase_to_attack_result,
)
from execution.pipeline_config import PipelineConfig
from generation.seed_loader import SeedLoader

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "DeepTeam-powered red-teaming runner. Replaces the "
            "MutationPromptBuilder+AttackerClient path with DeepTeam's "
            "variant synthesiser while keeping the existing connectors, DB, "
            "and result model."
        ),
    )
    p.add_argument(
        "--config", "-c",
        default="execution/pipeline_config.yaml",
        help="Path to pipeline YAML config (default: execution/pipeline_config.yaml).",
    )
    p.add_argument(
        "--target",
        metavar="MODEL",
        help="Override the target_model from the config (e.g. claude-sonnet-4-6).",
    )
    p.add_argument(
        "--simulator",
        metavar="MODEL",
        default="gpt-4o-mini",
        help=(
            "DeepTeam simulator model — used to synthesise attack variants "
            "from each vulnerability. Default: gpt-4o-mini."
        ),
    )
    p.add_argument(
        "--evaluator",
        metavar="MODEL",
        default="gpt-4o-mini",
        help=(
            "DeepTeam evaluator model — used as the default judge. The "
            "custom FinancialSafetyMetric replaces this later. "
            "Default: gpt-4o-mini."
        ),
    )
    p.add_argument(
        "--attacks-per-type", "-n",
        type=int,
        default=3,
        help="Variants per seed (maps to DeepTeam attacks_per_vulnerability_type). Default: 3.",
    )
    p.add_argument(
        "--max-concurrent",
        type=int,
        default=None,
        help="Override concurrency cap. Defaults to config.target_max_concurrent.",
    )
    p.add_argument(
        "--no-enhancers",
        action="store_true",
        help=(
            "Skip DeepTeam attack enhancers (PromptInjection/SystemOverride). "
            "Uses the simulator's raw variants only."
        ),
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return p.parse_args()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    if not verbose:
        for noisy in ("httpx", "openai", "anthropic", "httpcore", "deepeval", "deepteam"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Core run
# ---------------------------------------------------------------------------

def _build_attacks(no_enhancers: bool):
    """
    Pick DeepTeam attack enhancers appropriate for our current seed scope.

    For the direct_override (prompt_injection → direct_injection) seeds, the
    natural enhancers are PromptInjection and SystemOverride. These both
    take a base attack string and transform it — which matches our
    "variants of a seed" model.

    Returning an empty list means DeepTeam uses the raw simulator variants
    without applying enhancement transforms.
    """
    if no_enhancers:
        return []

    # Import lazily so --no-enhancers works even if any attack import fails.
    from deepteam.attacks.single_turn import PromptInjection, SystemOverride
    return [PromptInjection(), SystemOverride()]


def _risk_assessment_iter_test_cases(risk_assessment):
    """
    Yield every RTTestCase from a DeepTeam RiskAssessment, regardless of
    how the result object is structured across versions.

    The public surface is `risk_assessment.test_cases` in newer releases
    but earlier shapes grouped them under per-vulnerability containers.
    We try the common attributes in order and fall back to scanning dicts.
    """
    # Preferred: flat list on the assessment.
    direct = getattr(risk_assessment, "test_cases", None)
    if direct:
        for tc in direct:
            yield tc
        return

    # Alt: grouped by vulnerability → list.
    grouped = getattr(risk_assessment, "vulnerability_scores_breakdown", None)
    if grouped:
        for item in grouped:
            sub = getattr(item, "test_cases", None) or []
            for tc in sub:
                yield tc
        return

    # Last resort: scan the dump.
    try:
        dumped = risk_assessment.model_dump()  # pydantic
    except Exception:
        return
    for v in dumped.values():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and "test_cases" in item:
                    for tc in item["test_cases"]:
                        yield tc


async def run_deepteam_pipeline(
    cfg: PipelineConfig,
    *,
    simulator_model: str,
    evaluation_model: str,
    attacks_per_type: int,
    max_concurrent: int | None,
    no_enhancers: bool,
) -> list[AttackResult]:
    """
    End-to-end DeepTeam run. Returns the list of persisted AttackResult
    objects so the caller can inspect or write a JSONL log.
    """
    init_db()

    # 1. Load seeds
    loader = SeedLoader()
    seeds = loader.load(cfg.seed_filters)
    if not seeds:
        logger.error("No seeds matched filters: %s", cfg.seed_filters)
        return []

    # Map seed id → seed dict so we can rehydrate metadata after the run.
    seeds_by_id = {s["id"]: s for s in seeds if "id" in s}
    logger.info(
        "Loaded %d seed(s): %s",
        len(seeds),
        ", ".join(seeds_by_id.keys()),
    )

    # 2. Build one CustomVulnerability per seed
    vulnerabilities = [
        seed_to_custom_vulnerability(
            seed,
            simulator_model=simulator_model,
            evaluation_model=evaluation_model,
        )
        for seed in seeds
    ]

    # 3. Build the target callback
    connector = get_connector(cfg.target_model)
    callback = build_target_callback(
        connector,
        system_prompt=cfg.target_system_prompt,
    )
    logger.info(
        "Target connector ready | model=%s | system_prompt=%s",
        cfg.target_model,
        "set" if cfg.target_system_prompt else "none",
    )

    # 4. Pick attack enhancers
    attacks = _build_attacks(no_enhancers)
    if attacks:
        logger.info("DeepTeam enhancers: %s", [a.__class__.__name__ for a in attacks])
    else:
        logger.info("DeepTeam enhancers: none (raw simulator variants)")

    # 5. Run DeepTeam
    from deepteam import red_team  # import here to defer heavy deepeval import

    concurrency = max_concurrent or cfg.target_max_concurrent
    logger.info(
        "Calling red_team | simulator=%s | evaluator=%s | attacks_per_type=%d | concurrency=%d",
        simulator_model, evaluation_model, attacks_per_type, concurrency,
    )

    # DeepTeam's red_team is sync on the outside but drives an internal
    # event loop when async_mode=True. We call it via asyncio.to_thread so
    # the caller coroutine can still await it without nested-loop issues.
    risk_assessment = await asyncio.to_thread(
        red_team,
        model_callback=callback,
        vulnerabilities=vulnerabilities,
        attacks=attacks or None,
        simulator_model=simulator_model,
        evaluation_model=evaluation_model,
        attacks_per_vulnerability_type=attacks_per_type,
        async_mode=True,
        max_concurrent=concurrency,
        ignore_errors=True,
    )

    # 6. Convert + persist results
    results: list[AttackResult] = []
    unknown_count = 0

    for tc in _risk_assessment_iter_test_cases(risk_assessment):
        # RTTestCase.vulnerability is the CustomVulnerability name, which
        # we set to the seed id. Use it to rehydrate seed metadata.
        seed_id = getattr(tc, "vulnerability", None)
        seed = seeds_by_id.get(seed_id)
        if seed is None:
            unknown_count += 1
            logger.debug("Could not match test case to seed (vulnerability=%s)", seed_id)
            continue

        result = testcase_to_attack_result(tc, seed, cfg.target_model)
        save_result(result)
        results.append(result)

    if unknown_count:
        logger.warning("%d test case(s) had no matching seed", unknown_count)

    ok = sum(1 for r in results if r.response_text and not r.error)
    errs = sum(1 for r in results if r.error)
    logger.info(
        "DeepTeam run complete | results=%d | ok=%d | errors=%d",
        len(results), ok, errs,
    )

    return results


def write_jsonl(results: list[AttackResult], runs_dir: str, run_id: str) -> Path:
    runs = Path(runs_dir)
    runs.mkdir(parents=True, exist_ok=True)
    path = runs / f"deepteam_run_{run_id}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for r in results:
            row = r.model_dump()
            row["timestamp"] = r.timestamp.isoformat()
            f.write(json.dumps(row) + "\n")
    return path


async def _main() -> int:
    args = _parse_args()
    _setup_logging(args.verbose)

    config_path = Path(args.config)
    if not config_path.exists():
        logger.error("Config file not found: %s", config_path)
        return 1

    cfg = PipelineConfig.from_yaml(config_path)
    if args.target:
        cfg.target_model = args.target

    logger.info(
        "Config loaded | seed_filters=%s | target=%s",
        cfg.seed_filters,
        cfg.target_model,
    )

    results = await run_deepteam_pipeline(
        cfg,
        simulator_model=args.simulator,
        evaluation_model=args.evaluator,
        attacks_per_type=args.attacks_per_type,
        max_concurrent=args.max_concurrent,
        no_enhancers=args.no_enhancers,
    )

    if cfg.save_jsonl and results:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = write_jsonl(results, cfg.runs_dir, run_id)
        logger.info("JSONL written to %s", path)

    if not results:
        logger.error("No results produced.")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
