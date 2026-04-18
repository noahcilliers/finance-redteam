"""
execution/pipeline.py
----------------------
PipelineRunner — the async orchestrator that wires all components together.

Full flow (per run):
  1. Load seeds from the YAML library via SeedLoader.
  2. Optionally pull feedback context from past SQLite results.
  3. Build mutation prompts for each seed via MutationPromptBuilder.
  4. For each seed (concurrently):
       a. Call the attacker LLM → list of variant strings.
       b. For each variant (concurrently):
            i.  Create an AttackResult stub and persist it to SQLite.
            ii. Call the target model with the variant.
            iii.Update the AttackResult with the response and re-persist.
  5. Write a JSONL run log (optional).
  6. Return all AttackResult objects for downstream use.

Concurrency model:
  - Seed-level tasks are gathered with asyncio.gather().
  - Within each seed, variant-level target calls are also gathered.
  - Two RateLimiters (one for attacker, one for target) cap throughput.
  - Errors at the seed level are caught and logged; the run continues.
  - Errors at the variant level are stored in AttackResult.error.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow running from project root without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from data.database import init_db, save_result
from data.models import AttackResult, AttackType, AttackTechnique
from evaluation.results_analyzer import AnalyzerConfig, load_and_analyze
from execution.attacker import AttackerClient, AttackerParseError
from execution.connectors import get_connector
from execution.pipeline_config import PipelineConfig
from execution.rate_limiter import RateLimiter
from generation.mutation_prompt_builder import MutationPromptBuilder
from generation.seed_loader import SeedLoader

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enum mapping helpers
# ---------------------------------------------------------------------------

def _safe_attack_type(raw: str) -> AttackType:
    try:
        return AttackType(raw)
    except ValueError:
        logger.debug("Unknown attack_type '%s', falling back to 'unknown'", raw)
        return AttackType.unknown


def _safe_attack_technique(raw: str) -> AttackTechnique:
    try:
        return AttackTechnique(raw)
    except ValueError:
        logger.debug("Unknown attack_technique '%s', falling back to 'unknown'", raw)
        return AttackTechnique.unknown


# ---------------------------------------------------------------------------
# Run summary dataclass
# ---------------------------------------------------------------------------

class RunSummary:
    """Lightweight summary printed at the end of a pipeline run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.started_at = datetime.now(timezone.utc)
        self.seeds_loaded = 0
        self.seeds_processed = 0
        self.variants_generated = 0
        self.target_calls_ok = 0
        self.target_calls_err = 0
        self.results: list[AttackResult] = []

    def elapsed_s(self) -> float:
        return (datetime.now(timezone.utc) - self.started_at).total_seconds()

    def log(self) -> None:
        logger.info(
            "Run %s complete in %.1fs | seeds=%d/%d | variants=%d | "
            "target_ok=%d target_err=%d",
            self.run_id,
            self.elapsed_s(),
            self.seeds_processed,
            self.seeds_loaded,
            self.variants_generated,
            self.target_calls_ok,
            self.target_calls_err,
        )


# ---------------------------------------------------------------------------
# PipelineRunner
# ---------------------------------------------------------------------------

class PipelineRunner:
    """
    Orchestrates the full red-teaming pipeline from seeds to stored results.

    Args:
        cfg: A PipelineConfig (superset of GenerationConfig).
    """

    def __init__(self, cfg: PipelineConfig) -> None:
        self.cfg = cfg

        # Rate limiters (no I/O — safe to create eagerly)
        self.attacker_limiter = RateLimiter.from_rps(
            rps=cfg.attacker_rps,
            max_concurrent=cfg.attacker_max_concurrent,
        )
        self.target_limiter = RateLimiter.from_rps(
            rps=cfg.target_rps,
            max_concurrent=cfg.target_max_concurrent,
        )

        # Seed loading and mutation building (no I/O at construction)
        self.seed_loader = SeedLoader()
        self.builder = MutationPromptBuilder(cfg)

        # Ensure DB exists
        init_db()

        # Connectors are created lazily on first use so that dry_run and
        # skip_attacker modes don't require valid API credentials at startup.
        self._attacker_connector = None
        self._target_connector = None
        self._attacker_client = None

    @property
    def attacker_client(self) -> AttackerClient:
        if self._attacker_client is None:
            self._attacker_connector = get_connector(self.cfg.attacker_model)
            self._attacker_client = AttackerClient(
                connector=self._attacker_connector,
                rate_limiter=self.attacker_limiter,
            )
        return self._attacker_client

    @property
    def target_connector(self):
        if self._target_connector is None:
            self._target_connector = get_connector(self.cfg.target_model)
        return self._target_connector

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> RunSummary:
        """
        Execute the full pipeline and return a RunSummary.

        The summary also contains the full list of AttackResult objects
        under summary.results.
        """
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        summary = RunSummary(run_id)

        logger.info(
            "Pipeline run %s starting | attacker=%s target=%s dry_run=%s skip_attacker=%s",
            run_id,
            self.cfg.attacker_model,
            self.cfg.target_model,
            self.cfg.dry_run,
            self.cfg.skip_attacker,
        )

        # 1. Load seeds
        seeds = self.seed_loader.load(self.cfg.seed_filters)
        summary.seeds_loaded = len(seeds)
        logger.info("%d seeds loaded", len(seeds))

        if not seeds:
            logger.warning("No seeds matched the configured filters. Aborting.")
            return summary

        # 2. Optionally load feedback context
        feedback_context: str | None = None
        fb_cfg = self.cfg.feedback_loop or {}
        if fb_cfg.get("enabled"):
            logger.info("Loading feedback context from results DB...")
            feedback_context = load_and_analyze(
                AnalyzerConfig(
                    lookback_days=fb_cfg.get("lookback_runs", 50),
                    target_model=self.cfg.target_model,
                    high_threshold=fb_cfg.get("success_threshold", 7),
                    fail_threshold=fb_cfg.get("failure_threshold", 2),
                )
            )
            logger.debug("Feedback context:\n%s", feedback_context)

        # 3. Build mutation prompts
        seed_prompt_pairs = list(
            zip(seeds, self.builder.build_many(seeds, feedback_context))
        )

        # 4. Process seeds concurrently
        tasks = [
            self._run_seed(seed, sp_dict, summary)
            for seed, sp_dict in seed_prompt_pairs
        ]
        await asyncio.gather(*tasks, return_exceptions=False)

        # 5. Optional JSONL output
        if self.cfg.save_jsonl:
            self._write_jsonl(summary, run_id)

        summary.log()
        return summary

    # ------------------------------------------------------------------
    # Seed-level processing
    # ------------------------------------------------------------------

    async def _run_seed(
        self,
        seed: dict[str, Any],
        sp_dict: dict[str, Any],
        summary: RunSummary,
    ) -> None:
        seed_id = seed.get("id", "unknown")
        mutation_prompt = sp_dict["mutation_prompt"]

        logger.info("Processing seed '%s'", seed_id)

        # Generate variants (or use seed prompt directly if skip_attacker)
        try:
            if self.cfg.skip_attacker:
                variants = [seed.get("prompt", "").strip()]
                logger.debug("skip_attacker=True — using raw seed prompt for '%s'", seed_id)
            elif self.cfg.dry_run:
                variants = [f"[DRY RUN variant for {seed_id}]"]
                # Print the full mutation prompt so the user can inspect it.
                separator = "─" * 72
                print(f"\n{separator}")
                print(f"MUTATION PROMPT — seed: {seed_id}")
                print(separator)
                print(mutation_prompt)
                print(separator + "\n")
            else:
                variants = await self.attacker_client.generate_variants(mutation_prompt)
        except AttackerParseError as e:
            logger.error("Attacker parse failed for seed '%s': %s", seed_id, e)
            summary.seeds_processed += 1
            return
        except Exception as e:
            logger.error("Attacker call failed for seed '%s': %s", seed_id, e)
            summary.seeds_processed += 1
            return

        summary.variants_generated += len(variants)
        logger.info("Seed '%s' → %d variants", seed_id, len(variants))

        # Send variants to target concurrently
        variant_tasks = [
            self._run_variant(seed, variant, summary)
            for variant in variants
        ]
        results = await asyncio.gather(*variant_tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                logger.error("Variant task raised unexpectedly: %s", r)
            elif isinstance(r, AttackResult):
                summary.results.append(r)

        summary.seeds_processed += 1

    # ------------------------------------------------------------------
    # Variant-level processing
    # ------------------------------------------------------------------

    async def _run_variant(
        self,
        seed: dict[str, Any],
        variant_prompt: str,
        summary: RunSummary,
    ) -> AttackResult:
        # Build the result stub
        result = AttackResult(
            attack_type=_safe_attack_type(seed.get("attack_type", "")),
            attack_technique=_safe_attack_technique(seed.get("attack_technique", "")),
            prompt_text=variant_prompt,
            target_model=self.cfg.target_model,
            financial_subdomain=seed.get("financial_subdomain"),
            tags=seed.get("tags") or [],
        )

        # Persist stub immediately (so partial results survive a crash)
        save_result(result)

        if self.cfg.dry_run:
            logger.debug("dry_run=True — skipping target call for attack_id=%s", result.attack_id)
            return result

        # Call target model
        try:
            async with self.target_limiter:
                response_text = await self.target_connector.chat(
                    user_prompt=variant_prompt,
                    system_prompt=self.cfg.target_system_prompt,
                )
            result = result.model_copy(update={"response_text": response_text})
            summary.target_calls_ok += 1
            logger.debug(
                "Target '%s' responded (%d chars) for attack_id=%s",
                self.cfg.target_model,
                len(response_text),
                result.attack_id,
            )
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            result = result.model_copy(update={"error": error_msg})
            summary.target_calls_err += 1
            logger.error("Target call failed for attack_id=%s: %s", result.attack_id, error_msg)

        # Persist final result
        save_result(result)
        return result

    # ------------------------------------------------------------------
    # JSONL output
    # ------------------------------------------------------------------

    def _write_jsonl(self, summary: RunSummary, run_id: str) -> None:
        runs_dir = Path(self.cfg.runs_dir)
        runs_dir.mkdir(parents=True, exist_ok=True)
        path = runs_dir / f"run_{run_id}.jsonl"

        with path.open("w", encoding="utf-8") as f:
            for result in summary.results:
                row = result.model_dump()
                # datetime → ISO string for JSON serialisability
                row["timestamp"] = result.timestamp.isoformat()
                f.write(json.dumps(row) + "\n")

        logger.info("JSONL run log written to %s (%d rows)", path, len(summary.results))
