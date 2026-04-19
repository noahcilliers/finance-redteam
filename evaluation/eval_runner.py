"""
evaluation/eval_runner.py
--------------------------
Batch evaluator — reads AttackResult rows from SQLite, builds EvaluationInput
objects, calls FinancialSafetyJudge, and writes JudgeVerdict fields back.

Design:
  - Decoupled from execution: runs as a post-processing step after DeepTeam.
  - Evaluates rows where response_text IS NOT NULL.
  - By default only processes unevaluated rows (success IS NULL).
  - Writes back to the existing AttackResult schema without a DB migration:
      success        ← verdict.attack_succeeded  (bool)
      severity_score ← verdict.harm_realized     (float 0–10)
      judge_reasoning← verdict.full_reasoning_text()  (JSON prefix + text)
  - Configurable concurrency via asyncio.Semaphore.

CLI usage:
    # Evaluate all pending rows
    python3 -m evaluation.eval_runner

    # Re-evaluate everything (overwrite existing scores)
    python3 -m evaluation.eval_runner --all

    # Evaluate specific attack IDs
    python3 -m evaluation.eval_runner --ids abc123 def456

    # Dry run — print EvaluationInputs without calling the judge
    python3 -m evaluation.eval_runner --dry-run

    # Two-pass mode (cheaper for mostly-refused runs)
    python3 -m evaluation.eval_runner --two-pass
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import os
import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env from project root before anything that needs API keys.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except ImportError:
    pass  # python-dotenv not installed — rely on env vars being set externally

from data.models import AttackResult, AttackType, AttackTechnique
from evaluation.eval_schema import EvaluationInput
from evaluation.judge import FinancialSafetyJudge, JudgeConfig


# ---------------------------------------------------------------
# Config
# ---------------------------------------------------------------

@dataclass
class EvalRunnerConfig:
    judge_model: str = "claude-sonnet-4-6"
    batch_size: int = 20
    max_concurrent: int = 2         # keep low — 30k TPM rate limit bites fast
    fast_mode: bool = True          # False = two-pass (binary first)
    rubric_version: str = "v1"
    db_path: str = "data/results.db"
    skip_errors: bool = True        # continue if a single judge call fails
    api_key: Optional[str] = None   # falls back to ANTHROPIC_API_KEY env var
    retry_on_rate_limit: bool = True
    retry_max_attempts: int = 5
    retry_base_delay: float = 10.0  # seconds; doubles each attempt


# ---------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------

def _fetch_pending(db_path: str, batch_size: int) -> list[dict]:
    """Rows where response_text IS NOT NULL AND success IS NULL."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT * FROM attack_results
        WHERE response_text IS NOT NULL
          AND success IS NULL
        ORDER BY timestamp ASC
        LIMIT ?
        """,
        (batch_size,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def _fetch_all(db_path: str, batch_size: int, offset: int = 0) -> list[dict]:
    """All rows with a response_text, paginated."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT * FROM attack_results
        WHERE response_text IS NOT NULL
        ORDER BY timestamp ASC
        LIMIT ? OFFSET ?
        """,
        (batch_size, offset),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def _fetch_by_ids(db_path: str, attack_ids: list[str]) -> list[dict]:
    placeholders = ",".join("?" * len(attack_ids))
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        f"SELECT * FROM attack_results WHERE attack_id IN ({placeholders})",
        attack_ids,
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def _write_verdict(db_path: str, attack_id: str, success: bool, severity: float, reasoning: str) -> None:
    con = sqlite3.connect(db_path)
    con.execute(
        """
        UPDATE attack_results
        SET success = ?, severity_score = ?, judge_reasoning = ?
        WHERE attack_id = ?
        """,
        (1 if success else 0, severity, reasoning, attack_id),
    )
    con.commit()
    con.close()


# ---------------------------------------------------------------
# Row → EvaluationInput
# ---------------------------------------------------------------

def _row_to_eval_input(row: dict) -> EvaluationInput:
    """
    Build an EvaluationInput from a raw SQLite row dict.

    success_criteria and severity_potential are not stored in the DB — they
    live in the YAML seed.  We extract severity_potential from tags if present
    (tag format: "severity:7") and use an empty success_criteria as fallback.
    """
    tags: list[str] = []
    if row.get("tags"):
        try:
            tags = json.loads(row["tags"])
        except (json.JSONDecodeError, TypeError):
            tags = []

    severity_potential = 5  # default
    for tag in tags:
        if tag.startswith("severity:"):
            try:
                severity_potential = int(tag.split(":")[1])
            except (ValueError, IndexError):
                pass

    # Normalise subdomain: keep only "3a", "3b", "3c", treat anything else as None
    subdomain = row.get("financial_subdomain")
    if subdomain not in {"3a", "3b", "3c"}:
        subdomain = None

    return EvaluationInput(
        attack_id=row["attack_id"],
        financial_subdomain=subdomain,
        attack_type=row.get("attack_type", "unknown"),
        attack_technique=row.get("attack_technique", "unknown"),
        severity_potential=severity_potential,
        success_criteria={},          # not stored in DB; rubric used as proxy
        prompt=row["prompt_text"],
        response=row["response_text"],
        target_model=row.get("target_model", "unknown"),
    )


# ---------------------------------------------------------------
# Async evaluation core
# ---------------------------------------------------------------

async def _evaluate_one(
    eval_input: EvaluationInput,
    judge: FinancialSafetyJudge,
    semaphore: asyncio.Semaphore,
    cfg: EvalRunnerConfig,
) -> tuple[EvaluationInput, object, Optional[Exception]]:
    """
    Evaluate a single input under the semaphore.
    Returns (input, verdict_or_None, error_or_None).
    """
    async with semaphore:
        loop = asyncio.get_event_loop()
        try:
            # FinancialSafetyJudge is synchronous; run in executor to avoid blocking.
            verdict = await loop.run_in_executor(None, judge.judge, eval_input)
            return eval_input, verdict, None
        except Exception as exc:
            if cfg.skip_errors:
                return eval_input, None, exc
            raise


async def _evaluate_batch(
    rows: list[dict],
    judge: FinancialSafetyJudge,
    cfg: EvalRunnerConfig,
    db_path: str,
    dry_run: bool = False,
) -> tuple[int, int, int]:
    """
    Evaluate a batch of DB rows.
    Returns (evaluated, succeeded, errors).
    """
    semaphore = asyncio.Semaphore(cfg.max_concurrent)
    inputs = [_row_to_eval_input(r) for r in rows]

    if dry_run:
        for inp in inputs:
            print(f"\n[DRY RUN] attack_id={inp.attack_id}")
            print(f"  subdomain={inp.financial_subdomain}  technique={inp.attack_technique}")
            print(f"  prompt[:120]: {inp.prompt[:120]!r}")
            print(f"  response[:120]: {inp.response[:120]!r}")
        return len(inputs), 0, 0

    tasks = [
        _evaluate_one(inp, judge, semaphore, cfg)
        for inp in inputs
    ]
    results = await asyncio.gather(*tasks)

    evaluated = 0
    succeeded = 0
    errors = 0

    for inp, verdict, exc in results:
        if exc is not None:
            errors += 1
            print(f"  [ERROR] {inp.attack_id}: {exc}", file=sys.stderr)
            continue

        _write_verdict(
            db_path,
            inp.attack_id,
            verdict.attack_succeeded,
            verdict.harm_realized,
            verdict.full_reasoning_text(),
        )
        evaluated += 1
        if verdict.attack_succeeded:
            succeeded += 1

        status = "FAIL" if verdict.attack_succeeded else "PASS"
        print(
            f"  [{status}] {inp.attack_id[:8]}… "
            f"harm={verdict.harm_realized:.1f} "
            f"refusal={verdict.refusal_quality} "
            f"domain={verdict.domain_violation or 'none'}"
        )

    return evaluated, succeeded, errors


# ---------------------------------------------------------------
# EvalRunner
# ---------------------------------------------------------------

class EvalRunner:
    """
    Batch evaluator.  Reads from SQLite, calls the judge, writes back.
    """

    def __init__(self, cfg: EvalRunnerConfig) -> None:
        self.cfg = cfg
        # Set DB path via env var (how database.py resolves it) then init.
        os.environ.setdefault("FINANCE_REDTEAM_DB", cfg.db_path)
        from data.database import init_db
        init_db()
        judge_cfg = JudgeConfig(
            model=cfg.judge_model,
            fast_mode=cfg.fast_mode,
            rubric_version=cfg.rubric_version,
            api_key=cfg.api_key,
        )
        self.judge = FinancialSafetyJudge(judge_cfg)

    # ---- Public entry points ----------------------------------------

    def run_pending(self, dry_run: bool = False) -> None:
        """Evaluate all rows where success IS NULL."""
        print(f"[eval_runner] Evaluating pending rows (batch_size={self.cfg.batch_size})…")
        total_evaluated = 0
        total_succeeded = 0
        total_errors = 0

        while True:
            rows = _fetch_pending(self.cfg.db_path, self.cfg.batch_size)
            if not rows:
                break
            print(f"  Batch of {len(rows)} rows…")
            ev, su, er = asyncio.run(
                _evaluate_batch(rows, self.judge, self.cfg, self.cfg.db_path, dry_run)
            )
            total_evaluated += ev
            total_succeeded += su
            total_errors += er
            if dry_run:
                break  # dry run just shows first batch

        self._print_summary(total_evaluated, total_succeeded, total_errors)

    def run_all(self, dry_run: bool = False) -> None:
        """Re-evaluate all rows with a response_text (overwrites existing scores)."""
        print(f"[eval_runner] Re-evaluating ALL rows (batch_size={self.cfg.batch_size})…")
        total_evaluated = 0
        total_succeeded = 0
        total_errors = 0
        offset = 0

        while True:
            rows = _fetch_all(self.cfg.db_path, self.cfg.batch_size, offset)
            if not rows:
                break
            print(f"  Batch offset={offset}, {len(rows)} rows…")
            ev, su, er = asyncio.run(
                _evaluate_batch(rows, self.judge, self.cfg, self.cfg.db_path, dry_run)
            )
            total_evaluated += ev
            total_succeeded += su
            total_errors += er
            offset += len(rows)
            if dry_run:
                break

        self._print_summary(total_evaluated, total_succeeded, total_errors)

    def run_ids(self, attack_ids: list[str], dry_run: bool = False) -> None:
        """Evaluate specific rows by attack_id."""
        rows = _fetch_by_ids(self.cfg.db_path, attack_ids)
        if not rows:
            print(f"[eval_runner] No rows found for IDs: {attack_ids}")
            return
        print(f"[eval_runner] Evaluating {len(rows)} specified rows…")
        ev, su, er = asyncio.run(
            _evaluate_batch(rows, self.judge, self.cfg, self.cfg.db_path, dry_run)
        )
        self._print_summary(ev, su, er)

    # ---- Helpers ----------------------------------------------------

    @staticmethod
    def _print_summary(evaluated: int, succeeded: int, errors: int) -> None:
        if evaluated == 0 and errors == 0:
            print("[eval_runner] Nothing to evaluate.")
            return
        total = evaluated + errors
        asr = succeeded / evaluated if evaluated > 0 else 0.0
        print(
            f"\n[eval_runner] Done. "
            f"{evaluated}/{total} evaluated, "
            f"ASR={asr:.0%} ({succeeded} attacks succeeded), "
            f"{errors} errors."
        )


# ---------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run Phase 4 LLM judge evaluation on red-team results."
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--all",
        action="store_true",
        help="Re-evaluate all rows with a response (overwrites existing scores).",
    )
    mode.add_argument(
        "--ids",
        nargs="+",
        metavar="ATTACK_ID",
        help="Evaluate specific attack IDs.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print EvaluationInput objects without calling the judge.",
    )
    p.add_argument(
        "--two-pass",
        action="store_true",
        help="Use two-pass evaluation (binary pre-filter, cheaper for mostly-refused runs).",
    )
    p.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Anthropic model string for the judge (default: claude-sonnet-4-6).",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=20,
        help="DB rows per batch (default: 20).",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Max parallel Sonnet calls (default: 5).",
    )
    p.add_argument(
        "--db",
        default="data/results.db",
        help="Path to SQLite results DB (default: data/results.db).",
    )
    return p


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    cfg = EvalRunnerConfig(
        judge_model=args.model,
        batch_size=args.batch_size,
        max_concurrent=args.concurrency,
        fast_mode=not args.two_pass,
        db_path=args.db,
    )

    runner = EvalRunner(cfg)

    if args.ids:
        runner.run_ids(args.ids, dry_run=args.dry_run)
    elif args.all:
        runner.run_all(dry_run=args.dry_run)
    else:
        runner.run_pending(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
