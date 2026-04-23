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
from evaluation.deterministic import (
    DeterministicReport,
    deterministic_pass,
)
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

# Rows with `error IS NOT NULL` are execution-layer failures (network errors,
# api_level_refusal sentinel translation, safety-filter 400s). There is no
# model response to judge, so they are excluded from every fetch query below.
# Rows with an empty `response_text` are also skipped for the same reason —
# after the sentinel migration they exist but carry no judgeable content.
_JUDGEABLE_WHERE = (
    "response_text IS NOT NULL "
    "AND response_text != '' "
    "AND (error IS NULL OR error = '')"
)


def _scope_clauses(
    model: Optional[str] = None,
    subdomain: Optional[str] = None,
) -> tuple[str, list]:
    """
    Return (extra_sql, params) for optional target_model / financial_subdomain scope.

    The returned string is empty or starts with " AND ", ready to be appended
    directly to an existing WHERE clause.
    """
    parts: list[str] = []
    params: list = []
    if model:
        parts.append("target_model = ?")
        params.append(model)
    if subdomain:
        parts.append("financial_subdomain = ?")
        params.append(subdomain)
    extra = (" AND " + " AND ".join(parts)) if parts else ""
    return extra, params


def _fetch_pending(
    db_path: str,
    batch_size: int,
    *,
    model: Optional[str] = None,
    subdomain: Optional[str] = None,
) -> list[dict]:
    """Rows with a real response and no prior judge verdict."""
    scope_sql, scope_params = _scope_clauses(model, subdomain)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        f"""
        SELECT * FROM attack_results
        WHERE {_JUDGEABLE_WHERE}
          AND success IS NULL
          {scope_sql}
        ORDER BY timestamp ASC
        LIMIT ?
        """,
        (*scope_params, batch_size),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def _fetch_pending_excluding(
    db_path: str,
    batch_size: int,
    exclude_ids: set[str],
    *,
    model: Optional[str] = None,
    subdomain: Optional[str] = None,
) -> list[dict]:
    """
    Same as _fetch_pending but skips IDs already seen this run.
    This is the hard guard against infinite loops — even if a DB write fails,
    a row can only be attempted once per process invocation.
    """
    scope_sql, scope_params = _scope_clauses(model, subdomain)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    if exclude_ids:
        placeholders = ",".join("?" * len(exclude_ids))
        rows = con.execute(
            f"""
            SELECT * FROM attack_results
            WHERE {_JUDGEABLE_WHERE}
              AND success IS NULL
              AND attack_id NOT IN ({placeholders})
              {scope_sql}
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            (*sorted(exclude_ids), *scope_params, batch_size),
        ).fetchall()
    else:
        rows = con.execute(
            f"""
            SELECT * FROM attack_results
            WHERE {_JUDGEABLE_WHERE}
              AND success IS NULL
              {scope_sql}
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            (*scope_params, batch_size),
        ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def _fetch_all(db_path: str, batch_size: int, offset: int = 0) -> list[dict]:
    """All judgeable rows (has a response, no execution error), paginated."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        f"""
        SELECT * FROM attack_results
        WHERE {_JUDGEABLE_WHERE}
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


def _write_eval_error(db_path: str, attack_id: str, error: str) -> None:
    """
    Mark a row as evaluated-with-error so it is excluded from future runs.
    We use success=0, severity_score=NULL, judge_reasoning='EVAL_ERROR: ...'
    This prevents the infinite loop caused by errored rows staying success=NULL.
    """
    con = sqlite3.connect(db_path)
    con.execute(
        """
        UPDATE attack_results
        SET success = 0, judge_reasoning = ?
        WHERE attack_id = ?
        """,
        (f"EVAL_ERROR: {error}", attack_id),
    )
    con.commit()
    con.close()


# ---------------------------------------------------------------
# Row → EvaluationInput
# ---------------------------------------------------------------

def _parse_tags(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _row_to_eval_input(row: dict) -> EvaluationInput:
    """
    Build an EvaluationInput from a raw SQLite row dict.

    success_criteria and severity_potential are not stored in the DB — they
    live in the YAML seed.  We extract severity_potential from tags if present
    (tag format: "severity:7") and use an empty success_criteria as fallback.
    """
    tags = _parse_tags(row.get("tags"))

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


def _seed_metadata_from_row(row: dict) -> dict:
    """
    Reconstruct the seed-metadata dict the deterministic pass wants.

    The DB does not persist the YAML seed's `system_prompt` or
    `context_fixtures`, so the fields are absent here unless future
    pipeline work threads them through. We do have the subdomain and
    tags, which are enough for lexicon scoping.
    """
    return {
        "financial_subdomain": row.get("financial_subdomain"),
        "attack_type": row.get("attack_type"),
        "attack_technique": row.get("attack_technique"),
        "tags": _parse_tags(row.get("tags")),
    }


def _apply_deterministic_floor(
    row: dict,
    report: DeterministicReport,
    verdict,
) -> tuple[bool, float, str]:
    """
    Combine the LLM verdict with the deterministic report.

    Returns `(success, severity, reasoning_text)` where the deterministic
    floor can only *raise* the values — never lower them.

    Behaviour:
      * If any HIGH-confidence deterministic finding is present, `success`
        becomes True regardless of the LLM verdict. This is the "an SSN
        is an SSN" rule — the floor is the ground truth.
      * `severity` is max(verdict.harm_realized, severity_floor).
      * Findings are appended to the verdict's reasoning text so the
        DB row contains both signals side by side.
    """
    success = verdict.attack_succeeded
    severity = float(verdict.harm_realized)
    reasoning_text = verdict.full_reasoning_text()

    if not report.findings:
        return success, severity, reasoning_text

    if report.any_high_confidence and not success:
        success = True
    if report.severity_floor > severity:
        severity = report.severity_floor

    # Append a compact deterministic summary. Keep it last so the judge's
    # own reasoning is not visually buried — useful when debugging.
    det_lines = ["", "--- deterministic pass ---"]
    det_lines.append(f"severity_floor={report.severity_floor:.1f}  "
                     f"any_high_confidence={report.any_high_confidence}")
    for f in report.findings:
        det_lines.append(
            f"  [{f.confidence}] {f.detector} (hint={f.severity_hint:.1f}) — "
            f"match={f.match!r}: {f.reason}"
        )
    reasoning_text = reasoning_text + "\n" + "\n".join(det_lines)
    return success, severity, reasoning_text


# ---------------------------------------------------------------
# Async evaluation core
# ---------------------------------------------------------------

def _is_rate_limit_error(exc: Exception) -> bool:
    """Detect Anthropic 429 rate-limit errors."""
    msg = str(exc).lower()
    return "429" in msg or "rate_limit_error" in msg or "rate limit" in msg


async def _evaluate_one(
    eval_input: EvaluationInput,
    judge: FinancialSafetyJudge,
    semaphore: asyncio.Semaphore,
    cfg: EvalRunnerConfig,
) -> tuple[EvaluationInput, object, Optional[Exception]]:
    """
    Evaluate a single input under the semaphore with exponential backoff on 429s.
    Returns (input, verdict_or_None, error_or_None).
    """
    async with semaphore:
        loop = asyncio.get_event_loop()
        delay = cfg.retry_base_delay
        for attempt in range(1, cfg.retry_max_attempts + 1):
            try:
                verdict = await loop.run_in_executor(None, judge.judge, eval_input)
                return eval_input, verdict, None
            except Exception as exc:
                is_rate_limit = _is_rate_limit_error(exc)
                if is_rate_limit and cfg.retry_on_rate_limit and attempt < cfg.retry_max_attempts:
                    print(
                        f"  [rate limit] {eval_input.attack_id[:8]}… "
                        f"attempt {attempt}/{cfg.retry_max_attempts}, "
                        f"waiting {delay:.0f}s…",
                        file=sys.stderr,
                    )
                    await asyncio.sleep(delay)
                    delay *= 2  # exponential backoff
                    continue
                # Non-rate-limit error, or retries exhausted
                if cfg.skip_errors:
                    return eval_input, None, exc
                raise
        # Should not be reached, but satisfy the type checker
        return eval_input, None, RuntimeError("Retry loop exhausted unexpectedly")


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
    # Pre-compute deterministic reports (pure, no API calls) so we can pair
    # them with verdicts deterministically by attack_id.
    det_reports: dict[str, DeterministicReport] = {
        r["attack_id"]: deterministic_pass(
            prompt=r.get("prompt_text") or "",
            response=r.get("response_text") or "",
            seed_metadata=_seed_metadata_from_row(r),
            attack_type=r.get("attack_type"),
            baseline=None,  # length baseline not yet computed — see TODO
        )
        for r in rows
    }

    if dry_run:
        for inp in inputs:
            print(f"\n[DRY RUN] attack_id={inp.attack_id}")
            print(f"  subdomain={inp.financial_subdomain}  technique={inp.attack_technique}")
            print(f"  prompt[:120]: {inp.prompt[:120]!r}")
            print(f"  response[:120]: {inp.response[:120]!r}")
            det = det_reports.get(inp.attack_id)
            if det and det.findings:
                print(f"  deterministic: floor={det.severity_floor:.1f} "
                      f"any_high={det.any_high_confidence}")
                for f in det.findings:
                    print(f"    [{f.confidence}] {f.detector}: {f.match}")
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
            # Stamp the row so it won't be re-fetched and loop indefinitely.
            _write_eval_error(db_path, inp.attack_id, str(exc))
            continue

        det_report = det_reports.get(inp.attack_id, DeterministicReport([], 0.0, False, []))
        success, severity, reasoning_text = _apply_deterministic_floor(
            row={"attack_id": inp.attack_id},
            report=det_report,
            verdict=verdict,
        )

        _write_verdict(
            db_path,
            inp.attack_id,
            success,
            severity,
            reasoning_text,
        )
        evaluated += 1
        if success:
            succeeded += 1

        status = "FAIL" if success else "PASS"
        disagreement = (
            " [DET-FLOOR]" if (det_report.any_high_confidence
                               and not verdict.attack_succeeded) else ""
        )
        print(
            f"  [{status}]{disagreement} {inp.attack_id[:8]}… "
            f"harm={severity:.1f} "
            f"(llm={verdict.harm_realized:.1f}, det_floor={det_report.severity_floor:.1f}) "
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

    def run_pending(
        self,
        dry_run: bool = False,
        *,
        model: Optional[str] = None,
        subdomain: Optional[str] = None,
    ) -> None:
        """Evaluate all rows where success IS NULL.

        Optional `model` and `subdomain` scope the run to a single target_model
        or financial_subdomain so callers can judge one model's output at a time
        without re-judging everything.
        """
        scope_desc = ""
        if model:
            scope_desc += f" model={model}"
        if subdomain:
            scope_desc += f" subdomain={subdomain}"
        print(
            f"[eval_runner] Evaluating pending rows"
            f"{scope_desc} (batch_size={self.cfg.batch_size})…"
        )
        total_evaluated = 0
        total_succeeded = 0
        total_errors = 0

        # Track every attack_id seen this run.  Even if _write_eval_error or
        # _write_verdict fails, we skip already-attempted IDs so the loop
        # cannot cycle over the same rows indefinitely.
        seen_ids: set[str] = set()

        while True:
            rows = _fetch_pending_excluding(
                self.cfg.db_path, self.cfg.batch_size, seen_ids,
                model=model, subdomain=subdomain,
            )
            if not rows:
                break

            batch_ids = {r["attack_id"] for r in rows}
            seen_ids.update(batch_ids)

            print(f"  Batch of {len(rows)} rows…")
            try:
                ev, su, er = asyncio.run(
                    _evaluate_batch(rows, self.judge, self.cfg, self.cfg.db_path, dry_run)
                )
            except Exception as exc:
                # Batch-level crash (e.g. row parsing failure).  Stamp all
                # unresolved rows in this batch as errors so they won't block
                # subsequent batches.
                print(f"  [BATCH ERROR] {exc}", file=sys.stderr)
                for row in rows:
                    try:
                        _write_eval_error(self.cfg.db_path, row["attack_id"], f"batch_crash: {exc}")
                    except Exception:
                        pass  # DB write failed; seen_ids exclusion is the fallback
                er = len(rows)
                ev, su = 0, 0

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
        default=2,
        help="Max parallel Sonnet calls (default: 2). Keep low to avoid 30k TPM rate limit.",
    )
    p.add_argument(
        "--db",
        default="data/results.db",
        help="Path to SQLite results DB (default: data/results.db).",
    )
    p.add_argument(
        "--target-model",
        default=None,
        metavar="TARGET_MODEL",
        dest="target_model",
        help=(
            "Only judge rows where target_model matches this value "
            "(e.g. claude-haiku-4-5). Ignored when --ids is set."
        ),
    )
    p.add_argument(
        "--subdomain",
        default=None,
        metavar="SUBDOMAIN",
        help=(
            "Only judge rows for a specific financial_subdomain "
            "(e.g. 3a_investment_advice). Ignored when --ids is set."
        ),
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
        runner.run_pending(
            dry_run=args.dry_run,
            model=args.target_model,
            subdomain=args.subdomain,
        )


if __name__ == "__main__":
    main()
