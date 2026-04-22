"""
execution/replay_against_target.py
-----------------------------------
Replay previously-executed attack prompts against a new target model without
re-invoking DeepTeam's enhancer pipeline.

Motivation
~~~~~~~~~~
``deepteam_run`` builds attack variants by running the OpenAI simulator
through a stack of enhancers (Multilingual, PromptInjection, Roleplay, etc.).
That simulator path is slow and can time out on crowded OpenAI endpoints. Once
a set of variants has been built and persisted to ``data/results.db``, the
cheapest apples-to-apples way to compare two target models is to re-send the
*same* prompts against the new target.

Use case
~~~~~~~~
``source_target`` (e.g. ``claude-sonnet-4-6``) has 60 judged 3b attacks in the
DB, including the expensive Multilingual variants. We want to know how
``claude-haiku-4-5`` holds up on *that exact variant set*. Running
``deepteam_run --subdomain 3b --target claude-haiku-4-5`` would rebuild the
whole variant set from scratch (slow, new OpenAI calls, possibly different
variants). This script instead reuses the existing DB prompts.

Flow
~~~~
1. Query the DB for rows where ``target_model == source_target`` matching the
   subdomain/attack-type filters, with a genuine response (no api_level_refusal).
2. Load seed library and build a ``prompt_text → seed`` best-match map so we
   can re-resolve per-seed system prompts (needed for 3c PII context fixtures).
3. Fire every prompt at the new target connector via RateLimiter. Each
   generates a fresh ``AttackResult`` row with a new ``attack_id`` and
   ``target_model=new_target``; ``success``/``severity``/``judge_reasoning``
   are left ``None`` so ``eval_runner`` picks them up naturally.
4. Print a compact summary.

What it does NOT do
~~~~~~~~~~~~~~~~~~~
* Doesn't re-run the DeepTeam enhancers (that's the whole point).
* Doesn't call the judge — ``evaluation.eval_runner`` handles that on its
  next pass.
* Doesn't de-duplicate if you run it twice — new rows each time.

CLI
~~~
    python3 -m execution.replay_against_target \
        --source-target claude-sonnet-4-6 \
        --target claude-haiku-4-5 \
        --subdomain 3b

Flags:
    --source-target MODEL   Model whose prompts you want to re-use (required).
    --target MODEL          New target to fire those prompts at (required).
    --subdomain SUB         Short prefix or full name; repeat for multiple.
    --limit N               Cap replay to N prompts (smoke-test aid).
    --dry-run               List the rows that would be replayed, don't fire.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except ImportError:
    pass

from data.database import init_db, save_result
from data.models import AttackResult, AttackType, AttackTechnique
from execution.connectors import get_connector
from execution.deepteam_bridge import build_effective_system_prompt
from execution.pipeline_config import PipelineConfig
from execution.rate_limiter import RateLimiter
from generation.seed_loader import SeedLoader

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Seed matching
# ---------------------------------------------------------------------------

def _build_seed_indexes(seeds: list[dict]) -> tuple[
    dict[str, dict],               # by_id
    dict[str, dict],               # by_exact_prompt
    dict[tuple, list[dict]],       # by_signature
]:
    """
    Three indexes for progressively looser seed matching:
      * by_id             — canonical lookup once we know the seed id
      * by_exact_prompt   — matches the seed_raw variant verbatim
      * by_signature      — (subdomain, attack_type, attack_technique) bucket,
                            used as a fallback for enhanced variants where the
                            prompt has been mutated beyond recognition.
    """
    by_id: dict[str, dict] = {}
    by_exact_prompt: dict[str, dict] = {}
    by_signature: dict[tuple, list[dict]] = {}
    for s in seeds:
        sid = s.get("id")
        if sid:
            by_id[sid] = s
        prompt = (s.get("prompt") or "").strip()
        if prompt:
            by_exact_prompt.setdefault(prompt, s)
        sig = (
            s.get("financial_subdomain"),
            s.get("attack_type"),
            s.get("attack_technique"),
        )
        by_signature.setdefault(sig, []).append(s)
    return by_id, by_exact_prompt, by_signature


def _match_seed_for_row(
    row: dict,
    by_exact_prompt: dict[str, dict],
    by_signature: dict[tuple, list[dict]],
) -> tuple[Optional[dict], str]:
    """
    Best-effort map from a DB row to the seed that produced it.

    Returns ``(seed, match_kind)`` where ``match_kind`` is one of:
      * ``"exact_prompt"`` — seed_raw variant, seed.prompt == row.prompt_text
      * ``"unique_signature"`` — only one seed has this (subdomain, type,
        technique) triple; attribution is unambiguous
      * ``"ambiguous_signature_first"`` — multiple seeds match; picked the
        first. Replay is best-effort — for 3c this means the context
        fixtures may not match the original run exactly.
      * ``"none"`` — no matching seed; replay still fires but with no
        per-seed system prompt.
    """
    prompt = (row.get("prompt_text") or "").strip()
    if prompt and prompt in by_exact_prompt:
        return by_exact_prompt[prompt], "exact_prompt"

    sig = (
        row.get("financial_subdomain"),
        row.get("attack_type"),
        row.get("attack_technique"),
    )
    candidates = by_signature.get(sig, [])
    if len(candidates) == 1:
        return candidates[0], "unique_signature"
    if candidates:
        return candidates[0], "ambiguous_signature_first"
    return None, "none"


# ---------------------------------------------------------------------------
# DB selection
# ---------------------------------------------------------------------------

def _fetch_source_rows(
    db_path: str,
    source_target: str,
    subdomains: Optional[list[str]],
    attack_types: Optional[list[str]],
    limit: Optional[int],
) -> list[dict]:
    """
    Load candidate source rows — rows produced by ``source_target`` with a
    usable response body (non-empty, no api_level_refusal / other execution
    error). Subdomain filter accepts short prefixes (``3b`` → matches
    ``3b_fraud_and_scams``).
    """
    clauses = [
        "target_model = ?",
        "response_text IS NOT NULL",
        "response_text != ''",
        "(error IS NULL OR error = '')",
    ]
    params: list[Any] = [source_target]

    if subdomains:
        # Match either exact value or prefix (e.g. "3b" matches "3b_fraud_and_scams").
        ors: list[str] = []
        for s in subdomains:
            ors.append("LOWER(financial_subdomain) = ?")
            params.append(s.lower())
            ors.append("LOWER(financial_subdomain) LIKE ?")
            params.append(s.lower() + "%")
        clauses.append("(" + " OR ".join(ors) + ")")

    if attack_types:
        placeholders = ",".join("?" * len(attack_types))
        clauses.append(f"attack_type IN ({placeholders})")
        params.extend(attack_types)

    sql = f"SELECT * FROM attack_results WHERE {' AND '.join(clauses)} ORDER BY timestamp ASC"
    if limit:
        sql += " LIMIT ?"
        params.append(limit)

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(sql, params).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Replay execution
# ---------------------------------------------------------------------------

def _safe_enum(cls, raw: Optional[str]):
    try:
        return cls(raw or "")
    except (ValueError, TypeError):
        return cls.unknown


def _build_replay_tags(row: dict, seed: Optional[dict], match_kind: str) -> list[str]:
    """
    Tag the new row with provenance so we can trace replays back to their
    source. Preserves the original variant-identifying tags (deepteam_method,
    language flags, etc.) while adding replay-specific markers.
    """
    import json as _json
    raw = row.get("tags")
    try:
        base_tags = _json.loads(raw) if raw else []
    except (ValueError, TypeError):
        base_tags = []
    if not isinstance(base_tags, list):
        base_tags = []

    tags = [t for t in base_tags if isinstance(t, str)]
    tags.append(f"replayed_from:{row['attack_id']}")
    tags.append(f"replay_match:{match_kind}")
    if seed and seed.get("id"):
        tags.append(f"seed_id:{seed['id']}")
    return tags


async def _replay_one(
    row: dict,
    seed: Optional[dict],
    match_kind: str,
    connector,
    new_target: str,
    global_system_prompt: Optional[str],
    limiter: RateLimiter,
) -> AttackResult:
    """Fire one prompt at the new target and return a fresh AttackResult."""
    prompt_text = (row.get("prompt_text") or "").strip()
    system_prompt = (
        build_effective_system_prompt(seed, global_system_prompt=global_system_prompt)
        if seed is not None
        else global_system_prompt
    )

    async with limiter:
        response_text: Optional[str] = None
        error: Optional[str] = None
        try:
            response_text = await connector.chat(
                user_prompt=prompt_text,
                system_prompt=system_prompt,
            )
        except Exception as exc:  # noqa: BLE001 — surface all errors on the row
            error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "  [err] replay of %s failed: %s", row["attack_id"][:8], error,
            )

    return AttackResult(
        attack_type=_safe_enum(AttackType, row.get("attack_type")),
        attack_technique=_safe_enum(AttackTechnique, row.get("attack_technique")),
        prompt_text=prompt_text or "(empty)",
        target_model=new_target,
        response_text=response_text or "",
        error=error,
        financial_subdomain=row.get("financial_subdomain"),
        tags=_build_replay_tags(row, seed, match_kind),
    )


async def replay(
    *,
    source_target: str,
    new_target: str,
    subdomains: Optional[list[str]],
    attack_types: Optional[list[str]],
    limit: Optional[int],
    dry_run: bool,
    cfg: PipelineConfig,
    max_concurrent: Optional[int],
    target_rps_override: Optional[float],
) -> list[AttackResult]:
    """
    End-to-end replay. Returns the list of persisted AttackResult objects
    (empty if dry_run).
    """
    init_db()

    rows = _fetch_source_rows(
        db_path=os.environ.get("FINANCE_REDTEAM_DB", "data/results.db"),
        source_target=source_target,
        subdomains=subdomains,
        attack_types=attack_types,
        limit=limit,
    )
    logger.info(
        "Source rows found | model=%s | subdomains=%s | attack_types=%s | n=%d",
        source_target, subdomains, attack_types, len(rows),
    )
    if not rows:
        logger.error("Nothing to replay.")
        return []

    all_seeds = SeedLoader().load_all()
    _, by_exact_prompt, by_signature = _build_seed_indexes(all_seeds)

    # Annotate each row with its best-match seed up front — useful for the
    # dry-run summary and for downstream matching.
    matched: list[tuple[dict, Optional[dict], str]] = []
    match_counts: dict[str, int] = {}
    for r in rows:
        seed, kind = _match_seed_for_row(r, by_exact_prompt, by_signature)
        matched.append((r, seed, kind))
        match_counts[kind] = match_counts.get(kind, 0) + 1
    logger.info("Seed match breakdown: %s", match_counts)

    if dry_run:
        for r, seed, kind in matched[:20]:
            sys_pr = build_effective_system_prompt(
                seed, global_system_prompt=cfg.target_system_prompt,
            ) if seed else cfg.target_system_prompt
            print(
                f"[{kind}] {r['attack_id'][:8]}... "
                f"{r.get('financial_subdomain')} / {r.get('attack_technique')} "
                f"seed={seed.get('id') if seed else '-'}  "
                f"sys_prompt={'set (' + str(len(sys_pr)) + ' chars)' if sys_pr else 'none'}"
            )
        if len(matched) > 20:
            print(f"... ({len(matched) - 20} more)")
        return []

    connector = get_connector(new_target)
    concurrency = max_concurrent or cfg.target_max_concurrent
    effective_rps = target_rps_override if target_rps_override is not None else cfg.target_rps
    limiter = RateLimiter.from_rps(effective_rps, max_concurrent=concurrency)
    logger.info(
        "Replaying %d prompt(s) against %s | concurrency=%d | rps=%.3f (~%d RPM)",
        len(matched), new_target, concurrency, effective_rps, int(round(effective_rps * 60)),
    )

    async def _task(row, seed, kind):
        return await _replay_one(
            row, seed, kind,
            connector=connector,
            new_target=new_target,
            global_system_prompt=cfg.target_system_prompt,
            limiter=limiter,
        )

    results: list[AttackResult] = await asyncio.gather(*(_task(*m) for m in matched))

    # Persist in-order so failures mid-run still leave the earlier rows saved.
    ok = 0
    err = 0
    for res in results:
        save_result(res)
        if res.error:
            err += 1
        elif res.response_text:
            ok += 1
    logger.info("Replay complete | ok=%d errors=%d saved=%d", ok, err, len(results))
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Replay previously-executed attack prompts against a new target "
            "model, without re-invoking DeepTeam's enhancer pipeline."
        ),
    )
    p.add_argument(
        "--config", "-c",
        default="execution/pipeline_config.yaml",
        help="Path to pipeline YAML config (used for global system prompt + rate limits).",
    )
    p.add_argument(
        "--source-target",
        default="claude-sonnet-4-6",
        help="Model whose prompts to re-use (default: claude-sonnet-4-6).",
    )
    p.add_argument(
        "--target",
        required=True,
        help="New target model to fire the prompts at (e.g. claude-haiku-4-5).",
    )
    p.add_argument(
        "--subdomain",
        action="append",
        metavar="SUBDOMAIN",
        help=(
            "Restrict replay to one or more financial subdomains (repeat flag "
            "for multiple). Accepts '3a', '3b', '3c', or the full name."
        ),
    )
    p.add_argument(
        "--attack-type",
        action="append",
        metavar="TYPE",
        help="Restrict replay to specific attack_type values (repeat for multiple).",
    )
    p.add_argument(
        "--limit", "-n",
        type=int,
        default=None,
        help="Cap replay to the first N rows (smoke-test).",
    )
    p.add_argument(
        "--max-concurrent",
        type=int,
        default=None,
        help="Parallel requests cap. Defaults to config.target_max_concurrent.",
    )
    p.add_argument(
        "--rpm",
        type=float,
        default=None,
        help="Override target requests-per-minute ceiling. Default: config.target_rps*60.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print match summary for first 20 rows; don't call the target.",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="DEBUG-level logging.",
    )
    return p.parse_args()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    if not verbose:
        for noisy in ("httpx", "openai", "anthropic", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


async def _main() -> int:
    args = _parse_args()
    _setup_logging(args.verbose)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        logger.error("Config not found: %s", cfg_path)
        return 1
    cfg = PipelineConfig.from_yaml(cfg_path)

    results = await replay(
        source_target=args.source_target,
        new_target=args.target,
        subdomains=args.subdomain,
        attack_types=args.attack_type,
        limit=args.limit,
        dry_run=args.dry_run,
        cfg=cfg,
        max_concurrent=args.max_concurrent,
        target_rps_override=(args.rpm / 60.0) if args.rpm is not None else None,
    )
    if not results and not args.dry_run:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
