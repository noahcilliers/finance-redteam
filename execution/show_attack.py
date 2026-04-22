"""
execution/show_attack.py
------------------------
Inspect a single attack row, or compare the same attack prompt across two
different target models.

Two modes:

1. Show one row
     python3 -m execution.show_attack --attack-id a31bd1fb

   (Prefix match works — supply as many characters as uniquely identify the
    row.)

2. Compare the same attack across models

   The replay pipeline tags each replayed row with `replayed_from:{source_id}`,
   so we can walk from the original (Sonnet) row to every replay (Haiku, etc.)
   that was fired with the identical prompt. Give either the source id OR any
   replay id — the script resolves the cluster in both directions.

     python3 -m execution.show_attack --compare a31bd1fb

   Add --full to dump full prompt + response text for each row (otherwise
   they're truncated to keep the table readable).

This script is stdlib-only — it talks to the SQLite DB directly so it doesn't
need the pydantic/deepeval import chain.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import textwrap
from typing import Optional

DB_PATH = os.environ.get("FINANCE_REDTEAM_DB", "data/results.db")

# Columns we care about, in the order we pull them from SQLite.
_COLS = [
    "attack_id",
    "attack_type",
    "attack_technique",
    "prompt_text",
    "target_model",
    "response_text",
    "timestamp",
    "success",
    "severity_score",
    "judge_reasoning",
    "error",
    "financial_subdomain",
    "tags",
]

_COL_LIST = ", ".join(_COLS)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _connect() -> sqlite3.Connection:
    if not os.path.exists(DB_PATH):
        sys.exit(
            f"DB not found at {DB_PATH}. Set FINANCE_REDTEAM_DB or run from "
            "the project root."
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _resolve_attack_id(conn: sqlite3.Connection, query: str) -> sqlite3.Row:
    """Accept a full UUID or a unique prefix; return the matching row or exit."""
    rows = conn.execute(
        f"SELECT {_COL_LIST} FROM attack_results WHERE attack_id LIKE ?",
        (query + "%",),
    ).fetchall()
    if not rows:
        sys.exit(f"No attack_id starts with '{query}'.")
    if len(rows) > 1:
        print(f"'{query}' is ambiguous — {len(rows)} matches:", file=sys.stderr)
        for r in rows:
            print(
                f"  {r['attack_id']}  {r['target_model']}  "
                f"{r['attack_type']}/{r['attack_technique']}  "
                f"{r['financial_subdomain']}",
                file=sys.stderr,
            )
        sys.exit("Supply a longer prefix.")
    return rows[0]


def _parse_tags(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    try:
        loaded = json.loads(raw)
        if isinstance(loaded, list):
            return loaded
    except (json.JSONDecodeError, TypeError):
        pass
    return []


def _replayed_from(tags: list[str]) -> Optional[str]:
    for t in tags:
        if isinstance(t, str) and t.startswith("replayed_from:"):
            return t.split(":", 1)[1]
    return None


def _find_source_and_replays(
    conn: sqlite3.Connection, any_id: str
) -> tuple[sqlite3.Row, list[sqlite3.Row]]:
    """Given any id in a replay cluster, return (source_row, [replay_rows])."""
    seed_row = _resolve_attack_id(conn, any_id)
    seed_tags = _parse_tags(seed_row["tags"])
    source_id = _replayed_from(seed_tags)

    if source_id:
        # The id the user gave is itself a replay — walk back to the source.
        source_row = conn.execute(
            f"SELECT {_COL_LIST} FROM attack_results WHERE attack_id = ?",
            (source_id,),
        ).fetchone()
        if source_row is None:
            print(
                f"WARN: replay {seed_row['attack_id']} points at "
                f"replayed_from:{source_id} but that row is missing from the DB.",
                file=sys.stderr,
            )
            source_row = seed_row  # best-effort: treat the replay as the root
    else:
        source_row = seed_row

    # Find every row that tags back to source_row.
    replay_rows = conn.execute(
        f"SELECT {_COL_LIST} FROM attack_results "
        "WHERE tags LIKE ? ORDER BY target_model, timestamp",
        (f"%replayed_from:{source_row['attack_id']}%",),
    ).fetchall()
    return source_row, replay_rows


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _status(row: sqlite3.Row) -> str:
    s = row["success"]
    if s is None:
        return "UNJUDGED"
    return "FAIL" if s else "PASS"


def _sev(row: sqlite3.Row) -> str:
    v = row["severity_score"]
    return "-" if v is None else f"{v:.1f}"


def _truncate(text: Optional[str], limit: int) -> str:
    if not text:
        return "(empty)"
    text = text.replace("\r\n", "\n")
    if len(text) <= limit:
        return text
    return text[:limit] + f"… [+{len(text) - limit} chars]"


def _indent_block(text: str, prefix: str = "    ") -> str:
    return textwrap.indent(text, prefix)


def _print_row_detail(row: sqlite3.Row, full: bool) -> None:
    tags = _parse_tags(row["tags"])
    prompt_limit = 10_000 if full else 1_200
    response_limit = 10_000 if full else 2_000

    print("=" * 78)
    print(f"attack_id:           {row['attack_id']}")
    print(f"target_model:        {row['target_model']}")
    print(f"attack_type:         {row['attack_type']}")
    print(f"attack_technique:    {row['attack_technique']}")
    print(f"financial_subdomain: {row['financial_subdomain']}")
    print(f"timestamp:           {row['timestamp']}")
    print(f"status:              {_status(row)}  severity={_sev(row)}")
    if row["error"]:
        print(f"error:               {row['error']}")
    if tags:
        print(f"tags:                {tags}")
    print()
    print("PROMPT:")
    print(_indent_block(_truncate(row["prompt_text"], prompt_limit)))
    print()
    print("RESPONSE:")
    print(_indent_block(_truncate(row["response_text"], response_limit)))
    if row["judge_reasoning"]:
        print()
        print("JUDGE REASONING:")
        print(_indent_block(_truncate(row["judge_reasoning"], 4_000)))
    print()


def _print_compare_summary(
    source: sqlite3.Row, replays: list[sqlite3.Row]
) -> None:
    print("=" * 78)
    print("COMPARE: same prompt across models")
    print("=" * 78)
    print(f"attack_type:         {source['attack_type']}")
    print(f"attack_technique:    {source['attack_technique']}")
    print(f"financial_subdomain: {source['financial_subdomain']}")
    print(f"source attack_id:    {source['attack_id']}")
    print()
    print("PROMPT (shared across all rows below):")
    print(_indent_block(_truncate(source["prompt_text"], 1_200)))
    print()

    all_rows = [source] + list(replays)
    # Column widths
    w_model = max(len("target_model"), max(len(r["target_model"]) for r in all_rows))
    header = (
        f"{'target_model':<{w_model}}  "
        f"{'role':<8}  {'status':<8}  {'sev':>4}  {'attack_id':<36}"
    )
    print(header)
    print("-" * len(header))
    for r in all_rows:
        role = "SOURCE" if r["attack_id"] == source["attack_id"] else "REPLAY"
        print(
            f"{r['target_model']:<{w_model}}  "
            f"{role:<8}  {_status(r):<8}  {_sev(r):>4}  {r['attack_id']:<36}"
        )
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Print one attack row, or compare the same prompt across all "
            "target models (source + replays)."
        ),
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--attack-id",
        help="Print full detail for a single row. Prefix match is allowed.",
    )
    mode.add_argument(
        "--compare",
        help=(
            "Cluster mode: resolve source + all replays that share this prompt "
            "and print a side-by-side summary plus each row's response."
        ),
    )
    p.add_argument(
        "--full",
        action="store_true",
        help="Print full prompt and response text (default: truncated).",
    )
    p.add_argument(
        "--no-bodies",
        action="store_true",
        help=(
            "In --compare mode, skip per-row prompt/response bodies and "
            "print only the summary table. Ignored with --attack-id."
        ),
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    conn = _connect()

    if args.attack_id:
        row = _resolve_attack_id(conn, args.attack_id)
        _print_row_detail(row, full=args.full)
        return 0

    source, replays = _find_source_and_replays(conn, args.compare)
    _print_compare_summary(source, replays)

    if args.no_bodies:
        return 0

    # Full per-row bodies, source first, then replays in the order returned
    # (stable: target_model ASC, timestamp ASC).
    _print_row_detail(source, full=args.full)
    for r in replays:
        _print_row_detail(r, full=args.full)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
