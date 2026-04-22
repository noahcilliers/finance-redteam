"""
scripts/migrate_refusal_sentinel.py
------------------------------------
One-shot migration for the `[REFUSAL]` sentinel problem described in
docs/phase-4-completion-plan.md §1.

Context
-------
Older runs persisted rows where the target model's response was literally the
string "[REFUSAL]" — a sentinel emitted by
`execution/connectors/anthropic_connector.py` when the Anthropic API set
`stop_reason == 'refusal'` (provider-side block, no generated text). That
sentinel was fine as an in-memory placeholder but contaminates the DB:

  * the judge has nothing to score, so every such row flattens to
    severity = 0 once evaluated, diluting the 3b success distribution;
  * the `[REFUSAL]` string leaks into dashboards as if it were a real
    response body.

Going forward, `execution/deepteam_bridge.testcase_to_attack_result` translates
the sentinel at the DB boundary (empty `response_text` + `error='api_level_refusal'`).
This migration backfills the same translation onto rows that were written
before that fix.

What it does
------------
For every row where `response_text = '[REFUSAL]'`:
  * response_text     → ''
  * error             → 'api_level_refusal' (unless the row already has a
                         different error; then it's left alone)
  * success           → NULL
  * severity_score    → NULL
  * judge_reasoning   → NULL    (so the row is excluded from analytics, and
                                  the eval_runner won't pick it up either
                                  because of the error guard)

The script is **idempotent** — running it twice is a no-op on the second
pass because no rows will match `response_text = '[REFUSAL]'` anymore.

Usage
-----
    cd ~/finance-redteam && source redteam-env/bin/activate
    python3 -m scripts.migrate_refusal_sentinel              # default DB
    python3 -m scripts.migrate_refusal_sentinel --dry-run    # report only
    python3 -m scripts.migrate_refusal_sentinel --db path/to/results.db

The script backs up the DB to `<db>.backup-<timestamp>` before writing unless
you pass `--no-backup`.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone


SENTINEL = "[REFUSAL]"
API_LEVEL_REFUSAL_ERROR = "api_level_refusal"


def _report_pre_state(con: sqlite3.Connection) -> dict[str, int]:
    """Count what we're about to migrate, by attack_type."""
    cur = con.execute(
        """
        SELECT attack_type, COUNT(*)
        FROM attack_results
        WHERE response_text = ?
        GROUP BY attack_type
        ORDER BY COUNT(*) DESC
        """,
        (SENTINEL,),
    )
    breakdown = {row[0] or "(null)": row[1] for row in cur.fetchall()}
    total = sum(breakdown.values())
    print(f"Found {total} rows with response_text = '{SENTINEL}'.")
    for k, v in breakdown.items():
        print(f"  {k:<30} {v}")
    return {"total": total, **breakdown}


def _apply_migration(con: sqlite3.Connection) -> int:
    """Apply the UPDATE. Returns number of rows affected."""
    cur = con.execute(
        """
        UPDATE attack_results
        SET response_text  = '',
            error          = COALESCE(
                                CASE WHEN error IS NULL OR error = ''
                                     THEN ?
                                     ELSE error
                                END,
                                ?
                              ),
            success        = NULL,
            severity_score = NULL,
            judge_reasoning = NULL
        WHERE response_text = ?
        """,
        (API_LEVEL_REFUSAL_ERROR, API_LEVEL_REFUSAL_ERROR, SENTINEL),
    )
    return cur.rowcount


def _verify(con: sqlite3.Connection) -> None:
    """Post-condition checks."""
    leftover = con.execute(
        "SELECT COUNT(*) FROM attack_results WHERE response_text = ?",
        (SENTINEL,),
    ).fetchone()[0]
    assert leftover == 0, f"Migration left {leftover} sentinel rows behind"

    api_ref = con.execute(
        "SELECT COUNT(*) FROM attack_results WHERE error = ?",
        (API_LEVEL_REFUSAL_ERROR,),
    ).fetchone()[0]
    print(f"Post-migration: 0 sentinel rows, {api_ref} rows flagged "
          f"error='{API_LEVEL_REFUSAL_ERROR}'.")


def _backup(db_path: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dst = f"{db_path}.backup-{ts}"
    shutil.copy2(db_path, dst)
    print(f"Backup written to {dst}")
    return dst


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--db",
        default="data/results.db",
        help="Path to SQLite results DB (default: data/results.db).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change, don't write.",
    )
    ap.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating a .backup-<timestamp> copy before migrating.",
    )
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"DB not found: {args.db}", file=sys.stderr)
        return 2

    con = sqlite3.connect(args.db)
    try:
        _report_pre_state(con)
        if args.dry_run:
            print("Dry run — no writes.")
            return 0

        if not args.no_backup:
            _backup(args.db)

        with con:
            affected = _apply_migration(con)
        print(f"Updated {affected} rows.")

        _verify(con)
    finally:
        con.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
