import json
import os
import sqlite3
from datetime import datetime
from typing import Optional

from data.models import AttackResult, AttackType, AttackTechnique

# Results DB path. Defaults to data/results.db under the project root but can
# be overridden via the FINANCE_REDTEAM_DB env var — useful when the default
# project location is on a shared/mounted filesystem that doesn't tolerate
# SQLite's locking requirements.
DB_PATH = os.environ.get("FINANCE_REDTEAM_DB", "data/results.db")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS attack_results (
    attack_id           TEXT PRIMARY KEY,
    attack_type         TEXT NOT NULL,
    attack_technique    TEXT NOT NULL,
    prompt_text         TEXT NOT NULL,
    target_model        TEXT NOT NULL,
    response_text       TEXT,
    timestamp           TEXT NOT NULL,
    success             INTEGER,
    severity_score      REAL,
    judge_reasoning     TEXT,
    error               TEXT,
    financial_subdomain TEXT,
    tags                TEXT
)
"""

# Columns added after the initial schema — applied at init time if missing.
_MIGRATIONS = [
    "ALTER TABLE attack_results ADD COLUMN financial_subdomain TEXT",
    "ALTER TABLE attack_results ADD COLUMN tags TEXT",
]


def init_db() -> None:
    """Create the database and attack_results table if they don't exist.

    Also applies any additive column migrations so that existing databases
    gain the new columns without losing data.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(_CREATE_TABLE)
        for stmt in _MIGRATIONS:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass  # column already exists — safe to ignore
        conn.commit()


def save_result(result: AttackResult) -> None:
    """Insert or replace an AttackResult row (works for initial save and post-eval updates)."""
    success_int = None if result.success is None else int(result.success)
    tags_json = json.dumps(result.tags) if result.tags else None
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO attack_results (
                attack_id, attack_type, attack_technique, prompt_text, target_model,
                response_text, timestamp, success, severity_score, judge_reasoning, error,
                financial_subdomain, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.attack_id,
                result.attack_type,
                result.attack_technique,
                result.prompt_text,
                result.target_model,
                result.response_text,
                result.timestamp.isoformat(),
                success_int,
                result.severity_score,
                result.judge_reasoning,
                result.error,
                result.financial_subdomain,
                tags_json,
            ),
        )
        conn.commit()


def _row_to_result(row: sqlite3.Row) -> AttackResult:
    success = None if row["success"] is None else bool(row["success"])
    raw_tags = row["tags"]
    tags = json.loads(raw_tags) if raw_tags else []
    return AttackResult(
        attack_id=row["attack_id"],
        attack_type=AttackType(row["attack_type"]),
        attack_technique=AttackTechnique(row["attack_technique"]),
        prompt_text=row["prompt_text"],
        target_model=row["target_model"],
        response_text=row["response_text"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        success=success,
        severity_score=row["severity_score"],
        judge_reasoning=row["judge_reasoning"],
        error=row["error"],
        financial_subdomain=row["financial_subdomain"],
        tags=tags,
    )


def get_result(attack_id: str) -> Optional[AttackResult]:
    """Fetch a single result by UUID. Returns None if not found."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM attack_results WHERE attack_id = ?", (attack_id,)
        ).fetchone()
    return _row_to_result(row) if row else None


def get_all_results() -> list[AttackResult]:
    """Return all rows as AttackResult objects."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM attack_results").fetchall()
    return [_row_to_result(r) for r in rows]


def query_results(filters: dict) -> list[AttackResult]:
    """
    Filter results by any combination of:
      attack_type, attack_technique, target_model, success, min_severity, max_severity
    """
    clauses = []
    params = []

    if "attack_type" in filters:
        clauses.append("attack_type = ?")
        params.append(filters["attack_type"])
    if "attack_technique" in filters:
        clauses.append("attack_technique = ?")
        params.append(filters["attack_technique"])
    if "target_model" in filters:
        clauses.append("target_model = ?")
        params.append(filters["target_model"])
    if "success" in filters:
        clauses.append("success = ?")
        params.append(int(filters["success"]))
    if "min_severity" in filters:
        clauses.append("severity_score >= ?")
        params.append(filters["min_severity"])
    if "max_severity" in filters:
        clauses.append("severity_score <= ?")
        params.append(filters["max_severity"])

    sql = "SELECT * FROM attack_results"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_result(r) for r in rows]
