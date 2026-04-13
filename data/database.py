import sqlite3
from datetime import datetime
from typing import Optional

from data.models import AttackResult, AttackType, AttackTechnique

DB_PATH = "data/results.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS attack_results (
    attack_id        TEXT PRIMARY KEY,
    attack_type      TEXT NOT NULL,
    attack_technique TEXT NOT NULL,
    prompt_text      TEXT NOT NULL,
    target_model     TEXT NOT NULL,
    response_text    TEXT,
    timestamp        TEXT NOT NULL,
    success          INTEGER,
    severity_score   REAL,
    judge_reasoning  TEXT,
    error            TEXT
)
"""


def init_db() -> None:
    """Create the database and attack_results table if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(_CREATE_TABLE)
        conn.commit()


def save_result(result: AttackResult) -> None:
    """Insert or replace an AttackResult row (works for initial save and post-eval updates)."""
    success_int = None if result.success is None else int(result.success)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO attack_results (
                attack_id, attack_type, attack_technique, prompt_text, target_model,
                response_text, timestamp, success, severity_score, judge_reasoning, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        conn.commit()


def _row_to_result(row: sqlite3.Row) -> AttackResult:
    success = None if row["success"] is None else bool(row["success"])
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
