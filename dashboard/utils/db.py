"""SQLite query layer for the dashboard.

All queries live here. Every public loader is wrapped in @st.cache_data(ttl=60)
so the dashboard picks up new pipeline-run rows within a minute while still
serving repeat page loads quickly.

Scoring views (everything except the browser detail view) apply two filters:
  * success IS NOT NULL           — row has a judge verdict
  * error IS NULL OR error = ''   — exclude execution-layer failures
"""

from __future__ import annotations

import os
import sqlite3
from typing import Iterable, Optional

import pandas as pd
import streamlit as st


def _nan_to_none(values: Iterable) -> list:
    """Convert NaN entries in an iterable to None.

    pandas' read_sql returns float('nan') for SQL NULLs in TEXT columns on
    Python 3.13 / newer pandas, but None on older versions. Downstream code
    wants a single sentinel — we normalise to None everywhere.
    """
    return [None if (v is None or (isinstance(v, float) and pd.isna(v))) else v for v in values]


def _normalise_null_columns(df: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
    """Replace NaN with None in the named columns so downstream ``is None`` checks work."""
    for col in columns:
        if col in df.columns:
            df[col] = df[col].astype(object).where(df[col].notna(), None)
    return df

# Resolve the DB path relative to the project root (one level above dashboard/).
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))
DB_PATH = os.environ.get(
    "FINANCE_REDTEAM_DB",
    os.path.join(_PROJECT_ROOT, "data", "results.db"),
)


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def get_db_path() -> str:
    return DB_PATH


# --- Shared WHERE fragment ---------------------------------------------------

_SCORED_WHERE = "success IS NOT NULL AND (error IS NULL OR error = '')"


# --- Overview ----------------------------------------------------------------

@st.cache_data(ttl=60)
def load_overview_stats() -> dict:
    """Return headline numbers for the overview page.

    Keys: total, evaluated, asr (float 0..1), avg_severity_on_failures (float or None).
    """
    with _connect() as con:
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM attack_results")
        total = cur.fetchone()[0]

        cur.execute(f"SELECT COUNT(*) FROM attack_results WHERE {_SCORED_WHERE}")
        evaluated = cur.fetchone()[0]

        cur.execute(
            f"SELECT AVG(CAST(success AS REAL)) FROM attack_results WHERE {_SCORED_WHERE}"
        )
        asr = cur.fetchone()[0] or 0.0

        cur.execute(
            f"SELECT AVG(severity_score) FROM attack_results "
            f"WHERE success = 1 AND (error IS NULL OR error = '')"
        )
        avg_sev = cur.fetchone()[0]

    return {
        "total": int(total),
        "evaluated": int(evaluated),
        "asr": float(asr),
        "avg_severity_on_failures": float(avg_sev) if avg_sev is not None else None,
    }


@st.cache_data(ttl=60)
def load_asr_by_subdomain() -> pd.DataFrame:
    """Returns DataFrame: subdomain, total, successes, asr."""
    sql = f"""
        SELECT financial_subdomain AS subdomain,
               COUNT(*)            AS total,
               SUM(success)        AS successes,
               AVG(CAST(success AS REAL)) AS asr
        FROM attack_results
        WHERE {_SCORED_WHERE}
        GROUP BY financial_subdomain
    """
    with _connect() as con:
        df = pd.read_sql(sql, con)
    df["successes"] = df["successes"].fillna(0).astype(int)
    df["asr"] = df["asr"].fillna(0.0)
    _normalise_null_columns(df, ["subdomain"])
    return df


@st.cache_data(ttl=60)
def load_severity_distribution() -> pd.DataFrame:
    """Returns DataFrame with a `severity_score` column for all scored rows."""
    sql = f"""
        SELECT severity_score
        FROM attack_results
        WHERE {_SCORED_WHERE} AND severity_score IS NOT NULL
    """
    with _connect() as con:
        return pd.read_sql(sql, con)


@st.cache_data(ttl=60)
def load_top_techniques(min_attempts: int = 5) -> pd.DataFrame:
    """Per-technique stats. Filtered to techniques with ≥ min_attempts scored rows.

    Columns: technique, attempts, successes, asr, avg_severity — sorted by asr desc.
    """
    sql = f"""
        SELECT attack_technique       AS technique,
               COUNT(*)                AS attempts,
               SUM(success)            AS successes,
               AVG(CAST(success AS REAL)) AS asr,
               AVG(severity_score)     AS avg_severity
        FROM attack_results
        WHERE {_SCORED_WHERE} AND attack_technique IS NOT NULL
        GROUP BY attack_technique
        HAVING COUNT(*) >= ?
        ORDER BY asr DESC, attempts DESC
    """
    with _connect() as con:
        df = pd.read_sql(sql, con, params=(min_attempts,))
    df["successes"] = df["successes"].fillna(0).astype(int)
    return df


# --- Heatmap -----------------------------------------------------------------

@st.cache_data(ttl=60)
def load_heatmap_data(models: Optional[tuple[str, ...]] = None) -> pd.DataFrame:
    """Technique × subdomain counts. Optionally filter by models (tuple for cache hashability).

    Columns: attack_technique, financial_subdomain, attempts, successes, asr.
    """
    params: list = []
    filter_sql = ""
    if models:
        placeholders = ",".join("?" for _ in models)
        filter_sql = f" AND target_model IN ({placeholders})"
        params.extend(models)

    sql = f"""
        SELECT attack_technique,
               financial_subdomain,
               COUNT(*)            AS attempts,
               SUM(success)        AS successes,
               AVG(CAST(success AS REAL)) AS asr
        FROM attack_results
        WHERE {_SCORED_WHERE}
          AND attack_technique IS NOT NULL
          {filter_sql}
        GROUP BY attack_technique, financial_subdomain
    """
    with _connect() as con:
        df = pd.read_sql(sql, con, params=params)
    df["successes"] = df["successes"].fillna(0).astype(int)
    df["asr"] = df["asr"].fillna(0.0)
    _normalise_null_columns(df, ["financial_subdomain"])
    return df


@st.cache_data(ttl=60)
def load_technique_by_model(models: Optional[tuple[str, ...]] = None) -> pd.DataFrame:
    """Technique × target_model counts. Columns: attack_technique, target_model, attempts, successes, asr."""
    params: list = []
    filter_sql = ""
    if models:
        placeholders = ",".join("?" for _ in models)
        filter_sql = f" AND target_model IN ({placeholders})"
        params.extend(models)

    sql = f"""
        SELECT attack_technique,
               target_model,
               COUNT(*)            AS attempts,
               SUM(success)        AS successes,
               AVG(CAST(success AS REAL)) AS asr
        FROM attack_results
        WHERE {_SCORED_WHERE}
          AND attack_technique IS NOT NULL
          {filter_sql}
        GROUP BY attack_technique, target_model
    """
    with _connect() as con:
        df = pd.read_sql(sql, con, params=params)
    df["successes"] = df["successes"].fillna(0).astype(int)
    df["asr"] = df["asr"].fillna(0.0)
    return df


@st.cache_data(ttl=60)
def load_scope_count(models: Optional[tuple[str, ...]] = None) -> int:
    """Count of scored attacks in scope for the heatmap sidebar."""
    params: list = []
    filter_sql = ""
    if models:
        placeholders = ",".join("?" for _ in models)
        filter_sql = f" AND target_model IN ({placeholders})"
        params.extend(models)
    sql = f"SELECT COUNT(*) FROM attack_results WHERE {_SCORED_WHERE}{filter_sql}"
    with _connect() as con:
        cur = con.cursor()
        cur.execute(sql, params)
        return int(cur.fetchone()[0])


# --- Dimensions (for filter options) ----------------------------------------

@st.cache_data(ttl=60)
def load_filter_options() -> dict:
    """Returns available options for sidebar filters."""
    with _connect() as con:
        subdomains = pd.read_sql(
            f"SELECT DISTINCT financial_subdomain FROM attack_results WHERE {_SCORED_WHERE}",
            con,
        )["financial_subdomain"].tolist()
        models = pd.read_sql(
            f"SELECT DISTINCT target_model FROM attack_results WHERE {_SCORED_WHERE}",
            con,
        )["target_model"].tolist()
        techniques = pd.read_sql(
            f"SELECT DISTINCT attack_technique FROM attack_results "
            f"WHERE {_SCORED_WHERE} AND attack_technique IS NOT NULL",
            con,
        )["attack_technique"].tolist()
    # pandas returns NaN for SQL NULLs on newer Python / pandas versions —
    # normalise to None before sorting so the sort key doesn't compare nan to str.
    subdomains = _nan_to_none(subdomains)
    models = [m for m in _nan_to_none(models) if m is not None]
    techniques = [t for t in _nan_to_none(techniques) if t is not None]
    subdomains = sorted(subdomains, key=lambda v: (v is None, v or ""))
    models = sorted(models)
    techniques = sorted(techniques)
    return {
        "subdomains": subdomains,
        "models": models,
        "techniques": techniques,
    }


# --- Attack browser ----------------------------------------------------------

def _browser_where(filters: dict) -> tuple[str, list]:
    clauses = [_SCORED_WHERE]
    params: list = []

    subs = filters.get("subdomains") or []
    if subs:
        # Handle NULL sentinel ("__GENERIC__") alongside explicit values.
        explicit = [s for s in subs if s != "__GENERIC__"]
        parts = []
        if explicit:
            ph = ",".join("?" for _ in explicit)
            parts.append(f"financial_subdomain IN ({ph})")
            params.extend(explicit)
        if "__GENERIC__" in subs:
            parts.append("financial_subdomain IS NULL")
        if parts:
            clauses.append("(" + " OR ".join(parts) + ")")

    models = filters.get("models") or []
    if models:
        ph = ",".join("?" for _ in models)
        clauses.append(f"target_model IN ({ph})")
        params.extend(models)

    techs = filters.get("techniques") or []
    if techs:
        ph = ",".join("?" for _ in techs)
        clauses.append(f"attack_technique IN ({ph})")
        params.extend(techs)

    outcome = filters.get("success_filter") or "All"
    if outcome == "Successes only":
        clauses.append("success = 1")
    elif outcome == "Failures only":
        clauses.append("success = 0")

    sev_range = filters.get("severity_range")
    if sev_range is not None:
        lo, hi = sev_range
        # Keep rows where severity is NULL only when the full 0–10 range is selected.
        if (lo, hi) == (0.0, 10.0):
            clauses.append("(severity_score IS NULL OR (severity_score >= ? AND severity_score <= ?))")
        else:
            clauses.append("severity_score >= ? AND severity_score <= ?")
        params.extend([lo, hi])

    where = " AND ".join(clauses)
    return where, params


def _filters_cache_key(filters: dict) -> tuple:
    """Render filters into a tuple so @st.cache_data can hash them."""
    return (
        tuple(sorted(filters.get("subdomains") or [])),
        tuple(sorted(filters.get("models") or [])),
        tuple(sorted(filters.get("techniques") or [])),
        filters.get("success_filter") or "All",
        tuple(filters.get("severity_range") or (0.0, 10.0)),
    )


@st.cache_data(ttl=60)
def load_browser_results(
    filters_key: tuple,
    filters: dict,
    limit: int = 50,
    offset: int = 0,
) -> tuple[pd.DataFrame, int]:
    """Return (results_df, total_count) for the attack browser.

    `filters_key` is a hashable tuple derived from `filters`; pass both so the
    cache key is stable while the query still has access to the raw filter dict.
    The query intentionally omits prompt_text and response_text.
    """
    where, params = _browser_where(filters)
    count_sql = f"SELECT COUNT(*) FROM attack_results WHERE {where}"
    data_sql = f"""
        SELECT attack_id,
               attack_technique,
               financial_subdomain,
               target_model,
               severity_score,
               success,
               timestamp
        FROM attack_results
        WHERE {where}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    with _connect() as con:
        cur = con.cursor()
        cur.execute(count_sql, params)
        total = int(cur.fetchone()[0])
        df = pd.read_sql(data_sql, con, params=[*params, limit, offset])
    _normalise_null_columns(df, ["financial_subdomain"])
    return df, total


@st.cache_data(ttl=60)
def load_browser_export(filters_key: tuple, filters: dict) -> pd.DataFrame:
    """Full filtered result set (no pagination) for CSV export.

    Still excludes prompt_text and response_text to keep the file small.
    """
    where, params = _browser_where(filters)
    sql = f"""
        SELECT attack_id,
               attack_type,
               attack_technique,
               financial_subdomain,
               target_model,
               severity_score,
               success,
               timestamp,
               tags,
               judge_reasoning
        FROM attack_results
        WHERE {where}
        ORDER BY timestamp DESC
    """
    with _connect() as con:
        return pd.read_sql(sql, con, params=params)


def load_attack_detail(attack_id: str) -> dict:
    """Fetch a single row including prompt_text and response_text.

    Intentionally uncached — detail view should always reflect the latest row.
    """
    with _connect() as con:
        row = pd.read_sql(
            "SELECT * FROM attack_results WHERE attack_id = ?",
            con,
            params=(attack_id,),
        )
    return row.iloc[0].to_dict() if len(row) else {}


# --- Model comparison --------------------------------------------------------

@st.cache_data(ttl=60)
def load_model_comparison() -> pd.DataFrame:
    """Per-model × subdomain counts.

    Columns: target_model, financial_subdomain, attempts, successes, asr.
    """
    sql = f"""
        SELECT target_model,
               financial_subdomain,
               COUNT(*)            AS attempts,
               SUM(success)        AS successes,
               AVG(CAST(success AS REAL)) AS asr
        FROM attack_results
        WHERE {_SCORED_WHERE}
        GROUP BY target_model, financial_subdomain
    """
    with _connect() as con:
        df = pd.read_sql(sql, con)
    df["successes"] = df["successes"].fillna(0).astype(int)
    df["asr"] = df["asr"].fillna(0.0)
    _normalise_null_columns(df, ["financial_subdomain"])
    return df


@st.cache_data(ttl=60)
def load_model_summary() -> pd.DataFrame:
    """One row per target_model with total/evaluated/asr and subdomain coverage."""
    with _connect() as con:
        totals = pd.read_sql(
            "SELECT target_model, COUNT(*) AS total FROM attack_results GROUP BY target_model",
            con,
        )
        evaluated = pd.read_sql(
            f"""
            SELECT target_model,
                   COUNT(*)            AS evaluated,
                   AVG(CAST(success AS REAL)) AS asr
            FROM attack_results
            WHERE {_SCORED_WHERE}
            GROUP BY target_model
            """,
            con,
        )
        coverage = pd.read_sql(
            f"""
            SELECT DISTINCT target_model, financial_subdomain
            FROM attack_results
            WHERE {_SCORED_WHERE}
            """,
            con,
        )

    summary = totals.merge(evaluated, on="target_model", how="left")
    summary["evaluated"] = summary["evaluated"].fillna(0).astype(int)
    summary["asr"] = summary["asr"].fillna(0.0)

    cov_map: dict[str, list] = {}
    for model, sub in zip(coverage["target_model"], coverage["financial_subdomain"]):
        if isinstance(sub, float) and pd.isna(sub):
            sub = None
        cov_map.setdefault(model, []).append(sub)
    summary["subdomains"] = summary["target_model"].map(
        lambda m: sorted(cov_map.get(m, []), key=lambda v: (v is None, v or ""))
    )
    return summary


@st.cache_data(ttl=60)
def load_technique_by_model_for_subdomains(
    subdomains: tuple[Optional[str], ...],
    models: tuple[str, ...],
) -> pd.DataFrame:
    """For the comparison page's technique breakdown table.

    Returns a long DataFrame: technique, target_model, attempts, successes, asr.
    Only rows whose financial_subdomain is in `subdomains` and whose target_model
    is in `models`.
    """
    sub_clauses = []
    params: list = []
    explicit = [s for s in subdomains if s is not None]
    if explicit:
        ph = ",".join("?" for _ in explicit)
        sub_clauses.append(f"financial_subdomain IN ({ph})")
        params.extend(explicit)
    if None in subdomains:
        sub_clauses.append("financial_subdomain IS NULL")
    sub_where = "(" + " OR ".join(sub_clauses) + ")" if sub_clauses else "1=1"

    model_ph = ",".join("?" for _ in models)
    params.extend(models)

    sql = f"""
        SELECT attack_technique      AS technique,
               target_model,
               COUNT(*)               AS attempts,
               SUM(success)           AS successes,
               AVG(CAST(success AS REAL)) AS asr
        FROM attack_results
        WHERE {_SCORED_WHERE}
          AND attack_technique IS NOT NULL
          AND {sub_where}
          AND target_model IN ({model_ph})
        GROUP BY attack_technique, target_model
    """
    with _connect() as con:
        df = pd.read_sql(sql, con, params=params)
    df["successes"] = df["successes"].fillna(0).astype(int)
    df["asr"] = df["asr"].fillna(0.0)
    return df


@st.cache_data(ttl=60)
def load_severity_by_model(models: tuple[str, ...]) -> pd.DataFrame:
    """Severity scores for successful attacks, one row per attack, per model."""
    ph = ",".join("?" for _ in models)
    sql = f"""
        SELECT target_model, severity_score
        FROM attack_results
        WHERE success = 1
          AND (error IS NULL OR error = '')
          AND severity_score IS NOT NULL
          AND target_model IN ({ph})
    """
    with _connect() as con:
        return pd.read_sql(sql, con, params=list(models))


# --- Judge page --------------------------------------------------------------

# Rows that have a response but no judge verdict yet.
_UNJUDGED_WHERE = (
    "response_text IS NOT NULL "
    "AND response_text != '' "
    "AND (error IS NULL OR error = '') "
    "AND success IS NULL"
)


@st.cache_data(ttl=30)
def load_unjudged_summary() -> pd.DataFrame:
    """Count of unjudged rows grouped by (target_model, financial_subdomain).

    Columns: target_model, financial_subdomain, count.
    Sorted by count desc.
    """
    sql = f"""
        SELECT target_model,
               financial_subdomain,
               COUNT(*) AS count
        FROM attack_results
        WHERE {_UNJUDGED_WHERE}
        GROUP BY target_model, financial_subdomain
        ORDER BY count DESC
    """
    with _connect() as con:
        df = pd.read_sql(sql, con)
    _normalise_null_columns(df, ["financial_subdomain"])
    return df


@st.cache_data(ttl=30)
def load_judge_status() -> dict:
    """Headline numbers for the judge page status panel.

    Keys: total, judged, unjudged, pending_judgeable.
    """
    with _connect() as con:
        cur = con.cursor()

        cur.execute("SELECT COUNT(*) FROM attack_results")
        total = cur.fetchone()[0]

        cur.execute(f"SELECT COUNT(*) FROM attack_results WHERE {_SCORED_WHERE}")
        judged = cur.fetchone()[0]

        cur.execute(f"SELECT COUNT(*) FROM attack_results WHERE {_UNJUDGED_WHERE}")
        unjudged = cur.fetchone()[0]

    return {
        "total": int(total),
        "judged": int(judged),
        "unjudged": int(unjudged),
    }


# Expose the cache-key helper so pages can use it when calling cached loaders.
filters_cache_key = _filters_cache_key
