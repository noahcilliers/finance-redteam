"""Judge Attacks — batch evaluation launcher.

Reads unjudged AttackResult rows from the DB, lets the user scope and configure
the judge, then spawns `python -m evaluation.eval_runner` as a subprocess with
live log tailing.

Once rows gain a `success` + `severity_score` verdict they automatically appear
in the Overview, Heatmap, Browser and Comparison pages — those pages filter on
`success IS NOT NULL`, so no extra wiring is needed.

Subprocess model mirrors run.py:
  st.session_state.judge_process  — Popen handle
  st.session_state.judge_run      — ActiveRun snapshot for display / log path
  st.session_state.last_judge_run — kept after completion for post-mortem view
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import streamlit as st

_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

from utils.db import (  # noqa: E402
    load_judge_status,
    load_unjudged_summary,
)
from utils.runner import (  # noqa: E402
    LAUNCHER_LOG_DIR,
    PROJECT_ROOT,
    read_log_tail,
)
from utils.styles import (  # noqa: E402
    ACCENT,
    BORDER,
    DANGER,
    SUCCESS,
    SURFACE,
    TEXT_MUTED,
    inject_styles,
    subdomain_label,
)

inject_styles()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EVAL_MODULE = "evaluation.eval_runner"

# Judge implementations exposed in the UI. The CLI flag values
# (claude / gpt4o) match what evaluation.eval_runner expects via --judge.
JUDGE_OPTIONS: dict[str, dict] = {
    "claude": {
        "label": "Claude (Anthropic)",
        "models": ("claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-6"),
        "cost_per_row": {"sonnet": 0.003, "haiku": 0.0003, "opus": 0.015},
        "default_cost": 0.003,
    },
    "gpt4o": {
        "label": "GPT-4o (OpenAI)",
        "models": ("gpt-4o", "gpt-4o-mini"),
        "cost_per_row": {"gpt-4o-mini": 0.0004, "gpt-4o": 0.003},
        "default_cost": 0.003,
    },
}


def _row_cost_for(judge_key: str, model: str) -> float:
    """Pick a rough $/row figure for the cost preview."""
    spec = JUDGE_OPTIONS[judge_key]
    for needle, price in spec["cost_per_row"].items():
        if needle in model:
            return price
    return spec["default_cost"]


# ---------------------------------------------------------------------------
# Subprocess helpers (mirrors runner.py pattern)
# ---------------------------------------------------------------------------

@dataclass
class JudgeRun:
    pid: int
    started_at: float
    log_path: str
    argv: list[str]

    def pretty_argv(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    def wall_seconds(self) -> float:
        return max(0.0, time.time() - self.started_at)


def _launch_judge(argv: list[str]) -> tuple[subprocess.Popen, JudgeRun]:
    LAUNCHER_LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    log_path = LAUNCHER_LOG_DIR / f"judge_{ts}.log"
    log_file = log_path.open("w", encoding="utf-8", buffering=1)
    log_file.write(f"# Judge run {ts} UTC\n# argv: {' '.join(shlex.quote(a) for a in argv)}\n\n")
    log_file.flush()

    popen_kwargs: dict = dict(
        cwd=str(PROJECT_ROOT),
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    if hasattr(os, "setsid"):
        popen_kwargs["preexec_fn"] = os.setsid
    else:
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    proc = subprocess.Popen(argv, **popen_kwargs)
    run = JudgeRun(
        pid=proc.pid,
        started_at=time.time(),
        log_path=str(log_path),
        argv=list(argv),
    )
    return proc, run


def _process_alive(proc: Optional[subprocess.Popen]) -> bool:
    return proc is not None and proc.poll() is None


def _stop_judge(proc: subprocess.Popen, grace: float = 5.0) -> str:
    if proc.poll() is not None:
        return f"already exited (rc={proc.returncode})"
    try:
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError) as e:
        return f"terminate failed: {e}"
    try:
        proc.wait(timeout=grace)
        return f"terminated (rc={proc.returncode})"
    except subprocess.TimeoutExpired:
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
            proc.wait(timeout=grace)
            return f"killed (rc={proc.returncode})"
        except Exception as e:
            return f"kill failed: {e}"


# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------

st.title("Judge Attacks")
st.caption(
    "Run the LLM-as-judge evaluation pass on attacks that have a response but no "
    "verdict yet. Scored rows feed directly into the Overview, Heatmap, Browser, "
    "and Comparison pages."
)

# ---------------------------------------------------------------------------
# Status banner
# ---------------------------------------------------------------------------

status = load_judge_status()

s_col1, s_col2, s_col3 = st.columns(3)
s_col1.metric("Total attacks in DB", f"{status['total']:,}")
s_col2.metric("Already judged", f"{status['judged']:,}")
s_col3.metric(
    "Awaiting judgment",
    f"{status['unjudged']:,}",
    delta=f"−{status['unjudged']:,}" if status["unjudged"] == 0 else None,
    delta_color="normal" if status["unjudged"] == 0 else "off",
)

if status["unjudged"] == 0:
    st.success("All attacks with a response have been judged. Nothing pending.")

# ---------------------------------------------------------------------------
# Active-run section
# ---------------------------------------------------------------------------


def _render_log_panel(log_path: str, title_suffix: str = "") -> None:
    tail = read_log_tail(log_path, max_lines=400)
    if not tail.strip():
        st.caption("_Log is empty so far — the judge subprocess is booting…_")
    else:
        st.code(tail, language="text")
    st.caption(f"Showing last 400 lines · {log_path}{title_suffix}")


def _render_active_judge() -> None:
    proc = st.session_state.get("judge_process")
    run: JudgeRun = st.session_state.get("judge_run")
    if not run:
        return

    alive = _process_alive(proc)
    rc = None if alive else (proc.returncode if proc is not None else None)

    if alive:
        badge_color, badge_text = ACCENT, "RUNNING"
    elif rc == 0:
        badge_color, badge_text = SUCCESS, "COMPLETED"
    elif rc is None:
        badge_color, badge_text = TEXT_MUTED, "UNKNOWN"
    else:
        badge_color, badge_text = DANGER, f"FAILED (rc={rc})"

    elapsed = run.wall_seconds()
    mins, secs = divmod(int(elapsed), 60)
    st.markdown(
        f"""
        <div style="background:var(--color-surface);border:1px solid var(--color-border);
                    border-left:4px solid {badge_color};
                    border-radius:8px;padding:14px 18px;margin-bottom:10px;">
            <span style="font-size:12px;color:var(--color-muted);letter-spacing:0.5px;">STATUS</span>
            <h3 style="margin:2px 0 6px 0;color:{badge_color};">{badge_text}</h3>
            <div style="color:var(--color-muted);font-size:13px;">
                pid <code>{run.pid}</code>
                &nbsp;·&nbsp; elapsed <strong>{mins}m {secs:02d}s</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    ctrl1, ctrl2, ctrl3 = st.columns([1, 1, 4])
    with ctrl1:
        if st.button("⏹ Stop", disabled=not alive, type="secondary"):
            if proc is not None:
                msg = _stop_judge(proc)
                st.toast(f"Stop: {msg}")
                time.sleep(0.5)
                st.rerun()
    with ctrl2:
        if not alive and st.button("Dismiss"):
            st.session_state.last_judge_run = run
            st.session_state.pop("judge_run", None)
            st.session_state.pop("judge_process", None)
            st.rerun()
    with ctrl3:
        st.caption(f"Command: `{run.pretty_argv()}`")

    st.subheader("Live log")
    if alive:
        @st.fragment(run_every=2)
        def _log_fragment():
            still = _process_alive(st.session_state.get("judge_process"))
            _render_log_panel(run.log_path, title_suffix="  (tailing)")
            if not still:
                st.rerun()
        _log_fragment()
    else:
        _render_log_panel(run.log_path)
        if rc == 0:
            st.info(
                "Judging complete. The Overview, Heatmap, Browser and Comparison "
                "pages will reflect the new scores within ~60 s (cache TTL)."
            )


if st.session_state.get("judge_run") is not None:
    _render_active_judge()
    st.stop()


# ---------------------------------------------------------------------------
# Configuration form (only shown when no active judge run)
# ---------------------------------------------------------------------------

if status["unjudged"] == 0:
    # Show the last-run log if available, then stop.
    if st.session_state.get("last_judge_run"):
        lr: JudgeRun = st.session_state["last_judge_run"]
        with st.expander(f"Last judge run log · pid {lr.pid} · {Path(lr.log_path).name}"):
            _render_log_panel(lr.log_path)
    st.stop()

# --- Unjudged breakdown table -----------------------------------------------

st.subheader("1 · Unjudged attacks")
unjudged_df = load_unjudged_summary()

if unjudged_df.empty:
    st.warning("No unjudged attacks found.")
    st.stop()

# Display a compact breakdown table
display_df = unjudged_df.copy()
display_df["financial_subdomain"] = display_df["financial_subdomain"].apply(
    lambda v: subdomain_label(v) if v is not None else "Generic / untagged"
)
display_df = display_df.rename(columns={
    "target_model": "Target model",
    "financial_subdomain": "Subdomain",
    "count": "Unjudged attacks",
})
st.dataframe(display_df, use_container_width=True, hide_index=True)

# --- Scope filters ----------------------------------------------------------

st.subheader("2 · Scope")

scope_col1, scope_col2 = st.columns(2)

available_models = sorted(unjudged_df["target_model"].dropna().unique().tolist())
available_subdomains = sorted(
    unjudged_df["financial_subdomain"].unique().tolist(),
    key=lambda v: (v is None, v or ""),
)

with scope_col1:
    scope_all = st.checkbox(
        "Judge all pending attacks",
        value=True,
        help="When checked, judges every unjudged row regardless of model or subdomain.",
    )

with scope_col2:
    st.caption("_Scope filters below are ignored when 'Judge all' is checked._")

scope_model: Optional[str] = None
scope_subdomain: Optional[str] = None

if not scope_all:
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        model_options = ["(all models)"] + available_models
        selected_model = st.selectbox(
            "Restrict to target model",
            options=model_options,
            index=0,
        )
        if selected_model != "(all models)":
            scope_model = selected_model

    with filter_col2:
        sub_options = ["(all subdomains)"] + [
            s if s is not None else "__GENERIC__" for s in available_subdomains
        ]
        selected_sub = st.selectbox(
            "Restrict to subdomain",
            options=sub_options,
            format_func=lambda v: (
                "(all subdomains)" if v == "(all subdomains)"
                else subdomain_label(None if v == "__GENERIC__" else v)
            ),
            index=0,
        )
        if selected_sub not in ("(all subdomains)", "__GENERIC__"):
            scope_subdomain = selected_sub

# Compute scoped count for preview
if scope_all:
    scoped_count = int(status["unjudged"])
    scope_note = "all models · all subdomains"
else:
    mask = unjudged_df["count"] >= 0  # start with all rows
    if scope_model:
        mask &= unjudged_df["target_model"] == scope_model
    if scope_subdomain:
        mask &= unjudged_df["financial_subdomain"] == scope_subdomain
    scoped_count = int(unjudged_df.loc[mask, "count"].sum())
    parts = []
    if scope_model:
        parts.append(f"model={scope_model}")
    if scope_subdomain:
        parts.append(f"subdomain={scope_subdomain}")
    scope_note = " · ".join(parts) if parts else "all models · all subdomains"

# --- Judge config -----------------------------------------------------------

st.subheader("3 · Judge configuration")

cfg_col1, cfg_col2, cfg_col3 = st.columns(3)

with cfg_col1:
    judge_keys = list(JUDGE_OPTIONS.keys())
    judge_choice = st.selectbox(
        "Judge implementation",
        options=judge_keys,
        index=0,
        format_func=lambda k: JUDGE_OPTIONS[k]["label"],
        help=(
            "Pick which LLM judge to run. Both implementations use the same "
            "rubric and produce the same JudgeVerdict shape — only the "
            "underlying model differs."
        ),
    )
    judge_model = st.selectbox(
        "Judge model",
        options=list(JUDGE_OPTIONS[judge_choice]["models"]),
        index=0,
        help="Model snapshot used as the judge. Sonnet/4o-class models give the best cost/quality balance.",
    )

with cfg_col2:
    concurrency = st.slider(
        "Concurrency",
        min_value=1,
        max_value=5,
        value=2,
        help="Parallel judge calls. Keep ≤ 2 to stay under the 30k TPM Anthropic rate limit.",
    )
    batch_size = st.number_input(
        "Batch size",
        min_value=1,
        max_value=100,
        value=20,
        help="DB rows fetched per batch. Larger batches reduce overhead but use more memory.",
    )

with cfg_col3:
    two_pass = st.checkbox(
        "Two-pass mode",
        value=False,
        help=(
            "Run a cheap binary pre-filter before full scoring. "
            "Saves cost when most responses are clear refusals."
        ),
    )
    re_judge_all = st.checkbox(
        "Re-judge already-scored rows",
        value=False,
        help=(
            "Pass --all to overwrite existing verdicts. "
            "Use this to apply a new rubric version to old results."
        ),
    )
    dry_run = st.checkbox(
        "Dry run (no API calls)",
        value=False,
        help="Print evaluation inputs without calling the judge. Free smoke-test.",
    )

# --- Scope preview -----------------------------------------------------------

st.subheader("4 · Scope preview")

preview_color = DANGER if scoped_count == 0 else ACCENT

# Cost estimate is provider-aware (see JUDGE_OPTIONS[...]['cost_per_row']).
cost_per_row = _row_cost_for(judge_choice, judge_model)
est_cost = scoped_count * cost_per_row
est_time_min = max(1, scoped_count * 5 / 60 / max(1, concurrency))  # ~5s/row at concurrency

st.markdown(
    f"""
    <div style="background:var(--color-surface);border:1px solid var(--color-border);
                border-left:4px solid {preview_color};border-radius:8px;
                padding:14px 18px;">
        <div style="display:flex;gap:40px;flex-wrap:wrap;">
            <div>
                <div style="font-size:11px;color:var(--color-muted);">ROWS TO JUDGE</div>
                <div style="font-size:24px;font-weight:600;color:var(--color-text);">{scoped_count:,}</div>
                <div style="font-size:11px;color:var(--color-muted);">{scope_note}</div>
            </div>
            <div>
                <div style="font-size:11px;color:var(--color-muted);">EST. RUNTIME</div>
                <div style="font-size:24px;font-weight:600;color:var(--color-text);">~{est_time_min:.0f} min</div>
                <div style="font-size:11px;color:var(--color-muted);">(~5s/row · concurrency {concurrency})</div>
            </div>
            <div>
                <div style="font-size:11px;color:var(--color-muted);">EST. API COST</div>
                <div style="font-size:24px;font-weight:600;color:var(--color-text);">~${est_cost:.2f}</div>
                <div style="font-size:11px;color:var(--color-muted);">({judge_model})</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if scoped_count == 0 and not re_judge_all:
    st.warning("No unjudged rows match the current scope — adjust filters or enable Re-judge.")

# --- Launch -----------------------------------------------------------------

st.subheader("5 · Launch")

launch_disabled = (scoped_count == 0 and not re_judge_all)

launch_col1, launch_col2 = st.columns([1, 4])
with launch_col1:
    launch_clicked = st.button(
        "⚖️ Judge now",
        type="primary",
        disabled=launch_disabled,
    )
with launch_col2:
    st.caption(f"Runner: `python -m {EVAL_MODULE}` from `{PROJECT_ROOT}`")

if launch_clicked and not launch_disabled:
    argv = [sys.executable, "-u", "-m", EVAL_MODULE]

    # Mode
    if re_judge_all:
        argv.append("--all")
    if dry_run:
        argv.append("--dry-run")
    if two_pass:
        argv.append("--two-pass")

    # Judge implementation + model + scope
    argv += ["--judge", judge_choice]
    argv += ["--model", judge_model]
    argv += ["--batch-size", str(int(batch_size))]
    argv += ["--concurrency", str(int(concurrency))]

    if not scope_all:
        if scope_model:
            argv += ["--target-model", scope_model]
        if scope_subdomain:
            argv += ["--subdomain", scope_subdomain]

    proc, run = _launch_judge(argv)
    st.session_state.judge_process = proc
    st.session_state.judge_run = run
    st.toast(f"Judge launched (pid {proc.pid})", icon="⚖️")
    time.sleep(0.3)
    st.rerun()


# ---------------------------------------------------------------------------
# Recent judge logs
# ---------------------------------------------------------------------------

st.divider()
st.subheader("Recent judge logs")

log_dir = LAUNCHER_LOG_DIR
if log_dir.is_dir():
    judge_logs = sorted(
        (p for p in log_dir.glob("judge_*.log") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:5]
    if judge_logs:
        for lp in judge_logs:
            started = datetime.fromtimestamp(lp.stat().st_mtime, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            with st.expander(f"{lp.name} · {started}"):
                _render_log_panel(str(lp))
    else:
        st.caption("No previous judge log files found.")
else:
    st.caption("No previous judge log files found.")

# Show the last-run log at the bottom if it was dismissed
if st.session_state.get("last_judge_run") and st.session_state.get("judge_run") is None:
    lr: JudgeRun = st.session_state["last_judge_run"]
    with st.expander(f"Last judge run log · pid {lr.pid} · {Path(lr.log_path).name}"):
        _render_log_panel(lr.log_path)
