"""Run Attacks — launcher page.

Form-based configuration for a red-team run, scope preview, subprocess
launch + live log tail + stop button, and a recent-runs list.

Subprocess management model:
  * ``st.session_state.run_process``  — Popen handle (cleared when done)
  * ``st.session_state.active_run``   — ActiveRun dict snapshot (for display)
  * ``st.session_state.last_run``     — ActiveRun of the most recent run, kept
                                         after completion for post-mortem view

The live log is a fragment that auto-reruns every 2s, so the rest of the page
doesn't flicker while the log updates.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st
import yaml

_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

from utils.runner import (  # noqa: E402
    KNOWN_ATTACKER_MODELS,
    KNOWN_EVALUATOR_MODELS,
    KNOWN_TARGET_MODELS,
    ActiveRun,
    ScopeFilters,
    api_key_status,
    build_cli_args,
    build_config_dict,
    launch_run,
    list_recent_runs,
    load_base_config,
    load_seed_catalog,
    preview_scope,
    process_alive,
    project_root,
    read_log_tail,
    stop_run,
    write_config_file,
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

st.title("Run Attacks")
st.caption(
    "Launch a red-team run against a target model. Progress streams live; "
    "results land in `data/results.db` and show up on the other tabs within ~60s."
)


# ---------------------------------------------------------------------------
# API-key & environment banner
# ---------------------------------------------------------------------------

keys = api_key_status()

badge_cols = st.columns(4)
for col, name, ok in (
    (badge_cols[0], "OpenAI", keys.openai),
    (badge_cols[1], "Anthropic", keys.anthropic),
    (badge_cols[2], "Google", keys.google),
    (badge_cols[3], ".env file", keys.dotenv_found),
):
    color = SUCCESS if ok else DANGER
    state = "present" if ok else "missing"
    col.markdown(
        f"<div style='background:{SURFACE};border:1px solid {BORDER};"
        f"border-left:4px solid {color};border-radius:6px;padding:8px 12px;'>"
        f"<div style='font-size:11px;color:{TEXT_MUTED};'>{name}</div>"
        f"<div style='font-weight:600;color:{color};font-size:14px;'>{state}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

if not (keys.openai and keys.anthropic):
    st.warning(
        "At least one required API key is missing from the process environment "
        "and `.env`. Library-faithful mode with `--no-llm-enhancers` can run "
        "without OpenAI, but the default setup needs both."
    )


# ---------------------------------------------------------------------------
# Running-run section (renders if there's an active subprocess)
# ---------------------------------------------------------------------------


def _render_log_panel(log_path: str, title_suffix: str = "") -> None:
    """Shared renderer for live + historical log views."""
    tail = read_log_tail(log_path, max_lines=400)
    if not tail.strip():
        st.caption("_Log is empty so far — the subprocess is booting…_")
    else:
        st.code(tail, language="text")
    st.caption(f"Showing last 400 lines · {log_path}{title_suffix}")


def _render_active_run() -> None:
    proc = st.session_state.get("run_process")
    active: ActiveRun = st.session_state.get("active_run")
    if not active:
        return

    alive = process_alive(proc)
    rc = None if alive else (proc.returncode if proc is not None else None)

    # Status chip
    if alive:
        badge_color = ACCENT
        badge_text = "RUNNING"
    elif rc == 0:
        badge_color = SUCCESS
        badge_text = "COMPLETED"
    elif rc is None:
        badge_color = TEXT_MUTED
        badge_text = "UNKNOWN"
    else:
        badge_color = DANGER
        badge_text = f"FAILED (rc={rc})"

    elapsed = active.wall_seconds()
    mins, secs = divmod(int(elapsed), 60)
    st.markdown(
        f"""
        <div style="background:{SURFACE};border:1px solid {BORDER};
                    border-left:4px solid {badge_color};
                    border-radius:8px;padding:14px 18px;margin-bottom:10px;">
            <span style="font-size:12px;color:{TEXT_MUTED};letter-spacing:0.5px;">STATUS</span>
            <h3 style="margin:2px 0 6px 0;color:{badge_color};">{badge_text}</h3>
            <div style="color:{TEXT_MUTED};font-size:13px;">
                pid <code>{active.pid}</code>
                &nbsp;·&nbsp; elapsed <strong>{mins}m {secs:02d}s</strong>
                &nbsp;·&nbsp; config <code>{Path(active.config_path).name if active.config_path else '—'}</code>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1, 1, 4])
    with ctrl_col1:
        stop_disabled = not alive
        if st.button("⏹ Stop", disabled=stop_disabled, type="secondary"):
            if proc is not None:
                msg = stop_run(proc)
                st.toast(f"Stop: {msg}")
                time.sleep(0.5)
                st.rerun()
    with ctrl_col2:
        if not alive and st.button("Dismiss"):
            # Keep the record as last_run for the history section, but clear
            # the active-run slots so the form reappears.
            st.session_state.last_run = active
            st.session_state.pop("active_run", None)
            st.session_state.pop("run_process", None)
            st.rerun()
    with ctrl_col3:
        st.caption(f"Command: `{active.pretty_argv()}`")

    st.subheader("Live log")

    if alive:
        # Fragment auto-reruns every 2s without rebuilding the whole page.
        @st.fragment(run_every=2)
        def _log_fragment():
            still_alive = process_alive(st.session_state.get("run_process"))
            _render_log_panel(active.log_path, title_suffix="  (tailing)")
            if not still_alive:
                # Full page rerun so the status chip + buttons update.
                st.rerun()

        _log_fragment()
    else:
        _render_log_panel(active.log_path)


# If there's a run in flight (or one just finished but not dismissed), show it
# and return early so we don't offer a second Launch button.
if st.session_state.get("active_run") is not None:
    _render_active_run()

    st.divider()
    st.subheader("Recent runs")
    for rr in list_recent_runs(limit=5):
        started = datetime.fromtimestamp(rr.started_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        models = ", ".join(rr.target_models) or "—"
        st.markdown(
            f"- `{Path(rr.jsonl_path).name}` · {started} · "
            f"{rr.attack_count} attacks · targets: {models}"
        )
    st.stop()


# ---------------------------------------------------------------------------
# Configuration form (only reached when no active run)
# ---------------------------------------------------------------------------

catalog = load_seed_catalog()
if not catalog:
    st.error(
        "No attack YAML files found under `attacks/library/`. This page needs "
        "the seed library to build a run."
    )
    st.stop()

# Derive distinct filter options from the catalog itself so the UI stays in
# sync with whatever seeds are on disk.
all_subdomains = sorted({s.financial_subdomain for s in catalog}, key=lambda v: (v is None, v or ""))
all_attack_types = sorted({s.attack_type for s in catalog if s.attack_type})
all_techniques = sorted({s.attack_technique for s in catalog if s.attack_technique})
all_tags = sorted({t for s in catalog for t in s.tags})

base_cfg = load_base_config()

# Default seeds from the config (so the form reflects what a CLI user would
# get with no flags).
_default_cfg_subs = (base_cfg.get("seed_filters") or {}).get("financial_subdomain") or []
_default_cfg_tags_none = (base_cfg.get("seed_filters") or {}).get("tags_none") or []

st.subheader("1 · Attack scope")

with st.container():
    scope_col1, scope_col2 = st.columns(2)
    with scope_col1:
        # Use __GENERIC__ sentinel for the NULL subdomain so multiselect can
        # round-trip the value.
        sub_options = ["__GENERIC__" if s is None else s for s in all_subdomains]
        default_subs = [s for s in _default_cfg_subs if s in sub_options] or sub_options

        selected_subs = st.multiselect(
            "Financial subdomain",
            options=sub_options,
            default=default_subs,
            format_func=lambda v: subdomain_label(None if v == "__GENERIC__" else v),
            help="Which parts of the attack library to draw from.",
        )
        form_subdomains: list = [None if s == "__GENERIC__" else s for s in selected_subs]

        selected_attack_types = st.multiselect(
            "Attack type (OWASP-style category)",
            options=all_attack_types,
            default=[],
            help="Empty = all attack types.",
        )

    with scope_col2:
        selected_tags_any = st.multiselect(
            "Must have any of these tags",
            options=all_tags,
            default=[],
            help="Empty = no tag requirement. A seed matches if ANY listed tag is on it.",
        )
        selected_tags_none = st.multiselect(
            "Exclude seeds with any of these tags",
            options=all_tags,
            default=[t for t in _default_cfg_tags_none if t in all_tags],
            help="Example: exclude `requires_rag_fixture` to skip seeds that need special setup.",
        )

        sev_range = st.slider(
            "Severity potential",
            min_value=1,
            max_value=10,
            value=(1, 10),
            help="Each seed YAML declares a 1–10 severity. Tighten to focus the run.",
        )

st.subheader("2 · Target & attacker models")

model_col1, model_col2, model_col3 = st.columns(3)
with model_col1:
    target_model = st.selectbox(
        "Target model (being red-teamed)",
        options=list(KNOWN_TARGET_MODELS),
        index=list(KNOWN_TARGET_MODELS).index(base_cfg.get("target_model", "claude-sonnet-4-6"))
        if base_cfg.get("target_model") in KNOWN_TARGET_MODELS
        else 0,
        help="The model you're testing. Use the exact provider model id.",
    )
    target_custom = st.text_input(
        "…or custom target id",
        value="",
        placeholder="e.g. claude-opus-4-6",
        help="Overrides the dropdown above when non-empty. Supports any provider prefix the runner understands.",
    )
    if target_custom.strip():
        target_model = target_custom.strip()

with model_col2:
    attacker_model = st.selectbox(
        "Attacker (variant writer)",
        options=list(KNOWN_ATTACKER_MODELS),
        index=list(KNOWN_ATTACKER_MODELS).index(base_cfg.get("attacker_model", "gpt-4o"))
        if base_cfg.get("attacker_model") in KNOWN_ATTACKER_MODELS
        else 0,
        help="Model that generates the adversarial variants from each seed.",
    )
    simulator_model = st.selectbox(
        "Simulator (DeepTeam, simulator mode only)",
        options=list(KNOWN_EVALUATOR_MODELS),
        index=0,
    )

with model_col3:
    evaluator_model = st.selectbox(
        "Judge / evaluator",
        options=list(KNOWN_EVALUATOR_MODELS),
        index=0,
        help="Model used by DeepTeam to score whether each attack succeeded.",
    )

st.subheader("3 · Execution parameters")

exec_col1, exec_col2, exec_col3 = st.columns(3)
with exec_col1:
    variants_per_seed = st.number_input(
        "Variants per seed",
        min_value=1,
        max_value=20,
        value=int(base_cfg.get("variants_per_seed", 3)),
        help="Each matching seed gets this many mutated attack variants.",
    )
    mode = st.radio(
        "Attack generation mode",
        options=["library-faithful", "simulator"],
        index=0,
        help=(
            "**library-faithful**: use the seed's literal prompt as the canonical attack, "
            "then apply DeepTeam enhancers (Base64, ROT13, Leetspeak + PromptInjection, etc.) "
            "to produce variants. No simulator LLM call needed. "
            "**simulator**: hand the seed to DeepTeam's simulator as context only."
        ),
    )

with exec_col2:
    target_max_concurrent = st.slider(
        "Target concurrency",
        min_value=1,
        max_value=10,
        value=int(base_cfg.get("target_max_concurrent", 3)),
        help="Parallel in-flight calls to the target model.",
    )
    target_rps = st.slider(
        "Target RPS ceiling",
        min_value=0.1,
        max_value=5.0,
        value=float(base_cfg.get("target_rps", 0.8)),
        step=0.1,
        help="Requests per second to the target. 0.8 ≈ 48 RPM, safely under most 50 RPM caps.",
    )

with exec_col3:
    dry_run = st.checkbox(
        "Dry run (no API calls)",
        value=bool(base_cfg.get("dry_run", False)),
        help="Build prompts and log them, but don't actually call the target. Free + fast smoke test.",
    )
    no_llm_enhancers = st.checkbox(
        "Skip LLM-requiring enhancers",
        value=False,
        help="library-faithful mode only. Uses deterministic encoders (Base64/ROT13/Leetspeak) only — skips PromptInjection, SystemOverride, etc. Fine when OpenAI is unreachable.",
    )
    no_enhancers = st.checkbox(
        "No enhancers at all (simulator mode only)",
        value=False,
        help="Uses the simulator's raw variants as-is. Ignored when mode=library-faithful.",
    )
    verbose = st.checkbox(
        "Verbose log (DEBUG)",
        value=False,
    )

with st.expander("System prompt for target (optional)"):
    target_system_prompt = st.text_area(
        "Target model system prompt",
        value=base_cfg.get("target_system_prompt") or "",
        help="Leave blank to call the target with no system prompt. Fill in to simulate a deployed product persona.",
        height=100,
    )


# --- Scope preview ----------------------------------------------------------

filters = ScopeFilters(
    subdomains=form_subdomains,
    attack_types=selected_attack_types,
    tags_any=selected_tags_any,
    tags_none=selected_tags_none,
    min_severity=sev_range[0],
    max_severity=sev_range[1],
)
preview = preview_scope(
    catalog,
    filters,
    variants_per_seed=int(variants_per_seed),
    target_rps=float(target_rps),
    mode=mode,
    include_llm_enhancers=not no_llm_enhancers,
)

st.subheader("4 · Scope preview")

preview_color = DANGER if preview.matching_seeds == 0 else ACCENT
st.markdown(
    f"""
    <div style="background:{SURFACE};border:1px solid {BORDER};
                border-left:4px solid {preview_color};border-radius:8px;
                padding:14px 18px;">
        <div style="display:flex;gap:40px;flex-wrap:wrap;">
            <div><div style="font-size:11px;color:{TEXT_MUTED};">MATCHING SEEDS</div>
                 <div style="font-size:24px;font-weight:600;">{preview.matching_seeds}</div></div>
            <div><div style="font-size:11px;color:{TEXT_MUTED};">TOTAL ATTACKS</div>
                 <div style="font-size:24px;font-weight:600;">{preview.total_attacks:,}</div>
                 <div style="font-size:11px;color:{TEXT_MUTED};">{preview.attacks_note}</div></div>
            <div><div style="font-size:11px;color:{TEXT_MUTED};">EST. RUNTIME</div>
                 <div style="font-size:24px;font-weight:600;">{preview.humanised_runtime()}</div>
                 <div style="font-size:11px;color:{TEXT_MUTED};">(~90s/attack at {float(target_rps):.1f} rps)</div></div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if preview.matching_seeds == 0:
    st.warning("No seeds match the current filters — loosen one of the scope controls above.")
elif preview.total_attacks > 100:
    st.info(
        f"Scope includes **{preview.total_attacks:,}** attacks. "
        "Large runs cost real money and take hours — consider tightening tags or subdomain first."
    )

# --- Generated YAML (advanced) ----------------------------------------------

form_dict = {
    "subdomains": form_subdomains,
    "attack_types": selected_attack_types,
    "tags_any": selected_tags_any,
    "tags_none": selected_tags_none,
    "min_severity": sev_range[0],
    "max_severity": sev_range[1],
    "variants_per_seed": int(variants_per_seed),
    "attacker_model": attacker_model,
    "target_model": target_model,
    "simulator_model": simulator_model,
    "evaluator_model": evaluator_model,
    "target_max_concurrent": int(target_max_concurrent),
    "target_rps": float(target_rps),
    "dry_run": bool(dry_run),
    "no_llm_enhancers": bool(no_llm_enhancers),
    "no_enhancers": bool(no_enhancers),
    "mode": mode,
    "verbose": bool(verbose),
    "target_system_prompt": target_system_prompt.strip() or None,
}

generated_cfg = build_config_dict(form_dict)

with st.expander("Advanced · Preview generated config YAML"):
    st.caption(
        "This YAML is what gets written to `runs/dashboard_configs/` and passed via "
        "`--config` to the runner. Read-only here — edit the form controls to change it."
    )
    st.code(yaml.safe_dump(generated_cfg, sort_keys=False), language="yaml")

# --- Launch button ----------------------------------------------------------

st.subheader("5 · Launch")

launch_disabled = preview.matching_seeds == 0

blockers = []
if not keys.anthropic and str(target_model).startswith("claude"):
    blockers.append("`ANTHROPIC_API_KEY` is not set, but target is a Claude model.")
if not keys.openai and str(attacker_model).startswith("gpt") and not dry_run and not no_llm_enhancers:
    blockers.append("`OPENAI_API_KEY` is not set, but attacker is a GPT model.")

if blockers:
    for b in blockers:
        st.warning(b)

launch_col1, launch_col2 = st.columns([1, 4])
with launch_col1:
    launch_clicked = st.button(
        "▶ Launch run",
        type="primary",
        disabled=launch_disabled,
    )
with launch_col2:
    st.caption(
        f"Runner: `python -m execution.deepteam_run` from `{project_root()}`"
    )

if launch_clicked and not launch_disabled:
    config_path = write_config_file(generated_cfg)
    argv = build_cli_args(config_path, form_dict)
    proc, active = launch_run(argv)
    st.session_state.run_process = proc
    st.session_state.active_run = active
    st.toast(f"Launched pid {proc.pid}", icon="▶")
    time.sleep(0.3)
    st.rerun()


# ---------------------------------------------------------------------------
# Recent runs (below the form, always visible)
# ---------------------------------------------------------------------------

st.divider()
st.subheader("Recent runs")

recent = list_recent_runs(limit=5)
if not recent:
    st.caption("No previous run JSONL files found under `runs/`.")
else:
    for rr in recent:
        started = datetime.fromtimestamp(rr.started_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        models = ", ".join(rr.target_models) or "—"
        st.markdown(
            f"- `{Path(rr.jsonl_path).name}` · {started} · "
            f"**{rr.attack_count}** attacks · targets: {models}"
        )

# If there was a just-completed run the user hasn't dismissed, surface its log
if st.session_state.get("last_run") and st.session_state.get("active_run") is None:
    lr: ActiveRun = st.session_state["last_run"]
    with st.expander(f"Last run log · pid {lr.pid} · {Path(lr.log_path).name}"):
        _render_log_panel(lr.log_path)
