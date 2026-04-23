"""Attack Browser — filterable, paginated table of scored attacks with detail view."""

from __future__ import annotations

import json
import os
import sys

import pandas as pd
import streamlit as st

_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

from utils.db import (  # noqa: E402
    filters_cache_key,
    load_attack_detail,
    load_browser_export,
    load_browser_results,
    load_filter_options,
)
from utils.styles import MODEL_SHORT, inject_styles, subdomain_label  # noqa: E402

inject_styles()

PAGE_SIZE = 50


def _split_judge_reasoning(raw: str) -> tuple[object | None, str]:
    """Pull out a leading JSON block from the judge_reasoning field.

    Many judge records are of the form ``{"success": true, ...}\\n\\nfree-form text``.
    This helper returns ``(parsed_json_or_None, remaining_text)``. If no JSON can
    be parsed, returns ``(None, raw)``.
    """
    if not raw:
        return None, ""
    text = raw.strip()

    # Fast path: entire string is valid JSON.
    try:
        return json.loads(text), ""
    except json.JSONDecodeError:
        pass

    if not text.startswith("{"):
        return None, text

    # Scan for the matching closing brace, tracking string literals.
    depth = 0
    in_string = False
    escape = False
    end = -1
    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return None, text
    try:
        parsed = json.loads(text[: end + 1])
    except json.JSONDecodeError:
        return None, text
    return parsed, text[end + 1 :].strip()

st.title("Attack Browser")
st.caption("Searchable, filterable table of all scored attacks. Select a row to see the full prompt, response, and judge reasoning.")

# --- Sidebar filters --------------------------------------------------------

options = load_filter_options()

# Build subdomain option list with NULL → "__GENERIC__" sentinel so Streamlit can
# render and round-trip the value through multiselect.
sub_options = []
for s in options["subdomains"]:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        sub_options.append("__GENERIC__")
    else:
        sub_options.append(s)

with st.sidebar:
    st.subheader("Filters")

    selected_subs = st.multiselect(
        "Subdomain",
        options=sub_options,
        default=sub_options,
        format_func=lambda v: subdomain_label(None if v == "__GENERIC__" else v, short=False),
    )
    selected_models = st.multiselect(
        "Target model",
        options=options["models"],
        default=options["models"],
    )
    selected_techs = st.multiselect(
        "Technique",
        options=options["techniques"],
        default=options["techniques"],
    )
    outcome = st.radio(
        "Outcome",
        options=["All", "Successes only", "Failures only"],
        horizontal=False,
        index=0,
    )
    sev_range = st.slider(
        "Severity range",
        min_value=0.0,
        max_value=10.0,
        value=(0.0, 10.0),
        step=0.5,
    )

    filters = {
        "subdomains": selected_subs,
        "models": selected_models,
        "techniques": selected_techs,
        "success_filter": outcome,
        "severity_range": sev_range,
    }

# --- Pagination state -------------------------------------------------------

if "browser_page" not in st.session_state:
    st.session_state.browser_page = 0

# Reset pagination whenever filters change
f_key = filters_cache_key(filters)
if st.session_state.get("browser_filters_key") != f_key:
    st.session_state.browser_filters_key = f_key
    st.session_state.browser_page = 0

# --- Query ------------------------------------------------------------------

offset = st.session_state.browser_page * PAGE_SIZE
with st.spinner("Loading results…"):
    results_df, total = load_browser_results(f_key, filters, limit=PAGE_SIZE, offset=offset)

# Show scope count in the sidebar
with st.sidebar:
    st.caption(f"Showing **{len(results_df):,}** / {total:,} attacks")

# --- Format results for display --------------------------------------------

if results_df.empty:
    st.warning("No attacks match the current filters.")
    st.stop()

display_df = results_df.copy()
display_df["attack_id_short"] = display_df["attack_id"].str[:8]
display_df["subdomain_label"] = display_df["financial_subdomain"].apply(
    lambda v: subdomain_label(v, short=False)
)
display_df["model_short"] = display_df["target_model"].map(MODEL_SHORT).fillna(display_df["target_model"])
display_df["outcome"] = display_df["success"].map({1: "✓", 0: "✗"})
display_df["date"] = pd.to_datetime(display_df["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d")

table_df = display_df[
    [
        "attack_id_short",
        "attack_technique",
        "subdomain_label",
        "model_short",
        "severity_score",
        "outcome",
        "date",
    ]
].rename(
    columns={
        "attack_id_short": "Attack ID",
        "attack_technique": "Technique",
        "subdomain_label": "Subdomain",
        "model_short": "Model",
        "severity_score": "Severity",
        "outcome": "Outcome",
        "date": "Date",
    }
)

# --- Results table ----------------------------------------------------------

event = st.dataframe(
    table_df,
    use_container_width=True,
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
    key="attack_browser_table",
    column_config={
        "Attack ID": st.column_config.TextColumn("Attack ID", width="small"),
        "Severity": st.column_config.NumberColumn("Severity", format="%.1f"),
        "Outcome": st.column_config.TextColumn("Outcome", width="small"),
    },
)

# Persist the selected attack_id across reruns so sidebar tweaks and
# pagination don't silently clear the detail view.
selected_rows = event.selection.rows if hasattr(event, "selection") else []
if selected_rows:
    idx = selected_rows[0]
    st.session_state.selected_attack_id = str(results_df.iloc[idx]["attack_id"])

# --- Detail expander (immediately after table, before pagination) -----------
# Placed here so it's visible without scrolling after a row is clicked.

selected_attack_id = st.session_state.get("selected_attack_id")
if selected_attack_id:

    clear_col, _ = st.columns([1, 8])
    with clear_col:
        if st.button("✕ Clear selection"):
            st.session_state.selected_attack_id = None
            st.rerun()

    with st.expander(f"Detail — {selected_attack_id[:8]}", expanded=True):
        detail = load_attack_detail(selected_attack_id)
        if not detail:
            st.warning("Could not load detail for this attack_id.")
        else:
            # Metadata
            meta_col1, meta_col2, meta_col3 = st.columns(3)
            meta_col1.markdown(f"**Technique:** {detail.get('attack_technique', '—')}")
            meta_col2.markdown(
                f"**Subdomain:** {subdomain_label(detail.get('financial_subdomain'))}"
            )
            meta_col3.markdown(f"**Model:** {detail.get('target_model', '—')}")

            meta_col4, meta_col5, meta_col6 = st.columns(3)
            meta_col4.markdown(f"**Timestamp:** {detail.get('timestamp', '—')}")
            sev = detail.get("severity_score")
            meta_col5.markdown(
                f"**Severity:** {sev:.2f}" if isinstance(sev, (int, float)) else "**Severity:** —"
            )
            success_val = detail.get("success")
            success_str = "Success ✓" if success_val == 1 else ("Held ✗" if success_val == 0 else "—")
            meta_col6.markdown(f"**Outcome:** {success_str}")

            # Tags
            raw_tags = detail.get("tags")
            if raw_tags:
                try:
                    tag_list = json.loads(raw_tags) if isinstance(raw_tags, str) else raw_tags
                    if isinstance(tag_list, list) and tag_list:
                        st.markdown("**Tags:** " + ", ".join(f"`{t}`" for t in tag_list))
                except (json.JSONDecodeError, TypeError):
                    st.markdown(f"**Tags:** `{raw_tags}`")

            st.markdown(f"**Attack ID:** `{selected_attack_id}`")

            # Prompt
            st.markdown("##### Prompt")
            st.code(detail.get("prompt_text", "") or "(no prompt_text)", language="text")

            # Response
            st.markdown("##### Response")
            st.code(detail.get("response_text", "") or "(no response_text)", language="text")

            # Judge reasoning — parse JSON prefix if present
            st.markdown("##### Judge Reasoning")
            raw_reasoning = detail.get("judge_reasoning") or ""
            parsed_json, narrative = _split_judge_reasoning(raw_reasoning)
            if parsed_json is not None:
                st.json(parsed_json)
            if narrative.strip():
                st.markdown(narrative.strip())
            elif parsed_json is None and raw_reasoning:
                st.markdown(raw_reasoning)
            elif not raw_reasoning:
                st.caption("No judge reasoning recorded.")

# --- Pagination controls ----------------------------------------------------

total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
current_page = st.session_state.browser_page + 1

pcol1, pcol2, pcol3, pcol4 = st.columns([1, 1, 2, 6])

with pcol1:
    if st.button("← Previous", disabled=st.session_state.browser_page == 0):
        st.session_state.browser_page = max(0, st.session_state.browser_page - 1)
        st.rerun()
with pcol2:
    if st.button("Next →", disabled=current_page >= total_pages):
        st.session_state.browser_page = min(total_pages - 1, st.session_state.browser_page + 1)
        st.rerun()
with pcol3:
    st.markdown(f"Page **{current_page}** of **{total_pages}**")

st.divider()

# --- CSV export -------------------------------------------------------------

export_df = load_browser_export(f_key, filters)
st.download_button(
    "Export filtered results as CSV",
    data=export_df.to_csv(index=False),
    file_name="redteam_results.csv",
    mime="text/csv",
    help="Excludes prompt_text and response_text to keep the file small.",
)
