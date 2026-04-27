"""Coverage Progress page — visualises pipeline completeness against the
22,800-run benchmark defined in `Test Coverage Requirements & Progress
Specification` v1.0 (April 2026).

Four components per §7.2:
  1. Overall progress banner (red / amber / green by pct).
  2. Per-model progress bars (one per target model).
  3. Coverage heatmap (19 techniques × 3 subdomains, per-model dropdown).
  4. Gap priority table (top-20 most incomplete cells, with YAML export).

Data contract (§7.1) lives in utils.db.load_cell_coverage; applicability
matrix (§5.3) and labels live in utils.coverage. Caching is the standard
60-second TTL the rest of the dashboard uses; a manual refresh button is
provided.
"""

from __future__ import annotations

import os
import sys
from io import StringIO
from typing import Optional

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

from utils.charts import (  # noqa: E402
    ACCENT,
    BORDER,
    CREAM,
    DANGER,
    SUCCESS,
    SURFACE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    apply_chart_theme,
    get_palette,
)
from utils.coverage import (  # noqa: E402
    CELL_TARGET,
    CELLS_PER_MODEL,
    SUBDOMAIN_LABEL,
    SUBDOMAINS,
    TARGET_MODELS,
    TARGET_RUNS_PER_MODEL,
    TECHNIQUE_APPLICABILITY,
    TECHNIQUE_LABEL,
    TECHNIQUES,
    TOTAL_TARGET_RUNS,
    is_applicable,
)
from utils.db import load_cell_coverage, load_runs_per_day  # noqa: E402
from utils.styles import inject_styles  # noqa: E402

inject_styles()

# --- Palette for the progress page only ------------------------------------

# §7.2 — banner uses red 0-24%, amber 25-74%, green 75-100%.
# We pick muted shades that fit the cream/surface design system.
_RED = "#B83232"     # matches DANGER
_AMBER = "#C68A2E"   # warm amber (sits between cream and danger)
_GREEN = "#2D6A4F"   # matches SUCCESS

# N/A cells: light grey in light mode, dark grey in dark mode.
# Heatmap gradient base adjusts to current theme in _build_coverage_heatmap.
_NA_GREY_LIGHT = "#D9D5CD"
_NA_GREY_DARK  = "#2A2A2A"


def _status_color(pct: float) -> str:
    """Map a 0..1 progress fraction to the §7.2 red/amber/green band."""
    if pct < 0.25:
        return _RED
    if pct < 0.75:
        return _AMBER
    return _GREEN


def _status_label(pct: float) -> str:
    if pct < 0.25:
        return "Red"
    if pct < 0.75:
        return "Amber"
    return "Green"


# --- Page --------------------------------------------------------------------

st.title("🎯 Coverage Progress")
st.caption(
    "Pipeline completeness against the v1 benchmark — minimum 100 valid runs "
    "per applicable (model, technique, subdomain) cell. "
    "Valid run = fully judged response (non-empty response + judge score) "
    "**or** API-level refusal (provider blocked generation before producing text). "
    "Both count: API refusals are a real safety signal and enable cross-provider comparison."
)

# Refresh control — clears the 60-second cache on demand.
col_refresh, col_freshness = st.columns([1, 5])
if col_refresh.button("🔄 Refresh", help="Clear the 60s cache and re-query results.db"):
    load_cell_coverage.clear()
    load_runs_per_day.clear()
    st.rerun()
col_freshness.caption(
    "Live from `data/results.db`. Cached for 60 seconds; click refresh to force a re-query."
)

# Load data once for the whole page.
coverage_df = load_cell_coverage()
runs_per_day = load_runs_per_day(days=7)

# Index for fast lookups.
# valid_count  = total runs that count toward coverage (judged + api_refusals)
# refusal_count = subset that were API-level refusals
cell_lookup: dict[tuple[str, str, str], int] = {}
refusal_lookup: dict[tuple[str, str, str], int] = {}
for row in coverage_df.itertuples(index=False):
    key = (row.target_model, row.attack_technique, row.financial_subdomain)
    cell_lookup[key] = int(row.valid_count)
    refusal_lookup[key] = int(row.refusal_count)


def _cell_count(model: str, technique: str, subdomain: str) -> int:
    return cell_lookup.get((model, technique, subdomain), 0)


def _refusal_count(model: str, technique: str, subdomain: str) -> int:
    return refusal_lookup.get((model, technique, subdomain), 0)


# ============================================================================
# Component 1 — Overall Progress Banner
# ============================================================================

# Cap each cell at the target before summing — over-runs on one cell shouldn't
# mask under-runs elsewhere (§7.1: SUM(MIN(cell_valid_count, cell_target))).
total_valid_capped = 0
total_valid_raw = 0
for (model, _) in TARGET_MODELS:
    for technique, _ in TECHNIQUES:
        for subdomain, _ in SUBDOMAINS:
            if not is_applicable(technique, subdomain):
                continue
            count = _cell_count(model, technique, subdomain)
            total_valid_raw += count
            total_valid_capped += min(count, CELL_TARGET)

overall_pct = total_valid_capped / TOTAL_TARGET_RUNS if TOTAL_TARGET_RUNS else 0.0
runs_remaining = max(0, TOTAL_TARGET_RUNS - total_valid_capped)
banner_color = _status_color(overall_pct)

# Render as a horizontal flex row of four "metric" tiles inside a single
# coloured card. Streamlit's st.metric doesn't accept a background colour, so
# we build the row ourselves with CSS — keeps the design system consistent.
banner_html = f"""
<div style="
    background: linear-gradient(90deg, {banner_color}1A 0%, {banner_color}0D 100%);
    border: 1px solid {banner_color};
    border-left: 6px solid {banner_color};
    border-radius: 10px;
    padding: 18px 22px;
    margin-bottom: 8px;
    display: flex;
    flex-wrap: wrap;
    gap: 32px;
    align-items: center;
">
  <div style="min-width: 160px;">
    <div style="color: var(--color-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">
      Overall completion
    </div>
    <div style="color: {banner_color}; font-size: 32px; font-weight: 700; line-height: 1.1;">
      {overall_pct:.1%}
    </div>
    <div style="color: var(--color-muted); font-size: 12px;">
      Status: <strong style="color: {banner_color};">{_status_label(overall_pct)}</strong>
    </div>
  </div>
  <div style="min-width: 160px;">
    <div style="color: var(--color-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">
      Valid runs to date
    </div>
    <div style="color: var(--color-text); font-size: 28px; font-weight: 600;">
      {total_valid_capped:,}
    </div>
    <div style="color: var(--color-muted); font-size: 12px;">
      of {TOTAL_TARGET_RUNS:,} target ({total_valid_raw:,} including over-runs)
    </div>
  </div>
  <div style="min-width: 160px;">
    <div style="color: var(--color-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">
      Runs remaining
    </div>
    <div style="color: var(--color-text); font-size: 28px; font-weight: 600;">
      {runs_remaining:,}
    </div>
    <div style="color: var(--color-muted); font-size: 12px;">
      to clear the v1 benchmark floor
    </div>
  </div>
  <div style="min-width: 180px;">
    <div style="color: var(--color-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">
      Recent throughput
    </div>
    <div style="color: var(--color-text); font-size: 28px; font-weight: 600;">
      {runs_per_day:,.0f} <span style="font-size: 14px; color: var(--color-muted); font-weight: 400;">/day</span>
    </div>
    <div style="color: var(--color-muted); font-size: 12px;">
      {('~' + f'{runs_remaining / runs_per_day:,.0f}' + ' days to target') if runs_per_day > 0 else 'no valid runs in last 7 days'}
    </div>
  </div>
</div>
"""
st.markdown(banner_html, unsafe_allow_html=True)
st.caption(
    f"Denominator derived from §5.3 applicability matrix: "
    f"{CELLS_PER_MODEL} applicable cells × {len(TARGET_MODELS)} models × "
    f"{CELL_TARGET} runs = {TOTAL_TARGET_RUNS:,}."
)

st.divider()

# ============================================================================
# Component 2 — Per-Model Progress Bars
# ============================================================================

st.subheader("Per-Model Progress")
st.caption(
    f"Each model is judged out of {TARGET_RUNS_PER_MODEL:,} valid runs "
    f"({CELLS_PER_MODEL} applicable cells × {CELL_TARGET})."
)


def _render_model_bar(model: str, organisation: str) -> None:
    valid_capped = 0
    completed_cells = 0
    raw_total = 0
    for technique, _ in TECHNIQUES:
        for subdomain, _ in SUBDOMAINS:
            if not is_applicable(technique, subdomain):
                continue
            count = _cell_count(model, technique, subdomain)
            raw_total += count
            valid_capped += min(count, CELL_TARGET)
            if count >= CELL_TARGET:
                completed_cells += 1

    pct = valid_capped / TARGET_RUNS_PER_MODEL if TARGET_RUNS_PER_MODEL else 0.0
    color = _status_color(pct)
    chip = _status_label(pct)
    bar_width_pct = min(100.0, pct * 100.0)

    bar_html = f"""
    <div style="
        background-color: var(--color-surface);
        border: 1px solid var(--color-border);
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 10px;
    ">
      <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;">
        <div>
          <code style="font-size: 14px; color: var(--color-text);">{model}</code>
          <span style="color: var(--color-muted); font-size: 12px; margin-left: 8px;">{organisation}</span>
        </div>
        <div>
          <span style="
              background-color: {color};
              color: white;
              font-size: 11px;
              font-weight: 600;
              padding: 2px 8px;
              border-radius: 10px;
              text-transform: uppercase;
              letter-spacing: 0.04em;
          ">{chip}</span>
          <span style="color: var(--color-text); font-weight: 600; font-size: 14px; margin-left: 10px;">
            {valid_capped:,} / {TARGET_RUNS_PER_MODEL:,}
          </span>
          <span style="color: var(--color-muted); font-size: 13px; margin-left: 6px;">({pct:.1%})</span>
        </div>
      </div>
      <div style="
          background-color: var(--color-bg);
          border: 1px solid var(--color-border);
          border-radius: 4px;
          height: 12px;
          overflow: hidden;
      ">
        <div style="
            background-color: {color};
            width: {bar_width_pct}%;
            height: 100%;
        "></div>
      </div>
      <div style="margin-top: 6px; color: var(--color-muted); font-size: 12px;">
        {completed_cells} / {CELLS_PER_MODEL} cells complete
        (≥{CELL_TARGET} valid runs)
        {('· ' + f'{raw_total - valid_capped:,}' + ' over-run rows above target') if raw_total > valid_capped else ''}
      </div>
    </div>
    """
    st.markdown(bar_html, unsafe_allow_html=True)


for model, organisation in TARGET_MODELS:
    _render_model_bar(model, organisation)

st.divider()

# ============================================================================
# Component 3 — Coverage Heatmap
# ============================================================================

st.subheader("Coverage Heatmap")
st.caption(
    "Each cell shaded by valid-run count: white (0) → amber (~50) → green (≥100). "
    "N/A cells (per the §5.3 applicability matrix) are light grey. "
    "Cells with zero valid runs have a red outline."
)

selected_model = st.selectbox(
    "Target model",
    options=[m for m, _ in TARGET_MODELS],
    format_func=lambda m: f"{m}  —  {dict(TARGET_MODELS)[m]}",
    key="progress_heatmap_model",
)


def _build_coverage_heatmap(model: str) -> go.Figure:
    p = get_palette()
    na_grey = _NA_GREY_DARK if p["bg"] == "#111111" else _NA_GREY_LIGHT
    heatmap_gradient = [
        [0.0, p["surface"]],
        [0.5, "#F0C46B"],
        [1.0, "#2D6A4F"],
    ]

    technique_ids = [t for t, _ in TECHNIQUES]
    technique_labels = [TECHNIQUE_LABEL[t] for t in technique_ids]
    subdomain_ids = [s for s, _ in SUBDOMAINS]
    subdomain_labels = [SUBDOMAIN_LABEL[s] for s in subdomain_ids]

    # z = valid count clamped at CELL_TARGET so the colour saturates at green;
    # NaN where the cell is N/A so the heatmap leaves it transparent.
    z = np.full((len(technique_ids), len(subdomain_ids)), np.nan, dtype=float)
    counts = np.zeros_like(z, dtype=int)
    hover_text: list[list[str]] = []
    for i, tech in enumerate(technique_ids):
        row_hover: list[str] = []
        for j, sub in enumerate(subdomain_ids):
            if not is_applicable(tech, sub):
                row_hover.append(
                    f"<b>{TECHNIQUE_LABEL[tech]}</b><br>"
                    f"{SUBDOMAIN_LABEL[sub]}<br>"
                    f"<i>N/A — out of scope per §5.3</i>"
                )
                continue
            count = _cell_count(model, tech, sub)
            refusals = _refusal_count(model, tech, sub)
            judged = count - refusals
            counts[i, j] = count
            z[i, j] = min(count, CELL_TARGET)
            pct = count / CELL_TARGET
            row_hover.append(
                f"<b>{TECHNIQUE_LABEL[tech]}</b><br>"
                f"{SUBDOMAIN_LABEL[sub]}<br>"
                f"Valid runs: {count} / {CELL_TARGET} ({pct:.0%})<br>"
                f"&nbsp;· Judged (SECURE/VULN): {judged}<br>"
                f"&nbsp;· API-level refusals: {refusals}"
            )
        hover_text.append(row_hover)

    fig = go.Figure()

    # Main heatmap. NaN cells render transparent — we'll cover them with a
    # grey rectangle shape below.
    fig.add_trace(
        go.Heatmap(
            z=z,
            x=subdomain_labels,
            y=technique_labels,
            colorscale=heatmap_gradient,
            zmin=0,
            zmax=CELL_TARGET,
            xgap=2,
            ygap=2,
            hoverinfo="text",
            hovertext=hover_text,
            colorbar=dict(
                title=dict(text="Valid runs", side="right"),
                tickvals=[0, CELL_TARGET // 2, CELL_TARGET],
                ticktext=["0", str(CELL_TARGET // 2), f"{CELL_TARGET}+"],
                outlinecolor=p["border"],
                outlinewidth=1,
            ),
        )
    )

    # Shape overlays: grey for N/A cells, red outline for zero-valid cells.
    shapes = []
    for i, tech in enumerate(technique_ids):
        for j, sub in enumerate(subdomain_ids):
            x0, x1 = j - 0.5, j + 0.5
            y0, y1 = i - 0.5, i + 0.5
            if not is_applicable(tech, sub):
                shapes.append(
                    dict(
                        type="rect",
                        xref="x",
                        yref="y",
                        x0=x0,
                        x1=x1,
                        y0=y0,
                        y1=y1,
                        fillcolor=na_grey,
                        line=dict(color=p["border"], width=1),
                        layer="above",
                    )
                )
                # N/A label centered on the grey cell.
                fig.add_annotation(
                    x=j,
                    y=i,
                    text="N/A",
                    showarrow=False,
                    font=dict(color=p["muted"], size=11, family="Inter, system-ui, sans-serif"),
                )
            elif counts[i, j] == 0:
                shapes.append(
                    dict(
                        type="rect",
                        xref="x",
                        yref="y",
                        x0=x0,
                        x1=x1,
                        y0=y0,
                        y1=y1,
                        line=dict(color=_RED, width=2.5),
                        fillcolor="rgba(0,0,0,0)",
                        layer="above",
                    )
                )

    # Numeric annotation for applicable cells (skip N/A).
    for i, tech in enumerate(technique_ids):
        for j, sub in enumerate(subdomain_ids):
            if not is_applicable(tech, sub):
                continue
            count = counts[i, j]
            # Use white text on dark green, otherwise dark text.
            text_color = "#FFFFFF" if count >= 70 else p["text"]
            fig.add_annotation(
                x=j,
                y=i,
                text=str(count),
                showarrow=False,
                font=dict(color=text_color, size=11, family="Inter, system-ui, sans-serif"),
            )

    fig.update_layout(
        shapes=shapes,
        xaxis=dict(side="top", title="Subdomain", showgrid=False, zeroline=False),
        yaxis=dict(
            title="Technique",
            autorange="reversed",  # show technique 01 at the top
            showgrid=False,
            zeroline=False,
        ),
        height=max(480, 28 * len(technique_ids) + 120),
    )
    return apply_chart_theme(fig, f"Coverage matrix — {model}")


st.plotly_chart(_build_coverage_heatmap(selected_model), use_container_width=True)

st.divider()

# ============================================================================
# Component 4 — Gap Priority Table
# ============================================================================

st.subheader("Gap Priority")
st.caption(
    "Top 20 most incomplete cells across all models, ranked by runs remaining. "
    "Filter by model or subdomain; the YAML fragment below is regenerated to match."
)

# Build the long gap table from the applicability matrix.
gap_rows: list[dict] = []
for model, _ in TARGET_MODELS:
    for technique, _ in TECHNIQUES:
        for subdomain, _ in SUBDOMAINS:
            if not is_applicable(technique, subdomain):
                continue
            count = _cell_count(model, technique, subdomain)
            refusals = _refusal_count(model, technique, subdomain)
            remaining = max(0, CELL_TARGET - count)
            gap_rows.append(
                {
                    "Model": model,
                    "Technique": technique,
                    "Subdomain": subdomain,
                    "Valid Runs": count,
                    "API Refusals": refusals,
                    "Remaining": remaining,
                }
            )

gap_df = pd.DataFrame(gap_rows)


def _priority_label(remaining: int) -> str:
    if remaining >= CELL_TARGET:  # zero valid runs
        return "P1 — empty"
    if remaining >= 80:
        return "P2 — thin"
    if remaining > 0:
        return "P3 — top-up"
    return "Done"


gap_df["Priority"] = gap_df["Remaining"].apply(_priority_label)

# Filters.
filter_col1, filter_col2 = st.columns(2)
model_filter: list[str] = filter_col1.multiselect(
    "Filter by model",
    options=[m for m, _ in TARGET_MODELS],
    default=[m for m, _ in TARGET_MODELS],
)
subdomain_filter: list[str] = filter_col2.multiselect(
    "Filter by subdomain",
    options=[s for s, _ in SUBDOMAINS],
    default=[s for s, _ in SUBDOMAINS],
    format_func=lambda s: SUBDOMAIN_LABEL.get(s, s),
)

filtered = gap_df.copy()
if model_filter:
    filtered = filtered[filtered["Model"].isin(model_filter)]
if subdomain_filter:
    filtered = filtered[filtered["Subdomain"].isin(subdomain_filter)]

# Sort: largest remaining first, ties broken by model name + technique.
filtered = filtered.sort_values(
    ["Remaining", "Model", "Technique"], ascending=[False, True, True]
)

top_n = 20
top_gaps = filtered.head(top_n)

# Pretty subdomain labels for display only — keep raw IDs in the YAML export.
display_top = top_gaps.copy()
display_top["Subdomain"] = display_top["Subdomain"].map(
    lambda s: SUBDOMAIN_LABEL.get(s, s)
)
display_top["Technique"] = display_top["Technique"].map(
    lambda t: TECHNIQUE_LABEL.get(t, t)
)

st.dataframe(
    display_top,
    use_container_width=True,
    hide_index=True,
    column_config={
        "Model": st.column_config.TextColumn("Model", width="medium"),
        "Technique": st.column_config.TextColumn("Technique", width="medium"),
        "Subdomain": st.column_config.TextColumn("Subdomain", width="small"),
        "Valid Runs": st.column_config.NumberColumn("Valid Runs", format="%d",
            help="Judged responses + API-level refusals"),
        "API Refusals": st.column_config.NumberColumn("API Refusals", format="%d",
            help="Subset of valid runs blocked at the provider API level (stop_reason=refusal)"),
        "Remaining": st.column_config.NumberColumn("Remaining", format="%d"),
        "Priority": st.column_config.TextColumn("Priority", width="small"),
    },
)

if filtered.empty:
    st.success("No gaps for the current filter — all selected cells are at target.")
else:
    summary = (
        f"Showing top {len(top_gaps)} of {len(filtered)} incomplete cells "
        f"(filter total: {int(filtered['Remaining'].sum()):,} valid runs needed)."
    )
    st.caption(summary)


# --- Copy as run config (YAML fragment) -------------------------------------

def _yaml_for_gaps(gaps: pd.DataFrame) -> str:
    """Render the top-N gaps as a YAML fragment.

    Format matches the structure of generate_config.yaml — lists of values
    keyed by field — so an operator can paste it under a `coverage_gaps:`
    section and consume it from a custom planner. Each entry preserves the
    raw subdomain ID and technique ID so it round-trips into the DB.
    """
    if gaps.empty:
        return "# No gaps to export.\n"
    buf = StringIO()
    buf.write("# Generated by Coverage Progress dashboard\n")
    buf.write("# Top gaps ranked by runs remaining (target - valid_count).\n")
    buf.write(f"# Generated against {CELL_TARGET}-runs/cell target.\n")
    buf.write("coverage_gaps:\n")
    for _, row in gaps.iterrows():
        buf.write("  - target_model: " + str(row["Model"]) + "\n")
        buf.write("    attack_technique: " + str(row["Technique"]) + "\n")
        buf.write("    financial_subdomain: " + str(row["Subdomain"]) + "\n")
        buf.write(f"    valid_count: {int(row['Valid Runs'])}\n")
        buf.write(f"    remaining: {int(row['Remaining'])}\n")
    return buf.getvalue()


# Use the raw (un-prettified) top_gaps for the YAML so IDs stay machine-readable.
yaml_text = _yaml_for_gaps(top_gaps)

with st.expander("Copy as run config (YAML fragment)", expanded=False):
    st.caption(
        "Paste this block into your `generate_config.yaml` under a "
        "`coverage_gaps:` key, then have the run planner prioritise the "
        "listed (model, technique, subdomain) cells."
    )
    st.code(yaml_text, language="yaml")
    st.download_button(
        "Download as .yaml",
        data=yaml_text,
        file_name="coverage_gaps.yaml",
        mime="text/yaml",
    )
