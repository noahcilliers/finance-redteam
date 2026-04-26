"""Model Comparison page — side-by-side ASR / severity across target models."""

from __future__ import annotations

import os
import sys

import pandas as pd
import streamlit as st

_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

from utils.charts import (  # noqa: E402
    model_comparison_bar,
    severity_overlay_histogram,
)
from utils.db import (  # noqa: E402
    load_model_comparison,
    load_model_summary,
    load_severity_by_model,
    load_technique_by_model_for_subdomains,
)
from utils.styles import (  # noqa: E402
    MODEL_COLORS,
    MODEL_SHORT,
    SUBDOMAIN_LABELS,
    inject_styles,
    subdomain_label,
)

inject_styles()

COMPARE_MODELS = (
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
    "gpt-4o",
    "gpt-4o-mini",
)

st.title("Model Comparison")
st.caption("Side-by-side view of how each target model holds up against the current attack library.")

# --- Data coverage warning --------------------------------------------------

st.warning(
    "**Data coverage note:** coverage varies by model. "
    "sonnet-4-6 and gpt-4o cover all three subdomains; "
    "haiku-4-5 was run only against 3b (fraud) and 3c (PII); "
    "gpt-4o-mini coverage is partial. Direct cross-model comparison is most "
    "reliable on 3b and 3c."
)

# --- Model summary cards ----------------------------------------------------

summary_df = load_model_summary()
summary_df = summary_df[summary_df["target_model"].isin(COMPARE_MODELS)].copy()

if summary_df.empty:
    st.error(f"No data for any of: {', '.join(COMPARE_MODELS)}.")
    st.stop()

# Align ordering so the columns always render in COMPARE_MODELS order.
order_key = {m: i for i, m in enumerate(COMPARE_MODELS)}
summary_df["__order"] = summary_df["target_model"].map(order_key)
summary_df = summary_df.sort_values("__order").drop(columns="__order")

cols = st.columns(len(summary_df))
for col, (_, row) in zip(cols, summary_df.iterrows()):
    with col:
        model_name = row["target_model"]
        color = MODEL_COLORS.get(model_name, "#888")
        st.markdown(
            f"<h3 style='color:{color};margin-bottom:0.25rem;'>{model_name}</h3>",
            unsafe_allow_html=True,
        )
        mcol1, mcol2, mcol3 = st.columns(3)
        mcol1.metric("Total", f"{int(row['total']):,}")
        mcol2.metric("Evaluated", f"{int(row['evaluated']):,}")
        mcol3.metric("ASR", f"{row['asr']:.1%}")

        # Subdomain coverage badges
        badges_html = ""
        for sub in row["subdomains"]:
            label = subdomain_label(sub, short=True)
            badges_html += (
                f"<span style='background-color:#EEEBE4;border:1px solid #D4D0C8;"
                f"border-radius:12px;padding:2px 10px;margin:2px 4px 2px 0;"
                f"font-size:12px;color:#1A1A1A;display:inline-block;'>{label}</span>"
            )
        st.markdown(
            f"<div style='margin-top:8px;'><span style='color:#5A5A5A;font-size:12px;'>"
            f"Coverage:</span><br>{badges_html}</div>",
            unsafe_allow_html=True,
        )

st.divider()

# --- Grouped bar: ASR by subdomain × model ---------------------------------

st.subheader("ASR by Subdomain × Model")
st.caption("Only showing subdomain/model combinations with ≥ 5 scored attempts.")

asr_df = load_model_comparison()
asr_df = asr_df[asr_df["target_model"].isin(COMPARE_MODELS)]
if asr_df.empty:
    st.warning("No scored comparisons available.")
else:
    st.plotly_chart(model_comparison_bar(asr_df, min_n=5), use_container_width=True)

st.divider()

# --- Technique breakdown table (shared subdomains: 3b, 3c) -----------------

st.subheader("Technique Breakdown — Shared Subdomains (3b, 3c)")
shared_subdomains = ("3b_fraud_and_scams", "3c_pii_and_data_leakage")

tech_long = load_technique_by_model_for_subdomains(shared_subdomains, COMPARE_MODELS)

if tech_long.empty:
    st.info("No technique data available for shared subdomains yet.")
else:
    # Pivot to side-by-side layout, one column-pair per model.
    pivot = tech_long.pivot_table(
        index="technique",
        columns="target_model",
        values=["attempts", "successes", "asr"],
        aggfunc="first",
    )

    def _int(value, default=0):
        try:
            return int(value) if not pd.isna(value) else default
        except (ValueError, TypeError):
            return default

    def _float(value, default=0.0):
        try:
            return float(value) if pd.notna(value) else default
        except (ValueError, TypeError):
            return default

    rows = []
    for technique in pivot.index:
        row = {"Technique": technique}
        per_model_attempts = {}
        per_model_asr = {}
        for model in COMPARE_MODELS:
            label = MODEL_SHORT.get(model, model)
            attempts = _int(
                pivot.loc[technique, ("attempts", model)]
                if ("attempts", model) in pivot.columns
                else 0
            )
            asr = _float(
                pivot.loc[technique, ("asr", model)]
                if ("asr", model) in pivot.columns
                else None
            )
            per_model_attempts[model] = attempts
            per_model_asr[model] = asr
            row[f"{label} Attempts"] = attempts
            # Show empty cell (None) instead of 0% when the model never ran
            # this technique — keeps "untouched" visually distinct from "0%".
            row[f"{label} ASR"] = asr if attempts > 0 else None

        # Only show techniques with ≥ 3 attempts in at least one model column.
        if max(per_model_attempts.values(), default=0) < 3:
            continue
        # Average ASR across models that had any attempts (avoids dragging the
        # row down when one model never ran the technique).
        scored = [
            per_model_asr[m]
            for m in COMPARE_MODELS
            if per_model_attempts[m] > 0
        ]
        row["__avg_asr"] = sum(scored) / len(scored) if scored else 0.0
        rows.append(row)

    if not rows:
        st.info("No techniques meet the ≥ 3-attempt threshold in any model.")
    else:
        breakdown_df = (
            pd.DataFrame(rows)
            .sort_values("__avg_asr", ascending=False)
            .drop(columns="__avg_asr")
            .reset_index(drop=True)
        )
        column_config = {
            "Technique": st.column_config.TextColumn("Technique"),
        }
        for model in COMPARE_MODELS:
            label = MODEL_SHORT.get(model, model)
            column_config[f"{label} Attempts"] = st.column_config.NumberColumn(
                f"{label} Attempts", format="%d"
            )
            column_config[f"{label} ASR"] = st.column_config.NumberColumn(
                f"{label} ASR", format="%.0f%%"
            )
        st.dataframe(
            breakdown_df,
            use_container_width=True,
            hide_index=True,
            column_config=column_config,
        )

st.divider()

# --- Severity overlay histogram --------------------------------------------

st.subheader("Severity Distribution — Successful Attacks")
st.caption("Successful attacks only (success = 1). Overlay uses 60% opacity per model.")

sev_df = load_severity_by_model(COMPARE_MODELS)
if sev_df.empty:
    st.info("No successful attacks recorded for any of the compared models.")
else:
    st.plotly_chart(severity_overlay_histogram(sev_df), use_container_width=True)
