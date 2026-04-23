"""Model Comparison page — sonnet vs haiku, with room to grow."""

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

COMPARE_MODELS = ("claude-sonnet-4-6", "claude-haiku-4-5")

st.title("Model Comparison")
st.caption("Side-by-side view of how each target model holds up against the current attack library.")

# --- Data coverage warning --------------------------------------------------

st.warning(
    "**Data coverage note:** haiku-4-5 was run only against 3b (fraud) and 3c (PII) subdomains. "
    "sonnet-4-6 covers all subdomains. Direct comparison is only valid for 3b and 3c."
)

# --- Model summary cards ----------------------------------------------------

summary_df = load_model_summary()
summary_df = summary_df[summary_df["target_model"].isin(COMPARE_MODELS)].copy()

if summary_df.empty:
    st.error("No data for sonnet-4-6 or haiku-4-5.")
    st.stop()

# Align ordering so the columns always show sonnet first, haiku second.
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
    # Pivot to side-by-side layout.
    pivot = tech_long.pivot_table(
        index="technique",
        columns="target_model",
        values=["attempts", "successes", "asr"],
        aggfunc="first",
    )

    # Flatten column index.
    def _get(series_like, default=0):
        try:
            return int(series_like) if not pd.isna(series_like) else default
        except (ValueError, TypeError):
            return default

    rows = []
    for technique in pivot.index:
        sonnet_attempts = _get(pivot.loc[technique, ("attempts", "claude-sonnet-4-6")]
                               if ("attempts", "claude-sonnet-4-6") in pivot.columns else 0)
        sonnet_asr = (
            pivot.loc[technique, ("asr", "claude-sonnet-4-6")]
            if ("asr", "claude-sonnet-4-6") in pivot.columns
            else None
        )
        haiku_attempts = _get(pivot.loc[technique, ("attempts", "claude-haiku-4-5")]
                              if ("attempts", "claude-haiku-4-5") in pivot.columns else 0)
        haiku_asr = (
            pivot.loc[technique, ("asr", "claude-haiku-4-5")]
            if ("asr", "claude-haiku-4-5") in pivot.columns
            else None
        )
        # Only show techniques with ≥ 3 attempts in at least one model column.
        if sonnet_attempts < 3 and haiku_attempts < 3:
            continue
        rows.append(
            {
                "Technique": technique,
                "Sonnet Attempts": sonnet_attempts,
                "Sonnet ASR": float(sonnet_asr) if pd.notna(sonnet_asr) else 0.0,
                "Haiku Attempts": haiku_attempts,
                "Haiku ASR": float(haiku_asr) if pd.notna(haiku_asr) else 0.0,
            }
        )

    if not rows:
        st.info("No techniques meet the ≥ 3-attempt threshold in either model.")
    else:
        breakdown_df = pd.DataFrame(rows)
        breakdown_df["__avg_asr"] = (
            breakdown_df["Sonnet ASR"] + breakdown_df["Haiku ASR"]
        ) / 2
        breakdown_df = (
            breakdown_df.sort_values("__avg_asr", ascending=False)
            .drop(columns="__avg_asr")
            .reset_index(drop=True)
        )
        st.dataframe(
            breakdown_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Technique": st.column_config.TextColumn("Technique"),
                "Sonnet Attempts": st.column_config.NumberColumn("Sonnet Attempts", format="%d"),
                "Sonnet ASR": st.column_config.NumberColumn("Sonnet ASR", format="%.0f%%"),
                "Haiku Attempts": st.column_config.NumberColumn("Haiku Attempts", format="%d"),
                "Haiku ASR": st.column_config.NumberColumn("Haiku ASR", format="%.0f%%"),
            },
        )

st.divider()

# --- Severity overlay histogram --------------------------------------------

st.subheader("Severity Distribution — Successful Attacks")
st.caption("Successful attacks only (success = 1). Overlay uses 60% opacity per model.")

sev_df = load_severity_by_model(COMPARE_MODELS)
if sev_df.empty:
    st.info("No successful attacks recorded for either model.")
else:
    st.plotly_chart(severity_overlay_histogram(sev_df), use_container_width=True)
