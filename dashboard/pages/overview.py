"""Overview page — headline numbers and the 3a-weak-spot narrative."""

from __future__ import annotations

import os
import sys

import pandas as pd
import streamlit as st

# Ensure `utils` resolves when this page is executed directly by st.navigation.
_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

from utils.charts import (  # noqa: E402
    SURFACE,
    asr_by_subdomain_bar,
    severity_histogram,
    technique_table,
)
from utils.db import (  # noqa: E402
    load_asr_by_subdomain,
    load_overview_stats,
    load_severity_distribution,
    load_top_techniques,
)
from utils.styles import inject_styles  # noqa: E402

inject_styles()

st.title("Overview")
st.caption("Headline results from the finance red-team pipeline.")

# --- Metric row --------------------------------------------------------------

stats = load_overview_stats()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Attacks Run", f"{stats['total']:,}")
col2.metric("Evaluated", f"{stats['evaluated']:,}")
col3.metric("Overall ASR", f"{stats['asr']:.1%}")
if stats["avg_severity_on_failures"] is not None:
    col4.metric("Avg Severity (failures)", f"{stats['avg_severity_on_failures']:.1f} / 10")
else:
    col4.metric("Avg Severity (failures)", "—")

# --- Callout ----------------------------------------------------------------

st.info(
    "**Key finding:** 3a (Investment Advice) is the most vulnerable subdomain at 29% ASR — "
    "roughly 7× the rate of fraud and PII attacks. The `validation_framing` technique "
    "drives most of these failures at 40% ASR."
)

st.divider()

# --- ASR by subdomain -------------------------------------------------------

st.subheader("ASR by Subdomain")
asr_df = load_asr_by_subdomain()
if asr_df.empty:
    st.warning("No evaluated attacks yet.")
else:
    st.plotly_chart(asr_by_subdomain_bar(asr_df), use_container_width=True)

st.divider()

# --- Severity distribution --------------------------------------------------

st.subheader("Severity Distribution")
sev_df = load_severity_distribution()
if sev_df.empty:
    st.warning("No severity scores to plot yet.")
else:
    st.plotly_chart(severity_histogram(sev_df), use_container_width=True)
    low = int((sev_df["severity_score"] < 4.0).sum())
    high = int((sev_df["severity_score"] >= 4.0).sum())
    st.caption(
        f"Low severity (0–3): **{low}** scored attacks · "
        f"Partial-harm or above (4+): **{high}** scored attacks"
    )

st.divider()

# --- Top techniques ---------------------------------------------------------

st.subheader("Top Techniques by ASR")
st.caption("Filtered to techniques with at least 5 scored attempts.")
tech_df = load_top_techniques(min_attempts=5)
if tech_df.empty:
    st.warning("No techniques meet the minimum-attempts threshold yet.")
else:
    display_df = technique_table(tech_df)

    # Surface the top technique as a visual highlight above the table, since
    # st.dataframe has no native single-row highlight and pandas Styler drags
    # in a jinja2 dependency we'd rather not require.
    top_row = display_df.iloc[0]
    st.markdown(
        f"""
        <div style="
            background-color: {SURFACE};
            border: 1px solid #D4D0C8;
            border-left: 4px solid #B83232;
            border-radius: 6px;
            padding: 10px 14px;
            margin-bottom: 10px;
            font-size: 14px;">
            <strong>Top technique:</strong> <code>{top_row['Technique']}</code>
            &nbsp;·&nbsp; ASR <strong>{top_row['ASR']:.0%}</strong>
            &nbsp;·&nbsp; {int(top_row['Successes'])} / {int(top_row['Attempts'])} attempts
            &nbsp;·&nbsp; avg severity {top_row['Avg Severity']:.2f}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Technique": st.column_config.TextColumn("Technique", width="medium"),
            "Attempts": st.column_config.NumberColumn("Attempts", format="%d"),
            "Successes": st.column_config.NumberColumn("Successes", format="%d"),
            "ASR": st.column_config.NumberColumn("ASR", format="%.0f%%"),
            "Avg Severity": st.column_config.NumberColumn("Avg Severity", format="%.2f"),
        },
    )
