"""Heatmap page — technique × subdomain and technique × model cross-tabs."""

from __future__ import annotations

import os
import sys

import streamlit as st

_DASHBOARD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

from utils.charts import technique_model_heatmap, technique_subdomain_heatmap  # noqa: E402
from utils.db import (  # noqa: E402
    load_filter_options,
    load_heatmap_data,
    load_scope_count,
    load_technique_by_model,
)
from utils.styles import inject_styles  # noqa: E402

inject_styles()

st.title("Technique Heatmap")
st.caption("Cross-tabulation of attack technique × subdomain (and × model), colored by ASR.")

# --- Sidebar filters --------------------------------------------------------

options = load_filter_options()

with st.sidebar:
    st.subheader("Filters")
    selected_models = st.multiselect(
        "Target model",
        options=options["models"],
        default=options["models"],
        help="Restrict ASR calculation to specific target models.",
    )
    scope_total = load_scope_count(tuple(selected_models) if selected_models else None)
    st.caption(f"Showing **{scope_total:,}** scored attacks")

models_tuple = tuple(selected_models) if selected_models else None

# --- Heatmap 1: technique × subdomain ---------------------------------------

st.subheader("Technique × Subdomain")
heatmap_df = load_heatmap_data(models_tuple)
if heatmap_df.empty or not selected_models:
    st.warning("No scored attacks for the current filter.")
else:
    st.plotly_chart(
        technique_subdomain_heatmap(heatmap_df),
        use_container_width=True,
    )

st.divider()

# --- Heatmap 2: technique × model -------------------------------------------

st.subheader("Technique × Target Model")
model_df = load_technique_by_model(models_tuple)
if model_df.empty or not selected_models:
    st.warning("No scored attacks for the current filter.")
else:
    st.plotly_chart(
        technique_model_heatmap(model_df),
        use_container_width=True,
    )

st.divider()

# --- Observations -----------------------------------------------------------

with st.expander("Key observations", expanded=True):
    st.markdown(
        "- **validation_framing** is the highest-performing technique overall (40% ASR), "
        "exclusively against 3a subdomains.\n"
        "- All **encoding-based techniques** (base64, leetspeak, token_smuggling, "
        "unicode_homoglyph) score 0% — the models are not fooled by obfuscation.\n"
        "- **3b (fraud/scams)** and **3c (PII)** are highly resistant — combined ASR < 5% "
        "across all techniques.\n"
        "- **language_switch** achieves 11% against 3a, suggesting non-English prompts "
        "deserve more coverage in future runs."
    )
