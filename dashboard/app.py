"""Finance red-team dashboard — entry point.

Run from the project root:

    streamlit run dashboard/app.py

The file uses st.navigation for routing (Streamlit ≥ 1.36). DB path is resolved
relative to the project root so the app works from any working directory.
"""

from __future__ import annotations

import os
import sys

import streamlit as st

# Make `utils` importable whether Streamlit runs the script as
# `dashboard/app.py` or as an installed script.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from utils.styles import inject_styles, inject_theme_toggle  # noqa: E402


def main() -> None:
    st.set_page_config(
        page_title="Finance Red Team Dashboard",
        layout="wide",
        page_icon="🔍",
        initial_sidebar_state="expanded",
    )
    inject_styles()

    with st.sidebar:
        inject_theme_toggle()
        st.divider()

    pages = {
        "Analysis": [
            st.Page(
                os.path.join("pages", "overview.py"),
                title="Overview",
                icon="📊",
                default=True,
            ),
            st.Page(
                os.path.join("pages", "heatmap.py"),
                title="Technique Heatmap",
                icon="🗺️",
            ),
            st.Page(
                os.path.join("pages", "browser.py"),
                title="Attack Browser",
                icon="🔎",
            ),
            st.Page(
                os.path.join("pages", "comparison.py"),
                title="Model Comparison",
                icon="⚖️",
            ),
        ],
        "Operations": [
            st.Page(
                os.path.join("pages", "run.py"),
                title="Run Attacks",
                icon="▶️",
            ),
            st.Page(
                os.path.join("pages", "judge.py"),
                title="Judge Attacks",
                icon="⚖️",
            ),
            st.Page(
                os.path.join("pages", "progress.py"),
                title="Coverage Progress",
                icon="🎯",
            ),
        ],
    }
    nav = st.navigation(pages)
    nav.run()


if __name__ == "__main__":
    main()
else:
    # Streamlit imports the module rather than calling `python app.py`.
    main()
