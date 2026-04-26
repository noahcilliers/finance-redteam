"""Design-system tokens and CSS injection for the red-team dashboard.

Single source of truth for the palette. Import tokens from here (or from
utils.charts, which re-exports them) so pages never hard-code hex values.
"""

import streamlit as st

# --- Palette -----------------------------------------------------------------

CREAM = "#F7F4EF"          # page background
SURFACE = "#EEEBE4"        # cards / sidebar / inputs
TEXT_PRIMARY = "#1A1A1A"   # body text, numbers
TEXT_MUTED = "#5A5A5A"     # labels, captions
BORDER = "#D4D0C8"         # dividers, card outlines
SUCCESS = "#2D6A4F"        # pass / low severity (dark green)
DANGER = "#B83232"         # fail / high severity (muted red)
ACCENT = "#3D5A80"         # primary chart fill (slate blue)

# Model-specific chart colors (used across comparison page)
MODEL_COLORS = {
    "claude-sonnet-4-6": ACCENT,         # slate blue
    "claude-haiku-4-5": "#8B7355",       # warm brown
    "gpt-4o": "#2D6A4F",                 # green (matches SUCCESS token)
    "gpt-4o-mini": "#7FA88B",            # lighter sage
}

# --- Subdomain display labels -----------------------------------------------

SUBDOMAIN_LABELS = {
    "3a_investment_advice": "Investment Advice (3a)",
    "3b_fraud_and_scams": "Fraud & Scams (3b)",
    "3c_pii_and_data_leakage": "PII Leakage (3c)",
    None: "Generic / Cross-domain",
}

SUBDOMAIN_SHORT = {
    "3a_investment_advice": "3a Invest.",
    "3b_fraud_and_scams": "3b Fraud",
    "3c_pii_and_data_leakage": "3c PII",
    None: "Generic",
}

MODEL_SHORT = {
    "claude-sonnet-4-6": "sonnet",
    "claude-haiku-4-5": "haiku",
    "gpt-4o": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
}


def subdomain_label(value, short: bool = False) -> str:
    """Translate a raw subdomain value (possibly None/NaN/empty) to a friendly label."""
    # Treat NaN, None, and empty string as the generic/cross-domain bucket.
    try:
        is_nan = isinstance(value, float) and value != value  # NaN != NaN
    except Exception:
        is_nan = False
    if value in ("", None) or is_nan:
        value = None
    mapping = SUBDOMAIN_SHORT if short else SUBDOMAIN_LABELS
    return mapping.get(value, str(value))


def model_label(value: str, short: bool = False) -> str:
    if short:
        return MODEL_SHORT.get(value, value)
    return value


# --- CSS ---------------------------------------------------------------------

_CSS = f"""
<style>
/* Page background */
.stApp {{ background-color: {CREAM}; }}

/* Main content container padding */
.main .block-container {{ padding-top: 2rem; padding-bottom: 3rem; }}

/* Sidebar */
section[data-testid="stSidebar"] {{
    background-color: {SURFACE};
    border-right: 1px solid {BORDER};
}}

/* Metric cards */
[data-testid="metric-container"] {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 16px 20px;
}}
[data-testid="metric-container"] label {{ color: {TEXT_MUTED}; }}
[data-testid="metric-container"] [data-testid="stMetricValue"] {{ color: {TEXT_PRIMARY}; }}

/* Tables and dataframes */
.stDataFrame {{
    border: 1px solid {BORDER};
    border-radius: 6px;
}}

/* Headers */
h1, h2, h3, h4 {{ color: {TEXT_PRIMARY}; font-weight: 600; }}
p, li, span, div {{ color: {TEXT_PRIMARY}; }}

/* Captions */
[data-testid="stCaptionContainer"] {{ color: {TEXT_MUTED}; }}

/* Dividers */
hr {{ border-color: {BORDER}; margin: 20px 0; }}

/* Expanders */
.streamlit-expanderHeader,
[data-testid="stExpander"] details summary {{
    background-color: {SURFACE};
    border-radius: 6px;
    color: {TEXT_PRIMARY};
}}
[data-testid="stExpander"] {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    background-color: {SURFACE};
}}

/* Input controls */
.stSelectbox > div > div,
.stMultiSelect > div > div,
.stTextInput > div > div,
.stNumberInput > div > div {{
    background-color: {SURFACE};
    border-color: {BORDER};
}}

/* Buttons */
.stButton > button,
.stDownloadButton > button {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    color: {TEXT_PRIMARY};
}}
.stButton > button:hover,
.stDownloadButton > button:hover {{
    border-color: {ACCENT};
    color: {ACCENT};
}}

/* Alerts / callouts */
.stAlert {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    color: {TEXT_PRIMARY};
}}

/* Code blocks */
.stCodeBlock, pre, code {{
    background-color: {SURFACE} !important;
    border: 1px solid {BORDER};
    border-radius: 6px;
    color: {TEXT_PRIMARY} !important;
}}

/* Remove default Streamlit "Made with" footer padding */
footer {{ visibility: hidden; }}
#MainMenu {{ visibility: hidden; }}
header[data-testid="stHeader"] {{ background-color: {CREAM}; }}
</style>
"""


def inject_styles() -> None:
    """Inject the dashboard-wide CSS. Call once per page (or once in app.py)."""
    st.markdown(_CSS, unsafe_allow_html=True)
