"""Design-system tokens and CSS injection for the red-team dashboard.

Theming is controlled via st.session_state["dark_mode"] (bool, default False).
inject_styles() reads that flag on every page render and emits the correct
CSS custom properties. All inline HTML in pages should use var(--color-*)
so they automatically pick up the active theme.

Module-level constants (CREAM, SURFACE, etc.) remain as light-mode values
for Plotly chart builders that need raw hex. Use get_palette() for anything
that must respond to theme switches at runtime.
"""

import streamlit as st

# ---------------------------------------------------------------------------
# Palette definitions
# ---------------------------------------------------------------------------

_LIGHT: dict[str, str] = {
    "bg":      "#F7F4EF",   # creamy page background
    "surface": "#EEEBE4",   # cards, sidebar, inputs
    "text":    "#1A1A1A",   # primary body text
    "muted":   "#5A5A5A",   # labels, captions
    "border":  "#D4D0C8",   # dividers, outlines
    "success": "#2D6A4F",   # pass / low severity
    "danger":  "#B83232",   # fail / high severity
    "accent":  "#3D5A80",   # primary chart fill
}

_DARK: dict[str, str] = {
    "bg":      "#111111",
    "surface": "#1C1C1C",
    "text":    "#DEDEDE",
    "muted":   "#888888",
    "border":  "#2C2C2C",
    "success": "#3A9B6A",
    "danger":  "#D44545",
    "accent":  "#6B9CC4",
}

# ---------------------------------------------------------------------------
# Light-mode module constants (kept for Plotly builders + backward compat)
# ---------------------------------------------------------------------------

CREAM        = _LIGHT["bg"]
SURFACE      = _LIGHT["surface"]
TEXT_PRIMARY = _LIGHT["text"]
TEXT_MUTED   = _LIGHT["muted"]
BORDER       = _LIGHT["border"]
SUCCESS      = _LIGHT["success"]
DANGER       = _LIGHT["danger"]
ACCENT       = _LIGHT["accent"]

# Model-specific chart colors (used across comparison page)
MODEL_COLORS: dict[str, str] = {
    "claude-sonnet-4-6": "#3D5A80",
    "claude-haiku-4-5":  "#8B7355",
    "gpt-4o":            "#2D6A4F",
    "gpt-4o-mini":       "#7FA88B",
}

# ---------------------------------------------------------------------------
# Subdomain / model labels
# ---------------------------------------------------------------------------

SUBDOMAIN_LABELS: dict = {
    "3a_investment_advice":    "Investment Advice (3a)",
    "3b_fraud_and_scams":      "Fraud & Scams (3b)",
    "3c_pii_and_data_leakage": "PII Leakage (3c)",
    None:                      "Generic / Cross-domain",
}

SUBDOMAIN_SHORT: dict = {
    "3a_investment_advice":    "3a Invest.",
    "3b_fraud_and_scams":      "3b Fraud",
    "3c_pii_and_data_leakage": "3c PII",
    None:                      "Generic",
}

MODEL_SHORT: dict[str, str] = {
    "claude-sonnet-4-6": "sonnet",
    "claude-haiku-4-5":  "haiku",
    "gpt-4o":            "gpt-4o",
    "gpt-4o-mini":       "gpt-4o-mini",
}


def subdomain_label(value, short: bool = False) -> str:
    """Translate a raw subdomain value (possibly None/NaN/empty) to a friendly label."""
    try:
        is_nan = isinstance(value, float) and value != value
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


# ---------------------------------------------------------------------------
# Runtime palette accessor
# ---------------------------------------------------------------------------

def get_palette() -> dict[str, str]:
    """Return the active theme palette dict (reads st.session_state)."""
    return _DARK if st.session_state.get("dark_mode", False) else _LIGHT


# ---------------------------------------------------------------------------
# CSS injection
# ---------------------------------------------------------------------------

def inject_styles() -> None:
    """Inject dashboard-wide CSS for the current theme. Call once per page."""
    p = get_palette()
    bg      = p["bg"]
    surface = p["surface"]
    text    = p["text"]
    muted   = p["muted"]
    border  = p["border"]
    success = p["success"]
    danger  = p["danger"]
    accent  = p["accent"]

    css = f"""<style>
/* ── Disable Chrome auto dark mode — we own all theming ─────────────────── */
html {{ color-scheme: light; }}

/* ── CSS custom properties (used by inline HTML blocks in pages) ─────────── */
:root {{
  --color-bg:      {bg};
  --color-surface: {surface};
  --color-text:    {text};
  --color-muted:   {muted};
  --color-border:  {border};
  --color-success: {success};
  --color-danger:  {danger};
  --color-accent:  {accent};
}}

/* ── Page background ─────────────────────────────────────────────────────── */
.stApp {{ background-color: {bg}; }}
.main .block-container {{ padding-top: 2rem; padding-bottom: 3rem; }}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {{
    background-color: {surface};
    border-right: 1px solid {border};
}}
section[data-testid="stSidebar"] * {{ color: {text}; }}

/* ── Metric cards ────────────────────────────────────────────────────────── */
[data-testid="metric-container"] {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 16px 20px;
}}
[data-testid="metric-container"] label {{ color: {muted} !important; }}
[data-testid="metric-container"] [data-testid="stMetricValue"] {{ color: {text} !important; }}
[data-testid="stMetricDelta"] {{ color: {muted} !important; }}

/* ── Tables / dataframes ─────────────────────────────────────────────────── */
.stDataFrame {{ border: 1px solid {border}; border-radius: 6px; }}

/* ── Typography ──────────────────────────────────────────────────────────── */
h1, h2, h3, h4 {{ color: {text} !important; font-weight: 600; }}
p, li {{ color: {text}; }}

/* ── Captions ────────────────────────────────────────────────────────────── */
[data-testid="stCaptionContainer"],
[data-testid="stCaptionContainer"] * {{ color: {muted} !important; }}

/* ── Dividers ────────────────────────────────────────────────────────────── */
hr {{ border-color: {border}; margin: 20px 0; }}

/* ── Expanders ───────────────────────────────────────────────────────────── */
.streamlit-expanderHeader,
[data-testid="stExpander"] details summary {{
    background-color: {surface} !important;
    border-radius: 6px;
    color: {text} !important;
}}
[data-testid="stExpander"] {{
    border: 1px solid {border} !important;
    border-radius: 6px;
    background-color: {surface} !important;
}}
[data-testid="stExpander"] * {{ color: {text}; }}

/* ── Input controls — explicit override stops Chrome inverting them ───────── */
.stSelectbox > div > div,
.stMultiSelect > div > div,
.stTextInput > div > div,
.stNumberInput > div > div,
.stTextArea > div > div {{
    background-color: {surface} !important;
    border-color: {border} !important;
    color: {text} !important;
}}
.stSelectbox label,
.stMultiSelect label,
.stTextInput label,
.stNumberInput label,
.stTextArea label,
.stSlider label,
.stCheckbox label,
.stRadio label {{ color: {muted} !important; }}

/* BaseUI select internals */
[data-baseweb="select"] > div {{
    background-color: {surface} !important;
    border-color: {border} !important;
    color: {text} !important;
}}
[data-baseweb="select"] span,
[data-baseweb="select"] svg {{ color: {text} !important; fill: {text}; }}
[data-baseweb="popover"],
[data-baseweb="menu"] {{
    background-color: {surface} !important;
    border-color: {border} !important;
}}
[data-baseweb="menu"] li {{ color: {text} !important; }}
[data-baseweb="tag"] {{
    background-color: {bg} !important;
    border: 1px solid {border} !important;
}}
[data-baseweb="tag"] span {{ color: {text} !important; }}

/* Raw input/textarea elements */
input, input[type="text"], input[type="number"], textarea {{
    background-color: {surface} !important;
    color: {text} !important;
    border-color: {border} !important;
    -webkit-text-fill-color: {text} !important;
}}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
.stButton > button,
.stDownloadButton > button {{
    background-color: {surface} !important;
    border: 1px solid {border} !important;
    color: {text} !important;
}}
.stButton > button:hover,
.stDownloadButton > button:hover {{
    border-color: {accent} !important;
    color: {accent} !important;
    background-color: {surface} !important;
}}
button[data-testid="baseButton-primary"],
.stButton > button[kind="primary"] {{
    background-color: {accent} !important;
    border-color: {accent} !important;
    color: #ffffff !important;
}}
button[data-testid="baseButton-primary"]:hover {{
    opacity: 0.88;
}}

/* ── Alerts / callouts ───────────────────────────────────────────────────── */
.stAlert {{ background-color: {surface} !important; color: {text} !important; }}
.stAlert * {{ color: {text} !important; }}

/* ── Code blocks ─────────────────────────────────────────────────────────── */
.stCodeBlock, pre, code {{
    background-color: {surface} !important;
    border: 1px solid {border} !important;
    border-radius: 6px;
    color: {text} !important;
    -webkit-text-fill-color: {text} !important;
}}

/* ── Markdown ────────────────────────────────────────────────────────────── */
.stMarkdown {{ color: {text}; }}
.stMarkdown code {{
    background-color: {surface} !important;
    color: {text} !important;
    -webkit-text-fill-color: {text} !important;
}}

/* ── Nav links ───────────────────────────────────────────────────────────── */
[data-testid="stSidebarNav"] a {{ color: {text} !important; }}
[data-testid="stSidebarNav"] a:hover {{ color: {accent} !important; }}

/* ── Spinner ─────────────────────────────────────────────────────────────── */
[data-testid="stSpinner"] p {{ color: {muted} !important; }}

/* ── Footer / header ─────────────────────────────────────────────────────── */
footer {{ visibility: hidden; }}
#MainMenu {{ visibility: hidden; }}
header[data-testid="stHeader"] {{ background-color: {bg}; }}
</style>"""

    st.markdown(css, unsafe_allow_html=True)


def inject_theme_toggle() -> None:
    """Render a light/dark mode toggle button. Intended for the sidebar."""
    dark = st.session_state.get("dark_mode", False)
    label = "Light mode" if dark else "Dark mode"
    if st.button(label, key="_theme_toggle", use_container_width=True):
        st.session_state.dark_mode = not dark
        st.rerun()
