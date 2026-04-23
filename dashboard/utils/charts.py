"""Plotly chart builders for the red-team dashboard.

Every figure returned from this module has already been run through
apply_chart_theme() so pages don't need to know about the palette.
"""

from __future__ import annotations

from typing import Iterable, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from .styles import (
    ACCENT,
    BORDER,
    CREAM,
    DANGER,
    MODEL_COLORS,
    SUCCESS,
    SURFACE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    model_label,
    subdomain_label,
)

# Re-export so pages can import palette tokens from a single module.
__all__ = [
    "ACCENT", "BORDER", "CREAM", "DANGER", "MODEL_COLORS",
    "SUCCESS", "SURFACE", "TEXT_MUTED", "TEXT_PRIMARY",
    "apply_chart_theme",
    "asr_by_subdomain_bar",
    "severity_histogram",
    "technique_subdomain_heatmap",
    "technique_model_heatmap",
    "model_comparison_bar",
    "severity_overlay_histogram",
    "technique_table",
]


def apply_chart_theme(fig: go.Figure, title: str = "") -> go.Figure:
    """Apply the dashboard theme to any Plotly figure. Idempotent."""
    fig.update_layout(
        plot_bgcolor=CREAM,
        paper_bgcolor=CREAM,
        font=dict(color=TEXT_PRIMARY, family="Inter, system-ui, sans-serif", size=13),
        title=dict(
            text=title,
            font=dict(size=15, color=TEXT_PRIMARY),
            x=0,
            xanchor="left",
        ),
        xaxis=dict(gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_MUTED)),
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_MUTED)),
        legend=dict(bgcolor=SURFACE, bordercolor=BORDER, borderwidth=1),
        margin=dict(l=40, r=20, t=48, b=40),
        hoverlabel=dict(bgcolor=SURFACE, bordercolor=BORDER, font_color=TEXT_PRIMARY),
    )
    return fig


def _interp_color(t: float, c_low: tuple[int, int, int], c_high: tuple[int, int, int]) -> str:
    t = max(0.0, min(1.0, t))
    r = int(c_low[0] + (c_high[0] - c_low[0]) * t)
    g = int(c_low[1] + (c_high[1] - c_low[1]) * t)
    b = int(c_low[2] + (c_high[2] - c_low[2]) * t)
    return f"rgb({r},{g},{b})"


# --- Overview charts --------------------------------------------------------


def asr_by_subdomain_bar(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar of ASR by subdomain. Bars colored on a continuous SUCCESS→DANGER scale.

    Expects columns: subdomain, total, successes, asr.
    """
    data = df.copy()
    data["label"] = data["subdomain"].apply(lambda v: subdomain_label(v, short=False))
    data["count_annotation"] = data.apply(
        lambda r: f"({int(r['successes'])} / {int(r['total'])} attacks)", axis=1
    )
    # Sort ascending so the highest ASR sits at the top of a horizontal bar chart.
    data = data.sort_values("asr", ascending=True)

    success_rgb = (45, 106, 79)    # #2D6A4F
    danger_rgb = (184, 50, 50)     # #B83232
    # Normalise across the dataset; if all ASRs are zero, use flat SUCCESS.
    max_asr = max(data["asr"].max(), 0.01)
    bar_colors = [
        _interp_color(asr / max_asr, success_rgb, danger_rgb) for asr in data["asr"]
    ]

    fig = go.Figure(
        go.Bar(
            x=data["asr"],
            y=data["label"],
            orientation="h",
            marker=dict(color=bar_colors, line=dict(width=0)),
            text=[f"{v:.0%}" for v in data["asr"]],
            textposition="outside",
            customdata=data["count_annotation"],
            hovertemplate="<b>%{y}</b><br>ASR: %{x:.1%}<br>%{customdata}<extra></extra>",
        )
    )
    # Annotations showing N after each bar label
    fig.update_layout(
        xaxis=dict(tickformat=".0%", range=[0, max(data["asr"].max() * 1.25, 0.12)]),
        yaxis=dict(title=""),
        xaxis_title="Attack Success Rate",
        showlegend=False,
        bargap=0.35,
        height=60 * max(len(data), 3) + 80,
    )
    # Add count annotations to the right of each value label
    for asr, label, anno in zip(data["asr"], data["label"], data["count_annotation"]):
        fig.add_annotation(
            x=asr,
            y=label,
            text=anno,
            showarrow=False,
            xanchor="left",
            xshift=48,
            font=dict(color=TEXT_MUTED, size=11),
        )
    return apply_chart_theme(fig, "ASR by Subdomain")


def severity_histogram(df: pd.DataFrame) -> go.Figure:
    """Histogram of severity scores with an annotated partial-harm threshold."""
    fig = px.histogram(
        df,
        x="severity_score",
        nbins=11,
        range_x=[-0.5, 10.5],
        color_discrete_sequence=[ACCENT],
    )
    fig.update_traces(
        opacity=0.85,
        marker_line_color=BORDER,
        marker_line_width=1,
        xbins=dict(start=-0.5, end=10.5, size=1),
    )
    fig.update_layout(
        xaxis_title="Severity (0–10)",
        yaxis_title="Count",
        bargap=0.05,
    )
    fig.add_vline(
        x=4.0,
        line_width=1.5,
        line_dash="dash",
        line_color=DANGER,
        annotation_text="Partial harm threshold",
        annotation_position="top right",
        annotation=dict(font=dict(color=DANGER, size=11)),
    )
    return apply_chart_theme(fig, "Severity Distribution")


def technique_table(df: pd.DataFrame) -> pd.DataFrame:
    """Format the top-techniques DataFrame for st.dataframe rendering.

    Returns a new DataFrame; pages apply column_config + row highlight on top of this.
    """
    out = df.copy()
    out = out.rename(
        columns={
            "technique": "Technique",
            "attempts": "Attempts",
            "successes": "Successes",
            "asr": "ASR",
            "avg_severity": "Avg Severity",
        }
    )
    # Keep ASR as a float 0..1 so st.dataframe column_config can format it as %
    out["Avg Severity"] = out["Avg Severity"].fillna(0.0).round(2)
    return out


# --- Heatmap charts ---------------------------------------------------------


_HEATMAP_COLORSCALE = [
    [0.0, "#F7F4EF"],
    [0.3, "#C8D9E8"],
    [0.7, "#6B9BB8"],
    [1.0, "#B83232"],
]


def _build_heatmap(
    df: pd.DataFrame,
    row_col: str,
    col_col: str,
    col_ordering: Iterable,
    col_label_fn=lambda v: v,
    title: str = "",
    xaxis_title: str = "",
) -> go.Figure:
    """Build an annotated heatmap from a long-format DataFrame.

    Cells with < 3 attempts render as "—" and hover text makes the small-N clear.
    """
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No data for current filter.",
            showarrow=False,
            font=dict(color=TEXT_MUTED),
        )
        return apply_chart_theme(fig, title)

    # Pivot ASR + attempts + successes
    asr_pivot = df.pivot_table(
        index=row_col, columns=col_col, values="asr", aggfunc="first"
    )
    att_pivot = df.pivot_table(
        index=row_col, columns=col_col, values="attempts", aggfunc="first"
    ).fillna(0).astype(int)
    suc_pivot = df.pivot_table(
        index=row_col, columns=col_col, values="successes", aggfunc="first"
    ).fillna(0).astype(int)

    # Reindex columns in the requested order (drops unseen cols, adds missing cols empty).
    cols = [c for c in col_ordering if c in asr_pivot.columns]
    # Add any columns present in data but not listed so nothing disappears silently.
    for c in asr_pivot.columns:
        if c not in cols:
            cols.append(c)
    asr_pivot = asr_pivot.reindex(columns=cols)
    att_pivot = att_pivot.reindex(columns=cols, fill_value=0)
    suc_pivot = suc_pivot.reindex(columns=cols, fill_value=0)

    # Order rows by overall ASR descending (so most dangerous are at the top).
    row_rank = df.groupby(row_col)["asr"].mean().sort_values(ascending=False)
    row_order = [r for r in row_rank.index if r in asr_pivot.index]
    asr_pivot = asr_pivot.reindex(index=row_order)
    att_pivot = att_pivot.reindex(index=row_order, fill_value=0)
    suc_pivot = suc_pivot.reindex(index=row_order, fill_value=0)

    z = asr_pivot.values
    display_text = []
    hover_text = []
    for i, row_name in enumerate(asr_pivot.index):
        drow, hrow = [], []
        for j, col_name in enumerate(asr_pivot.columns):
            attempts = int(att_pivot.iloc[i, j])
            successes = int(suc_pivot.iloc[i, j])
            asr = asr_pivot.iloc[i, j]
            if attempts == 0:
                drow.append("")
                hrow.append(
                    f"<b>{row_name}</b><br>{col_label_fn(col_name)}<br>No attempts"
                )
            elif attempts < 3:
                drow.append("—")
                hrow.append(
                    f"<b>{row_name}</b><br>{col_label_fn(col_name)}<br>"
                    f"{successes} / {attempts} (sample too small)"
                )
            else:
                drow.append(f"{asr:.0%}" if pd.notna(asr) else "—")
                hrow.append(
                    f"<b>{row_name}</b><br>{col_label_fn(col_name)}<br>"
                    f"ASR {asr:.0%} — {successes} / {attempts}"
                )
        display_text.append(drow)
        hover_text.append(hrow)

    # For colorscale we want NaN cells to render at 0.
    import numpy as np
    z_plot = np.where(pd.isna(z), 0, z)

    fig = go.Figure(
        go.Heatmap(
            z=z_plot,
            x=[col_label_fn(c) for c in asr_pivot.columns],
            y=list(asr_pivot.index),
            colorscale=_HEATMAP_COLORSCALE,
            zmin=0.0,
            zmax=max(1.0, float(pd.Series(z_plot.flatten()).max() or 0.0)),
            text=display_text,
            texttemplate="%{text}",
            hoverinfo="text",
            hovertext=hover_text,
            colorbar=dict(
                title=dict(text="ASR", side="right"),
                tickformat=".0%",
                outlinecolor=BORDER,
                outlinewidth=1,
            ),
        )
    )
    fig.update_layout(
        xaxis=dict(title=xaxis_title, side="top"),
        yaxis=dict(title="Technique", autorange="reversed"),
        height=max(400, 30 * len(asr_pivot.index) + 120),
    )
    return apply_chart_theme(fig, title)


def technique_subdomain_heatmap(df: pd.DataFrame) -> go.Figure:
    """Heatmap of ASR for technique × financial_subdomain."""
    subdomain_order = [
        "3a_investment_advice",
        "3b_fraud_and_scams",
        "3c_pii_and_data_leakage",
        None,
    ]
    return _build_heatmap(
        df.rename(
            columns={"attack_technique": "technique", "financial_subdomain": "subdomain"}
        ),
        row_col="technique",
        col_col="subdomain",
        col_ordering=subdomain_order,
        col_label_fn=lambda v: subdomain_label(v, short=True),
        title="Technique × Subdomain (ASR)",
        xaxis_title="Subdomain",
    )


def technique_model_heatmap(df: pd.DataFrame) -> go.Figure:
    """Heatmap of ASR for technique × target_model."""
    model_order = ["claude-sonnet-4-6", "claude-haiku-4-5", "gpt-4o"]
    return _build_heatmap(
        df.rename(columns={"attack_technique": "technique"}),
        row_col="technique",
        col_col="target_model",
        col_ordering=model_order,
        col_label_fn=lambda v: model_label(v, short=True),
        title="Technique × Target Model (ASR)",
        xaxis_title="Target Model",
    )


# --- Comparison charts ------------------------------------------------------


def model_comparison_bar(df: pd.DataFrame, min_n: int = 5) -> go.Figure:
    """Grouped bar of ASR by subdomain × model. Drops subdomain/model combos with N < min_n.

    Expects columns: target_model, financial_subdomain, attempts, successes, asr.
    """
    data = df[df["attempts"] >= min_n].copy()
    if data.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="No model/subdomain combination has ≥ 5 scored attempts.",
            showarrow=False,
            font=dict(color=TEXT_MUTED),
        )
        return apply_chart_theme(fig, "ASR by Subdomain × Model")

    data["subdomain_label"] = data["financial_subdomain"].apply(
        lambda v: subdomain_label(v, short=True)
    )
    fig = px.bar(
        data,
        x="subdomain_label",
        y="asr",
        color="target_model",
        barmode="group",
        color_discrete_map=MODEL_COLORS,
        text=data["asr"].apply(lambda v: f"{v:.0%}"),
        category_orders={
            "subdomain_label": ["3a Invest.", "3b Fraud", "3c PII", "Generic"],
            "target_model": list(MODEL_COLORS.keys()),
        },
    )
    fig.update_traces(textposition="outside", marker_line_width=0, cliponaxis=False)
    fig.update_layout(
        xaxis_title="Subdomain",
        yaxis_title="ASR",
        yaxis=dict(tickformat=".0%", range=[0, max(data["asr"].max() * 1.25, 0.1)]),
        legend_title="Model",
    )
    return apply_chart_theme(fig, "ASR by Subdomain × Model")


def severity_overlay_histogram(df: pd.DataFrame) -> go.Figure:
    """Two-trace overlapping histogram of severity for successful attacks, per model.

    Expects columns: target_model, severity_score.
    """
    fig = go.Figure()
    for model, color in MODEL_COLORS.items():
        model_df = df[df["target_model"] == model]
        if model_df.empty:
            continue
        fig.add_trace(
            go.Histogram(
                x=model_df["severity_score"],
                name=model_label(model, short=True),
                opacity=0.6,
                marker=dict(color=color, line=dict(color=BORDER, width=1)),
                xbins=dict(start=-0.5, end=10.5, size=1),
            )
        )
    fig.update_layout(
        barmode="overlay",
        xaxis_title="Severity (0–10)",
        yaxis_title="Count of successful attacks",
        legend_title="Model",
    )
    return apply_chart_theme(fig, "Severity Distribution — Successful Attacks")
