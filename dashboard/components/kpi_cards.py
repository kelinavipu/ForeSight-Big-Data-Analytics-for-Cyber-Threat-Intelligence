"""
UI KPI Metric Cards with Cyberpunk City Theme (Midnight Glassmorphism).
Renders sleek, dark translucent cards with pink and blue gradient accents.
"""

import streamlit as st


def render_kpi_row(
    total_logs: int,
    known_iocs: int,
    unique_attackers: int,
    headline_matches: int,
    risk_level: str = "Medium"
):
    """Renders executive KPI metric cards styled with a midnight cyber aesthetic."""
    c1, c2, c3, c4, c5 = st.columns(5)

    risk_meta = {
        "Low": {"text": "LOW RISK", "color": "#10B981", "badge": "🟢 Normal Activity"},
        "Medium": {"text": "ELEVATED", "color": "#F59E0B", "badge": "🟡 Watchlist Active"},
        "High": {"text": "HIGH RISK", "color": "#FF2A85", "badge": "🔴 Active Intrusion"},
        "Critical": {"text": "CRITICAL", "color": "#F43F5E", "badge": "🚨 Severe Threat"}
    }.get(risk_level, {"text": "ELEVATED", "color": "#F59E0B", "badge": "🟡 Watchlist Active"})

    card_template = """
    <div style="
        background: linear-gradient(135deg, rgba(18, 22, 41, 0.85) 0%, rgba(13, 16, 31, 0.75) 100%);
        border: 1px solid rgba(0, 210, 255, 0.18);
        border-radius: 10px;
        padding: 14px 16px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        position: relative;
        overflow: hidden;
        min-height: 110px;
    ">
        <div style="
            position: absolute;
            top: 0; left: 0; right: 0; height: 3px;
            background: linear-gradient(90deg, {accent_left}, {accent_right});
        "></div>
        <div style="
            font-size: 0.72rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #94A3B8;
            margin-bottom: 6px;
        ">{label}</div>
        <div style="
            font-size: 1.6rem;
            font-weight: 700;
            color: {val_color};
            font-feature-settings: 'tnum';
            line-height: 1.1;
            margin-bottom: 4px;
        ">{value}</div>
        <div style="
            font-size: 0.76rem;
            color: {sub_color};
            font-weight: 500;
        ">{subtext}</div>
    </div>
    """

    with c1:
        st.markdown(card_template.format(
            accent_left="#00D2FF",
            accent_right="#3B82F6",
            label="Flows Analyzed",
            value=f"{total_logs:,}",
            val_color="#F8FAFC",
            sub_color="#38BDF8",
            subtext="⚡ PySpark / Parquet Engine"
        ), unsafe_allow_html=True)

    with c2:
        st.markdown(card_template.format(
            accent_left="#3B82F6",
            accent_right="#8B5CF6",
            label="Known Bad IOCs",
            value=f"{known_iocs:,}",
            val_color="#F8FAFC",
            sub_color="#A78BFA",
            subtext="🛡️ abuse.ch & CISA Catalog"
        ), unsafe_allow_html=True)

    with c3:
        st.markdown(card_template.format(
            accent_left="#8B5CF6",
            accent_right="#EC4899",
            label="Unique Attackers",
            value=f"{unique_attackers:,}",
            val_color="#F8FAFC",
            sub_color="#F472B6",
            subtext="🎯 Flajolet–Martin in O(1) Space"
        ), unsafe_allow_html=True)

    with c4:
        st.markdown(card_template.format(
            accent_left="#EC4899",
            accent_right="#FF2A85",
            label="C2 Feed Matches",
            value=f"{headline_matches:,}",
            val_color="#FF2A85",
            sub_color="#FDA4AF",
            subtext="⚠️ Internal Bots Flagged"
        ), unsafe_allow_html=True)

    with c5:
        st.markdown(card_template.format(
            accent_left="#FF2A85",
            accent_right="#00D2FF",
            label="Threat Posture",
            value=risk_meta["text"],
            val_color=risk_meta["color"],
            sub_color="#CBD5E1",
            subtext=risk_meta["badge"]
        ), unsafe_allow_html=True)
