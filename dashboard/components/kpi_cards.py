"""
UI KPI Metric Cards and Badges for ThreatLens.
Renders clean, modern executive metrics with color-coded risk levels.
"""

import streamlit as st


def render_kpi_row(
    total_logs: int,
    known_iocs: int,
    unique_attackers: int,
    headline_matches: int,
    risk_level: str = "Medium"
):
    """Renders the top executive KPI metric cards."""
    c1, c2, c3, c4, c5 = st.columns(5)

    risk_badge = {
        "Low": "🟢 Low Risk",
        "Medium": "🟡 Medium Risk",
        "High": "🔴 High Risk",
        "Critical": "🚨 Critical"
    }.get(risk_level, "🟡 Medium Risk")

    with c1:
        st.metric(
            label="📊 Flow Events Analyzed",
            value=f"{total_logs:,}",
            help="Total network flow records processed through the Big Data pipeline"
        )
    with c2:
        st.metric(
            label="🛡️ Threat IOCs Tracked",
            value=f"{known_iocs:,}",
            help="Known malicious IPs, URLs, and CVEs aggregated from threat feeds"
        )
    with c3:
        st.metric(
            label="🎯 Unique Attackers (FM)",
            value=f"{unique_attackers:,}",
            help="Distinct attacker IP cardinality estimated via Flajolet-Martin algorithm in O(1) space"
        )
    with c4:
        st.metric(
            label="⚠️ Malicious Feed Matches",
            value=f"{headline_matches:,}",
            delta=f"{headline_matches} flagged",
            delta_color="inverse",
            help="Internal network flows actively communicating with known criminal C2 infrastructure"
        )
    with c5:
        st.metric(
            label="⚡ Threat Posture Today",
            value=risk_badge,
            help="Composite threat posture assessed based on active C2 beacons and volumetric attacks"
        )
