"""
Interactive Visualization Components for ThreatLens Dashboard.
Designed with a sleek, atmospheric Midnight Cyberpunk City aesthetic (Pink & Blue tones).
"""

from typing import Dict, Any, List
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Cyberpunk City Color Palette
COLOR_CYBER_PINK = "#FF2A85"
COLOR_ELECTRIC_BLUE = "#00D2FF"
COLOR_VIOLET = "#8B5CF6"
COLOR_ROSE = "#F43F5E"
COLOR_SKY = "#38BDF8"
COLOR_MINT = "#10B981"
BG_DARK = "#090B14"
SURFACE_DARK = "#121629"
TEXT_LIGHT = "#E2E8F0"
GRID_MUTED = "rgba(148, 163, 184, 0.12)"

ATTACK_COLOR_MAP = {
    "BENIGN": COLOR_MINT,
    "DDoS": COLOR_CYBER_PINK,
    "PortScan": COLOR_ELECTRIC_BLUE,
    "Botnet": COLOR_VIOLET,
    "Brute Force": COLOR_ROSE,
    "Web Attack": COLOR_SKY
}


def apply_cyber_theme(fig: go.Figure, height: int = 400, title: str = "") -> go.Figure:
    """Applies consistent dark cyberpunk styling to any Plotly figure."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(14, 18, 33, 0.6)",
        plot_bgcolor="rgba(10, 13, 24, 0.4)",
        font=dict(color=TEXT_LIGHT, family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif"),
        title=dict(text=title, font=dict(size=15, color=COLOR_ELECTRIC_BLUE)) if title else None,
        height=height,
        margin=dict(t=40 if title else 25, b=25, l=25, r=25),
        xaxis=dict(
            gridcolor=GRID_MUTED,
            zerolinecolor=GRID_MUTED,
            tickfont=dict(color="#94A3B8")
        ),
        yaxis=dict(
            gridcolor=GRID_MUTED,
            zerolinecolor=GRID_MUTED,
            tickfont=dict(color="#94A3B8")
        )
    )
    return fig


def plot_attack_donut(df_attacks: pd.DataFrame) -> go.Figure:
    """Renders a sleek donut chart of attack category distributions in cyberpunk city tones."""
    fig = px.pie(
        df_attacks,
        names="Label",
        values="count",
        hole=0.62,
        color="Label",
        color_discrete_map=ATTACK_COLOR_MAP
    )
    fig.update_traces(
        textposition="inside",
        textinfo="percent+label",
        hovertemplate="<b>%{label}</b><br>Observed Flows: %{value:,}<br>Share: %{percent}<extra></extra>",
        marker=dict(line=dict(color="#090B14", width=2))
    )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(14, 18, 33, 0.6)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT_LIGHT),
        showlegend=True,
        margin=dict(t=20, b=10, l=10, r=10),
        legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5, font=dict(color="#94A3B8")),
        height=380
    )
    return fig


def plot_pca_clusters(pca_df: pd.DataFrame, color_by: str = "cluster") -> go.Figure:
    """Renders 2D PCA cluster projection scatter plot with cyberpunk tones."""
    plot_data = pca_df.copy()
    if color_by == "cluster":
        plot_data["Cluster_Name"] = "Group " + plot_data["cluster"].astype(str)
        color_col = "Cluster_Name"
        palette = [COLOR_CYBER_PINK, COLOR_ELECTRIC_BLUE, COLOR_VIOLET, COLOR_ROSE, COLOR_SKY, COLOR_MINT]
        fig = px.scatter(
            plot_data,
            x="pca_1",
            y="pca_2",
            color=color_col,
            color_discrete_sequence=palette,
            hover_data=["Label", "Dst_Port", "Flow_Duration"],
            opacity=0.85
        )
    else:
        fig = px.scatter(
            plot_data,
            x="pca_1",
            y="pca_2",
            color="Label",
            color_discrete_map=ATTACK_COLOR_MAP,
            hover_data=["Label", "Dst_Port", "Flow_Duration"],
            opacity=0.85
        )

    fig.update_traces(marker=dict(size=6, line=dict(width=0.5, color="#FFFFFF")))
    apply_cyber_theme(fig, height=450, title="Behavioral Flow Clusters (2D PCA Projection)")
    fig.update_layout(
        xaxis_title="Principal Component 1 (Flow Volume & Packet Rates)",
        yaxis_title="Principal Component 2 (Flow Duration & Flags)"
    )
    return fig


def plot_geo_threat_map(geo_df: pd.DataFrame) -> go.Figure:
    """Renders global geographic threat distribution on midnight cyberpunk world map."""
    fig = px.scatter_geo(
        geo_df,
        lat="Latitude",
        lon="Longitude",
        size="attack_count",
        color="Country",
        hover_name="Country",
        hover_data={"attack_count": True, "Label": True, "Latitude": False, "Longitude": False},
        projection="natural earth",
        color_discrete_sequence=[COLOR_CYBER_PINK, COLOR_ELECTRIC_BLUE, COLOR_VIOLET, COLOR_ROSE, COLOR_SKY, "#F59E0B"]
    )
    fig.update_geos(
        showcountries=True,
        countrycolor="#2A3352",
        showocean=True,
        oceancolor="#070913",
        showland=True,
        landcolor="#12162A",
        showlakes=False,
        bgcolor="#090B14"
    )
    fig.update_traces(marker=dict(line=dict(width=0.8, color="#FFFFFF"), opacity=0.85))
    apply_cyber_theme(fig, height=480, title="Global Attack Source Origin Map (Midnight Matrix)")
    return fig


def plot_hourly_heatmap(df_heatmap: pd.DataFrame) -> go.Figure:
    """Renders Day of Week vs Hour of Day attack intensity heatmap in pink/blue gradient."""
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot = df_heatmap.pivot(index="DayOfWeek", columns="Hour", values="attack_count").fillna(0)
    existing_days = [d for d in days_order if d in pivot.index]
    pivot = pivot.reindex(existing_days)

    # Midnight Navy -> Cyber Indigo -> Neon Pink Colorscale
    cyber_colorscale = [
        [0.0, "#090B14"],
        [0.35, "#1E1B4B"],
        [0.7, "#6366F1"],
        [1.0, COLOR_CYBER_PINK]
    ]

    fig = px.imshow(
        pivot,
        labels=dict(x="Hour of Day (0-23 UTC)", y="Day of Week", color="Attacks"),
        x=list(range(24)),
        color_continuous_scale=cyber_colorscale,
        aspect="auto"
    )
    apply_cyber_theme(fig, height=330, title="Attack Timing Heatmap: When Do Threat Actors Attack?")
    fig.update_coloraxes(colorbar=dict(tickfont=dict(color="#94A3B8"), title=dict(font=dict(color="#94A3B8"))))
    return fig


def plot_threat_network(graph_data: Dict[str, Any]) -> go.Figure:
    """Renders interactive 2D node-link threat infrastructure graph with PageRank sizing."""
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes:
        return go.Figure()

    node_pos = {n["id"]: (n["x"], n["y"]) for n in nodes}

    # Cyberpunk City Node Color Mapping
    def get_cyber_node_color(ntype: str):
        if ntype == "malware_family":
            return COLOR_CYBER_PINK
        elif ntype in ["c2_domain", "c2_ip"]:
            return COLOR_ELECTRIC_BLUE
        elif ntype == "attacker_ip":
            return COLOR_VIOLET
        else:
            return COLOR_SKY

    # Edge Traces (Soft Cyan Glowing Links)
    edge_x, edge_y = [], []
    for e in edges:
        u, v = e["source"], e["target"]
        if u in node_pos and v in node_pos:
            x0, y0 = node_pos[u]
            x1, y1 = node_pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.9, color="rgba(0, 210, 255, 0.22)"),
        hoverinfo="none",
        mode="lines"
    )

    # Node Traces
    node_x = [n["x"] for n in nodes]
    node_y = [n["y"] for n in nodes]
    node_text = [
        f"<b>{n['name']}</b><br>Type: {n['type']}<br>PageRank: {n['pagerank']:.5f}"
        for n in nodes
    ]
    node_color = [get_cyber_node_color(n.get("type", "")) for n in nodes]
    node_size = [max(9, min(36, n["size"])) for n in nodes]

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=[n["name"].split(":")[-1].strip() if n["type"] == "malware_family" else "" for n in nodes],
        textposition="top center",
        hovertext=node_text,
        textfont=dict(color="#E2E8F0", size=10),
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=1.5, color="#090B14")
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(text="Threat Infrastructure Graph: PageRank Kingpin Analysis", font=dict(size=15, color=COLOR_ELECTRIC_BLUE)),
            template="plotly_dark",
            paper_bgcolor="rgba(14, 18, 33, 0.6)",
            plot_bgcolor="rgba(10, 13, 24, 0.4)",
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=20, r=20, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=500
        )
    )
    return fig


def plot_benchmark_memory(benchmarks: Dict[str, Any]) -> go.Figure:
    """Renders memory reduction comparison bar chart in Cyber Pink & Blue."""
    labels, trad_mem, algo_mem = [], [], []

    if "bloom_filter" in benchmarks:
        bf = benchmarks["bloom_filter"]
        labels.append("IP Lookup (Bloom vs Set)")
        trad_mem.append(bf.get("set_memory_kb", 100))
        algo_mem.append(bf.get("bloom_memory_kb", 5))

    if "flajolet_martin" in benchmarks:
        fm = benchmarks["flajolet_martin"]
        labels.append("Unique IPs (FM vs Set)")
        trad_mem.append(fm.get("exact_set_memory_bytes", 1000) / 1024)
        algo_mem.append(fm.get("fm_memory_bytes", 128) / 1024)

    if "storage_benchmark" in benchmarks:
        sb = benchmarks["storage_benchmark"]
        labels.append("Logs (Parquet vs CSV)")
        trad_mem.append(sb.get("csv_size_mb", 50) * 1024)
        algo_mem.append(sb.get("parquet_size_mb", 10) * 1024)

    fig = go.Figure(data=[
        go.Bar(
            name="Traditional Baseline (KB)",
            x=labels,
            y=trad_mem,
            marker=dict(color=COLOR_ROSE, line=dict(color="#090B14", width=1))
        ),
        go.Bar(
            name="Big Data Optimization (KB)",
            x=labels,
            y=algo_mem,
            marker=dict(color=COLOR_ELECTRIC_BLUE, line=dict(color="#090B14", width=1))
        )
    ])
    apply_cyber_theme(fig, height=360, title="Physical Memory / Storage Footprint Comparison (Log Scale)")
    fig.update_layout(
        barmode="group",
        yaxis_type="log",
        yaxis_title="Memory Footprint in KB (Log Scale)",
        legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5, font=dict(color="#94A3B8"))
    )
    return fig
