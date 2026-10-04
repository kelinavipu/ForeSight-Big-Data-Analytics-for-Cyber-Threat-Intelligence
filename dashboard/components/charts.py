"""
Interactive Visualization Components for ThreatLens Dashboard.
Built using Plotly Express and Graph Objects for responsive, publication-quality graphics.
"""

from typing import Dict, Any, List
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def plot_attack_donut(df_attacks: pd.DataFrame) -> go.Figure:
    """Renders a sleek donut chart of attack category distributions."""
    fig = px.pie(
        df_attacks,
        names="Label",
        values="count",
        hole=0.55,
        color="Label",
        color_discrete_map={
            "BENIGN": "#2ECC71",
            "DDoS": "#E74C3C",
            "PortScan": "#F39C12",
            "Botnet": "#9B59B6",
            "Brute Force": "#E67E22",
            "Web Attack": "#D35400"
        }
    )
    fig.update_traces(
        textposition="inside",
        textinfo="percent+label",
        hovertemplate="<b>%{label}</b><br>Observed Flows: %{value:,}<br>Share: %{percent}<extra></extra>"
    )
    fig.update_layout(
        showlegend=True,
        margin=dict(t=30, b=10, l=10, r=10),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        height=380
    )
    return fig


def plot_pca_clusters(pca_df: pd.DataFrame, color_by: str = "cluster") -> go.Figure:
    """Renders 2D PCA cluster projection scatter plot."""
    plot_data = pca_df.copy()
    if color_by == "cluster":
        plot_data["Cluster_Name"] = "Group " + plot_data["cluster"].astype(str)
        color_col = "Cluster_Name"
    else:
        color_col = "Label"

    fig = px.scatter(
        plot_data,
        x="pca_1",
        y="pca_2",
        color=color_col,
        hover_data=["Label", "Dst_Port", "Flow_Duration"],
        opacity=0.75,
        title="Behavioral Flow Clusters (2D PCA Projection)"
    )
    fig.update_traces(marker=dict(size=7))
    fig.update_layout(
        xaxis_title="Principal Component 1 (Flow Volume & Packet Rates)",
        yaxis_title="Principal Component 2 (Flow Duration & Flags)",
        margin=dict(t=40, b=20, l=20, r=20),
        height=450
    )
    return fig


def plot_geo_threat_map(geo_df: pd.DataFrame) -> go.Figure:
    """Renders global geographic threat distribution on world map."""
    fig = px.scatter_geo(
        geo_df,
        lat="Latitude",
        lon="Longitude",
        size="attack_count",
        color="Country",
        hover_name="Country",
        hover_data={"attack_count": True, "Label": True, "Latitude": False, "Longitude": False},
        projection="natural earth",
        title="Global Attack Source Origin Map"
    )
    fig.update_geos(
        showcountries=True,
        countrycolor="#444444",
        showocean=True,
        oceancolor="#1E293B",
        showland=True,
        landcolor="#0F172A",
        showlakes=False
    )
    fig.update_layout(
        margin=dict(t=40, b=10, l=10, r=10),
        height=480
    )
    return fig


def plot_hourly_heatmap(df_heatmap: pd.DataFrame) -> go.Figure:
    """Renders Day of Week vs Hour of Day attack intensity heatmap."""
    # Pivot for heatmap
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot = df_heatmap.pivot(index="DayOfWeek", columns="Hour", values="attack_count").fillna(0)
    # Reindex days if present
    existing_days = [d for d in days_order if d in pivot.index]
    pivot = pivot.reindex(existing_days)

    fig = px.imshow(
        pivot,
        labels=dict(x="Hour of Day (0-23 UTC)", y="Day of Week", color="Attacks"),
        x=list(range(24)),
        color_continuous_scale="Reds",
        aspect="auto",
        title="Attack Timing Heatmap: When Do Threat Actors Attack?"
    )
    fig.update_layout(
        margin=dict(t=40, b=20, l=20, r=20),
        height=320
    )
    return fig


def plot_threat_network(graph_data: Dict[str, Any]) -> go.Figure:
    """Renders interactive 2D node-link threat infrastructure graph with PageRank sizing."""
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes:
        return go.Figure()

    node_pos = {n["id"]: (n["x"], n["y"]) for n in nodes}

    # Build Edge Traces
    edge_x = []
    edge_y = []
    for e in edges:
        u, v = e["source"], e["target"]
        if u in node_pos and v in node_pos:
            x0, y0 = node_pos[u]
            x1, y1 = node_pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.8, color="#555555"),
        hoverinfo="none",
        mode="lines"
    )

    # Build Node Traces
    node_x = [n["x"] for n in nodes]
    node_y = [n["y"] for n in nodes]
    node_text = [
        f"<b>{n['name']}</b><br>Type: {n['type']}<br>PageRank: {n['pagerank']:.5f}"
        for n in nodes
    ]
    node_color = [n["color"] for n in nodes]
    node_size = [max(8, min(35, n["size"])) for n in nodes]

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=[n["name"].split(":")[-1].strip() if n["type"] == "malware_family" else "" for n in nodes],
        textposition="top center",
        hovertext=node_text,
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=1.5, color="#FFFFFF")
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title="Threat Infrastructure Graph: PageRank Kingpin Analysis",
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
    """Renders memory reduction comparison bar chart across Big Data algorithms."""
    labels = []
    trad_mem = []
    algo_mem = []

    # Bloom Filter vs Set
    if "bloom_filter" in benchmarks:
        bf = benchmarks["bloom_filter"]
        labels.append("IP Lookup (Bloom Filter vs Set)")
        trad_mem.append(bf.get("set_memory_kb", 100))
        algo_mem.append(bf.get("bloom_memory_kb", 5))

    # Flajolet-Martin vs Set
    if "flajolet_martin" in benchmarks:
        fm = benchmarks["flajolet_martin"]
        labels.append("Unique IPs (FM vs Hash Set)")
        trad_mem.append(fm.get("exact_set_memory_bytes", 1000) / 1024)
        algo_mem.append(fm.get("fm_memory_bytes", 128) / 1024)

    # Parquet vs CSV
    if "storage_benchmark" in benchmarks:
        sb = benchmarks["storage_benchmark"]
        labels.append("Flow Logs (Parquet vs CSV)")
        trad_mem.append(sb.get("csv_size_mb", 50) * 1024)
        algo_mem.append(sb.get("parquet_size_mb", 10) * 1024)

    fig = go.Figure(data=[
        go.Bar(name="Standard Storage / Python Set (KB)", x=labels, y=trad_mem, marker_color="#E74C3C"),
        go.Bar(name="Big Data Algorithm / Parquet (KB)", x=labels, y=algo_mem, marker_color="#2ECC71")
    ])
    fig.update_layout(
        barmode="group",
        title="Physical Memory / Storage Footprint Comparison (Log Scale)",
        yaxis_type="log",
        yaxis_title="Memory Footprint in Kilobytes (Log Scale)",
        margin=dict(t=40, b=20, l=20, r=20),
        height=360
    )
    return fig
