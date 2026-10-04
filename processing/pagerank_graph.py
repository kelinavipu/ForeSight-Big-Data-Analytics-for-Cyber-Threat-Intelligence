"""
Threat Infrastructure Graph and PageRank Centrality Analysis.
Models cyber threat relationships (Attacker IP <-> C2 Domain <-> Malware Family <-> Target Service)
and computes PageRank to pinpoint kingpin infrastructure servers.
"""

from typing import Dict, List, Tuple, Any
import networkx as nx
import pandas as pd


class ThreatGraphAnalyzer:
    """Builds multi-source threat infrastructure graphs and computes PageRank rankings."""
    def __init__(self, damping_factor: float = 0.85):
        self.alpha = damping_factor
        self.graph = nx.DiGraph()
        self.pagerank_scores: Dict[str, float] = {}

    def build_graph(self, feeds_df: pd.DataFrame, logs_df: pd.DataFrame, max_edges: int = 500):
        """Builds directed threat graph from threat intelligence feeds and network logs."""
        self.graph.clear()

        # 1. Feed Infrastructure: IP -> Malware Family, Domain -> Malware Family
        sample_feeds = feeds_df.head(max_edges // 2)
        for _, row in sample_feeds.iterrows():
            ioc = str(row.get("ioc_value", "")).strip()
            fam = str(row.get("malware_family", "Unknown")).strip()
            threat = str(row.get("threat_type", "Threat")).strip()
            ip = str(row.get("ip_address", "")).strip()

            if not fam:
                continue

            fam_node = f"Family: {fam}"
            self.graph.add_node(fam_node, node_type="malware_family", color="#FF4B4B", size=25)

            if ip:
                ip_node = f"IP: {ip}"
                self.graph.add_node(ip_node, node_type="c2_ip", color="#FFAA00", size=15)
                self.graph.add_edge(ip_node, fam_node, relation="belongs_to_family", weight=1.5)

            if "http" in ioc or "/" in ioc:
                domain = ioc.split("/")[2] if len(ioc.split("/")) > 2 else ioc[:30]
                dom_node = f"Domain: {domain}"
                self.graph.add_node(dom_node, node_type="c2_domain", color="#9B51E0", size=18)
                self.graph.add_edge(dom_node, fam_node, relation="delivers_malware", weight=2.0)
                if ip:
                    self.graph.add_edge(dom_node, f"IP: {ip}", relation="resolves_to", weight=1.2)

        # 2. Log Attacks: Attacker IP -> Target Port / Target Server
        attack_logs = logs_df[logs_df["is_attack"] == 1].head(max_edges // 2)
        for _, row in attack_logs.iterrows():
            src = f"IP: {row['Src_IP']}"
            dst = f"Target: {row['Dst_IP']}:{row['Dst_Port']}"
            label = str(row.get("Label", "Attack"))

            self.graph.add_node(src, node_type="attacker_ip", color="#FF7F0E", size=12)
            self.graph.add_node(dst, node_type="victim_asset", color="#1F77B4", size=16)
            self.graph.add_edge(src, dst, relation=f"attacks_via_{label}", weight=1.0)

        # Compute PageRank
        if len(self.graph) > 0:
            self.pagerank_scores = nx.pagerank(self.graph, alpha=self.alpha, max_iter=100)
            # Store PR score as node attribute
            for n, score in self.pagerank_scores.items():
                self.graph.nodes[n]["pagerank"] = round(float(score), 6)

    def top_kingpins(self, n: int = 15) -> List[Dict[str, Any]]:
        """Returns the top nodes sorted by PageRank influence."""
        sorted_nodes = sorted(self.pagerank_scores.items(), key=lambda x: -x[1])
        results = []
        for rank, (node_name, score) in enumerate(sorted_nodes[:n], start=1):
            attr = self.graph.nodes.get(node_name, {})
            results.append({
                "rank": rank,
                "node": node_name,
                "type": attr.get("node_type", "unknown"),
                "pagerank": round(score, 6),
                "in_degree": self.graph.in_degree(node_name),
                "out_degree": self.graph.out_degree(node_name)
            })
        return results

    def export_graph_data(self) -> Dict[str, Any]:
        """Exports nodes and links in format ready for Plotly or PyVis network visualization."""
        pos = nx.spring_layout(self.graph, seed=42, k=0.3) if len(self.graph) > 0 else {}
        nodes_data = []
        for n, d in self.graph.nodes(data=True):
            coord = pos.get(n, (0, 0))
            nodes_data.append({
                "id": n,
                "name": n,
                "type": d.get("node_type", "node"),
                "color": d.get("color", "#888888"),
                "pagerank": d.get("pagerank", 0.001),
                "x": float(coord[0]),
                "y": float(coord[1]),
                "size": int(d.get("size", 10) + d.get("pagerank", 0.001) * 300)
            })

        edges_data = []
        for u, v, d in self.graph.edges(data=True):
            edges_data.append({
                "source": u,
                "target": v,
                "relation": d.get("relation", "connected"),
                "weight": d.get("weight", 1.0)
            })

        return {"nodes": nodes_data, "edges": edges_data}


if __name__ == "__main__":
    from ingestion.fetch_feeds import fetch_all_feeds
    from ingestion.load_logs import generate_flow_logs
    df_f = fetch_all_feeds()
    df_l = generate_flow_logs(num_records=500)
    analyzer = ThreatGraphAnalyzer()
    analyzer.build_graph(df_f, df_l)
    print("Total nodes:", analyzer.graph.number_of_nodes())
    print("Total edges:", analyzer.graph.number_of_edges())
    print("\nTop 5 Kingpin Infrastructure Nodes:")
    for kp in analyzer.top_kingpins(5):
        print(f"  #{kp['rank']} {kp['node']} ({kp['type']}) - PR: {kp['pagerank']}")
