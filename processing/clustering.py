"""
K-Means Clustering on Network Flow Behavioral Vectors.
Scalable flow clustering, silhouette evaluation, and automated cluster interpretation
mapping behavioral clusters to real-world attack types.
"""

from typing import List, Dict, Tuple, Any
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score

FEATURE_COLS = [
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Backward_Packets",
    "Flow_Bytes/s",
    "Flow_Packets/s",
    "Packet_Length_Mean",
    "SYN_Flag_Count"
]


class NetworkFlowClusterer:
    """K-Means clustering pipeline with automated labeling and silhouette evaluation."""
    def __init__(self, k_range: Tuple[int, int] = (3, 7)):
        self.k_range = k_range
        self.scaler = StandardScaler()
        self.best_k = 5
        self.best_model: KMeans = None
        self.silhouette_scores: Dict[int, float] = {}
        self.cluster_profiles: List[Dict[str, Any]] = []

    def fit_predict(self, df: pd.DataFrame, sample_size: int = 10_000) -> pd.DataFrame:
        """
        Fits optimal K-Means model on flow features and returns enriched DataFrame.
        """
        # Sample if large for silhouette calculation efficiency
        working_df = df.copy()
        if len(working_df) > sample_size:
            eval_df = working_df.sample(n=sample_size, random_state=42)
        else:
            eval_df = working_df

        X_eval = eval_df[FEATURE_COLS].fillna(0).values
        X_eval_scaled = self.scaler.fit_transform(X_eval)

        # Silhouette search for best k
        best_score = -1.0
        for k in range(self.k_range[0], self.k_range[1] + 1):
            km = KMeans(n_clusters=k, random_state=42, n_init=5)
            labels = km.fit_predict(X_eval_scaled)
            # Sample for silhouette if eval set is large
            sub_idx = np.random.choice(len(labels), min(3000, len(labels)), replace=False)
            score = float(silhouette_score(X_eval_scaled[sub_idx], labels[sub_idx]))
            self.silhouette_scores[k] = round(score, 3)
            if score > best_score:
                best_score = score
                self.best_k = k

        # Fit final model on full dataset
        X_full = working_df[FEATURE_COLS].fillna(0).values
        X_full_scaled = self.scaler.transform(X_full)
        self.best_model = KMeans(n_clusters=self.best_k, random_state=42, n_init=10)
        working_df["cluster"] = self.best_model.fit_predict(X_full_scaled)

        # Build human-readable cluster profiles
        self._build_cluster_profiles(working_df)
        return working_df

    def _build_cluster_profiles(self, df: pd.DataFrame):
        """Analyzes cluster distributions against ground truth labels."""
        self.cluster_profiles = []
        for c in range(self.best_k):
            sub = df[df["cluster"] == c]
            if len(sub) == 0:
                continue
            size = len(sub)
            pct_total = round((size / len(df)) * 100, 1)

            # Dominant label & purity
            label_counts = sub["Label"].value_counts()
            top_label = label_counts.index[0]
            top_label_pct = round((label_counts.iloc[0] / size) * 100, 1)

            # Feature averages
            avg_duration = round(sub["Flow_Duration"].mean(), 1)
            avg_pkts = round(sub["Total_Fwd_Packets"].mean() + sub["Total_Backward_Packets"].mean(), 1)
            avg_len = round(sub["Packet_Length_Mean"].mean(), 1)
            syn_rate = round(sub["SYN_Flag_Count"].mean() * 100, 1)

            # Human-friendly interpretation
            if "DDoS" in top_label or (avg_pkts > 100 and syn_rate > 50):
                interp = "High-volume flood: Massive packet rates with short durations (DDoS Signature)"
                risk = "🔴 High Risk"
            elif "PortScan" in top_label or (avg_duration < 100 and syn_rate > 50):
                interp = "Rapid reconnaissance: Probing multiple ports with low packet counts"
                risk = "🟡 Medium Risk"
            elif "Botnet" in top_label or avg_duration > 10000:
                interp = "Persistent communication: Long flow duration indicating C2 beaconing"
                risk = "🔴 High Risk"
            elif "Brute" in top_label or "Patator" in top_label:
                interp = "Credential attack: Repetitive authentication flows against remote access ports"
                risk = "🔴 High Risk"
            else:
                interp = "Standard network exchange: Normal bidirectional packet flows"
                risk = "🟢 Low Risk"

            self.cluster_profiles.append({
                "cluster_id": c,
                "size": size,
                "pct_total": pct_total,
                "dominant_label": top_label,
                "purity_pct": top_label_pct,
                "risk_level": risk,
                "avg_duration_ms": avg_duration,
                "avg_packets": avg_pkts,
                "avg_packet_length": avg_len,
                "syn_flag_pct": syn_rate,
                "interpretation": interp
            })


if __name__ == "__main__":
    from ingestion.load_logs import generate_flow_logs
    df = generate_flow_logs(num_records=2000)
    clusterer = NetworkFlowClusterer(k_range=(3, 6))
    res_df = clusterer.fit_predict(df)
    print("Silhouette scores by k:", clusterer.silhouette_scores)
    print(f"Optimal k: {clusterer.best_k}")
    for prof in clusterer.cluster_profiles:
        print(f"Cluster {prof['cluster_id']}: {prof['dominant_label']} ({prof['purity_pct']}%) - {prof['risk_level']}")
