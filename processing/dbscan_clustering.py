"""
DBSCAN Density-Based Clustering for Cyber Threat Detection.
Discovers arbitrary-shaped attack clusters and detects anomalous outliers / noise.
"""

from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

FEATURE_COLS = [
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Backward_Packets",
    "Flow_Bytes/s",
    "Flow_Packets/s",
    "Packet_Length_Mean",
    "SYN_Flag_Count"
]


class FlowDBSCAN:
    """DBSCAN density clustering with anomaly/noise isolation."""
    def __init__(self, eps: float = 1.2, min_samples: int = 15):
        self.eps = eps
        self.min_samples = min_samples
        self.scaler = StandardScaler()
        self.model = DBSCAN(eps=eps, min_samples=min_samples)

    def fit_predict(self, df: pd.DataFrame, max_rows: int = 5000) -> pd.DataFrame:
        """Runs DBSCAN on sample of network flows."""
        working_df = df.head(max_rows).copy()
        X = working_df[FEATURE_COLS].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)

        labels = self.model.fit_predict(X_scaled)
        working_df["dbscan_cluster"] = labels

        return working_df

    def get_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Summarizes dense clusters vs noise points."""
        labels = df["dbscan_cluster"].values
        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise = int(np.sum(labels == -1))
        noise_pct = round((n_noise / len(labels)) * 100, 2)

        return {
            "num_dense_clusters": n_clusters,
            "noise_outliers_count": n_noise,
            "noise_percentage": noise_pct,
            "total_analyzed": len(labels)
        }
