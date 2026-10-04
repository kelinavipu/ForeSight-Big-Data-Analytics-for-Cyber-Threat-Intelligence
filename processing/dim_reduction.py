"""
Dimensionality Reduction (PCA & t-SNE) for Cluster Visualizations.
Projects multi-dimensional flow metrics into 2D coordinates for intuitive interactive scatter plots.
"""

from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
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


class DimensionReducer:
    """Computes 2D PCA projection for network flows."""
    def __init__(self, n_components: int = 2):
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=n_components, random_state=42)
        self.explained_variance: Tuple[float, float] = (0.0, 0.0)

    def fit_transform(self, df: pd.DataFrame, max_rows: int = 4000) -> pd.DataFrame:
        """Projects sample of DataFrame to 2D coordinates pca_1, pca_2."""
        sample_df = df.head(max_rows).copy()
        X = sample_df[FEATURE_COLS].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)

        coords = self.pca.fit_transform(X_scaled)
        sample_df["pca_1"] = [round(float(c[0]), 3) for c in coords]
        sample_df["pca_2"] = [round(float(c[1]), 3) for c in coords]

        self.explained_variance = (
            round(float(self.pca.explained_variance_ratio_[0]) * 100, 1),
            round(float(self.pca.explained_variance_ratio_[1]) * 100, 1)
        )

        return sample_df

    def get_variance_info(self) -> Dict[str, Any]:
        """Returns explained variance details."""
        return {
            "pc1_variance_pct": self.explained_variance[0],
            "pc2_variance_pct": self.explained_variance[1],
            "total_explained_variance_pct": round(sum(self.explained_variance), 1)
        }
