"""
Unsupervised Anomaly Detection using Isolation Forest.
Flags anomalous network traffic flows and zero-day threat patterns without prior labels.
"""

from typing import Dict, Any, Tuple
import pandas as pd
from sklearn.ensemble import IsolationForest
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


class AnomalyDetector:
    """Isolation Forest anomaly detection on network flow features."""
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            n_jobs=-1
        )

    def fit_predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Trains Isolation Forest and attaches anomaly labels and decision scores."""
        working_df = df.copy()
        X = working_df[FEATURE_COLS].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)

        # -1 = anomaly, 1 = normal
        raw_preds = self.model.fit_predict(X_scaled)
        scores = self.model.decision_function(X_scaled)

        working_df["anomaly_label"] = ["Anomaly" if p == -1 else "Normal" for p in raw_preds]
        working_df["anomaly_score"] = [round(float(s), 4) for s in scores]
        working_df["is_anomaly"] = [1 if p == -1 else 0 for p in raw_preds]

        return working_df

    def get_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Summarizes anomaly detection statistics."""
        n_total = len(df)
        n_anom = int(df["is_anomaly"].sum())
        anom_pct = round((n_anom / max(1, n_total)) * 100, 2)

        # Cross-reference with true labels
        attack_in_anom = df[df["is_anomaly"] == 1]["is_attack"].sum()
        detection_purity = round((attack_in_anom / max(1, n_anom)) * 100, 1)

        return {
            "total_analyzed": n_total,
            "anomalies_flagged": n_anom,
            "anomaly_rate_pct": anom_pct,
            "attacks_caught_in_anomalies": int(attack_in_anom),
            "unsupervised_purity_pct": detection_purity
        }
