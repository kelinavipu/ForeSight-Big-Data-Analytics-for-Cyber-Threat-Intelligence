"""
Master Big Data Cyber Threat Intelligence Pipeline Engine.
Coordinates data ingestion (Bronze), schema normalization & Parquet persistence (Silver),
execution of all 13 Big Data / ML algorithms, and analytical aggregation (Gold).
"""

import os
import json
import logging
import time
from typing import Dict, Any
import pandas as pd
import numpy as np

from ingestion.fetch_feeds import fetch_all_feeds
from ingestion.load_logs import generate_flow_logs
from processing.bloom_filter import BloomFilter
from processing.dgim import DGIM, ExactSlidingWindow
from processing.flajolet_martin import FlajoletMartin
from processing.count_min_sketch import CountMinSketch
from processing.reservoir_sampling import ReservoirSampler
from processing.minhash_lsh import MinHashLSH
from processing.clustering import NetworkFlowClusterer
from processing.dbscan_clustering import FlowDBSCAN
from processing.fpgrowth_rules import AssociationRuleMiner, discretize_flow_to_tags
from processing.pagerank_graph import ThreatGraphAnalyzer
from processing.anomaly import AnomalyDetector
from processing.dim_reduction import DimensionReducer
from processing.benchmarks import run_all_benchmarks

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PipelineEngine")


class PipelineEngine:
    def __init__(
        self,
        raw_dir: str = "data/raw",
        clean_dir: str = "data/clean",
        gold_dir: str = "data/gold"
    ):
        self.raw_dir = raw_dir
        self.clean_dir = clean_dir
        self.gold_dir = gold_dir
        for d in [raw_dir, clean_dir, gold_dir]:
            os.makedirs(d, exist_ok=True)

    def run_full_pipeline(self, num_logs: int = 25_000) -> Dict[str, Any]:
        """Executes Bronze -> Silver -> ML/Algorithms -> Gold analytics."""
        t_start = time.perf_counter()
        logger.info("=== STEP 1: INGESTION (BRONZE LAYER) ===")
        
        # 1. Ingest Threat Intelligence Feeds
        df_feeds = fetch_all_feeds(raw_dir=self.raw_dir)
        feed_ips = df_feeds[df_feeds["ioc_type"].isin(["ip", "ip:port"])]["ip_address"].dropna().unique().tolist()
        feed_urls = df_feeds[df_feeds["ioc_type"] == "url"]["ioc_value"].dropna().unique().tolist()
        logger.info(f"Loaded {len(df_feeds):,} IOCs ({len(feed_ips):,} IPs, {len(feed_urls):,} URLs).")

        # 2. Ingest / Generate Network Flow Logs (CIC-IDS2017)
        csv_path = os.path.join(self.raw_dir, "cicids2017_flows.csv")
        df_logs = generate_flow_logs(
            num_records=num_logs,
            seed_threat_ips=feed_ips[:200],
            output_path=csv_path
        )

        logger.info("=== STEP 2: PARQUET STORAGE & CLEANING (SILVER LAYER) ===")
        # Save normalized clean datasets to Parquet
        silver_logs_path = os.path.join(self.clean_dir, "logs.parquet")
        silver_feeds_path = os.path.join(self.clean_dir, "threat_iocs.parquet")
        
        df_logs.to_parquet(silver_logs_path, index=False, engine="pyarrow", compression="snappy")
        df_feeds.to_parquet(silver_feeds_path, index=False, engine="pyarrow", compression="snappy")
        logger.info(f"Silver Parquet written: logs ({os.path.getsize(silver_logs_path)/1024:.1f} KB)")

        logger.info("=== STEP 3: BIG DATA & STREAMING ALGORITHMS ===")

        # 3.1 Bloom Filter: Index known-bad IOCs
        logger.info("Running Algorithm 1: Bloom Filter...")
        bf = BloomFilter(expected_elements=max(1000, len(feed_ips)), false_positive_rate=0.01)
        for ip in feed_ips:
            bf.add(ip)
        clean_ips_sample = [f"10.0.{i//256}.{i%256}" for i in range(5000)]
        bf_stats = bf.benchmark_comparison(clean_ips_sample)

        # Cross-reference: find log IPs matching threat feeds (Headline Join result!)
        matched_threat_logs = df_logs[df_logs["Src_IP"].apply(lambda ip: ip in bf)]
        headline_match_count = len(matched_threat_logs)
        logger.info(f"Bloom Filter Headline: {headline_match_count:,} log events matched known criminal C2 servers!")

        # 3.2 DGIM: Sliding window bit counter
        logger.info("Running Algorithm 2: DGIM Sliding Window...")
        dgim = DGIM(window_size=2000)
        attack_stream = df_logs["is_attack"].tolist()
        for bit in attack_stream:
            dgim.update(bit)
        dgim_est = dgim.count()

        # 3.3 Flajolet-Martin: Unique attacker IPs
        logger.info("Running Algorithm 3: Flajolet-Martin Distinct Count...")
        attacker_ips = df_logs[df_logs["is_attack"] == 1]["Src_IP"].tolist()
        fm = FlajoletMartin(num_hashes=32, num_groups=4)
        fm.update_batch(attacker_ips)
        fm_est = fm.estimate()
        true_unique_attackers = len(set(attacker_ips))

        # 3.4 Count-Min Sketch: Frequency estimation & Top Ports
        logger.info("Running Algorithm 4: Count-Min Sketch...")
        cms = CountMinSketch(epsilon=0.002, delta=0.01)
        ports_stream = df_logs[df_logs["is_attack"] == 1]["Dst_Port"].astype(str).tolist()
        for p in ports_stream:
            cms.add(p)
        top_ports_cms = cms.top_k(10)

        # 3.5 Reservoir Sampling: Live sample pool
        logger.info("Running Algorithm 5: Reservoir Sampling...")
        reservoir = ReservoirSampler(capacity=200)
        reservoir.feed_batch(df_logs.to_dict(orient="records"))
        live_sample = reservoir.get_sample()

        # 3.6 MinHash + LSH: Phishing campaign near-duplicate grouping
        logger.info("Running Algorithm 6: MinHash & LSH Near-Duplicate Detection...")
        lsh = MinHashLSH(num_bands=12, rows_per_band=4, shingle_k=3)
        lsh.index_documents(feed_urls)
        phishing_clusters = lsh.find_all_clusters(threshold=0.55)

        # 3.7 K-Means Clustering: Network flow behaviors
        logger.info("Running Algorithm 7: K-Means Clustering on Flows...")
        clusterer = NetworkFlowClusterer(k_range=(3, 6))
        clustered_df = clusterer.fit_predict(df_logs)

        # 3.8 DBSCAN: Density clustering & Outlier noise
        logger.info("Running Algorithm 8: DBSCAN Outlier Detection...")
        dbscan = FlowDBSCAN(eps=1.2, min_samples=15)
        dbscan_df = dbscan.fit_predict(clustered_df, max_rows=5000)
        dbscan_summary = dbscan.get_summary(dbscan_df)

        # 3.9 FP-Growth Association Rules
        logger.info("Running Algorithm 9: FP-Growth Association Rules...")
        transactions = [discretize_flow_to_tags(row) for _, row in df_logs.head(10000).iterrows()]
        miner = AssociationRuleMiner(min_support=0.015, min_confidence=0.5)
        association_rules = miner.fit(transactions)

        # 3.10 PageRank on Threat Graph
        logger.info("Running Algorithm 10: PageRank Centrality on Threat Infrastructure Graph...")
        graph_analyzer = ThreatGraphAnalyzer(damping_factor=0.85)
        graph_analyzer.build_graph(df_feeds, df_logs, max_edges=600)
        kingpins = graph_analyzer.top_kingpins(15)
        graph_data = graph_analyzer.export_graph_data()

        # 3.11 Isolation Forest: Zero-day Anomaly Detection
        logger.info("Running Algorithm 11: Isolation Forest Anomaly Detection...")
        anom_detector = AnomalyDetector(contamination=0.05)
        anom_df = anom_detector.fit_predict(clustered_df.head(5000))
        anom_metrics = anom_detector.get_metrics(anom_df)

        # 3.12 PCA 2D Dimensionality Reduction
        logger.info("Running Algorithm 12: PCA 2D Projection...")
        dim_reducer = DimensionReducer(n_components=2)
        pca_df = dim_reducer.fit_transform(clustered_df, max_rows=4000)
        pca_info = dim_reducer.get_variance_info()

        # 3.13 Algorithm Benchmarks
        logger.info("Running Algorithm 13: Empirical Algorithm Benchmarks...")
        benchmarks_data = run_all_benchmarks(
            feed_ips=feed_ips,
            log_ips=attacker_ips,
            log_ports=df_logs["Dst_Port"].tolist(),
            attack_stream=attack_stream,
            csv_path=csv_path,
            parquet_path=silver_logs_path
        )

        logger.info("=== STEP 4: GOLD AGGREGATIONS & ARTIFACTS PERSISTENCE ===")
        # 4.1 Attacks by type
        attacks_by_type = (
            df_logs.groupby("Label")
            .agg(
                count=("Label", "count"),
                avg_duration=("Flow_Duration", "mean"),
                avg_bytes_s=("Flow_Bytes/s", "mean"),
                avg_packet_len=("Packet_Length_Mean", "mean")
            )
            .reset_index()
            .sort_values(by="count", ascending=False)
        )
        attacks_by_type.to_parquet(os.path.join(self.gold_dir, "attacks_by_type.parquet"), index=False)

        # 4.2 Top Attacked Ports
        top_ports = (
            df_logs[df_logs["is_attack"] == 1]
            .groupby("Dst_Port")
            .size()
            .reset_index(name="count")
            .sort_values(by="count", ascending=False)
            .head(20)
        )
        top_ports.to_parquet(os.path.join(self.gold_dir, "top_attacked_ports.parquet"), index=False)

        # 4.3 Hourly & Day of Week Attack Heatmap
        hourly_heatmap = (
            df_logs[df_logs["is_attack"] == 1]
            .groupby(["DayOfWeek", "Hour"])
            .size()
            .reset_index(name="attack_count")
        )
        hourly_heatmap.to_parquet(os.path.join(self.gold_dir, "hourly_attack_heatmap.parquet"), index=False)

        # 4.4 Geo Threat Map coordinates
        geo_threats = (
            df_logs[df_logs["is_attack"] == 1]
            .groupby(["Country", "Country_Code", "Latitude", "Longitude", "Label"])
            .size()
            .reset_index(name="attack_count")
        )
        geo_threats.to_parquet(os.path.join(self.gold_dir, "geo_threat_map.parquet"), index=False)

        # 4.5 2D PCA Cluster visualization points
        pca_export_cols = ["pca_1", "pca_2", "cluster", "Label", "is_attack", "Dst_Port", "Flow_Duration"]
        pca_df[pca_export_cols].to_parquet(os.path.join(self.gold_dir, "pca_clusters.parquet"), index=False)

        # 4.6 Save JSON metadata artifacts
        gold_metadata = {
            "execution_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_flow_logs": len(df_logs),
            "total_attack_logs": int(df_logs["is_attack"].sum()),
            "threat_iocs_tracked": len(df_feeds),
            "threat_ips_indexed": len(feed_ips),
            "headline_feed_matches": headline_match_count,
            "flajolet_martin_estimate": fm_est,
            "flajolet_martin_exact": true_unique_attackers,
            "dgim_sliding_window_count": dgim_est,
            "optimal_kmeans_k": clusterer.best_k,
            "silhouette_scores": clusterer.silhouette_scores,
            "cluster_profiles": clusterer.cluster_profiles,
            "dbscan_summary": dbscan_summary,
            "top_kingpin_nodes": kingpins,
            "graph_visualization": graph_data,
            "association_rules": association_rules[:15],
            "phishing_campaign_clusters": phishing_clusters[:10],
            "anomaly_detection_metrics": anom_metrics,
            "pca_variance": pca_info,
            "benchmarks": benchmarks_data
        }

        with open(os.path.join(self.gold_dir, "gold_summary.json"), "w", encoding="utf-8") as f:
            json.dump(gold_metadata, f, indent=2)

        elapsed = time.perf_counter() - t_start
        logger.info(f"✅ Pipeline executed successfully in {elapsed:.2f} seconds!")
        return gold_metadata


if __name__ == "__main__":
    engine = PipelineEngine()
    summary = engine.run_full_pipeline(num_logs=20000)
    print("\n--- Pipeline Summary ---")
    print(f"Total Logs: {summary['total_flow_logs']:,}")
    print(f"Headline Feed Matches: {summary['headline_feed_matches']:,}")
    print(f"FM Attacker Estimate: {summary['flajolet_martin_estimate']:,} (True: {summary['flajolet_martin_exact']:,})")
    print(f"DGIM Sliding Window Count: {summary['dgim_sliding_window_count']:,}")
