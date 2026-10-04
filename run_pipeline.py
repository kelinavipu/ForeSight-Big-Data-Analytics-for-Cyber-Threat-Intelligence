"""
One-Command Execution Script for Cyber Threat Intelligence Analytics.
Runs Bronze -> Silver -> ML / Streaming Algorithms -> Gold Analytics.
"""

import sys
import os
import time

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from processing.pipeline_engine import PipelineEngine


def main():
    print("=" * 70)
    print("🛡️  STARTING BIG DATA CYBER THREAT INTELLIGENCE ANALYTICS PIPELINE")
    print("=" * 70)

    engine = PipelineEngine()
    summary = engine.run_full_pipeline(num_logs=25_000)

    print("\n" + "=" * 70)
    print("✅  PIPELINE EXECUTION COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    print(f"📊 Total Flow Logs Processed:       {summary['total_flow_logs']:,}")
    print(f"🛡️  Threat Feeds Tracked:            {summary['threat_iocs_tracked']:,}")
    print(f"🚨 Headline Feed Matches:           {summary['headline_feed_matches']:,}")
    print(f"🎯 Unique Attackers (FM Estimate):  {summary['flajolet_martin_estimate']:,} (True: {summary['flajolet_martin_exact']:,})")
    print(f"⚡ DGIM Sliding Window Count:       {summary['dgim_sliding_window_count']:,} attacks in last 2,000 events")
    print(f"🧩 Optimal K-Means Clusters:        k = {summary['optimal_kmeans_k']}")
    print(f"👑 Top Kingpin C2 Server:           {summary['top_kingpin_nodes'][0]['node']} (PR: {summary['top_kingpin_nodes'][0]['pagerank']})")
    print("\n🚀 TO LAUNCH THE INTERACTIVE WEB DASHBOARD (HTML/CSS):")
    print("   python web_app.py  👉  http://localhost:8000")
    print("   (Optional Streamlit: streamlit run dashboard/app.py)\n")
    print("📁 Parquet datasets stored in:")
    print("   - Silver Layer: data/clean/logs.parquet")
    print("   - Gold Layer:   data/gold/*.parquet")
    print("=" * 70)


if __name__ == "__main__":
    main()
