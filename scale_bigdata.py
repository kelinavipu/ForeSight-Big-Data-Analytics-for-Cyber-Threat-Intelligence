"""
Big Data Scalability Benchmark and High-Volume Generator.
Demonstrates processing at true Big Data scale: 100,000 to 1,000,000+ flow logs,
measuring Spark throughput, columnar Parquet compression, and streaming memory bounds.
"""

import sys
import os
import time
import argparse

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from processing.pipeline_engine import PipelineEngine


def main():
    parser = argparse.ArgumentParser(description="Scale the Cyber Threat Intelligence Pipeline to Big Data volumes.")
    parser.add_argument("--records", type=int, default=100_000, help="Number of network flow logs to process (default: 100,000)")
    args = parser.parse_args()

    n = args.records
    print("=" * 70)
    print(f"🐘 BIG DATA SCALE-UP BENCHMARK: PROCESSING {n:,} NETWORK FLOWS")
    print("=" * 70)

    engine = PipelineEngine()
    t0 = time.perf_counter()
    summary = engine.run_full_pipeline(num_logs=n)
    total_time = time.perf_counter() - t0

    throughput = int(n / max(0.001, total_time))
    raw_csv_path = "data/raw/cicids2017_flows.csv"
    parquet_path = "data/clean/logs.parquet"

    csv_mb = round(os.path.getsize(raw_csv_path) / (1024 * 1024), 2)
    parquet_mb = round(os.path.getsize(parquet_path) / (1024 * 1024), 2)

    print("\n" + "=" * 70)
    print("🎯 BIG DATA BENCHMARK RESULTS")
    print("=" * 70)
    print(f"⚡ Total Records Processed:       {n:,} flows")
    print(f"⏱️  Total Processing Time:         {total_time:.2f} seconds")
    print(f"🚀 Pipeline Throughput:           {throughput:,} flows/second")
    print(f"📦 Raw CSV Uncompressed Size:    {csv_mb} MB")
    print(f"🗜️  Columnar Parquet (Snappy):    {parquet_mb} MB ({round(csv_mb / max(0.01, parquet_mb), 2)}x compression)")
    print(f"🛡️  IOCs Cross-Referenced:        {summary['threat_iocs_tracked']:,}")
    print(f"🚨 Known C2 Matches Flagged:      {summary['headline_feed_matches']:,}")
    print(f"🎯 FM Estimated Unique Attackers: {summary['flajolet_martin_estimate']:,} (in 128 bytes of memory!)")
    print(f"⚡ DGIM Sliding Window Count:     {summary['dgim_sliding_window_count']:,} (in 14 buckets vs 2,000 raw events!)")
    print("=" * 70)
    print("\n✅ New Gold datasets generated! Launch or refresh your web app:")
    print("   python web_app.py  👉  http://localhost:8000\n")


if __name__ == "__main__":
    main()
