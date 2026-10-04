"""
Big Data Algorithms Benchmarking Suite.
Runs rigorous comparative experiments to measure efficiency, memory savings,
latency, and error bounds for all streaming and big data algorithms.
"""

import sys
import time
import os
from typing import Dict, List, Any
import numpy as np
import pandas as pd

from processing.bloom_filter import BloomFilter
from processing.dgim import DGIM, ExactSlidingWindow
from processing.flajolet_martin import FlajoletMartin
from processing.count_min_sketch import CountMinSketch


def run_all_benchmarks(
    feed_ips: List[str],
    log_ips: List[str],
    log_ports: List[int],
    attack_stream: List[int],
    csv_path: str = "data/raw/cicids2017_flows.csv",
    parquet_path: str = "data/clean/logs.parquet"
) -> Dict[str, Any]:
    """Runs end-to-end benchmark experiments across all algorithms."""
    results = {}

    # 1. Bloom Filter vs Python Set
    clean_sample = [f"10.240.{i // 256}.{i % 256}" for i in range(10_000)]
    bf = BloomFilter(expected_elements=max(1000, len(feed_ips)), false_positive_rate=0.01)
    for ip in feed_ips:
        bf.add(ip)

    py_set = set(feed_ips)

    # Benchmark Set lookup
    t0 = time.perf_counter()
    _ = [ip in py_set for ip in clean_sample]
    set_lookup_time = (time.perf_counter() - t0) / len(clean_sample) * 1_000_000

    bf_stats = bf.benchmark_comparison(clean_sample)
    set_mem_kb = round(sys.getsizeof(py_set) / 1024, 2)

    results["bloom_filter"] = {
        "items_indexed": len(feed_ips),
        "bloom_memory_kb": bf_stats["bloom_memory_kb"],
        "set_memory_kb": set_mem_kb,
        "memory_reduction_pct": round((1 - bf_stats["bloom_memory_kb"] / max(0.1, set_mem_kb)) * 100, 1),
        "bloom_lookup_us": bf_stats["avg_lookup_microseconds"],
        "set_lookup_us": round(set_lookup_time, 3),
        "theoretical_fpr": bf_stats["theoretical_fpr"],
        "measured_fpr": bf_stats["measured_fpr"]
    }

    # 2. Flajolet-Martin vs Exact Distinct Count
    fm = FlajoletMartin(num_hashes=32, num_groups=4)
    fm_res = fm.benchmark(log_ips)
    results["flajolet_martin"] = fm_res

    # 3. DGIM vs Exact Sliding Window
    window_size = 2000
    dgim = DGIM(window_size=window_size)
    exact_win = ExactSlidingWindow(window_size=window_size)

    for bit in attack_stream:
        dgim.update(bit)
        exact_win.update(bit)

    dgim_est = dgim.count()
    exact_cnt = exact_win.count()
    dgim_err = abs(dgim_est - exact_cnt) / max(1, exact_cnt) * 100

    results["dgim"] = {
        "window_size": window_size,
        "stream_length": len(attack_stream),
        "dgim_estimate": dgim_est,
        "exact_count": exact_cnt,
        "relative_error_pct": round(dgim_err, 2),
        "buckets_stored": len(dgim.buckets),
        "raw_bits_stored": window_size,
        "storage_reduction_pct": round((1 - (len(dgim.buckets) * 8) / (window_size * 1)) * 100, 1)
    }

    # 4. Count-Min Sketch vs Exact Hash Counter
    cms = CountMinSketch(epsilon=0.002, delta=0.01)
    cms_res = cms.benchmark([str(p) for p in log_ports], top_n=5)
    results["count_min_sketch"] = cms_res

    # 5. Parquet vs CSV Storage & Latency
    if os.path.exists(csv_path) and os.path.exists(parquet_path):
        csv_size_mb = round(os.path.getsize(csv_path) / (1024 * 1024), 2)
        # Parquet might be directory or single file
        if os.path.isdir(parquet_path):
            p_size = sum(os.path.getsize(os.path.join(parquet_path, f)) for f in os.listdir(parquet_path) if f.endswith(".parquet"))
        else:
            p_size = os.path.getsize(parquet_path)
        parquet_size_mb = round(p_size / (1024 * 1024), 2)

        # Query read latency
        t0 = time.perf_counter()
        _ = pd.read_csv(csv_path, usecols=["Label", "Flow_Duration"])
        csv_read_sec = round(time.perf_counter() - t0, 3)

        t0 = time.perf_counter()
        _ = pd.read_parquet(parquet_path, columns=["Label", "Flow_Duration"])
        parquet_read_sec = round(time.perf_counter() - t0, 3)

        results["storage_benchmark"] = {
            "csv_size_mb": csv_size_mb,
            "parquet_size_mb": parquet_size_mb,
            "compression_ratio": round(csv_size_mb / max(0.01, parquet_size_mb), 2),
            "csv_read_sec": csv_read_sec,
            "parquet_read_sec": parquet_read_sec,
            "speedup_factor": round(csv_read_sec / max(0.001, parquet_read_sec), 2)
        }

    return results
