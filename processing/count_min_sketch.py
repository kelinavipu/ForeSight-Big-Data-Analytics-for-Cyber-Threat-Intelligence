"""
Count-Min Sketch (CMS) for Stream Frequency and Top-Talkers Estimation.
Tracks high-frequency destination ports and attacker IPs in sub-linear space
with provable error bounds: a_hat <= a + epsilon * ||a||_1 with probability >= 1 - delta.
"""

import math
from typing import Dict, List, Tuple, Any
import numpy as np
from processing.hashes import murmur3_32


class CountMinSketch:
    """
    Count-Min Sketch 2D array data structure.
    w: width (controls error epsilon)
    d: depth (controls failure probability delta)
    """
    def __init__(self, epsilon: float = 0.005, delta: float = 0.01):
        self.epsilon = epsilon
        self.delta = delta
        # w = ceil(e / epsilon), d = ceil(ln(1 / delta))
        self.w = int(math.ceil(math.e / epsilon))
        self.d = int(math.ceil(math.log(1.0 / delta)))
        self.table = np.zeros((self.d, self.w), dtype=np.int64)
        self.total_count = 0
        self.heavy_hitters_candidates = set()

    def add(self, item: str, count: int = 1):
        """Adds an item with frequency count into the sketch."""
        item_str = str(item)
        self.total_count += count
        self.heavy_hitters_candidates.add(item_str)
        for i in range(self.d):
            col = murmur3_32(item_str, seed=i, signed=False) % self.w
            self.table[i, col] += count

    def query(self, item: str) -> int:
        """Point query returning estimated frequency (never underestimates)."""
        item_str = str(item)
        min_val = float("inf")
        for i in range(self.d):
            col = murmur3_32(item_str, seed=i, signed=False) % self.w
            min_val = min(min_val, self.table[i, col])
        return int(min_val)

    def top_k(self, k: int = 10) -> List[Tuple[str, int]]:
        """Returns top-k most frequent items among tracked candidates."""
        scored = [(item, self.query(item)) for item in self.heavy_hitters_candidates]
        scored.sort(key=lambda x: -x[1])
        return scored[:k]

    def memory_bytes(self) -> int:
        """Physical array memory usage."""
        return self.table.nbytes

    def benchmark(self, items: List[str], top_n: int = 10) -> Dict[str, Any]:
        """Compares Count-Min Sketch frequency estimations against exact Counter."""
        from collections import Counter
        exact_counts = Counter(items)

        # Reset sketch and populate
        self.table.fill(0)
        self.total_count = 0
        self.heavy_hitters_candidates.clear()

        for it in items:
            self.add(it)

        # Evaluate top N exact items
        top_exact = exact_counts.most_common(top_n)
        cms_eval = []
        for it, true_c in top_exact:
            est_c = self.query(it)
            overest = est_c - true_c
            cms_eval.append({
                "item": str(it),
                "exact_count": true_c,
                "cms_estimate": est_c,
                "overestimation": overest
            })

        cms_mem = self.memory_bytes()
        exact_mem = len(exact_counts) * 72  # approx memory for dict entry

        return {
            "sketch_dimensions": f"{self.d} rows x {self.w} cols",
            "cms_memory_kb": round(cms_mem / 1024, 2),
            "exact_dict_memory_kb": round(exact_mem / 1024, 2),
            "total_items_processed": self.total_count,
            "unique_items": len(exact_counts),
            "top_evaluations": cms_eval
        }


if __name__ == "__main__":
    cms = CountMinSketch(epsilon=0.001, delta=0.01)
    ports = ["443"] * 5000 + ["80"] * 3500 + ["22"] * 1200 + ["8080"] * 600 + ["3389"] * 400
    res = cms.benchmark(ports, top_n=5)
    print("CMS dimensions:", res["sketch_dimensions"])
    for r in res["top_evaluations"]:
        print(f"Port {r['item']}: Exact={r['exact_count']}, CMS={r['cms_estimate']}, Over={r['overestimation']}")
