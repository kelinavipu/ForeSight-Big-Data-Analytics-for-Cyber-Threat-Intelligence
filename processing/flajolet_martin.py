"""
Flajolet-Martin (FM) Algorithm for Distinct Count Estimation.
Estimates the cardinality of unique attacker IP addresses in continuous streams
using O(1) constant memory with stochastic averaging (median-of-means).
"""

import math
from typing import List, Dict, Any, Iterable
from processing.hashes import murmur3_32


def trailing_zeros(x: int) -> int:
    """Computes the number of trailing zero bits in binary representation of x."""
    if x == 0:
        return 32
    return (x & -x).bit_length() - 1


class FlajoletMartin:
    """
    Flajolet-Martin distinct estimator using multiple hash functions
    and median-of-means grouping.
    """
    # Flajolet-Martin correction constant phi approx 0.77351
    PHI = 0.77351

    def __init__(self, num_hashes: int = 32, num_groups: int = 4):
        self.num_hashes = num_hashes
        self.num_groups = max(1, min(num_groups, num_hashes))
        self.hashes_per_group = self.num_hashes // self.num_groups
        self.max_trailing_zeros = [0] * self.num_hashes

    def update(self, item: str):
        """Processes an incoming stream item (e.g. IP address)."""
        item_str = str(item)
        for i in range(self.num_hashes):
            h = murmur3_32(item_str, seed=i, signed=False)
            r = trailing_zeros(h)
            if r > self.max_trailing_zeros[i]:
                self.max_trailing_zeros[i] = r

    def update_batch(self, items: Iterable[str]):
        """Processes a batch of items."""
        for it in items:
            self.update(it)

    def estimate(self) -> int:
        """
        Calculates cardinality estimate using median-of-means:
        1. For each group, compute arithmetic mean of (2^R / PHI).
        2. Take median across all groups.
        """
        group_means = []
        for g in range(self.num_groups):
            start = g * self.hashes_per_group
            end = start + self.hashes_per_group
            group_vals = [ (2 ** self.max_trailing_zeros[i]) / self.PHI for i in range(start, end) ]
            group_mean = sum(group_vals) / len(group_vals)
            group_means.append(group_mean)

        group_means.sort()
        mid = len(group_means) // 2
        if len(group_means) % 2 == 1:
            median_est = group_means[mid]
        else:
            median_est = (group_means[mid - 1] + group_means[mid]) / 2.0

        return int(round(median_est))

    def benchmark(self, items: List[str]) -> Dict[str, Any]:
        """Compares FM estimate against exact set cardinality."""
        self.max_trailing_zeros = [0] * self.num_hashes
        self.update_batch(items)

        fm_est = self.estimate()
        exact_cnt = len(set(items))
        rel_error = abs(fm_est - exact_cnt) / max(1, exact_cnt) * 100

        # Memory calculation: FM stores num_hashes integers (bytes) vs hash table for set
        fm_bytes = self.num_hashes * 4
        set_bytes = len(set(items)) * 64  # approx 64 bytes per string in set

        return {
            "fm_estimate": fm_est,
            "exact_distinct_count": exact_cnt,
            "relative_error_pct": round(rel_error, 2),
            "fm_memory_bytes": fm_bytes,
            "exact_set_memory_bytes": set_bytes,
            "memory_reduction_pct": round((1 - fm_bytes / max(1, set_bytes)) * 100, 2)
        }


if __name__ == "__main__":
    import random
    unique_pool = [f"185.220.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(5000)]
    stream = [random.choice(unique_pool) for _ in range(25000)]

    fm = FlajoletMartin(num_hashes=32, num_groups=4)
    res = fm.benchmark(stream)
    print("Flajolet-Martin Benchmark:", res)
