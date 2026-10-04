"""
Bloom Filter Implementation for Cyber Threat Intelligence.
Provides O(1) set membership testing for millions of malicious IOCs (IPs, URLs, hashes)
with zero false negatives and mathematically controlled false positive rates.
"""

import math
import sys
import time
from typing import List, Tuple, Dict, Any, Union
from processing.hashes import murmur3_32, create_bitarray


class BloomFilter:
    """
    Space-efficient probabilistic data structure for IOC lookup.
    m: number of bits in array
    k: number of hash functions
    """
    def __init__(self, expected_elements: int = 100_000, false_positive_rate: float = 0.01):
        if expected_elements <= 0:
            expected_elements = 1000
        if not (0 < false_positive_rate < 1):
            false_positive_rate = 0.01

        self.expected_elements = expected_elements
        self.target_fpr = false_positive_rate

        # Optimal m = - (n * ln(p)) / (ln(2)^2)
        self.size = int(- (expected_elements * math.log(false_positive_rate)) / (math.log(2) ** 2))
        self.size = max(64, self.size)

        # Optimal k = (m / n) * ln(2)
        self.num_hashes = int((self.size / expected_elements) * math.log(2))
        self.num_hashes = max(1, self.num_hashes)

        self.bits = create_bitarray(self.size)
        self.count = 0

    def add(self, item: str):
        """Adds an IOC string (IP, URL, Hash) into the Bloom filter."""
        item_str = str(item).strip()
        for seed in range(self.num_hashes):
            idx = murmur3_32(item_str, seed, signed=False) % self.size
            self.bits[idx] = 1
        self.count += 1

    def __contains__(self, item: str) -> bool:
        """O(1) query returning True if item might be in set, False if definitely not."""
        item_str = str(item).strip()
        for seed in range(self.num_hashes):
            idx = murmur3_32(item_str, seed, signed=False) % self.size
            if not self.bits[idx]:
                return False
        return True

    def current_theoretical_fpr(self) -> float:
        """Calculates theoretical FPR based on current number of elements added."""
        if self.count == 0:
            return 0.0
        # (1 - e^(-k * n / m))^k
        exponent = - (self.num_hashes * self.count) / float(self.size)
        return (1.0 - math.exp(exponent)) ** self.num_hashes

    def memory_bytes(self) -> int:
        """Returns physical bitarray memory usage in bytes."""
        return (self.size + 7) // 8

    def benchmark_comparison(
        self,
        clean_test_items: List[str]
    ) -> Dict[str, Any]:
        """
        Benchmarks lookup speed, memory usage, and measured false positive rate
        against Python set.
        """
        # Test lookups on clean items to measure false positive rate
        t0 = time.perf_counter()
        false_positives = sum(1 for item in clean_test_items if item in self)
        lookup_time = time.perf_counter() - t0

        measured_fpr = false_positives / max(1, len(clean_test_items))
        avg_lookup_us = (lookup_time / max(1, len(clean_test_items))) * 1_000_000

        return {
            "bloom_size_bits": self.size,
            "bloom_memory_kb": round(self.memory_bytes() / 1024, 2),
            "num_hashes": self.num_hashes,
            "items_indexed": self.count,
            "theoretical_fpr": round(self.current_theoretical_fpr(), 4),
            "measured_fpr": round(measured_fpr, 4),
            "clean_items_tested": len(clean_test_items),
            "false_positives_detected": false_positives,
            "avg_lookup_microseconds": round(avg_lookup_us, 3)
        }


if __name__ == "__main__":
    bf = BloomFilter(expected_elements=10000, false_positive_rate=0.01)
    malicious = [f"194.26.29.{i}" for i in range(1, 5000)]
    clean = [f"10.0.0.{i}" for i in range(1, 5000)]

    for ip in malicious:
        bf.add(ip)

    print("Bloom Filter initialised.")
    print(f"Memory: {bf.memory_bytes() / 1024:.2f} KB")
    print(f"Malicious IP in BF? {'194.26.29.10' in bf}")
    print(f"Clean IP in BF? {'10.0.0.10' in bf}")
    stats = bf.benchmark_comparison(clean)
    print("Benchmark stats:", stats)
