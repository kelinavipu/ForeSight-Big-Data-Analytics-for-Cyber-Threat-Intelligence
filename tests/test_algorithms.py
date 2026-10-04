"""
Comprehensive Unit Tests for Big Data and Streaming Algorithms.
Validates correctness, invariant guarantees, and error bounds.
"""

import unittest
import random
import os
import sys

# Ensure root path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from processing.bloom_filter import BloomFilter
from processing.dgim import DGIM, ExactSlidingWindow
from processing.flajolet_martin import FlajoletMartin
from processing.count_min_sketch import CountMinSketch
from processing.reservoir_sampling import ReservoirSampler
from processing.minhash_lsh import MinHashLSH, get_k_shingles, jaccard_similarity
from processing.fpgrowth_rules import AssociationRuleMiner


class TestBigDataAlgorithms(unittest.TestCase):

    def test_bloom_filter_no_false_negatives(self):
        """Invariant: Bloom filter MUST NEVER return False for an added element."""
        bf = BloomFilter(expected_elements=1000, false_positive_rate=0.01)
        added_items = [f"192.168.1.{i}" for i in range(500)]
        for item in added_items:
            bf.add(item)

        # Zero false negatives test
        for item in added_items:
            self.assertTrue(item in bf, f"Bloom filter failed to find added item: {item}")

    def test_bloom_filter_controlled_fpr(self):
        """Verifies empirical false positive rate stays close to target."""
        bf = BloomFilter(expected_elements=2000, false_positive_rate=0.05)
        added = [f"malicious_{i}" for i in range(1000)]
        for x in added:
            bf.add(x)

        clean = [f"clean_{i}" for i in range(2000)]
        false_positives = sum(1 for x in clean if x in bf)
        empirical_fpr = false_positives / len(clean)
        self.assertLess(empirical_fpr, 0.10, f"Empirical FPR too high: {empirical_fpr}")

    def test_dgim_error_bound(self):
        """Invariant: DGIM estimate error must be <= 50% of the true count."""
        window = 500
        dgim = DGIM(window_size=window)
        exact = ExactSlidingWindow(window_size=window)

        random.seed(42)
        stream = [1 if random.random() < 0.35 else 0 for _ in range(2000)]
        for bit in stream:
            dgim.update(bit)
            exact.update(bit)

        est = dgim.count()
        true_cnt = exact.count()
        if true_cnt > 0:
            rel_err = abs(est - true_cnt) / true_cnt
            self.assertLessEqual(rel_err, 0.50, f"DGIM error exceeded theoretical 50% bound: {rel_err*100:.1f}%")

    def test_flajolet_martin_distinct_count(self):
        """Verifies Flajolet-Martin gives a reasonable estimate of distinct elements."""
        fm = FlajoletMartin(num_hashes=32, num_groups=4)
        unique_items = [f"attacker_ip_{i}" for i in range(2000)]
        # Duplicate stream
        stream = unique_items * 3
        random.shuffle(stream)

        fm.update_batch(stream)
        estimate = fm.estimate()
        true_distinct = len(unique_items)

        # FM should be within a factor of 2 for stochastic averaging
        self.assertGreater(estimate, true_distinct * 0.4)
        self.assertLess(estimate, true_distinct * 2.5)

    def test_count_min_sketch_never_underestimates(self):
        """Invariant: Count-Min Sketch count estimate must always be >= true count."""
        cms = CountMinSketch(epsilon=0.005, delta=0.01)
        frequencies = {"port_22": 450, "port_80": 1200, "port_443": 3400, "port_3389": 120}

        for item, count in frequencies.items():
            for _ in range(count):
                cms.add(item)

        for item, true_cnt in frequencies.items():
            est_cnt = cms.query(item)
            self.assertGreaterEqual(est_cnt, true_cnt, f"CMS underestimated frequency for {item}: {est_cnt} < {true_cnt}")

    def test_reservoir_sampling_capacity(self):
        """Verifies reservoir maintains exactly k items when stream length > k."""
        k = 50
        rs = ReservoirSampler(capacity=k, seed=123)
        stream = [f"event_{i}" for i in range(500)]
        rs.feed_batch(stream)

        sample = rs.get_sample()
        self.assertEqual(len(sample), k)
        self.assertEqual(rs.total_seen, 500)

    def test_minhash_lsh_near_duplicates(self):
        """Verifies LSH successfully detects near-duplicate phishing URLs."""
        lsh = MinHashLSH(num_bands=8, rows_per_band=4, shingle_k=3)
        urls = [
            "https://secure-paypal-login-verify.com/auth/login?session=1",
            "https://secure-paypal-login-verify.com/auth/login?session=2",
            "https://completely-different-news-site.org/sports/today"
        ]
        lsh.index_documents(urls)
        matches = lsh.query(urls[0], threshold=0.5)

        matched_urls = [m["matched_document"] for m in matches]
        self.assertIn(urls[0], matched_urls)
        self.assertIn(urls[1], matched_urls)
        self.assertNotIn(urls[2], matched_urls)

    def test_association_rule_metrics(self):
        """Verifies association rules compute valid Support, Confidence, and Lift."""
        transactions = [
            ["port_22", "time_night", "TARGET_Brute Force"],
            ["port_22", "time_night", "TARGET_Brute Force"],
            ["port_22", "time_night", "TARGET_Brute Force"],
            ["port_80", "time_day", "TARGET_BENIGN"],
            ["port_80", "time_day", "TARGET_BENIGN"],
        ]
        miner = AssociationRuleMiner(min_support=0.2, min_confidence=0.5)
        rules = miner.fit(transactions)

        self.assertGreater(len(rules), 0)
        for r in rules:
            self.assertGreaterEqual(r["support"], 0.0)
            self.assertLessEqual(r["support"], 1.0)
            self.assertGreaterEqual(r["confidence"], 0.5)
            self.assertGreater(r["lift"], 0.0)


if __name__ == "__main__":
    unittest.main()
