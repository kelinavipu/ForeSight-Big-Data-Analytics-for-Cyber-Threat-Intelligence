"""
DGIM Algorithm (Datar-Gionis-Indyk-Motwani) for Sliding Window Stream Counting.
Tracks attack frequencies in the last N events with O(log^2 N) memory
and a guaranteed theoretical error bound <= 50%.
"""

from collections import deque
from typing import List, Tuple, Dict, Any


class DGIM:
    """
    DGIM sliding window bit counter.
    Buckets contain (timestamp, size).
    At most two buckets of any given size.
    """
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.t = 0
        self.buckets: List[Tuple[int, int]] = []  # List of (timestamp, size), ordered newest to oldest

    def update(self, bit: int):
        """Processes a new incoming stream bit (1 = Attack, 0 = Benign)."""
        self.t += 1
        bit = 1 if bit else 0

        # 1. Expire buckets older than window
        cutoff = self.t - self.window_size
        while self.buckets and self.buckets[-1][0] <= cutoff:
            self.buckets.pop()

        if bit == 0:
            return

        # 2. Add new bucket of size 1 at the beginning (newest)
        self.buckets.insert(0, (self.t, 1))

        # 3. Enforce invariant: at most 2 buckets of each size
        idx = 0
        while idx < len(self.buckets) - 2:
            size = self.buckets[idx][1]
            # Check if there are 3 consecutive buckets of the same size
            if self.buckets[idx + 1][1] == size and self.buckets[idx + 2][1] == size:
                # Merge the oldest two of the three
                t2, s2 = self.buckets[idx + 1]
                t3, s3 = self.buckets[idx + 2]
                merged = (t3, size * 2)
                # Remove idx+1 and idx+2, insert merged
                self.buckets.pop(idx + 2)
                self.buckets.pop(idx + 1)
                self.buckets.insert(idx + 1, merged)
                # Move to inspect next sizes
                idx += 1
            else:
                idx += 1

    def count(self, k: int = None) -> int:
        """
        Estimates the number of 1s in the last k events (default k = window_size).
        Returns sum of all buckets entirely within window + 0.5 * oldest bucket.
        """
        if not self.buckets:
            return 0

        target_k = k if k is not None else self.window_size
        cutoff = self.t - target_k

        total = 0
        for i, (ts, size) in enumerate(self.buckets):
            if ts <= cutoff:
                # Oldest bucket that overlaps window boundary
                total += size // 2
                break
            if i == len(self.buckets) - 1:
                # The very oldest bucket in the store
                total += size // 2
            else:
                total += size

        return total

    def bucket_distribution(self) -> Dict[int, int]:
        """Returns distribution of bucket sizes currently stored."""
        dist = {}
        for _, size in self.buckets:
            dist[size] = dist.get(size, 0) + 1
        return dist


class ExactSlidingWindow:
    """Exact ground-truth baseline for benchmarking DGIM."""
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.queue = deque()

    def update(self, bit: int):
        self.queue.append(1 if bit else 0)
        if len(self.queue) > self.window_size:
            self.queue.popleft()

    def count(self) -> int:
        return sum(self.queue)


if __name__ == "__main__":
    import random
    window = 1000
    dgim = DGIM(window_size=window)
    exact = ExactSlidingWindow(window_size=window)

    stream = [1 if random.random() < 0.3 else 0 for _ in range(5000)]
    for bit in stream:
        dgim.update(bit)
        exact.update(bit)

    est = dgim.count()
    true_cnt = exact.count()
    err = abs(est - true_cnt) / max(1, true_cnt) * 100

    print(f"True count in last {window}: {true_cnt}")
    print(f"DGIM estimate: {est}")
    print(f"Relative error: {err:.2f}% (Theoretical guarantee: <= 50%)")
    print(f"Total buckets stored: {len(dgim.buckets)} (vs {window} bits for exact)")
