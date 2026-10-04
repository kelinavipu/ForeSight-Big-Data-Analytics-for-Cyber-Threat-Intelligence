"""
Reservoir Sampling (Algorithm R) for Unbounded Security Event Streams.
Guarantees every streaming log event has an equal probability (k / N)
of selection in a fixed-size memory reservoir.
"""

import random
from typing import List, Any, Optional


class ReservoirSampler:
    """
    Reservoir Sampler of fixed capacity k.
    """
    def __init__(self, capacity: int = 100, seed: Optional[int] = 42):
        self.capacity = capacity
        self.reservoir: List[Any] = []
        self.total_seen = 0
        if seed is not None:
            random.seed(seed)

    def feed(self, item: Any):
        """Processes one streaming event item."""
        self.total_seen += 1
        if len(self.reservoir) < self.capacity:
            self.reservoir.append(item)
        else:
            # Generate random index j in [0, total_seen - 1]
            j = random.randint(0, self.total_seen - 1)
            if j < self.capacity:
                self.reservoir[j] = item

    def feed_batch(self, items: List[Any]):
        """Processes a list of items."""
        for it in items:
            self.feed(it)

    def get_sample(self) -> List[Any]:
        """Returns the current representative uniform sample."""
        return list(self.reservoir)

    def reset(self):
        """Clears the reservoir."""
        self.reservoir.clear()
        self.total_seen = 0


if __name__ == "__main__":
    rs = ReservoirSampler(capacity=5)
    for i in range(100):
        rs.feed(f"event_{i}")
    print("Reservoir sample of 100 events:", rs.get_sample())
