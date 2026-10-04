"""
Real-Time Security Event Streaming Replayer and Simulator.
Replays stored network flow logs as a live stream, emitting events with realistic pacing,
updating streaming sketches (DGIM, Bloom Filter, CMS) in real-time.
"""

import os
import time
import json
import random
from typing import Generator, Dict, Any
import pandas as pd

from processing.bloom_filter import BloomFilter
from processing.dgim import DGIM
from processing.count_min_sketch import CountMinSketch


class SecurityStreamReplayer:
    """Simulates real-time live log traffic from historical Parquet dataset."""
    def __init__(self, parquet_path: str = "data/clean/logs.parquet", stream_dir: str = "data/stream"):
        self.parquet_path = parquet_path
        self.stream_dir = stream_dir
        os.makedirs(stream_dir, exist_ok=True)
        self.output_file = os.path.join(stream_dir, "event_stream.json")

    def stream_generator(
        self,
        batch_size: int = 1,
        delay_seconds: float = 0.05,
        max_events: int = 1000
    ) -> Generator[Dict[str, Any], None, None]:
        """Yields streaming network events continuously."""
        if not os.path.exists(self.parquet_path):
            raise FileNotFoundError(f"Parquet file {self.parquet_path} not found. Run pipeline first.")

        df = pd.read_parquet(self.parquet_path)
        sampled = df.sample(frac=1.0, random_state=random.randint(1, 9999)).reset_index(drop=True)

        count = 0
        for _, row in sampled.iterrows():
            if count >= max_events:
                break
            record = row.to_dict()
            record["stream_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

            # Append to file for external readers (Spark Streaming / file watchers)
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")

            yield record
            count += 1
            if delay_seconds > 0:
                time.sleep(delay_seconds)


if __name__ == "__main__":
    replayer = SecurityStreamReplayer()
    print("Starting simulated security event stream (Press Ctrl+C to stop)...")
    for event in replayer.stream_generator(max_events=10, delay_seconds=0.1):
        print(f"[{event['stream_timestamp']}] Src={event['Src_IP']} DstPort={event['Dst_Port']} Attack={event['is_attack']} ({event['Label']})")
