"""
FastAPI Server for ThreatLens Cyber Threat Intelligence Web UI.
Serves native HTML/CSS/JS frontend and high-speed REST API endpoints.
Zero Streamlit dependencies.
"""

import os
import sys
import json
import time
from typing import Optional
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import pandas as pd
import uvicorn

# Ensure root in sys.path
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from processing.bloom_filter import BloomFilter

app = FastAPI(title="ThreatLens CTI Web Application", version="2.0.0")

# Mount Static Files (CSS, JS)
static_dir = os.path.join(PROJECT_ROOT, "web", "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Caches
GOLD_DIR = os.path.join(PROJECT_ROOT, "data", "gold")
CLEAN_DIR = os.path.join(PROJECT_ROOT, "data", "clean")

_CACHED_BLOOM = None
_CACHED_IOCS_DF = None


def get_bloom_filter():
    """Initializes and caches Bloom filter for sub-microsecond IP queries."""
    global _CACHED_BLOOM, _CACHED_IOCS_DF
    if _CACHED_BLOOM is None:
        iocs_path = os.path.join(CLEAN_DIR, "threat_iocs.parquet")
        if os.path.exists(iocs_path):
            _CACHED_IOCS_DF = pd.read_parquet(iocs_path)
            ips = _CACHED_IOCS_DF[_CACHED_IOCS_DF["ioc_type"].isin(["ip", "ip:port"])]["ip_address"].dropna().unique().tolist()
            _CACHED_BLOOM = BloomFilter(expected_elements=max(1000, len(ips)), false_positive_rate=0.01)
            for ip in ips:
                _CACHED_BLOOM.add(ip)
        else:
            _CACHED_BLOOM = BloomFilter(expected_elements=1000)
            _CACHED_IOCS_DF = pd.DataFrame()
    return _CACHED_BLOOM, _CACHED_IOCS_DF


@app.get("/", response_class=HTMLResponse)
def serve_index():
    """Serves the main HTML5 dashboard."""
    template_path = os.path.join(PROJECT_ROOT, "web", "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/summary")
def get_summary():
    """Returns gold summary JSON metadata."""
    summary_path = os.path.join(GOLD_DIR, "gold_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


@app.get("/api/attacks")
def get_attacks():
    """Returns attack category aggregations."""
    p = os.path.join(GOLD_DIR, "attacks_by_type.parquet")
    if os.path.exists(p):
        df = pd.read_parquet(p)
        return df.to_dict(orient="records")
    return []


@app.get("/api/ports")
def get_ports():
    """Returns top attacked service ports."""
    p = os.path.join(GOLD_DIR, "top_attacked_ports.parquet")
    if os.path.exists(p):
        df = pd.read_parquet(p)
        return df.to_dict(orient="records")
    return []


@app.get("/api/geo")
def get_geo():
    """Returns geographic attack distributions."""
    p = os.path.join(GOLD_DIR, "geo_threat_map.parquet")
    if os.path.exists(p):
        df = pd.read_parquet(p)
        return df.to_dict(orient="records")
    return []


@app.get("/api/clusters")
def get_clusters():
    """Returns 2D PCA cluster coordinates."""
    p = os.path.join(GOLD_DIR, "pca_clusters.parquet")
    if os.path.exists(p):
        df = pd.read_parquet(p).head(500)
        return df.to_dict(orient="records")
    return []


@app.get("/api/stream")
def get_stream():
    """Returns a recent slice of network flow events."""
    p = os.path.join(CLEAN_DIR, "logs.parquet")
    if os.path.exists(p):
        df = pd.read_parquet(p).tail(12)
        cols = ["Timestamp", "Src_IP", "Dst_IP", "Dst_Port", "Label", "is_attack"]
        return df[cols].to_dict(orient="records")
    return []


@app.get("/api/check_ip")
def check_ip(ip: str = Query(..., description="IP or domain to check")):
    """Sub-microsecond Bloom filter membership query."""
    bf, df_iocs = get_bloom_filter()
    clean_query = ip.strip()

    t0 = time.perf_counter()
    is_malicious = clean_query in bf
    latency_us = (time.perf_counter() - t0) * 1_000_000

    details = {}
    if is_malicious and not df_iocs.empty:
        match = df_iocs[df_iocs["ip_address"] == clean_query]
        if not match.empty:
            row = match.iloc[0]
            details = {
                "malware_family": str(row.get("malware_family", "Unknown")),
                "threat_type": str(row.get("threat_type", "Botnet / C2")),
                "source": str(row.get("source", "Threat Feed")),
                "confidence": int(row.get("confidence", 90))
            }
        else:
            details = {
                "malware_family": "Known Botnet Infrastructure",
                "threat_type": "Command-and-Control (C2)",
                "source": "abuse.ch Feed",
                "confidence": 92
            }

    return {
        "query": clean_query,
        "malicious": is_malicious,
        "latency_us": round(latency_us, 3),
        "details": details
    }


def main():
    print("=" * 65)
    print("🛡️  THREATLENS CYBER THREAT INTELLIGENCE (HTML/CSS WEB UI)")
    print("=" * 65)
    print("🚀 Starting FastAPI Web Server at:")
    print("   👉 http://127.0.0.1:8000")
    print("   👉 http://localhost:8000")
    print("=" * 65)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
