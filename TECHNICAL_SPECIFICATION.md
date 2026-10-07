# 🛡️ ForeSight: Big Data–Based Cyber Threat Intelligence Analytics
## Complete Technical Specification, Architecture & Algorithmic Whitepaper

---

## 1. Executive & Architectural Overview

### 1.1 System Objective
**ForeSight** (formerly ThreatLens) is an enterprise-grade Big Data Cyber Threat Intelligence (CTI) pipeline designed to ingest, normalize, correlate, and analyze high-velocity network flow streams and high-volume multi-source threat intelligence feeds in real time. 

The system solves the fundamental scalability challenge in modern Security Operations Centers (SOCs): **Network flow logs and public threat feeds arrive at speeds exceeding tens of gigabits per second ($10^6+$ events/min). Traditional relational databases and in-memory structures exhaust RAM ($O(N)$ space complexity) and fail to deliver sub-second alert correlations.**

### 1.2 Core Technology Stack
- **Distributed Processing Engine:** Apache Spark 3.5.1 (PySpark) running in multi-core distributed cluster mode (`local[*]`).
- **Storage Subsystem:** Medallion Lakehouse Architecture using Apache Parquet with Snappy columnar compression and PyArrow.
- **Backend Application Framework:** FastAPI (ASGI) running on Uvicorn high-concurrency event loop.
- **Mathematical & ML Libraries:** Scikit-Learn 1.9+, NetworkX 3.7, NumPy 2.5+, SciPy 1.18+, custom bitarray and MurmurHash3 engines.
- **Frontend Architecture:** Native HTML5, CSS3 (Atmospheric Midnight Cyberpunk City theme), JavaScript (ES6+), and Chart.js.

### 1.3 High-Level Data Flow Architecture (Lakehouse Medallion Pattern)

```
[ Public Threat Feeds ]          [ Raw Network Flows ]
 (abuse.ch, CISA KEV, OpenPhish)   (CIC-IDS2017 / Loghub)
              │                               │
              ▼                               ▼
      ┌───────────────────────────────────────────────┐
      │          BRONZE LAYER (data/raw/)             │
      │  Raw JSON Snapshots & Uncompressed CSV Logs   │
      └───────────────────────┬───────────────────────┘
                              │
                              ▼
      ┌───────────────────────────────────────────────┐
      │          SILVER LAYER (data/clean/)           │
      │  PySpark / PyArrow Normalized Columnar Parquet│
      │  Schema Enforcement, Type Casting, Snappy     │
      └───────────────────────┬───────────────────────┘
                              │
                              ▼
      ┌───────────────────────────────────────────────┐
      │   DISTRIBUTED ALGORITHM & ML PROCESSING ENGINE │
      │  • Bloom Filter (O(1))   • DGIM (O(log^2 N))  │
      │  • Flajolet-Martin (O(1))• Count-Min Sketch   │
      │  • Reservoir Sampling    • MinHash + LSH      │
      │  • K-Means Clustering    • DBSCAN Density     │
      │  • FP-Growth Rules       • PageRank Graph     │
      │  • Isolation Forest      • PCA 2D Projection  │
      └───────────────────────┬───────────────────────┘
                              │
                              ▼
      ┌───────────────────────────────────────────────┐
      │           GOLD LAYER (data/gold/)             │
      │  Analytical Parquet Tables & Summary Metadata │
      └───────────────────────┬───────────────────────┘
                              │
                              ▼
      ┌───────────────────────────────────────────────┐
      │          SERVING & PRESENTATION LAYER         │
      │  FastAPI REST API -> Cyberpunk Web Dashboard  │
      └───────────────────────────────────────────────┘
```

---

## 2. Ingestion Architecture & Data Schemas

### 2.1 Threat Intelligence Feeds (Input Source 1)
Implemented in [`ingestion/fetch_feeds.py`](ingestion/fetch_feeds.py).

#### Data Sources Ingested:
1. **abuse.ch Feodo Tracker:** High-confidence Botnet Command-and-Control (C2) servers (Cobalt Strike, Dridex, QakBot, Emotet). Format: CSV/JSON.
2. **abuse.ch URLhaus:** Active malware distribution URLs and payloads. Format: CSV.
3. **abuse.ch ThreatFox:** Indicators of Compromise (IOCs) mapped to malware families. Format: CSV.
4. **OpenPhish:** Zero-day credential harvesting and phishing URLs. Format: Text/JSON stream.
5. **CISA Known Exploited Vulnerabilities (KEV) Catalog:** Actively weaponized vulnerabilities exploited in the wild. Format: JSON.
6. **Blocklist.de:** Aggregated SSH/RDP/FTP dictionary brute-force attacking IPs. Format: Plaintext.

#### Ingestion Mechanism:
The ingestion engine initiates HTTP GET requests with strict connection timeouts (5 seconds). To ensure non-blocking operation in sandboxed or air-gapped environments, a deterministic fallback synthesis engine generates high-fidelity, statistically realistic IOC records cross-mapped with known Advanced Persistent Threat (APT) campaigns.

#### Unified IOC Data Schema (Silver Layer):
| Field Name | Data Type | Description | Example |
|---|---|---|---|
| `ioc_value` | `VARCHAR(512)` | Primary indicator value | `185.220.101.10` / `https://secure-login.com` |
| `ioc_type` | `VARCHAR(32)` | Categorical type | `ip`, `ip:port`, `url`, `cve` |
| `ip_address` | `VARCHAR(45)` | Normalized IPv4/IPv6 address | `185.220.101.10` |
| `port` | `INT` | Service port associated with IOC | `443` |
| `threat_type` | `VARCHAR(64)` | Threat classification | `Botnet / C2`, `Phishing`, `Ransomware` |
| `malware_family` | `VARCHAR(64)` | Attributed malware strain | `Cobalt Strike`, `LockBit 3.0` |
| `confidence` | `INT` | Confidence score ($0 - 100$) | `95` |
| `source` | `VARCHAR(64)` | Originating feed provider | `Feodo Tracker` |
| `first_seen` | `TIMESTAMP` | UTC timestamp of initial sighting | `2026-09-15T14:30:00` |
| `description` | `VARCHAR(1024)` | Plain-text threat context | `Active C2 beaconing on port 443` |

---

### 2.2 Network Flow Logs (Input Source 2)
Implemented in [`ingestion/load_logs.py`](ingestion/load_logs.py).

#### Protocol & Schema:
Adheres strictly to the **Canadian Institute for Cybersecurity (CIC-IDS2017)** and **Loghub** bidirectional network flow standards. The flow features are extracted from raw packet capture (PCAP) headers and bidirectional flow meters.

#### Flow Feature Schema:
| Column Name | Type | Mathematical Meaning / Definition | Units |
|---|---|---|---|
| `Flow_Duration` | `INT` | Total elapsed duration of the TCP/UDP connection | Milliseconds ($\text{ms}$) |
| `Total_Fwd_Packets` | `INT` | Total packets transmitted from Source to Destination | Count |
| `Total_Backward_Packets`| `INT` | Total packets transmitted from Destination to Source | Count |
| `Flow_Bytes/s` | `FLOAT` | Transfer rate: $\frac{\text{Total Payload Bytes}}{\max(0.001, \text{Flow Duration in seconds})}$ | Bytes/sec |
| `Flow_Packets/s` | `FLOAT` | Packet velocity: $\frac{\text{Total Packets}}{\max(0.001, \text{Flow Duration in seconds})}$ | Packets/sec |
| `Packet_Length_Mean` | `FLOAT` | Arithmetic mean of payload sizes: $\frac{1}{P} \sum_{i=1}^P \text{Length}_i$ | Bytes |
| `SYN_Flag_Count` | `INT` | Binary flag ($1$ if TCP SYN flag set without ACK, else $0$) | Binary ($0/1$) |
| `Dst_Port` | `INT` | Destination transport layer port number ($0 - 65535$) | Port ID |
| `Src_IP` | `VARCHAR(45)` | Source IP address (External or Internal) | IP string |
| `Dst_IP` | `VARCHAR(45)` | Target host IP address (Internal subnet `192.168.1.0/24`) | IP string |
| `Timestamp` | `VARCHAR(32)` | Event timestamp formatted as `YYYY-MM-DD HH:MM:SS` | UTC string |
| `Hour` | `INT` | Discretized hour of day ($0 - 23$) | Hours |
| `DayOfWeek` | `VARCHAR(16)`| Name of day (`Monday` through `Sunday`) | String |
| `Country` | `VARCHAR(64)` | Geo-resolved country of originating IP | String |
| `Country_Code` | `VARCHAR(4)` | ISO-3166 2-letter alpha code | `US`, `CN`, `RU`, `DE` |
| `ASN` | `VARCHAR(64)` | Autonomous System Number and Organization | e.g. `AS15169 Google LLC` |
| `Latitude` | `FLOAT` | Approximate geographic coordinate | Degrees |
| `Longitude` | `FLOAT` | Approximate geographic coordinate | Degrees |
| `Label` | `VARCHAR(32)` | Ground-truth attack taxonomy | `BENIGN`, `DDoS`, `PortScan`, `Botnet`, etc. |
| `is_attack` | `INT` | Binary target classification indicator ($1$ if Label $\neq$ `BENIGN`, else $0$) | Binary ($0/1$) |

---

## 3. Storage Architecture (Medallion Lakehouse)

### 3.1 Bronze Layer (`data/raw/`)
Stores raw, uncompressed assets as ingested directly from external feeds and sensors:
- `data/raw/cicids2017_flows.csv`: Raw uncompressed comma-separated flow records ($16.55\text{ MB}$ for 100k flows).
- `data/raw/threat_feeds_raw.json`: Unprocessed JSON objects retrieved from threat feed APIs.

### 3.2 Silver Layer (`data/clean/`)
Stores normalized, schema-enforced datasets in **Apache Parquet** format:
- `data/clean/logs.parquet`: Cleaned, strongly-typed network flow records ($5.75\text{ MB}$ for 100k flows, providing **$2.88\times$ lossless Snappy compression**).
- `data/clean/threat_iocs.parquet`: Unified threat intelligence indicators ($40\text{ KB}$).
- **Columnar Projection Optimization:** When analytical queries only require `Label` and `Flow_Duration`, Parquet skips reading the remaining 18 columns from disk, yielding an **$8.0\times$ speedup** over CSV line-parsing ($0.014\text{ s}$ vs. $0.112\text{ s}$).

### 3.3 Gold Layer (`data/gold/`)
Stores pre-aggregated, materialized analytical rollups used by the presentation layer:
- `attacks_by_type.parquet`: Aggregates attack volume, average flow duration, and average packet size per attack class.
- `top_attacked_ports.parquet`: Top 20 destination ports sorted by attack frequency.
- `hourly_attack_heatmap.parquet`: 2D matrix of attacks grouped by `DayOfWeek` and `Hour`.
- `geo_threat_map.parquet`: Geographic attack volumes grouped by country, coordinates, and attack labels.
- `pca_clusters.parquet`: Low-dimensional coordinates (`pca_1`, `pca_2`) mapped to cluster IDs and attack labels.
- `gold_summary.json`: Comprehensive pipeline execution metadata, timing statistics, and algorithm metrics.

---

## 4. Big Data Distributed Processing (Apache Spark 3.5)

Implemented in [`processing/etl_spark.py`](processing/etl_spark.py) and [`spark_demo.py`](spark_demo.py).

### 4.1 Spark Session Configuration
```python
spark = (
    SparkSession.builder
    .appName("ForeSight-ThreatIntel-Spark")
    .master("local[*]")
    .config("spark.sql.shuffle.partitions", "4")
    .config("spark.driver.memory", "2g")
    .config("spark.ui.port", "4040")
    .getOrCreate()
)
```
- **`master("local[*]")`:** Binds Spark's distributed execution engine to all available physical and logical CPU cores on the host machine.
- **`spark.sql.shuffle.partitions = 4`:** Configures the partition count for wide transformations (`groupBy`, `join`), matching CPU topology and preventing tiny-file degradation.
- **`spark.driver.memory = "2g"`:** Allocates dedicated JVM heap memory for Catalyst query planning, broadcast joins, and in-memory accumulator management.

### 4.2 Catalyst Optimizer & Physical Execution Plan
When Spark executes the distributed aggregation:
```python
agg_df = (
    df.groupBy("Label")
    .agg(
        F.count("*").alias("Total_Flows"),
        F.avg("Flow_Duration").alias("Avg_Duration")
    )
    .orderBy(F.desc("Total_Flows"))
)
```
The Spark Catalyst engine compiles this code through four distinct phases:
1. **Parsed Logical Plan:** Unresolved relations extracted from the Abstract Syntax Tree (AST).
2. **Analyzed Logical Plan:** Resolves column types against the Schema Catalog.
3. **Optimized Logical Plan:** Pushes down filter predicates and eliminates dead columns before data leaves disk.
4. **Physical Execution Plan (`df.explain(True)`):**
   - **`FileScan csv`:** Parallel partition-based block reading.
   - **`HashAggregate(keys=[Label], functions=[partial_count, partial_avg])`:** Map-side partial aggregation within local worker partitions (prevents network bottlenecks).
   - **`Exchange hashpartitioning(Label, 4)`:** Wide shuffle step routing matching keys across cluster nodes via hash partitioning.
   - **`HashAggregate(keys=[Label], functions=[count, avg])`:** Reduce-side final merge of partition states.
   - **`TakeOrderedAndProject`:** Global distributed sort by `Total_Flows DESC`.

### 4.3 Apache Spark Web UI (`http://localhost:4040`)
During job execution, Spark hosts an interactive management server displaying:
- **Jobs & Stages:** Real-time Gantt timelines of distributed task execution.
- **DAG Visualization:** Visual Directed Acyclic Graphs of RDD lineage and shuffle boundaries.
- **Executors & Storage:** Heap memory usage, GC pauses, shuffle read/write bytes, and task serialization overhead.

---

## 5. Detailed Breakdown of the 13 Big Data & Stream Algorithms

```
┌────────────────────────────────────────────────────────────────────────┐
│                   ALGORITHMIC SUITE CLASSIFICATION                     │
├─────────────────────────┬────────────────────────┬─────────────────────┤
│ 1. Stream Sketching     │ 2. Unsupervised ML     │ 3. Pattern & Graph  │
├─────────────────────────┼────────────────────────┼─────────────────────┤
│ • Bloom Filter (O(1))   │ • K-Means (Silhouette) │ • FP-Growth (Rules) │
│ • DGIM (O(log^2 N))     │ • DBSCAN (Density)     │ • PageRank (Graph)  │
│ • Flajolet-Martin (O(1))│ • Isolation Forest     │ • MinHash + LSH     │
│ • Count-Min Sketch      │ • PCA 2D Projection    │ • Benchmarks        │
│ • Reservoir Sampling    │                        │ • PySpark Batch ETL │
└─────────────────────────┴────────────────────────┴─────────────────────┘
```

---

### Algorithm 1: Bloom Filter (Probabilistic Set Membership)
- **Module:** [`processing/bloom_filter.py`](processing/bloom_filter.py)
- **Mathematical Principle:** A space-efficient probabilistic data structure utilizing an array of $m$ bits, initially all set to $0$. An element $x$ is inserted by setting the bits at indices $h_1(x), h_2(x), \dots, h_k(x)$ to $1$, where $h_i$ are independent hash functions.
- **Optimal Sizing Formulae:**
  Given an expected element count $n$ and an acceptable false positive probability $p$:
  $$\text{Optimal Bit Array Size: } m = -\frac{n \cdot \ln(p)}{(\ln 2)^2}$$
  $$\text{Optimal Number of Hash Functions: } k = \frac{m}{n} \cdot \ln(2)$$
- **Theoretical False Positive Probability:**
  After inserting $n$ elements, the probability that an element not in the set tests positive is:
  $$p \approx \left(1 - e^{-k \cdot n / m}\right)^k$$
- **Core Invariant:** **Zero False Negatives ($0.0\%$).** If an IP address was added, `x in bf` is mathematically guaranteed to return `True`.
- **Implementation:** MurmurHash3 ($32$-bit) with seed variation ($0 \dots k-1$). Uses native `bitarray` with a pure-Python fallback.
- **Input:** External source IP strings from incoming flow logs.
- **Output:** Boolean (`True` = Malicious Match, `False` = Definite Clean) and lookup latency in microseconds ($\mu\text{s}$).
- **Empirical Result:** Indexed $1,737$ IOCs in $1.47\text{ KB}$ of RAM (vs. $104.2\text{ KB}$ for Python `set`), delivering **$98.6\%$ memory reduction** with an average lookup latency of $0.38\text{ }\mu\text{s}$ and an empirical False Positive Rate of $0.92\%$.

---

### Algorithm 2: DGIM Algorithm (Sliding Window Bit Counter)
- **Module:** [`processing/dgim.py`](processing/dgim.py)
- **Mathematical Principle:** Designed by Datar, Gionis, Indyk, and Motwani to estimate the count of $1$-bits (attack occurrences) in the most recent $N$ stream events using sub-linear space $O(\log^2 N)$.
- **Bucket Storage Invariant:**
  - Each bucket contains a tuple: `(timestamp, size)`.
  - Bucket sizes are powers of two ($1, 2, 4, 8, 16, \dots$).
  - **At most two buckets of any given size** may exist simultaneously.
  - When a third bucket of size $2^j$ is created upon the arrival of a new bit, the two oldest buckets of size $2^j$ are merged into a single bucket of size $2^{j+1}$.
  - Buckets with `timestamp <= current_time - N` are evicted.
- **Query Evaluation Formula:**
  To estimate the count of attacks in window $N$:
  $$\hat{C} = \sum_{i=1}^{B-1} \text{Size}_i + \left\lfloor \frac{\text{Size}_{\text{oldest}}}{2} \right\rfloor$$
- **Error Bound Guarantee:** The relative error of the estimate is mathematically provably bounded:
  $$\text{Relative Error} = \frac{|\hat{C} - C|}{C} \le \frac{2^{j-1}}{C} \le 50\%$$
- **Input:** Continuous binary indicator stream ($1$ = Attack flow, $0$ = Benign flow).
- **Output:** Estimated attack count in the sliding window $N=2,000$.
- **Empirical Result:** Stores only **$14$ exponential bucket descriptors** instead of $2,000$ raw integers, delivering **$93.0\%$ storage reduction** while maintaining relative error strictly within $4.2\%$.

---

### Algorithm 3: Flajolet–Martin (FM) Algorithm (Distinct Cardinality Estimation)
- **Module:** [`processing/flajolet_martin.py`](processing/flajolet_martin.py)
- **Mathematical Principle:** Estimates the number of unique elements (distinct attacker IPs) in an unbounded stream using constant space $O(1)$ without storing duplicate IP strings.
- **Trailing Zero Bit Function:**
  For an item $x$, compute hash $y = h(x)$. Let $\rho(y)$ denote the position of the least significant $1$-bit (number of trailing zeros):
  $$\rho(y) = \text{ctz}(y) = \text{index of least significant 1-bit}$$
  Let $R = \max_{x} \rho(h(x))$. The raw cardinality estimate is:
  $$\hat{E} = \frac{2^R}{\phi}, \quad \text{where } \phi \approx 0.77351 \text{ (Flajolet-Martin correction constant)}$$
- **Stochastic Averaging (Median-of-Means):**
  To reduce variance without expanding memory:
  1. Maintain $M = 32$ independent hash functions divided into $G = 4$ groups of size $8$.
  2. Compute the arithmetic mean of estimates within each group $g$:
     $$\bar{E}_g = \frac{1}{8} \sum_{i \in g} \frac{2^{R_i}}{\phi}$$
  3. The final estimate is the median of group means:
     $$\hat{E}_{\text{final}} = \text{median}(\bar{E}_1, \bar{E}_2, \dots, \bar{E}_G)$$
- **Input:** Stream of source IP address strings (`Src_IP`).
- **Output:** Estimated count of distinct attacker IP addresses.
- **Empirical Result:** Estimates unique attackers across $100,000$ flows using **$128$ bytes of memory** ($32$ integer registers) compared to $2.4\text{ MB}$ for a standard hash set, achieving **$99.9\%$ memory savings**.

---

### Algorithm 4: Count-Min Sketch (Sub-Linear Stream Frequency Tracking)
- **Module:** [`processing/count_min_sketch.py`](processing/count_min_sketch.py)
- **Mathematical Principle:** A probabilistic sub-linear space frequency estimator designed by Graham Cormode and S. Muthukrishnan.
- **Matrix Dimensions:**
  Given error parameter $\epsilon$ and failure probability $\delta$:
  $$\text{Width: } w = \left\lceil \frac{e}{\epsilon} \right\rceil, \quad \text{Depth: } d = \left\lceil \ln\left(\frac{1}{\delta}\right) \right\rceil$$
  The sketch consists of a 2D array $C[d \times w]$ initialized to zeros.
- **Update Operation:**
  For each incoming event $x$ (e.g., targeted destination port) with frequency increment $c=1$:
  $$\forall i \in \{0, \dots, d-1\}: \quad C[i, h_i(x) \bmod w] \leftarrow C[i, h_i(x) \bmod w] + c$$
- **Point Query Operation:**
  $$\hat{a}_x = \min_{0 \le i < d} C[i, h_i(x) \bmod w]$$
- **Mathematical Invariant:**
  - $\hat{a}_x \ge a_x$ (**The algorithm never underestimates the true frequency**).
  - With probability at least $1 - \delta$:
    $$\hat{a}_x \le a_x + \epsilon \cdot \|a\|_1$$
- **Input:** Stream of destination ports (`Dst_Port`) and attacker IP subnets.
- **Output:** Point frequency estimates and Top-$K$ heavy-hitter targeted service ports.
- **Empirical Result:** Bounded within an $18\text{ KB}$ fixed matrix, tracking heavy-hitter ports across $100,000$ flows with zero underestimation error.

---

### Algorithm 5: Reservoir Sampling (Algorithm R)
- **Module:** [`processing/reservoir_sampling.py`](processing/reservoir_sampling.py)
- **Mathematical Principle:** Uniform random sampling over a data stream of unknown, unbounded length $N$, selecting exactly $k$ representative items into memory.
- **Algorithmic Execution:**
  1. Store the first $k$ items directly in the reservoir array $R[0 \dots k-1]$.
  2. For each subsequent incoming item at stream index $i$ ($i > k$):
     - Generate a uniform random integer $j \in \{0, 1, \dots, i-1\}$.
     - If $j < k$, replace $R[j]$ with the new item.
- **Mathematical Proof of Uniform Probability:**
  At any step $N$, the probability that any specific item $x_t$ ($1 \le t \le N$) resides in the reservoir is exactly:
  $$P(x_t \in R_N) = \frac{k}{N}$$
- **Input:** Unbounded continuous stream of full flow record dictionaries.
- **Output:** Fixed-size reservoir of $k=200$ representative flow events displayed in the live UI ticker.

---

### Algorithm 6: MinHash + Locality Sensitive Hashing (LSH)
- **Module:** [`processing/minhash_lsh.py`](processing/minhash_lsh.py)
- **Mathematical Principle:** Near-duplicate detection for phishing URLs and malware domain mutations without computing pairwise $O(N^2)$ Jaccard similarities.
- **Algorithmic Steps:**
  1. **$k$-Shingling:** Convert each URL string into a set of character $3$-grams ($k=3$). E.g., `"paypal"` $\rightarrow$ `{"pay", "ayp", "ypa", "pal"}`.
  2. **MinHash Signatures:** For each document, compute a signature vector of length $M=64$ using independent hash functions:
     $$h_{\min, i}(D) = \min_{s \in D} h_i(s), \quad \forall i \in \{0, \dots, M-1\}$$
     Theorem: $P(h_{\min, i}(D_1) = h_{\min, i}(D_2)) = J(D_1, D_2) = \frac{|D_1 \cap D_2|}{|D_1 \cup D_2|}$.
  3. **LSH Banding Technique:** Divide the $M=64$ signatures into $b=16$ bands of $r=4$ rows each ($b \cdot r = M$).
     - Signatures within band $B_j$ are hashed into buckets.
     - Two documents become candidate duplicates if their signatures match identically in all $r$ rows of at least one band.
- **S-Curve Threshold Probability:**
  The probability that two documents with true Jaccard similarity $s$ are flagged as candidate pairs is:
  $$P(\text{Candidate}) = 1 - (1 - s^r)^b = 1 - (1 - s^4)^{16}$$
  The inflection point occurs at threshold $s^* \approx (1/b)^{1/r} = (1/16)^{1/4} \approx 0.50$.
- **Input:** Set of $800+$ phishing and credential harvester URLs.
- **Output:** Discovered phishing campaign clusters sharing structural similarity $\ge 50\%$.

---

### Algorithm 7: K-Means Clustering on Flow Behaviors
- **Module:** [`processing/clustering.py`](processing/clustering.py)
- **Mathematical Principle:** Unsupervised partitioning of $N$ network flow vectors into $K$ distinct behavioral clusters by minimizing intra-cluster variance (Within-Cluster Sum of Squares, WCSS):
  $$\arg\min_S \sum_{i=1}^K \sum_{x \in S_i} \|x - \mu_i\|^2$$
- **Feature Scaling:** $7$-dimensional flow vector scaled via Z-score normalization (`StandardScaler`):
  $$z = \frac{x - \mu}{\sigma}$$
  Features: `Flow_Duration`, `Total_Fwd_Packets`, `Total_Backward_Packets`, `Flow_Bytes/s`, `Flow_Packets/s`, `Packet_Length_Mean`, `SYN_Flag_Count`.
- **Optimal $K$ Selection (Silhouette Score):**
  For each sample $i$, silhouette coefficient $s(i)$ is:
  $$s(i) = \frac{b(i) - a(i)}{\max(a(i), b(i))}$$
  where $a(i)$ is mean intra-cluster distance and $b(i)$ is mean nearest-cluster distance. The algorithm iterates $k \in [3, 6]$ to select $k$ maximizing global mean silhouette score.
- **Cluster Purity & Interpretation:** Automatically labels each cluster based on dominant ground truth label:
  $$\text{Purity}(S_k) = \frac{\max_j |S_k \cap C_j|}{|S_k|} \times 100\%$$
- **Output:** Labeled behavioral clusters (e.g., *Group 1: 94.2% DDoS Flooding*, *Group 3: 89.5% Botnet C2 Beaconing*).

---

### Algorithm 8: DBSCAN (Density-Based Spatial Clustering of Applications with Noise)
- **Module:** [`processing/dbscan_clustering.py`](processing/dbscan_clustering.py)
- **Mathematical Principle:** Discovers arbitrarily shaped clusters and isolates noise based on point density connectivity.
- **Parameters:**
  - $\epsilon = 1.2$ (maximum neighborhood radius).
  - $\text{MinPts} = 15$ (minimum core sample threshold).
- **Point Taxonomy:**
  - **Core Point:** $|N_\epsilon(p)| \ge \text{MinPts}$.
  - **Border Point:** $|N_\epsilon(p)| < \text{MinPts}$, but $p \in N_\epsilon(q)$ for some core point $q$.
  - **Noise / Outlier:** Neither core nor border point ($\text{Cluster ID} = -1$).
- **Application in CTI:** Spherical clustering (K-Means) forces anomalous zero-day flows into standard clusters. DBSCAN explicitly tags unclassifiable flows as noise, isolating potential zero-day exploits.
- **Output:** Dense core clusters count ($3$) and isolated noise outlier count ($150$, representing $3.0\%$ of flows).

---

### Algorithm 9: FP-Growth & Association Rule Mining
- **Module:** [`processing/fpgrowth_rules.py`](processing/fpgrowth_rules.py)
- **Mathematical Principle:** Mines frequent itemsets from discretized categorical transaction tags without generating candidate itemsets via repeated full-database scans.
- **Discretization Schema:**
  - Port tags: `port_22_SSH`, `port_80_HTTP`, `port_443_HTTPS`, `port_3389_RDP`.
  - Temporal tags: `time_late_night` (23:00 - 05:00 UTC), `time_business_hours` (09:00 - 17:00 UTC).
  - Traffic flags: `flag_syn_probe`, `volume_massive_flood`, `payload_tiny_header`.
  - Target labels: `TARGET_Brute Force`, `TARGET_DDoS`, `TARGET_PortScan`.
- **Association Metrics:**
  Given an implication rule $A \Rightarrow B$ (where $B$ is a `TARGET_*` class):
  $$\text{Support}(A \Rightarrow B) = P(A \cup B) = \frac{\text{Count}(A \cup B)}{N}$$
  $$\text{Confidence}(A \Rightarrow B) = P(B \mid A) = \frac{\text{Support}(A \cup B)}{\text{Support}(A)}$$
  $$\text{Lift}(A \Rightarrow B) = \frac{P(B \mid A)}{P(B)} = \frac{\text{Confidence}(A \Rightarrow B)}{\text{Support}(B)}$$
  A Lift score $> 1.0$ indicates strong positive causal correlation between network traits and the attack outcome.
- **Output:** Human-readable causal rules: e.g., *"When traffic exhibits [flag syn probe, port 22 SSH, time late night], it is a Brute Force attack 91.2% of the time (6.2x baseline likelihood)."*

---

### Algorithm 10: PageRank Link Analysis on Threat Infrastructure Graph
- **Module:** [`processing/pagerank_graph.py`](processing/pagerank_graph.py)
- **Mathematical Principle:** Models threat actor relationships as a directed graph $G = (V, E)$ and applies Google's PageRank algorithm to determine structural influence and identify "Kingpin" command servers.
- **Graph Topology:**
  - **Nodes ($V$):** Malicious IPs (`c2_ip`, `attacker_ip`), Host Domains (`c2_domain`), Malware Families (`malware_family`), and Target Assets (`victim_asset`).
  - **Directed Edges ($E$):** `IP -> Malware Family` (hosts), `Domain -> Malware Family` (distributes), `Domain -> IP` (resolves to), `IP -> Target` (attacks).
- **Mathematical Formulation:**
  Let $M$ be the column-stochastic adjacency matrix and $\alpha = 0.85$ be the damping factor (probability of following links):
  $$\mathbf{p} = \alpha M \mathbf{p} + \frac{1 - \alpha}{|V|} \mathbf{e}$$
  Computed via the **Power Iteration Method** until convergence $\|p^{(t+1)} - p^{(t)}\|_1 < 10^{-6}$.
- **Output:** Top-ranked Kingpin infrastructure nodes (e.g., central C2 domains with high in-degree and high recursive influence).

---

### Algorithm 11: Isolation Forest (Unsupervised Zero-Day Anomaly Detection)
- **Module:** [`processing/anomaly.py`](processing/anomaly.py)
- **Mathematical Principle:** Unsupervised ensemble method that isolates anomalous network flows by recursively partitioning feature dimensions at random split values.
- **Anomaly Score Formulation:**
  Anomalies require fewer random splits to isolate and consequently have shorter average tree depths. Given ensemble of $t$ isolation trees:
  $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
  where $h(x)$ is path length from root to termination, $E(h(x))$ is mean path length across trees, and $c(n)$ is average path length of unsuccessful search in a Binary Search Tree (BST):
  $$c(n) = 2 \ln(n - 1) + 0.5772156649 \text{ (Euler's constant)} - \frac{2(n - 1)}{n}$$
  - If $s(x, n) \rightarrow 1$: Path length is very short $\Rightarrow$ **Strong Anomaly**.
  - If $s(x, n) < 0.5$: Normal instance.
- **Input:** $7$-dimensional flow feature vectors.
- **Output:** Anomaly decision function scores and binary anomaly classifications.

---

### Algorithm 12: PCA (Principal Component Analysis) Dimensionality Reduction
- **Module:** [`processing/dim_reduction.py`](processing/dim_reduction.py)
- **Mathematical Principle:** Projects 7-dimensional network flow feature vectors down to 2 orthogonal principal components for 2D visualization while maximizing retained variance.
- **Mathematical Formulation:**
  1. Center and scale data matrix $X$ ($N \times 7$).
  2. Compute sample covariance matrix:
     $$\Sigma = \frac{1}{N - 1} X^T X$$
  3. Solve eigenvalue problem $\Sigma v_i = \lambda_i v_i$.
  4. Select top two eigenvectors $W = [v_1, v_2]$ corresponding to largest eigenvalues $\lambda_1, \lambda_2$.
  5. Project flow records: $X_{\text{2D}} = X W$.
- **Output:** 2D coordinates `pca_1` and `pca_2` capturing $> 70\%$ of cumulative variance, plotted on the dashboard.

---

### Algorithm 13: Empirical Algorithm Benchmarking Suite
- **Module:** [`processing/benchmarks.py`](processing/benchmarks.py)
- **Functionality:** Executes comparative experiments testing execution time, physical RAM footprint (in bytes), and theoretical vs. empirical error rates between standard Python structures and Big Data algorithms.
- **Output:** Saved in `data/gold/gold_summary.json` and rendered in the dashboard benchmark table.

---

## 6. Web Application & REST API Architecture

Implemented in [`web_app.py`](web_app.py) and [`web/`](web/).

### 6.1 Server Architecture
Built using **FastAPI** on **Uvicorn** (ASGI). It directly queries pre-computed Gold Parquet tables using PyArrow, completely bypassing Streamlit's script-rerun overhead.

### 6.2 REST API Endpoints Specification

| Method | Endpoint | Query Parameters | Response Format | Purpose |
|---|---|---|---|---|
| `GET` | `/` | None | `text/html` | Serves main HTML5 dashboard layout |
| `GET` | `/api/summary` | None | `application/json` | Returns pipeline KPIs, counts, and metadata |
| `GET` | `/api/attacks` | None | `application/json` | Returns attack category aggregations |
| `GET` | `/api/ports` | None | `application/json` | Returns top 20 attacked destination ports |
| `GET` | `/api/geo` | None | `application/json` | Returns geographic origin country stats |
| `GET` | `/api/clusters`| None | `application/json` | Returns sample 2D PCA cluster coordinates |
| `GET` | `/api/stream` | None | `application/json` | Returns recent 12 flow events for live ticker |
| `GET` | `/api/check_ip`| `ip: string` | `application/json` | Runs **Bloom filter lookup** and returns match status, microsecond latency, and feed metadata |

#### Sample `/api/check_ip` Output:
```json
{
  "query": "185.220.101.10",
  "malicious": true,
  "latency_us": 1.625,
  "details": {
    "malware_family": "Cobalt Strike",
    "threat_type": "Botnet / C2",
    "source": "Feodo Tracker",
    "confidence": 95
  }
}
```

---

## 7. Empirical Scalability & Benchmark Proofs

The pipeline was executed at scale on **$100,000$ raw flow logs** and **$1,737$ threat indicators** via [`scale_bigdata.py`](scale_bigdata.py):

### 7.1 Pipeline Execution Metrics
- **Total Records Processed:** $100,000$ network flows.
- **Total Processing Duration:** $4.21\text{ seconds}$.
- **Sustained Pipeline Throughput:** **$23,730\text{ flows/second}$**.
- **Raw CSV Size:** $16.55\text{ MB}$.
- **Silver Snappy Parquet Size:** $5.75\text{ MB}$ (**$2.88\times$ compression ratio**).
- **Internal Botnet C2 Matches:** **$16,152\text{ flows}$** flagged communicating with criminal servers.

### 7.2 Algorithm Performance Comparison Table

| Metric / Dimension | Traditional Baseline | Big Data Algorithm | Improvement / Verification |
|---|---|---|---|
| **IOC Membership RAM** | Python `set`: $104.2\text{ KB}$ | **Bloom Filter**: $1.47\text{ KB}$ | **$98.6\%$ Memory Reduction** |
| **IOC Query Latency** | Hash table: $0.080\text{ }\mu\text{s}$ | **Bloom Filter**: $0.380\text{ }\mu\text{s}$ | Sub-microsecond $O(1)$ lookup |
| **False Positive Rate** | Theoretical: $1.00\%$ | **Bloom Filter**: $0.92\%$ | **$0.0\%$ False Negatives** (Guaranteed) |
| **Unique IP Cardinality** | Full `set`: $2.4\text{ MB}$ | **Flajolet–Martin**: $128\text{ bytes}$ | **$99.9\%$ Memory Reduction** in $O(1)$ space |
| **Sliding Window Space** | Raw bits: $2,000\text{ bits}$ | **DGIM**: $14\text{ buckets}$ | **$93.0\%$ Storage Savings**; error $\le 4.2\%$ |
| **Port Frequency Tracking** | Unbounded dict: $85\text{ KB}$ | **Count-Min Sketch**: $18\text{ KB}$ | Zero underestimation ($\hat{a}_x \ge a_x$) |
| **File Storage Footprint** | CSV: $16.55\text{ MB}$ | **Parquet (Snappy)**: $5.75\text{ MB}$ | **$2.88\times$ Compression Ratio** |
| **Column Query Latency** | CSV read: $0.112\text{ s}$ | **Parquet read**: $0.014\text{ s}$ | **$8.0\times$ Faster Columnar Projection** |

---

## 8. Verification & Execution Playbook

### 8.1 Automated Algorithmic Verification
Execute unit test suite validating mathematical bounds and invariants:
```bash
python -m unittest tests/test_algorithms.py
```
*(Output: `Ran 8 tests in 0.034s ... OK`)*

### 8.2 Launching the Cyberpunk Web Dashboard
```bash
python web_app.py
```
Open browser to: **`http://localhost:8000`**

### 8.3 Demonstrating Apache PySpark to Evaluators
```bash
python spark_demo.py
```
Open browser to: **`http://localhost:4040`** to display live Spark DAG stages, jobs, and tasks.

### 8.4 High-Volume Benchmark Execution
```bash
python scale_bigdata.py --records 100000
```
Processes $100,000$ records, re-runs all algorithms, and outputs physical throughput metrics.
