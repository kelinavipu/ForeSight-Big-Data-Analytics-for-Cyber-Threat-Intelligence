"""
MinHash and Locality Sensitive Hashing (LSH) for Threat Intelligence.
Finds near-duplicate phishing URLs and malware domain variants in sub-quadratic time O(N)
using character k-shingles and banding technique.
"""

from collections import defaultdict
from typing import List, Set, Dict, Tuple, Any
from processing.hashes import murmur3_32


def get_k_shingles(text: str, k: int = 3) -> Set[str]:
    """Extracts character k-grams (shingles) from text."""
    clean_text = text.lower().strip()
    if len(clean_text) < k:
        return {clean_text}
    return {clean_text[i:i + k] for i in range(len(clean_text) - k + 1)}


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Computes exact Jaccard similarity between two sets."""
    if not set_a and not set_b:
        return 1.0
    union_len = len(set_a.union(set_b))
    if union_len == 0:
        return 0.0
    return len(set_a.intersection(set_b)) / union_len


class MinHashLSH:
    """
    MinHash and LSH index for fast near-duplicate detection.
    num_hashes: total number of hash functions (m = b * r)
    num_bands: number of bands (b)
    rows_per_band: rows per band (r)
    """
    def __init__(self, num_bands: int = 16, rows_per_band: int = 4, shingle_k: int = 3):
        self.b = num_bands
        self.r = rows_per_band
        self.m = self.b * self.r  # total hash functions
        self.k = shingle_k
        self.buckets: List[Dict[int, List[int]]] = [defaultdict(list) for _ in range(self.b)]
        self.documents: List[str] = []
        self.signatures: List[List[int]] = []
        self.shingles_list: List[Set[str]] = []

    def _compute_signature(self, shingles: Set[str]) -> List[int]:
        """Computes MinHash signature vector of length m."""
        sig = [0xFFFFFFFF] * self.m
        for shingle in shingles:
            for seed in range(self.m):
                h = murmur3_32(shingle, seed=seed, signed=False)
                if h < sig[seed]:
                    sig[seed] = h
        return sig

    def index_documents(self, docs: List[str]):
        """Indexes a collection of URLs or threat strings into LSH bands."""
        self.documents = list(docs)
        self.signatures = []
        self.shingles_list = []
        self.buckets = [defaultdict(list) for _ in range(self.b)]

        for doc_id, doc in enumerate(docs):
            shingles = get_k_shingles(doc, self.k)
            self.shingles_list.append(shingles)
            sig = self._compute_signature(shingles)
            self.signatures.append(sig)

            # Insert into bands
            for band_idx in range(self.b):
                start = band_idx * self.r
                end = start + self.r
                band_tuple = tuple(sig[start:end])
                band_hash = hash(band_tuple)
                self.buckets[band_idx][band_hash].append(doc_id)

    def query(self, query_doc: str, threshold: float = 0.5) -> List[Dict[str, Any]]:
        """
        Finds all candidate documents with estimated Jaccard similarity >= threshold.
        """
        q_shingles = get_k_shingles(query_doc, self.k)
        q_sig = self._compute_signature(q_shingles)

        candidates = set()
        for band_idx in range(self.b):
            start = band_idx * self.r
            end = start + self.r
            band_tuple = tuple(q_sig[start:end])
            band_hash = hash(band_tuple)
            for cand_id in self.buckets[band_idx].get(band_hash, []):
                candidates.add(cand_id)

        results = []
        for cand_id in candidates:
            # Estimate similarity from MinHash signatures
            cand_sig = self.signatures[cand_id]
            sig_matches = sum(1 for i in range(self.m) if q_sig[i] == cand_sig[i])
            minhash_sim = sig_matches / self.m

            # True Jaccard similarity
            exact_sim = jaccard_similarity(q_shingles, self.shingles_list[cand_id])

            if exact_sim >= threshold:
                results.append({
                    "matched_id": cand_id,
                    "matched_document": self.documents[cand_id],
                    "exact_jaccard": round(exact_sim, 4),
                    "minhash_estimated_jaccard": round(minhash_sim, 4)
                })

        results.sort(key=lambda x: -x["exact_jaccard"])
        return results

    def find_all_clusters(self, threshold: float = 0.5) -> List[List[str]]:
        """Finds groups/clusters of near-duplicate documents across entire dataset."""
        n = len(self.documents)
        visited = set()
        clusters = []

        for i in range(n):
            if i in visited:
                continue
            matches = self.query(self.documents[i], threshold=threshold)
            cluster_ids = {i}
            for m in matches:
                cluster_ids.add(m["matched_id"])

            if len(cluster_ids) > 1:
                for cid in cluster_ids:
                    visited.add(cid)
                clusters.append([self.documents[cid] for cid in cluster_ids])

        return clusters


if __name__ == "__main__":
    urls = [
        "https://secure-paypal-login-verify.com/auth/login?user=1",
        "https://secure-paypal-login-verify.com/auth/login?user=2",
        "https://secure-paypal-login-verify.com/auth/login?session=urgent",
        "https://apple-id-verify-service.live/account/recovery",
        "https://apple-id-verify-service.live/account/confirm",
        "https://totally-normal-website.org/news/sports"
    ]
    lsh = MinHashLSH(num_bands=8, rows_per_band=4, shingle_k=3)
    lsh.index_documents(urls)
    clusters = lsh.find_all_clusters(threshold=0.6)
    print(f"Identified {len(clusters)} phishing campaign clusters:")
    for c in clusters:
        print("  ->", c)
