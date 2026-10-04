"""
Frequent Itemset Mining and Association Rules (FP-Growth / Apriori).
Discovers actionable attack patterns and causal associations:
{port 22, night_time, failed_auth} => {Brute Force Attack} with Support, Confidence, and Lift.
"""

from collections import defaultdict
from itertools import combinations
from typing import List, Dict, Set, Tuple, Any
import pandas as pd


def discretize_flow_to_tags(row: pd.Series) -> List[str]:
    """Converts a raw network flow row into discrete, descriptive tags."""
    tags = []
    
    # Port tag
    port = int(row.get("Dst_Port", 0))
    if port == 22:
        tags.append("port_22_SSH")
    elif port in [80, 8080]:
        tags.append("port_80_HTTP")
    elif port in [443, 8443]:
        tags.append("port_443_HTTPS")
    elif port == 3389:
        tags.append("port_3389_RDP")
    elif port in [21, 23]:
        tags.append("port_insecure_telnet_ftp")
    elif port == 53:
        tags.append("port_53_DNS")
    else:
        tags.append("port_ephemeral")

    # Time of day
    hour = int(row.get("Hour", 12))
    if hour >= 23 or hour <= 5:
        tags.append("time_late_night")
    elif 9 <= hour <= 17:
        tags.append("time_business_hours")
    else:
        tags.append("time_evening")

    # Packet volume
    pkts = int(row.get("Total_Fwd_Packets", 0)) + int(row.get("Total_Backward_Packets", 0))
    if pkts > 100:
        tags.append("volume_massive_flood")
    elif pkts < 4:
        tags.append("volume_micro_probe")
    else:
        tags.append("volume_moderate")

    # SYN flag
    if int(row.get("SYN_Flag_Count", 0)) > 0:
        tags.append("flag_syn_probe")

    # Payload length
    pkt_len = float(row.get("Packet_Length_Mean", 0))
    if pkt_len < 60:
        tags.append("payload_tiny_header_only")
    elif pkt_len > 500:
        tags.append("payload_large_data")

    # Label target
    label = str(row.get("Label", "BENIGN"))
    tags.append(f"TARGET_{label}")

    return tags


class AssociationRuleMiner:
    """Mines frequent itemsets and derives association rules with Support, Confidence, and Lift."""
    def __init__(self, min_support: float = 0.02, min_confidence: float = 0.5):
        self.min_support = min_support
        self.min_confidence = min_confidence
        self.rules: List[Dict[str, Any]] = []

    def fit(self, transactions: List[List[str]]) -> List[Dict[str, Any]]:
        """Mines association rules from transaction list."""
        n_trans = len(transactions)
        if n_trans == 0:
            return []

        # 1. Count 1-itemsets
        item_counts = defaultdict(int)
        for t in transactions:
            for item in set(t):
                item_counts[frozenset([item])] += 1

        # Filter by min_support
        frequent_itemsets = {}
        for itemset, cnt in item_counts.items():
            supp = cnt / n_trans
            if supp >= self.min_support:
                frequent_itemsets[itemset] = supp

        # 2. Count 2-itemsets
        pair_counts = defaultdict(int)
        for t in transactions:
            unique_t = sorted(list(set(t)))
            for c in combinations(unique_t, 2):
                pair_counts[frozenset(c)] += 1

        for pair, cnt in pair_counts.items():
            supp = cnt / n_trans
            if supp >= self.min_support:
                frequent_itemsets[pair] = supp

        # 3. Count 3-itemsets
        triplet_counts = defaultdict(int)
        for t in transactions:
            unique_t = sorted(list(set(t)))
            if len(unique_t) >= 3:
                for c in combinations(unique_t, 3):
                    triplet_counts[frozenset(c)] += 1

        for triplet, cnt in triplet_counts.items():
            supp = cnt / n_trans
            if supp >= self.min_support:
                frequent_itemsets[triplet] = supp

        # 4. Generate Association Rules: Antecedent -> Consequent (focus on TARGET_*)
        rules = []
        for itemset, supp_both in frequent_itemsets.items():
            if len(itemset) < 2:
                continue

            for item in itemset:
                # Target consequent
                if str(item).startswith("TARGET_"):
                    consequent = frozenset([item])
                    antecedent = itemset - consequent
                    supp_ante = frequent_itemsets.get(antecedent, 0)
                    supp_cons = frequent_itemsets.get(consequent, 0)

                    if supp_ante > 0 and supp_cons > 0:
                        conf = supp_both / supp_ante
                        lift = conf / supp_cons

                        if conf >= self.min_confidence:
                            ante_list = sorted([str(x) for x in antecedent])
                            target_label = str(list(consequent)[0]).replace("TARGET_", "")
                            
                            # Construct plain English description
                            ante_readable = ", ".join([a.replace("_", " ") for a in ante_list])
                            desc = f"When network traffic exhibits [{ante_readable}], it indicates a {target_label} attack {round(conf * 100)}% of the time ({round(lift, 1)}x baseline likelihood)."

                            rules.append({
                                "antecedent": ante_list,
                                "consequent": target_label,
                                "support": round(supp_both, 4),
                                "confidence": round(conf, 4),
                                "lift": round(lift, 2),
                                "plain_english": desc
                            })

        rules.sort(key=lambda x: (-x["lift"], -x["confidence"]))
        self.rules = rules
        return rules


if __name__ == "__main__":
    from ingestion.load_logs import generate_flow_logs
    df = generate_flow_logs(num_records=3000)
    txs = [discretize_flow_to_tags(row) for _, row in df.iterrows()]
    miner = AssociationRuleMiner(min_support=0.015, min_confidence=0.55)
    rules = miner.fit(txs)
    print(f"Discovered {len(rules)} association rules:")
    for r in rules[:5]:
        print(f"  * {r['plain_english']} [Conf: {r['confidence']*100:.1f}%, Lift: {r['lift']}]")
