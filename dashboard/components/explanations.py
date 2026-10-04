"""
Threat Intelligence Explanations & MITRE ATT&CK Mappings.
Provides plain-English everyday analogies for non-technical stakeholders
and formal MITRE ATT&CK technique breakdowns for security teams.
"""

ATTACK_KNOWLEDGE_BASE = {
    "Phishing": {
        "analogy": "A fake bank letter asking for your PIN",
        "plain_explanation": "Attackers send fraudulent communications (emails, fake login sites) that pretend to come from trusted companies (PayPal, Google, Bank) to trick you into revealing passwords or credit cards.",
        "mitre_id": "T1566 - Phishing",
        "impact": "Account takeover, identity theft, unauthorized credential theft.",
        "defense": "Deploy multi-factor authentication (MFA), email domain verification (DMARC/SPF), and employee awareness training.",
        "severity": "High"
    },
    "Malware": {
        "analogy": "A trojan horse gift",
        "plain_explanation": "Harmful software hidden inside seemingly harmless files (downloads, email attachments) that secretly damages, spies on, or takes over your computer once opened.",
        "mitre_id": "T1204 - User Execution: Malicious File",
        "impact": "System corruption, data leakage, surveillance.",
        "defense": "Endpoint Detection & Response (EDR), strict application whitelisting, routine patch management.",
        "severity": "High"
    },
    "Ransomware": {
        "analogy": "Someone locks your house and demands money to give you the keys back",
        "plain_explanation": "Criminals gain access to your systems, encrypt all vital files so you cannot open them, and extort huge sums of money (often millions in cryptocurrency) to restore access.",
        "mitre_id": "T1486 - Data Encrypted for Impact",
        "impact": "Total business shutdown, catastrophic data loss, reputational damage.",
        "defense": "Immutable offline air-gapped backups, network micro-segmentation, rapid incident isolation.",
        "severity": "Critical"
    },
    "Botnet / C2": {
        "analogy": "A remote-controlled zombie army",
        "plain_explanation": "Malware infects thousands of computers and smart devices worldwide, turning them into 'bots' that quietly obey commands from a central hacker server (the C2) to launch coordinated strikes.",
        "mitre_id": "T1071 - Application Layer Protocol: C2",
        "impact": "Distributed attacks, proxy relays, internal lateral movement.",
        "defense": "Threat intelligence IP/domain blocking (Feodo Tracker, Bloom filter edge firewalls), egress traffic monitoring.",
        "severity": "Critical"
    },
    "DDoS": {
        "analogy": "Thousands of people blocking a shop entrance so real customers cannot enter",
        "plain_explanation": "Attackers flood a web server with millions of fake requests at the same second until the server is overwhelmed, runs out of memory, and crashes for everyone.",
        "mitre_id": "T1498 - Network Denial of Service",
        "impact": "Website downtime, service unavailability, revenue loss.",
        "defense": "Cloud DDoS protection (Cloudflare/Akamai), rate limiting, SYN flood cookies, BGP scrubbing centers.",
        "severity": "High"
    },
    "Brute Force": {
        "analogy": "Trying every key on a massive keyring until one unlocks the door",
        "plain_explanation": "Automated scripts guess common usernames and passwords hundreds of times per second against SSH, RDP, or login screens until they crack the right password.",
        "mitre_id": "T1110 - Brute Force",
        "impact": "Unauthorized administrative shell access, initial network breach.",
        "defense": "Disable public SSH/RDP (use VPN/Zero Trust), enforce strong passwords, account lockout after 5 attempts, Fail2Ban.",
        "severity": "High"
    },
    "Port Scan": {
        "analogy": "A burglar walking down the street checking every door and window to see which is unlocked",
        "plain_explanation": "Attackers send quick probe packets across all 65,535 network ports to map out which services (SSH, web, database) are running and might have vulnerable versions.",
        "mitre_id": "T1046 - Network Service Discovery",
        "impact": "Reconnaissance leading to targeted exploitation of discovered services.",
        "defense": "Stealth firewall rules, close unused ports, IPS automated IP blacklisting upon scan detection.",
        "severity": "Medium"
    },
    "Web Attack": {
        "analogy": "Writing a trick command inside a standard form box",
        "plain_explanation": "Attackers enter SQL queries or malicious code directly into search boxes or login forms to fool the backend database into dumping confidential customer data.",
        "mitre_id": "T1190 - Exploit Public-Facing Application",
        "impact": "Database exfiltration, unauthorized administrative data modification.",
        "defense": "Web Application Firewall (WAF), parameterized SQL queries, rigorous input sanitization.",
        "severity": "High"
    },
    "Exploited Vulnerability": {
        "analogy": "A known broken lock on your front door that everyone knows about",
        "plain_explanation": "A flaw discovered in widely used software (like Log4j or Citrix) that security agencies catalog in CISA KEV because active criminals are actively breaking in using it.",
        "mitre_id": "T1203 - Exploitation for Client Execution",
        "impact": "Remote code execution, full host takeover.",
        "defense": "Immediate patching of CISA KEV cataloged vulnerabilities, virtual patching via IPS.",
        "severity": "Critical"
    }
}

ALGORITHM_EXPLANATIONS = {
    "Bloom Filter": {
        "title": "Bloom Filter (Fast Membership Testing)",
        "question": "Is this IP address among the 10 million known criminal servers?",
        "plain_how": "Instead of checking a massive spreadsheet line-by-line (which is slow and eats gigabytes of RAM), a Bloom filter turns each address into a few math fingerprints and flips bits in a tiny memory strip. It checks whether an IP is malicious in less than a microsecond using 98% less memory, with 0% risk of missing a real criminal!",
        "analogy": "Like a bouncer with a high-speed VIP stamp rather than reading a 10,000-page book for every person entering the club."
    },
    "DGIM": {
        "title": "DGIM Algorithm (Counting in Sliding Windows)",
        "question": "How many attacks hit us in the last 15 minutes?",
        "plain_how": "Storing every single packet from an infinite high-speed stream will quickly crash any computer. DGIM groups recent attacks into smart exponential buckets (sizes 1, 2, 4, 8...). It counts millions of recent attacks using almost zero memory, guaranteeing the count is never off by more than half!",
        "analogy": "Like an odometer that records recent mileage by grouping trips into exponentially larger odometer buckets."
    },
    "Flajolet-Martin": {
        "title": "Flajolet-Martin (Unique Attacker Counting)",
        "question": "How many unique attacker computers tried to hack us today?",
        "plain_how": "Normally, counting unique items requires keeping every IP in a giant set. Flajolet-Martin looks at the rarest patterns of coin flips (trailing zeros) in hashed IPs. By observing the rarest pattern seen, it estimates with high accuracy how many distinct hackers appeared—using just a handful of bytes!",
        "analogy": "Like estimating how many people are in a stadium by asking for someone whose birthday is Feb 29 (a rare event)."
    },
    "Count-Min Sketch": {
        "title": "Count-Min Sketch (Top Talkers & Ports)",
        "question": "Which network ports are being hammered the hardest right now?",
        "plain_how": "Maintains a compact 2D grid of counters. Incoming events hash into grid cells. To ask how many times Port 22 was hit, it checks the corresponding cells and takes the minimum, guaranteeing it never underestimates traffic.",
        "analogy": "A multi-lane toll booth counter that tracks traffic distribution across dozens of lanes simultaneously with fixed counters."
    },
    "MinHash + LSH": {
        "title": "MinHash & LSH (Finding Copycat Phishing Sites)",
        "question": "Which fake phishing websites belong to the same scam campaign?",
        "plain_how": "Scammers change a few words or parameters in URLs to evade filters. MinHash breaks text into character shingles and compresses them into compact signatures. Locality Sensitive Hashing groups similar signatures into identical buckets without comparing every URL against every other URL ($N^2$).",
        "analogy": "Like matching fingerprints by looking at key ridge loops rather than scanning every microscopic pore."
    },
    "PageRank": {
        "title": "PageRank (Pinpointing Cyber Kingpins)",
        "question": "Which criminal server is the mastermind behind the botnet?",
        "plain_how": "Threat actors operate complex webs of hacked routers, intermediary domains, and C2 servers. By modeling this as a graph and running Google's PageRank algorithm, we identify the 'kingpin' infrastructure nodes whose takedown disrupts the largest number of attacks.",
        "analogy": "Like uncovering the head of a criminal syndicate by analyzing who receives calls from all the low-level operatives."
    }
}
