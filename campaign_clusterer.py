#!/usr/bin/env python3
"""
Campaign Clusterer — Correlate honeypot attacker sessions into botnet campaigns.

Analyzes post-login behavior from the sacrificial VM to identify coordinated
attack campaigns by clustering IPs that share:
  - Identical credentials
  - Same malware drops (SHA256)
  - Same download URLs / C2 infrastructure
  - Same SSH keys installed
  - Same command sequences
  - Same ASN / hosting provider

Outputs campaign clusters to Elasticsearch and optionally MISP.

Usage:
    python3 campaign_clusterer.py                  # analyze last 7 days
    python3 campaign_clusterer.py --days 30        # analyze last 30 days
    python3 campaign_clusterer.py --reindex        # force reindex all clusters
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
import urllib3
urllib3.disable_warnings()

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
AGENT_NAME = os.environ.get("SACRIFICIAL_AGENT_NAME", "ds-prod-web01")
CLUSTER_INDEX = "campaign-clusters"
FILEBEAT_INDEX = ".ds-filebeat-*"
MALWARE_INDEX = "malware-analysis"

# Clustering weights — how much each signal contributes to "same campaign"
# CRITICAL: credentials alone are NOT enough. Leaked password lists are shared
# across unrelated botnets. Behavioral signals (malware, URLs, keys) are definitive.
WEIGHTS = {
    "same_malware_hash": 10,    # DEFINITIVE — same binary = same operator
    "same_download_url": 10,    # DEFINITIVE — same C2/staging server
    "same_ssh_key": 10,         # DEFINITIVE — same operator key
    "same_commands": 5,         # STRONG — identical post-login command sequence
    "same_subnet": 4,           # STRONG — sequential IPs = same infra
    "same_credentials": 1,      # WEAK — leaked lists shared across botnets
    "same_asn": 1,              # WEAK — VPS providers host many unrelated bots
    "timing_correlation": 1,    # WEAK — can be coincidence on popular targets
}
CLUSTER_THRESHOLD = 5  # minimum score — requires at least one strong signal


def es_query(index, body, size=10000):
    """Query Elasticsearch."""
    resp = requests.post(
        f"{ES_URL}/{index}/_search",
        json={**body, "size": size},
        headers={"Content-Type": "application/json"},
        timeout=60,
    )
    if resp.status_code == 200:
        return resp.json()
    return {"hits": {"hits": [], "total": {"value": 0}}}


def es_index(index, doc_id, body):
    """Index a document."""
    resp = requests.put(
        f"{ES_URL}/{index}/_doc/{doc_id}",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    return resp.status_code in (200, 201)


def es_create_index(index):
    """Create index with mapping if it doesn't exist."""
    # Delete and recreate to ensure clean mapping
    requests.delete(f"{ES_URL}/{index}", timeout=10)
    mapping = {
        "mappings": {
            "properties": {
                "campaign_id": {"type": "keyword"},
                "campaign_name": {"type": "keyword"},
                "first_seen": {"type": "date"},
                "last_seen": {"type": "date"},
                "indexed_at": {"type": "date"},
                "ip_count": {"type": "integer"},
                "session_count": {"type": "integer"},
                "ips": {"type": "keyword"},
                "asns": {"type": "keyword"},
                "countries": {"type": "keyword"},
                "credentials": {"type": "keyword"},
                "malware_hashes": {"type": "keyword"},
                "download_urls": {"type": "keyword"},
                "ssh_keys_installed": {"type": "keyword"},
                "command_fingerprint": {"type": "keyword"},
                "common_commands": {"type": "text"},
                "classification": {"type": "keyword"},
                "confidence": {"type": "keyword"},
                "cluster_signals": {"type": "text"},
                "ttps": {"type": "keyword"},
                "summary": {"type": "text"},
            }
        }
    }
    requests.put(f"{ES_URL}/{index}", json=mapping, timeout=10)


# ---------------------------------------------------------------------------
# Step 1: Extract sessions from ES
# ---------------------------------------------------------------------------

def extract_sessions(days=7):
    """Pull all successful login sessions with post-login behavior."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    print(f"[*] Extracting sessions from last {days} days...")

    # Get all successful password logins (external only)
    logins = es_query(FILEBEAT_INDEX, {
        "query": {"bool": {"must": [
            {"term": {"agent.name": AGENT_NAME}},
            {"match_phrase": {"message": "Accepted password"}},
            {"range": {"@timestamp": {"gte": since}}},
        ], "must_not": [
            {"match_phrase": {"message": "192.168."}},
        ]}},
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "message"],
    })

    sessions = {}  # keyed by IP
    login_pattern = re.compile(
        r'Accepted password for (\S+) from (\S+) port (\d+)'
    )

    # Build a PID→IP correlation map from sshd messages
    # "sshd[PID]: Accepted password for root from IP"
    pid_ip_map = {}

    for hit in logins["hits"]["hits"]:
        msg = hit["_source"]["message"]
        ts = hit["_source"]["@timestamp"]
        m = login_pattern.search(msg)
        if not m:
            continue
        user, ip, port = m.groups()

        # Extract sshd PID for session correlation
        pid_match = re.search(r'sshd\[(\d+)\]', msg)
        if pid_match:
            pid_ip_map[pid_match.group(1)] = ip

        if ip not in sessions:
            sessions[ip] = {
                "ip": ip,
                "first_seen": ts,
                "last_seen": ts,
                "login_count": 0,
                "credentials": set(),
                "commands": [],
                "download_urls": set(),
                "malware_hashes": set(),
                "ssh_keys": set(),
                "ssh_client": "",
                "session_duration": [],
                "login_timestamps": [],
            }
        sessions[ip]["login_count"] += 1
        sessions[ip]["last_seen"] = ts
        sessions[ip]["login_timestamps"].append(ts)
        # Don't add generic "root:*" — only track specific credentials from failures

    print(f"  Found {len(sessions)} unique IPs with {sum(s['login_count'] for s in sessions.values())} logins")

    # Get credentials attempted (from PAM/auth failures before success)
    cred_attempts = es_query(FILEBEAT_INDEX, {
        "query": {"bool": {"must": [
            {"term": {"agent.name": AGENT_NAME}},
            {"bool": {"should": [
                {"match_phrase": {"message": "Failed password"}},
                {"match_phrase": {"message": "Invalid user"}},
            ]}},
            {"range": {"@timestamp": {"gte": since}}},
        ], "must_not": [
            {"match_phrase": {"message": "192.168."}},
        ]}},
        "_source": ["@timestamp", "message"],
    })

    cred_pattern = re.compile(
        r'(?:Failed password|Invalid user)\s+(?:for\s+(?:invalid user\s+)?)?(\S+)\s+from\s+(\S+)'
    )
    for hit in cred_attempts["hits"]["hits"]:
        msg = hit["_source"]["message"]
        m = cred_pattern.search(msg)
        if m:
            user, ip = m.groups()
            if ip in sessions:
                sessions[ip]["credentials"].add(f"{user}:attempted")

    # Also check for honeypot PAM logs which capture the actual password
    pam_logins = es_query(FILEBEAT_INDEX, {
        "query": {"bool": {"must": [
            {"term": {"agent.name": AGENT_NAME}},
            {"match_phrase": {"message": "honeypot_pam"}},
            {"range": {"@timestamp": {"gte": since}}},
        ]}},
        "_source": ["@timestamp", "message"],
    })
    pam_cred_pattern = re.compile(r'user=(\S+)\s+password=(\S+)\s+from=(\S+)')
    for hit in pam_logins["hits"]["hits"]:
        msg = hit["_source"]["message"]
        m = pam_cred_pattern.search(msg)
        if m:
            user, passwd, ip = m.groups()
            if ip in sessions:
                sessions[ip]["credentials"].add(f"{user}:{passwd}")

    # Get post-login commands from auditd proctitle
    proctitles = es_query(FILEBEAT_INDEX, {
        "query": {"bool": {"must": [
            {"term": {"agent.name": AGENT_NAME}},
            {"match_phrase": {"message": "proctitle="}},
            {"range": {"@timestamp": {"gte": since}}},
        ], "must_not": [
            {"match_phrase": {"message": "honeypot"}},
            {"match_phrase": {"message": "filebeat"}},
            {"match_phrase": {"message": "auditd"}},
        ]}},
        "_source": ["@timestamp", "message"],
    })

    hex_pattern = re.compile(r'proctitle=([0-9A-Fa-f]{4,})')
    # Collect all commands centrally — can't easily correlate to IP without ppid→sshd→IP chain
    # Instead, group by timestamp proximity to login events
    all_commands = []
    for hit in proctitles["hits"]["hits"]:
        msg = hit["_source"]["message"]
        ts = hit["_source"]["@timestamp"]
        m = hex_pattern.search(msg)
        if m:
            try:
                decoded = bytes.fromhex(m.group(1)).decode("utf-8", errors="replace").replace("\x00", " ").strip()
                if decoded and len(decoded) > 2:
                    all_commands.append((ts, decoded))
            except Exception:
                pass
    # Note: command→IP correlation requires ppid chain which auditd tracks but
    # is complex to parse. For now, commands are not per-IP correlated.
    # The clustering will rely on malware hashes, download URLs, SSH keys, ASN, and credentials.

    # Get download URLs from messages (wget, curl, tftp)
    downloads = es_query(FILEBEAT_INDEX, {
        "query": {"bool": {"must": [
            {"term": {"agent.name": AGENT_NAME}},
            {"bool": {"should": [
                {"match_phrase": {"message": "wget"}},
                {"match_phrase": {"message": "curl"}},
                {"match_phrase": {"message": "tftp"}},
                {"match_phrase": {"message": "http://"}},
                {"match_phrase": {"message": "ftp://"}},
            ]}},
            {"range": {"@timestamp": {"gte": since}}},
        ]}},
        "_source": ["@timestamp", "message"],
    })

    url_pattern = re.compile(r'(https?://\S+|ftp://\S+)')
    ip_in_msg = re.compile(r'from\s+(\d+\.\d+\.\d+\.\d+)')
    for hit in downloads["hits"]["hits"]:
        msg = hit["_source"]["message"]
        urls = url_pattern.findall(msg)
        # Try to correlate via IP in the same message or PID
        pid_match = re.search(r'sshd\[(\d+)\]', msg)
        correlated_ip = None
        if pid_match and pid_match.group(1) in pid_ip_map:
            correlated_ip = pid_ip_map[pid_match.group(1)]
        if not correlated_ip:
            ip_match = ip_in_msg.search(msg)
            if ip_match and ip_match.group(1) in sessions:
                correlated_ip = ip_match.group(1)
        for url in urls:
            url = url.rstrip("'\")")
            if correlated_ip and correlated_ip in sessions:
                sessions[correlated_ip]["download_urls"].add(url)

    # Get SSH key installations
    ssh_keys = es_query(FILEBEAT_INDEX, {
        "query": {"bool": {"must": [
            {"term": {"agent.name": AGENT_NAME}},
            {"match_phrase": {"message": "authorized_keys"}},
            {"range": {"@timestamp": {"gte": since}}},
        ], "must_not": [
            {"match_phrase": {"message": "192.168."}},
            {"match_phrase": {"message": "vYE1Gs2Ci3Q2WJ"}},  # our own key
        ]}},
        "_source": ["@timestamp", "message"],
    })

    key_pattern = re.compile(r'SHA256:(\S+)')
    for hit in ssh_keys["hits"]["hits"]:
        msg = hit["_source"]["message"]
        m = key_pattern.search(msg)
        if m:
            # Correlate via PID or IP in message
            pid_match = re.search(r'sshd\[(\d+)\]', msg)
            correlated_ip = None
            if pid_match and pid_match.group(1) in pid_ip_map:
                correlated_ip = pid_ip_map[pid_match.group(1)]
            if correlated_ip and correlated_ip in sessions:
                sessions[correlated_ip]["ssh_keys"].add(m.group(1))

    # Get malware hashes from the malware-analysis index
    malware = es_query(MALWARE_INDEX, {
        "query": {"range": {"indexed_at": {"gte": since}}},
        "_source": ["sha256", "source_ip", "classification", "download_url"],
    }, size=500)

    for hit in malware["hits"]["hits"]:
        src = hit["_source"]
        sha = src.get("sha256", "")
        src_ip = src.get("source_ip", "")
        dl_url = src.get("download_url", "")
        if src_ip and src_ip in sessions:
            sessions[src_ip]["malware_hashes"].add(sha[:16])
            if dl_url:
                sessions[src_ip]["download_urls"].add(dl_url)

    # Enrich with ASN/geo
    print(f"  Enriching {len(sessions)} IPs with ASN/geo data...")
    for ip, sess in sessions.items():
        sess["asn"] = ""
        sess["country"] = ""
        sess["org"] = ""
        try:
            # Use ip-api.com for free lookups (rate limited)
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,as,isp",
                timeout=5,
            )
            if resp.status_code == 200:
                geo = resp.json()
                if geo.get("status") == "success":
                    sess["asn"] = geo.get("as", "").split()[0] if geo.get("as") else ""
                    sess["country"] = geo.get("countryCode", "")
                    sess["org"] = geo.get("org", "") or geo.get("isp", "")
            time.sleep(0.5)  # rate limit
        except Exception:
            pass

    # Convert sets to lists for JSON serialization
    for sess in sessions.values():
        sess["credentials"] = sorted(sess["credentials"])
        sess["download_urls"] = sorted(sess["download_urls"])
        sess["malware_hashes"] = sorted(sess["malware_hashes"])
        sess["ssh_keys"] = sorted(sess["ssh_keys"])
        sess["commands"] = sess["commands"][:50]  # cap

    return sessions


# ---------------------------------------------------------------------------
# Step 2: Compute similarity and cluster
# ---------------------------------------------------------------------------

def compute_similarity(sess_a, sess_b):
    """Compute a similarity score between two sessions.

    Philosophy: behavioral evidence (same malware, same URLs, same keys) is definitive.
    Credential overlap alone is weak — leaked password lists are shared across unrelated
    botnets. We require at least one strong signal to cluster.
    """
    score = 0
    signals = []
    has_strong_signal = False

    # --- DEFINITIVE signals (any one of these = confirmed same campaign) ---

    # Malware hash overlap — same binary = same operator
    mal_a = set(sess_a["malware_hashes"])
    mal_b = set(sess_b["malware_hashes"])
    if mal_a and mal_b and (mal_a & mal_b):
        score += WEIGHTS["same_malware_hash"]
        has_strong_signal = True
        signals.append(f"DEFINITIVE shared_malware: {', '.join(list(mal_a & mal_b)[:3])}")

    # Download URL overlap — same C2/staging = same operator
    urls_a = set(sess_a["download_urls"])
    urls_b = set(sess_b["download_urls"])
    if urls_a and urls_b and (urls_a & urls_b):
        score += WEIGHTS["same_download_url"]
        has_strong_signal = True
        signals.append(f"DEFINITIVE shared_download_urls: {', '.join(list(urls_a & urls_b)[:3])}")

    # SSH key overlap — same key = same operator
    keys_a = set(sess_a["ssh_keys"])
    keys_b = set(sess_b["ssh_keys"])
    if keys_a and keys_b and (keys_a & keys_b):
        score += WEIGHTS["same_ssh_key"]
        has_strong_signal = True
        signals.append(f"DEFINITIVE shared_ssh_key: {', '.join(list(keys_a & keys_b)[:2])}")

    # --- STRONG signals (need corroboration) ---

    # Command sequence fingerprint — same post-login behavior
    cmds_a = _command_fingerprint(sess_a["commands"])
    cmds_b = _command_fingerprint(sess_b["commands"])
    if cmds_a and cmds_b and cmds_a == cmds_b:
        score += WEIGHTS["same_commands"]
        has_strong_signal = True
        signals.append(f"STRONG identical_command_sequence ({cmds_a})")

    # Subnet proximity — IPs in the same /24 = likely same infrastructure
    try:
        net_a = ipaddress.ip_address(sess_a["ip"])
        net_b = ipaddress.ip_address(sess_b["ip"])
        # Same /24 subnet
        if int(net_a) >> 8 == int(net_b) >> 8:
            score += WEIGHTS["same_subnet"]
            has_strong_signal = True
            signals.append(f"STRONG same_/24_subnet: {sess_a['ip']}, {sess_b['ip']}")
        # Same /16 subnet (weaker)
        elif int(net_a) >> 16 == int(net_b) >> 16:
            score += WEIGHTS["same_subnet"] // 2
            signals.append(f"same_/16_subnet")
    except Exception:
        pass

    # --- WEAK signals (supporting evidence only, never sufficient alone) ---

    # Credential overlap — WEAK because leaked lists are shared
    creds_a = set(sess_a["credentials"])
    creds_b = set(sess_b["credentials"])
    # Only count non-trivial creds (not just "root:attempted")
    creds_a_real = {c for c in creds_a if c != "root:attempted" and ":attempted" not in c}
    creds_b_real = {c for c in creds_b if c != "root:attempted" and ":attempted" not in c}
    if creds_a_real and creds_b_real and (creds_a_real & creds_b_real):
        score += WEIGHTS["same_credentials"]
        overlap = creds_a_real & creds_b_real
        signals.append(f"weak shared_specific_creds: {', '.join(list(overlap)[:3])}")
    elif creds_a & creds_b:
        # Generic credential overlap (root:attempted) — minimal weight
        nontrivial = {c for c in (creds_a & creds_b) if "root:attempted" not in c}
        if nontrivial:
            score += WEIGHTS["same_credentials"]
            signals.append(f"weak shared_creds: {', '.join(list(nontrivial)[:3])}")

    # ASN match — WEAK because big cloud providers host thousands of unrelated bots
    if sess_a.get("asn") and sess_b.get("asn") and sess_a["asn"] == sess_b["asn"]:
        # Only count if it's NOT a mega-provider
        mega_asns = {"AS14061", "AS16276", "AS24940", "AS63949", "AS8075", "AS396982",
                     "AS13335", "AS20473", "AS16509", "AS15169"}  # DO, OVH, Hetzner, Azure, etc.
        if sess_a["asn"] not in mega_asns:
            score += WEIGHTS["same_asn"]
            signals.append(f"weak same_asn: {sess_a['asn']} ({sess_a.get('org','')})")

    # Timing correlation — WEAK, logins within 30 seconds
    try:
        from dateutil.parser import parse as parse_dt
        # Check all login timestamps, not just last_seen
        timestamps_a = sess_a.get("login_timestamps", [sess_a["last_seen"]])
        timestamps_b = sess_b.get("login_timestamps", [sess_b["last_seen"]])
        for ta in timestamps_a[-5:]:  # check last 5 logins
            for tb in timestamps_b[-5:]:
                t_a = parse_dt(ta)
                t_b = parse_dt(tb)
                if abs((t_a - t_b).total_seconds()) < 30:
                    score += WEIGHTS["timing_correlation"]
                    signals.append(f"weak timing_correlated (<30s)")
                    break
            else:
                continue
            break
    except Exception:
        pass

    return score, signals


def _command_fingerprint(commands):
    """Create a normalized fingerprint of a command sequence."""
    if not commands:
        return ""
    # Normalize: strip paths, IPs, sort
    normalized = []
    for cmd in commands[:20]:
        # Remove IPs, paths, hashes — keep just the command structure
        cmd = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', cmd)
        cmd = re.sub(r'/tmp/\S+', '/tmp/FILE', cmd)
        cmd = re.sub(r'[a-f0-9]{32,}', 'HASH', cmd)
        normalized.append(cmd.strip().lower())
    return hashlib.md5("|".join(sorted(set(normalized))).encode()).hexdigest()[:12]


def cluster_sessions(sessions):
    """Group sessions into campaigns using union-find clustering."""
    ips = list(sessions.keys())
    parent = {ip: ip for ip in ips}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    all_signals = defaultdict(list)

    print(f"[*] Computing pairwise similarity for {len(ips)} IPs...")
    comparisons = 0
    for i in range(len(ips)):
        for j in range(i + 1, len(ips)):
            score, signals = compute_similarity(sessions[ips[i]], sessions[ips[j]])
            if score >= CLUSTER_THRESHOLD:
                union(ips[i], ips[j])
                all_signals[(ips[i], ips[j])] = signals
                comparisons += 1

    # Group by cluster root
    clusters = defaultdict(list)
    for ip in ips:
        clusters[find(ip)].append(ip)

    print(f"  {comparisons} pairs exceeded threshold, {len(clusters)} clusters formed")
    return clusters, all_signals


# ---------------------------------------------------------------------------
# Step 3: Build campaign objects
# ---------------------------------------------------------------------------

def build_campaigns(clusters, sessions, all_signals):
    """Build campaign objects from clusters."""
    campaigns = []

    for cluster_id, (root, ips) in enumerate(sorted(clusters.items(), key=lambda x: -len(x[1]))):
        if len(ips) < 2:
            continue  # skip singletons — not a campaign

        # Aggregate session data
        all_creds = set()
        all_hashes = set()
        all_urls = set()
        all_keys = set()
        all_cmds = []
        all_asns = set()
        all_countries = set()
        all_orgs = set()
        first_seen = None
        last_seen = None
        total_logins = 0

        for ip in ips:
            sess = sessions[ip]
            all_creds.update(sess["credentials"])
            all_hashes.update(sess["malware_hashes"])
            all_urls.update(sess["download_urls"])
            all_keys.update(sess["ssh_keys"])
            all_cmds.extend(sess["commands"][:10])
            if sess.get("asn"):
                all_asns.add(sess["asn"])
            if sess.get("country"):
                all_countries.add(sess["country"])
            if sess.get("org"):
                all_orgs.add(sess["org"])
            total_logins += sess["login_count"]

            if not first_seen or sess["first_seen"] < first_seen:
                first_seen = sess["first_seen"]
            if not last_seen or sess["last_seen"] > last_seen:
                last_seen = sess["last_seen"]

        # Collect signals that linked these IPs
        signals = set()
        for (a, b), sigs in all_signals.items():
            if a in ips or b in ips:
                signals.update(sigs)

        # Classify confidence based on signal strength
        has_definitive = any("DEFINITIVE" in s for s in signals)
        has_strong = any("STRONG" in s for s in signals)
        weak_only = all("weak" in s.lower() or "same_asn" in s for s in signals)
        confidence = ("confirmed" if has_definitive else
                      "high" if has_strong and len(ips) >= 3 else
                      "medium" if has_strong else
                      "low")

        # Classify campaign type
        if any("malware" in s for s in signals):
            classification = "malware_dropper"
        elif any("ssh_key" in s for s in signals):
            classification = "ssh_backdoor"
        elif total_logins > len(ips) * 3:
            classification = "credential_harvester"
        else:
            classification = "scanner"

        # Generate campaign name
        primary_country = sorted(all_countries)[0] if all_countries else "UNK"
        campaign_name = f"CAMPAIGN-{primary_country}-{cluster_id:03d}"

        # Identify TTPs
        ttps = []
        if all_creds:
            ttps.append("T1110.001")  # Brute Force: Password Guessing
        if all_hashes:
            ttps.append("T1105")      # Ingress Tool Transfer
        if all_keys:
            ttps.append("T1098.004")  # Account Manipulation: SSH Authorized Keys
        if all_urls:
            ttps.append("T1071.001")  # Application Layer Protocol: Web
        if any("wget" in c or "curl" in c for c in all_cmds):
            ttps.append("T1059.004")  # Command and Scripting Interpreter: Unix Shell

        # Build summary
        orgs_str = ", ".join(sorted(all_orgs)[:3]) if all_orgs else "unknown providers"
        summary = (
            f"{len(ips)} IPs from {orgs_str} ({', '.join(sorted(all_countries))}) "
            f"sharing {', '.join(sorted(signals)[:5])}. "
            f"{total_logins} total logins over {len(ips)} source IPs. "
            f"Classification: {classification} ({confidence} confidence)."
        )

        campaign_id = hashlib.sha256(
            f"{sorted(ips)}".encode()
        ).hexdigest()[:16]

        campaign = {
            "campaign_id": campaign_id,
            "campaign_name": campaign_name,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "indexed_at": datetime.now(timezone.utc).isoformat(),
            "ip_count": len(ips),
            "session_count": total_logins,
            "ips": sorted(ips),
            "asns": sorted(all_asns),
            "countries": sorted(all_countries),
            "orgs": sorted(all_orgs),
            "credentials": sorted(all_creds)[:20],
            "malware_hashes": sorted(all_hashes)[:20],
            "download_urls": sorted(all_urls)[:20],
            "ssh_keys_installed": sorted(all_keys)[:10],
            "command_fingerprint": _command_fingerprint(all_cmds),
            "common_commands": "\n".join(sorted(set(all_cmds))[:20]),
            "classification": classification,
            "confidence": confidence,
            "cluster_signals": "\n".join(sorted(signals)),
            "ttps": ttps,
            "summary": summary,
        }
        campaigns.append(campaign)

    return campaigns


# ---------------------------------------------------------------------------
# Step 4: Index to ES
# ---------------------------------------------------------------------------

def index_campaigns(campaigns):
    """Index campaign clusters to Elasticsearch."""
    es_create_index(CLUSTER_INDEX)
    indexed = 0
    for c in campaigns:
        if es_index(CLUSTER_INDEX, c["campaign_id"], c):
            indexed += 1
    print(f"[+] Indexed {indexed}/{len(campaigns)} campaigns to {CLUSTER_INDEX}")
    return indexed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Cluster honeypot attacker sessions into campaigns")
    parser.add_argument("--days", type=int, default=7, help="Days to analyze (default: 7)")
    parser.add_argument("--reindex", action="store_true", help="Force reindex all clusters")
    parser.add_argument("--dry-run", action="store_true", help="Analyze but don't index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    sessions = extract_sessions(days=args.days)
    if not sessions:
        print("[!] No sessions found")
        return

    clusters, signals = cluster_sessions(sessions)

    campaigns = build_campaigns(clusters, sessions, signals)
    campaigns.sort(key=lambda c: -c["ip_count"])

    print(f"\n{'='*70}")
    print(f"  CAMPAIGN CLUSTERS — {len(campaigns)} identified")
    print(f"{'='*70}")

    for c in campaigns:
        print(f"\n  {c['campaign_name']} ({c['confidence']} confidence)")
        print(f"    IPs:           {c['ip_count']} ({', '.join(c['ips'][:5])}{'...' if c['ip_count'] > 5 else ''})")
        print(f"    Sessions:      {c['session_count']}")
        print(f"    Countries:     {', '.join(c['countries'])}")
        print(f"    ASNs:          {', '.join(c['asns'][:3])}")
        print(f"    Providers:     {', '.join(c['orgs'][:3])}")
        print(f"    Classification: {c['classification']}")
        print(f"    Signals:       {c['cluster_signals'][:200]}")
        if c["malware_hashes"]:
            print(f"    Malware:       {', '.join(c['malware_hashes'][:3])}")
        if c["download_urls"]:
            print(f"    Download URLs: {', '.join(c['download_urls'][:3])}")
        if c["ttps"]:
            print(f"    ATT&CK:        {', '.join(c['ttps'])}")

    if not args.dry_run and campaigns:
        print(f"\n[*] Indexing campaigns to Elasticsearch...")
        index_campaigns(campaigns)

    print(f"\n[+] Done. {len(campaigns)} campaigns, {sum(c['ip_count'] for c in campaigns)} IPs clustered.")


if __name__ == "__main__":
    main()
