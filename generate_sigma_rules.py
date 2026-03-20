#!/usr/bin/env python3
"""
Sigma Rule Generator — Convert analysis results to Sigma detection rules.

Reads malware analysis results from Elasticsearch and generates
Sigma-format detection rules that can be shared with the community
or imported into SIEMs.

Usage:
    python3 generate_sigma_rules.py                    # generate for all samples
    python3 generate_sigma_rules.py <sha256>           # specific sample
    python3 generate_sigma_rules.py --latest           # most recent sample

Output: /home/legs/reports/sigma_rules/
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

ES_URL = "http://localhost:9200"
RESULT_INDEX = "malware-analysis"
OUTPUT_DIR = Path("/home/legs/reports/sigma_rules")


def get_sample(sha256):
    resp = requests.get(f"{ES_URL}/{RESULT_INDEX}/_doc/{sha256}", timeout=10)
    if resp.status_code == 200 and resp.json().get("found"):
        return resp.json()["_source"]
    return {}


def get_latest():
    resp = requests.post(f"{ES_URL}/{RESULT_INDEX}/_search", json={
        "size": 1, "sort": [{"indexed_at": "desc"}],
    }, timeout=10)
    hits = resp.json().get("hits", {}).get("hits", [])
    return hits[0]["_source"] if hits else {}


def get_all():
    resp = requests.post(f"{ES_URL}/{RESULT_INDEX}/_search", json={
        "size": 100, "sort": [{"indexed_at": "desc"}],
    }, timeout=10)
    return [h["_source"] for h in resp.json().get("hits", {}).get("hits", [])]


def sanitize_name(s):
    return re.sub(r'[^a-zA-Z0-9_]', '_', s)[:50]


def generate_sigma_rules(sample: dict) -> list[dict]:
    """Generate Sigma rules from a single sample's analysis."""
    sha256 = sample.get("sha256", "unknown")
    classification = sample.get("classification", "unknown")
    severity = sample.get("severity", "medium")
    file_type = sample.get("file_type", "unknown")
    strings = sample.get("interesting_strings", [])
    yara = sample.get("yara_matches", [])
    dyn = sample.get("dynamic_analysis", {}) or {}
    ghidra = sample.get("ghidra") or {}

    sigma_level = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(severity, "medium")
    rules = []
    date = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    # --- Rule 1: Network IOC detection (C2 IPs and domains) ---
    c2_ips = []
    c2_domains = []
    c2_urls = []

    for s in strings:
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', s)
        if ip_match:
            ip = ip_match.group(1)
            if not ip.startswith(("10.", "192.168.", "127.", "0.", "255.")):
                c2_ips.append(ip)
        url_match = re.search(r'(https?://\S+)', s)
        if url_match:
            c2_urls.append(url_match.group(1).rstrip(")'\""))

    for d in dyn.get("dns_queries", []):
        c2_domains.append(d)
    for c in dyn.get("outbound_connections", []):
        c2_ips.append(c["ip"])

    c2_ips = list(set(c2_ips))[:20]
    c2_domains = list(set(c2_domains))[:20]
    c2_urls = list(set(c2_urls))[:20]

    if c2_ips or c2_domains:
        network_rule = {
            "title": f"ELKIE Honeypot — {classification.title()} C2 Communication ({sha256[:8]})",
            "id": f"elkie-{sha256[:16]}-network",
            "status": "experimental",
            "description": f"Detects network communication to C2 infrastructure observed in {classification} sample {sha256[:16]}. Captured by ELKIE SOC honeypot lab.",
            "author": "ELKIE SOC (automated)",
            "date": date,
            "tags": [
                f"attack.command_and_control",
                "attack.t1071",
            ],
            "logsource": {
                "category": "firewall",
            },
            "detection": {},
            "level": sigma_level,
            "falsepositives": ["Legitimate traffic to these IPs/domains"],
            "references": [
                f"https://www.virustotal.com/gui/file/{sha256}",
                f"https://bazaar.abuse.ch/sample/{sha256}/",
            ],
        }

        detection = {}
        conditions = []

        if c2_ips:
            detection["dst_ip"] = {"DestinationIp": c2_ips}
            conditions.append("dst_ip")

        if c2_domains:
            detection["dns"] = {"QueryName|endswith": c2_domains}
            conditions.append("dns")

        detection["condition"] = " or ".join(conditions) if len(conditions) > 1 else conditions[0]
        network_rule["detection"] = detection
        rules.append(network_rule)

    # --- Rule 2: Process execution detection ---
    suspicious_cmds = []
    for s in strings:
        if any(kw in s.lower() for kw in ["wget", "curl", "chmod", "crontab", "/tmp/", "/dev/shm",
                                            "base64", "eval", "nc ", "ncat", "/etc/shadow",
                                            "xmrig", "stratum", "pool."]):
            # Clean for Sigma
            clean = s.strip()[:100]
            if clean:
                suspicious_cmds.append(clean)

    if suspicious_cmds:
        proc_rule = {
            "title": f"ELKIE Honeypot — {classification.title()} Process Execution ({sha256[:8]})",
            "id": f"elkie-{sha256[:16]}-process",
            "status": "experimental",
            "description": f"Detects suspicious process execution patterns from {classification} sample {sha256[:16]}.",
            "author": "ELKIE SOC (automated)",
            "date": date,
            "tags": [
                "attack.execution",
                "attack.t1059",
            ],
            "logsource": {
                "category": "process_creation",
                "product": "linux",
            },
            "detection": {
                "selection": {
                    "CommandLine|contains": suspicious_cmds[:10],
                },
                "condition": "selection",
            },
            "level": sigma_level,
            "falsepositives": ["System administration tasks"],
        }
        rules.append(proc_rule)

    # --- Rule 3: File hash detection ---
    hash_rule = {
        "title": f"ELKIE Honeypot — {classification.title()} File Hash ({sha256[:8]})",
        "id": f"elkie-{sha256[:16]}-hash",
        "status": "experimental",
        "description": f"Detects {classification} malware by file hash. Captured by ELKIE SOC honeypot.",
        "author": "ELKIE SOC (automated)",
        "date": date,
        "tags": [
            "attack.execution",
        ],
        "logsource": {
            "category": "file_event",
        },
        "detection": {
            "selection": {
                "Hashes|contains": [sha256],
            },
            "condition": "selection",
        },
        "level": sigma_level,
        "references": [
            f"https://www.virustotal.com/gui/file/{sha256}",
        ],
    }

    if sample.get("md5"):
        hash_rule["detection"]["selection"]["Hashes|contains"].append(sample["md5"])

    rules.append(hash_rule)

    # --- Rule 4: DNS-based detection (from sandbox) ---
    if c2_domains:
        dns_rule = {
            "title": f"ELKIE Honeypot — {classification.title()} DNS Resolution ({sha256[:8]})",
            "id": f"elkie-{sha256[:16]}-dns",
            "status": "experimental",
            "description": f"Detects DNS resolution of C2 domains observed during sandbox detonation of {classification} sample.",
            "author": "ELKIE SOC (automated)",
            "date": date,
            "tags": [
                "attack.command_and_control",
                "attack.t1071.004",
            ],
            "logsource": {
                "category": "dns",
            },
            "detection": {
                "selection": {
                    "QueryName|endswith": c2_domains,
                },
                "condition": "selection",
            },
            "level": sigma_level,
            "falsepositives": ["Legitimate DNS queries"],
        }
        rules.append(dns_rule)

    # --- Rule 5: Dropped files detection (from sandbox) ---
    new_files = dyn.get("new_files", [])
    suspicious_paths = [f for f in new_files if any(p in f for p in ["/tmp/", "/dev/shm", "/var/tmp"])]
    if suspicious_paths:
        file_rule = {
            "title": f"ELKIE Honeypot — {classification.title()} File Drop ({sha256[:8]})",
            "id": f"elkie-{sha256[:16]}-filedrop",
            "status": "experimental",
            "description": f"Detects files dropped by {classification} malware in temporary directories during sandbox execution.",
            "author": "ELKIE SOC (automated)",
            "date": date,
            "tags": [
                "attack.persistence",
                "attack.t1105",
            ],
            "logsource": {
                "category": "file_event",
                "product": "linux",
            },
            "detection": {
                "selection": {
                    "TargetFilename|contains": suspicious_paths[:10],
                },
                "condition": "selection",
            },
            "level": sigma_level,
        }
        rules.append(file_rule)

    return rules


def save_rules(rules: list[dict], sha256: str):
    """Save Sigma rules as individual YAML files."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    saved = []
    for rule in rules:
        rule_id = rule.get("id", "unknown")
        filename = f"{rule_id}.yml"
        filepath = OUTPUT_DIR / filename

        with open(filepath, "w") as f:
            yaml.dump(rule, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

        saved.append(filepath)

    return saved


def main():
    parser = argparse.ArgumentParser(description="Sigma Rule Generator")
    parser.add_argument("sha256", nargs="?")
    parser.add_argument("--latest", action="store_true")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    if args.all:
        samples = get_all()
        print(f"Generating Sigma rules for {len(samples)} samples...")
        total = 0
        for sample in samples:
            rules = generate_sigma_rules(sample)
            if rules:
                saved = save_rules(rules, sample["sha256"])
                total += len(saved)
                print(f"  {sample['sha256'][:16]} ({sample.get('classification','?')}): {len(rules)} rules")
        print(f"\nTotal: {total} Sigma rules in {OUTPUT_DIR}")

    elif args.latest:
        sample = get_latest()
        if not sample:
            print("No samples found")
            sys.exit(1)
        rules = generate_sigma_rules(sample)
        saved = save_rules(rules, sample["sha256"])
        print(f"Generated {len(rules)} rules for {sample['sha256'][:16]}")
        for s in saved:
            print(f"  {s}")

    elif args.sha256:
        sample = get_sample(args.sha256)
        if not sample:
            print(f"Sample {args.sha256} not found")
            sys.exit(1)
        rules = generate_sigma_rules(sample)
        saved = save_rules(rules, args.sha256)
        print(f"Generated {len(rules)} rules")
        for s in saved:
            print(f"  {s}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
