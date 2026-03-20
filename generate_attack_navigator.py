#!/usr/bin/env python3
"""
ATT&CK Navigator Layer Generator

Reads all malware analysis results from Elasticsearch and generates
a MITRE ATT&CK Navigator heatmap layer showing which techniques
your honeypots are detecting.

Usage:
    python3 generate_attack_navigator.py              # generate layer
    python3 generate_attack_navigator.py --serve       # generate + serve on port 8889

Output: /home/legs/reports/attack_navigator_layer.json
Load at: https://mitre-attack.github.io/attack-navigator/
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

import requests

ES_URL = "http://localhost:9200"
RESULT_INDEX = "malware-analysis"
OUTPUT_DIR = Path("/home/legs/reports")

# Map capa namespaces to ATT&CK technique IDs
CAPA_TO_ATTACK = {
    # Execution
    "execution": "T1059",
    "execution/command-and-scripting-interpreter": "T1059",
    "execution/shared-modules": "T1129",
    "execution/native-api": "T1106",
    # Persistence
    "persistence": "T1547",
    "persistence/boot-or-logon-autostart-execution": "T1547",
    "persistence/scheduled-task-job": "T1053",
    "persistence/create-or-modify-system-process": "T1543",
    "persistence/registry-run-keys": "T1547.001",
    # Privilege Escalation
    "privilege-escalation": "T1548",
    # Defense Evasion
    "defense-evasion": "T1027",
    "defense-evasion/obfuscated-files-or-information": "T1027",
    "defense-evasion/deobfuscate-decode-files-or-information": "T1140",
    "defense-evasion/indicator-removal": "T1070",
    "defense-evasion/file-and-directory-permissions-modification": "T1222",
    "defense-evasion/virtualization-sandbox-evasion": "T1497",
    "defense-evasion/process-injection": "T1055",
    # Credential Access
    "credential-access": "T1003",
    "credential-access/os-credential-dumping": "T1003",
    "credential-access/input-capture": "T1056",
    # Discovery
    "discovery": "T1082",
    "discovery/system-information-discovery": "T1082",
    "discovery/file-and-directory-discovery": "T1083",
    "discovery/process-discovery": "T1057",
    "discovery/system-network-configuration-discovery": "T1016",
    "discovery/system-owner-user-discovery": "T1033",
    "discovery/remote-system-discovery": "T1018",
    "discovery/query-registry": "T1012",
    # Lateral Movement
    "lateral-movement": "T1021",
    # Collection
    "collection": "T1005",
    "collection/data-from-local-system": "T1005",
    "collection/input-capture": "T1056",
    "collection/clipboard-data": "T1115",
    "collection/screen-capture": "T1113",
    # Command and Control
    "communication": "T1071",
    "communication/http": "T1071.001",
    "communication/dns": "T1071.004",
    "communication/socket": "T1095",
    "communication/c2": "T1071",
    "c2": "T1071",
    "c2/http": "T1071.001",
    "c2/file-transfer": "T1105",
    # Exfiltration
    "exfiltration": "T1041",
    "exfiltration/exfiltration-over-c2-channel": "T1041",
    # Impact
    "impact": "T1486",
    "impact/data-encrypted-for-impact": "T1486",
    "impact/resource-hijacking": "T1496",
    "impact/service-stop": "T1489",
    # Data manipulation
    "data-manipulation": "T1565",
    # Host interaction
    "host-interaction/file-system": "T1083",
    "host-interaction/process": "T1057",
    "host-interaction/registry": "T1012",
    "host-interaction/network": "T1016",
    "host-interaction/os": "T1082",
    "host-interaction/cli": "T1059",
    "host-interaction/gui": "T1059",
    # Lib
    "lib/http": "T1071.001",
    "lib/dns": "T1071.004",
    "lib/crypto": "T1027",
    "lib/encode": "T1027",
}

# Map common YARA rule names to ATT&CK
YARA_TO_ATTACK = {
    "mirai": ["T1059", "T1071", "T1496", "T1095"],
    "gafgyt": ["T1059", "T1071", "T1496", "T1095"],
    "tsunami": ["T1059", "T1071", "T1095"],
    "xmrig": ["T1496"],
    "cryptominer": ["T1496"],
    "miner": ["T1496"],
    "upx": ["T1027.002"],
    "packed": ["T1027.002"],
    "emotet": ["T1059", "T1055", "T1071.001", "T1547"],
    "trickbot": ["T1059", "T1055", "T1071.001", "T1003"],
    "cobalt": ["T1059", "T1055", "T1071.001", "T1105"],
    "metasploit": ["T1059", "T1055", "T1071", "T1105"],
    "reverse_shell": ["T1059", "T1095"],
    "backdoor": ["T1059", "T1543", "T1095"],
    "ransomware": ["T1486", "T1490"],
    "keylogger": ["T1056.001"],
    "rat": ["T1059", "T1071", "T1105", "T1056"],
}

# Map suspicious Ghidra APIs to ATT&CK
API_TO_ATTACK = {
    "CreateRemoteThread": "T1055",
    "VirtualAllocEx": "T1055",
    "WriteProcessMemory": "T1055",
    "NtUnmapViewOfSection": "T1055.012",
    "SetWindowsHookEx": "T1056.001",
    "CreateProcess": "T1106",
    "ShellExecute": "T1059",
    "WinExec": "T1106",
    "URLDownloadToFile": "T1105",
    "InternetOpen": "T1071.001",
    "HttpSendRequest": "T1071.001",
    "WSAStartup": "T1095",
    "connect": "T1095",
    "socket": "T1095",
    "RegSetValueEx": "T1547.001",
    "CreateService": "T1543.003",
    "CryptEncrypt": "T1486",
    "IsDebuggerPresent": "T1497.001",
    "GetProcAddress": "T1106",
    "LoadLibrary": "T1129",
    "VirtualProtect": "T1055",
    "OpenProcess": "T1055",
    "execve": "T1059.004",
    "fork": "T1106",
    "ptrace": "T1055",
    "mprotect": "T1055",
    "dlopen": "T1129",
    "system": "T1059.004",
    "popen": "T1059.004",
    "chmod": "T1222",
    "chown": "T1222",
    "setuid": "T1548",
}


def get_all_samples():
    resp = requests.post(f"{ES_URL}/{RESULT_INDEX}/_search", json={
        "size": 500, "_source": ["sha256", "capa_capabilities", "yara_matches",
                                  "ghidra", "classification", "severity", "analyzed_at",
                                  "interesting_strings", "llm_summary"],
    }, timeout=15)
    return [h["_source"] for h in resp.json().get("hits", {}).get("hits", [])]


def generate_layer():
    samples = get_all_samples()
    if not samples:
        print("No samples found in ES")
        return None

    print(f"Processing {len(samples)} samples...")

    technique_counts = Counter()
    technique_samples = {}  # technique -> list of sha256s

    for sample in samples:
        sha = sample.get("sha256", "?")[:16]
        techniques_found = set()

        # capa capabilities → ATT&CK
        for cap in sample.get("capa_capabilities", []):
            ns = cap.get("namespace", "").lower()
            # Try exact match, then prefix matches
            if ns in CAPA_TO_ATTACK:
                techniques_found.add(CAPA_TO_ATTACK[ns])
            else:
                for capa_prefix, tech_id in CAPA_TO_ATTACK.items():
                    if ns.startswith(capa_prefix):
                        techniques_found.add(tech_id)
                        break

        # YARA matches → ATT&CK
        for yara in sample.get("yara_matches", []):
            yara_lower = yara.lower()
            for pattern, techs in YARA_TO_ATTACK.items():
                if pattern in yara_lower:
                    techniques_found.update(techs)

        # Ghidra suspicious APIs → ATT&CK
        ghidra = sample.get("ghidra")
        if ghidra and isinstance(ghidra, dict):
            for api in ghidra.get("suspicious_apis", []):
                if api in API_TO_ATTACK:
                    techniques_found.add(API_TO_ATTACK[api])

        # String-based technique detection
        all_strings = " ".join(sample.get("interesting_strings", []))
        llm = sample.get("llm_summary", "") or ""
        combined = (all_strings + " " + llm).lower()

        string_to_attack = [
            (r"wget.*\|.*bash|curl.*\|.*sh", ["T1059.004", "T1105"]),  # download & execute
            (r"crontab|/etc/cron", ["T1053.003"]),  # scheduled task
            (r"authorized_keys|ssh-keygen", ["T1098.004"]),  # SSH persistence
            (r"/etc/shadow|/etc/passwd", ["T1003.008"]),  # credential access
            (r"xmrig|stratum|pool\.|monero|cryptonight", ["T1496"]),  # crypto mining
            (r"chmod\s+\+s|setuid", ["T1548.001"]),  # SUID/SGID
            (r"iptables|ufw|firewall", ["T1562.004"]),  # disable firewall
            (r"history\s+-c|unset\s+HISTFILE", ["T1070.003"]),  # clear history
            (r"base64\s+-d|eval|exec", ["T1140"]),  # deobfuscation
            (r"nc\s+-[le]|/dev/tcp|mkfifo", ["T1059.004", "T1095"]),  # reverse shell
            (r"useradd|adduser", ["T1136.001"]),  # create account
            (r"systemctl\s+(stop|disable)", ["T1489"]),  # stop service
            (r"dd\s+.*of=/dev|mkfs", ["T1561"]),  # disk wipe
            (r"wget\s+http|curl\s+http|tftp", ["T1105"]),  # ingress tool transfer
            (r"/dev/watchdog", ["T1496"]),  # resource hijacking indicator
            (r"\.ssh/|ssh\s+\S+@", ["T1021.004"]),  # remote SSH
            (r"python.*import|perl\s+-e", ["T1059"]),  # scripting
        ]

        for pattern, techs in string_to_attack:
            if re.search(pattern, combined, re.I):
                techniques_found.update(techs)

        # Classification-based defaults
        cls = sample.get("classification", "")
        if cls == "botnet":
            techniques_found.update(["T1059", "T1071", "T1095", "T1496"])
        elif cls == "miner":
            techniques_found.add("T1496")
        elif cls == "ransomware":
            techniques_found.update(["T1486", "T1490"])
        elif cls == "backdoor":
            techniques_found.update(["T1059", "T1095", "T1543"])
        elif cls == "trojan":
            techniques_found.update(["T1059", "T1071", "T1105"])
        elif cls == "dropper":
            techniques_found.update(["T1105", "T1059"])

        for tech in techniques_found:
            technique_counts[tech] += 1
            if tech not in technique_samples:
                technique_samples[tech] = []
            technique_samples[tech].append(sha)

    if not technique_counts:
        print("No ATT&CK techniques mapped")
        return None

    # Build Navigator layer
    max_count = max(technique_counts.values())

    techniques = []
    for tech_id, count in technique_counts.items():
        # Score 1-100 based on frequency
        score = max(1, int((count / max_count) * 100))

        # Color gradient: green (low) -> yellow -> red (high)
        comment = f"Seen in {count} sample(s): {', '.join(technique_samples[tech_id][:5])}"
        if len(technique_samples[tech_id]) > 5:
            comment += f" (+{len(technique_samples[tech_id]) - 5} more)"

        techniques.append({
            "techniqueID": tech_id,
            "score": score,
            "comment": comment,
            "enabled": True,
            "showSubtechniques": True,
        })

    layer = {
        "name": "ELKIE SOC — Honeypot Detection Coverage",
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"ATT&CK techniques observed across {len(samples)} malware samples captured by ELKIE honeypot lab. Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "filters": {
            "platforms": ["Linux", "Windows", "macOS"],
        },
        "sorting": 3,  # sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#57F287", "#FEE75C", "#FE8D2F", "#ED4245"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Low frequency (1 sample)", "color": "#57F287"},
            {"label": "Medium frequency", "color": "#FEE75C"},
            {"label": "High frequency", "color": "#FE8D2F"},
            {"label": "Very high frequency", "color": "#ED4245"},
        ],
        "metadata": [{
            "name": "ELKIE SOC",
            "value": f"Generated from {len(samples)} samples | {len(technique_counts)} techniques mapped",
        }],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
    }

    return layer


def main():
    parser = argparse.ArgumentParser(description="ATT&CK Navigator Layer Generator")
    parser.add_argument("--serve", action="store_true", help="Serve the layer on port 8889")
    parser.add_argument("--output", default=str(OUTPUT_DIR / "attack_navigator_layer.json"))
    args = parser.parse_args()

    layer = generate_layer()
    if not layer:
        sys.exit(1)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)

    print(f"\nLayer saved to: {output_path}")
    print(f"Techniques mapped: {len(layer['techniques'])}")
    print(f"\nTo view: Go to https://mitre-attack.github.io/attack-navigator/")
    print(f"  → Open Existing Layer → Upload from local → select {output_path.name}")

    if args.serve:
        print(f"\nServing on http://0.0.0.0:8889/ ...")

        # Create a simple HTML page that loads the navigator
        index_html = output_path.parent / "navigator.html"
        with open(index_html, "w") as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head><title>ELKIE SOC — ATT&CK Coverage</title></head>
<body style="margin:0;padding:20px;font-family:sans-serif;background:#1a1a2e;color:white;">
<h1>ELKIE SOC — ATT&CK Detection Coverage</h1>
<p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<p>Techniques detected: {len(layer['techniques'])}</p>
<h3>How to view:</h3>
<ol>
<li>Go to <a href="https://mitre-attack.github.io/attack-navigator/" style="color:#5865F2;">ATT&CK Navigator</a></li>
<li>Click "Open Existing Layer"</li>
<li>Click "Upload from local"</li>
<li>Select the layer JSON: <a href="/attack_navigator_layer.json" style="color:#57F287;">Download Layer JSON</a></li>
</ol>
<h3>Top techniques:</h3>
<ul>
{"".join(f'<li><b>{t["techniqueID"]}</b> (score: {t["score"]}) — {t["comment"][:60]}</li>' for t in sorted(layer['techniques'], key=lambda x: -x['score'])[:15])}
</ul>
</body></html>""")

        import os
        os.chdir(str(output_path.parent))

        class QuietHandler(SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

        server = HTTPServer(("0.0.0.0", 8889), QuietHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
