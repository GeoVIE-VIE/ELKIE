#!/bin/bash
# Report attacker IPs to AbuseIPDB with enriched honeypot intel
ELKIE_HOME="${ELKIE_HOME:-/home/legs}"
source "$ELKIE_HOME/.sample_analyzer_env" 2>/dev/null
source "$ELKIE_HOME/.env" 2>/dev/null
API_KEY="${ABUSEIPDB_API_KEY:-}"
REPORTED_FILE="${ELKIE_HOME}/reported_ips.txt"
ES_URL="${ES_URL:-http://localhost:9200}"
INDEX="${ES_FILEBEAT_INDEX:-filebeat-*}"
AGENT_NAME="${SACRIFICIAL_AGENT_NAME:-ds-prod-web01}"
AGENT_ALT="${SACRIFICIAL_AGENT_ALT:-prodction1}"

touch $REPORTED_FILE

# Get successful logins from both Cowrie container events AND PAM auth events
{
  curl -s "$ES_URL/$INDEX/_search" -H 'Content-Type: application/json' -d '{
    "size": 0,
    "query": {"term": {"honeypot.eventid": "cowrie.login.success"}},
    "aggs": {"unique_ips": {"terms": {"field": "src_ip", "size": 1000}}}
  }' | jq -r '.aggregations.unique_ips.buckets[].key' 2>/dev/null

  curl -s "$ES_URL/$INDEX/_search" -H 'Content-Type: application/json' -d '{
    "size": 0,
    "query": {"bool": {"must": [
      {"term": {"honeypot_event": "ssh_auth"}},
      {"term": {"auth_success": true}}
    ]}},
    "aggs": {"unique_ips": {"terms": {"field": "src_ip", "size": 1000}}}
  }' | jq -r '.aggregations.unique_ips.buckets[].key' 2>/dev/null
} | sort -u | while read IP; do

  [[ -z "$IP" ]] && continue
  grep -q "$IP" $REPORTED_FILE && continue
  [[ "$IP" =~ ^192\.168\. ]] && continue
  [[ "$IP" =~ ^10\. ]] && continue
  [[ "$IP" =~ ^172\. ]] && continue

  INTEL=$(python3 << PYEOF
import json, requests

ip = "$IP"
es = "$ES_URL"
idx = "$INDEX"

# --- 1. Brute force stats (PAM auth + old Cowrie) ---
brute = {}
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 0,
    "query": {"bool": {"must": [{"term": {"src_ip": ip}},
        {"bool": {"should": [
            {"term": {"honeypot.eventid": "cowrie.login.success"}},
            {"term": {"honeypot.eventid": "cowrie.login.failed"}},
            {"term": {"honeypot_event": "ssh_auth"}}
        ], "minimum_should_match": 1}}
    ]}},
    "aggs": {
        "usernames": {"terms": {"field": "honeypot.username", "size": 5}},
        "passwords": {"terms": {"field": "honeypot.password", "size": 5}},
        "pam_users": {"terms": {"field": "username", "size": 5}},
        "pam_passes": {"terms": {"field": "password", "size": 5}},
        "total": {"value_count": {"field": "@timestamp"}},
        "successes": {"filter": {"bool": {"should": [
            {"term": {"honeypot.eventid": "cowrie.login.success"}},
            {"term": {"auth_success": True}}
        ], "minimum_should_match": 1}}},
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}}
    }
}, timeout=10)

if r.status_code == 200:
    aggs = r.json().get("aggregations", {})
    brute["total"] = int(aggs.get("total", {}).get("value", 0))
    brute["success"] = aggs.get("successes", {}).get("doc_count", 0)
    users = [b["key"] for b in aggs.get("usernames", {}).get("buckets", [])]
    users += [b["key"] for b in aggs.get("pam_users", {}).get("buckets", []) if b["key"] not in users]
    passes = [b["key"] for b in aggs.get("passwords", {}).get("buckets", [])]
    passes += [b["key"] for b in aggs.get("pam_passes", {}).get("buckets", []) if b["key"] not in passes]
    brute["users"] = [u for u in users if u and u != "\\b"][:5]
    brute["passes"] = [p for p in passes if p and p != "\\b"][:5]
    brute["first"] = aggs.get("first_seen", {}).get("value_as_string", "")[:16]
    brute["last"] = aggs.get("last_seen", {}).get("value_as_string", "")[:16]

# --- 2. Attacker commands from auditd (wget/curl URLs, suspicious binaries) ---
commands = []
download_urls = []
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 20,
    "query": {"bool": {"must": [
        {"term": {"service.type": "auditd"}},
        {"term": {"event.action": "execve"}},
        {"bool": {"should": [
            {"term": {"agent.name": "'"$AGENT_NAME"'"}},
            {"term": {"agent.name": "'"$AGENT_ALT"'"}}
        ], "minimum_should_match": 1}}
    ], "must_not": [
        {"terms": {"process.executable": [
            "bash", "sh", "dash", "ps", "tr", "head", "tail", "cat", "cut",
            "awk", "sed", "grep", "find", "ls", "readlink", "stat", "wc",
            "mkdir", "chmod", "chown", "rm", "cp", "mv", "touch", "sleep",
            "date", "echo", "env", "id", "whoami", "uname", "hostname",
            "ss", "netstat", "ip", "ping", "systemctl", "journalctl",
            "crontab", "iptables", "python3", "python", "perl",
            "sshd", "ssh", "scp", "sftp", "sudo", "su",
            "auditctl", "auditd", "filebeat", "chronyc",
            "dpkg", "apt", "apt-get", "honeypot_guard", "honeypot_pam",
            "nohup", "timeout", "kill", "pkill", "free", "df", "mount",
            "chattr", "lsattr", "passwd", "useradd", "usermod", "groupadd",
            "dirname", "sort", "expr"
        ]}}
    ]}},
    "_source": ["process.executable", "process.args"],
    "sort": [{"@timestamp": "desc"}]
}, timeout=10)

if r.status_code == 200:
    seen = set()
    for h in r.json().get("hits", {}).get("hits", []):
        exe = h["_source"].get("process", {}).get("executable", "")
        args = h["_source"].get("process", {}).get("args", [])
        cmd = " ".join(args) if args else exe
        if not cmd or cmd in seen:
            continue
        seen.add(cmd)
        # Extract download URLs from wget/curl commands
        if exe in ("wget", "curl") and args:
            for a in args:
                if a.startswith("http"):
                    download_urls.append(a[:80])
        # Non-system binary execution
        elif "/" in exe and not exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib/")):
            commands.append(f"executed {exe}")
        else:
            commands.append(cmd[:60])

# --- 3. Also get wget/curl specifically (they might be in the excluded list above) ---
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 10,
    "query": {"bool": {"must": [
        {"term": {"service.type": "auditd"}},
        {"term": {"event.action": "execve"}},
        {"terms": {"process.executable": ["wget", "curl"]}},
        {"bool": {"should": [
            {"term": {"agent.name": "'"$AGENT_NAME"'"}},
            {"term": {"agent.name": "'"$AGENT_ALT"'"}}
        ], "minimum_should_match": 1}}
    ]}},
    "_source": ["process.args"],
    "sort": [{"@timestamp": "desc"}]
}, timeout=10)

if r.status_code == 200:
    for h in r.json().get("hits", {}).get("hits", []):
        args = h["_source"].get("process", {}).get("args", [])
        if args:
            for a in args:
                if a.startswith("http") and a not in download_urls:
                    # Skip our test URLs
                    if not any(x in a for x in ["example.com", "portquiz", "httpbin", "google.com", "192.168.", "192.0.2."]):
                        download_urls.append(a[:80])

# --- 4. Malware analysis results ---
malware_info = []
r = requests.post(f"{es}/malware-analysis/_search", json={
    "size": 5,
    "query": {"match_all": {}},
    "_source": ["classification", "severity", "sha256", "virustotal"]
}, timeout=5)
if r.status_code == 200:
    for h in r.json().get("hits", {}).get("hits", []):
        s = h["_source"]
        vt = s.get("virustotal", {})
        det = f", VT {vt['detections']}/{vt.get('total','?')}" if vt and vt.get("detections") else ""
        malware_info.append(f"{s.get('classification','?')} ({s.get('severity','?')}{det})")

# --- 5. Guard alerts (rogue sshd, rootkit, passwd changes) ---
guard_alerts = []
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 10,
    "query": {"bool": {"must": [
        {"bool": {"should": [
            {"term": {"agent.name": "'"$AGENT_NAME"'"}},
            {"term": {"agent.name": "'"$AGENT_ALT"'"}}
        ], "minimum_should_match": 1}},
        {"bool": {"should": [
            {"wildcard": {"message": "*ALERT*"}},
            {"wildcard": {"message": "*CAPTURED*"}},
            {"wildcard": {"message": "*Rogue*"}},
            {"wildcard": {"message": "*processhider*"}},
            {"wildcard": {"message": "*tampered*"}}
        ], "minimum_should_match": 1}}
    ]}},
    "_source": ["message"],
    "sort": [{"@timestamp": "desc"}]
}, timeout=10)

if r.status_code == 200:
    seen_alerts = set()
    for h in r.json().get("hits", {}).get("hits", []):
        msg = h["_source"].get("message", "")
        # Extract the meaningful part
        for keyword in ["CAPTURED", "ALERT", "Rogue", "processhider", "tampered"]:
            if keyword in msg:
                alert = msg.split("- ")[-1].strip()[:80] if "- " in msg else msg[:80]
                if alert not in seen_alerts:
                    guard_alerts.append(alert)
                    seen_alerts.add(alert)
                break

# --- 6. IP info ---
ipinfo = {}
try:
    r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
    if r.status_code == 200:
        ipinfo = r.json()
except:
    pass

# --- Build report ---
lines = []

# Summary
lines.append(f"SSH brute force on port 22 — {brute.get('total',0)} attempts, {brute.get('success',0)} successful.")

# Credentials
creds = [f"{u}:{p}" for u, p in zip(brute.get("users", [])[:3], brute.get("passes", [])[:3])]
if creds:
    lines.append(f"Credentials: {', '.join(creds)}.")

# Timeframe
if brute.get("first") and brute.get("last"):
    lines.append(f"Active: {brute['first']} to {brute['last']}.")

# Download URLs (the money shot)
if download_urls:
    lines.append(f"Downloaded: {'; '.join(download_urls[:2])}.")

# Post-login commands
if commands:
    lines.append(f"Post-login: {'; '.join(commands[:3])}.")

# Guard detections
if guard_alerts:
    lines.append(f"Detected: {'; '.join(guard_alerts[:2])}.")

# Malware classification
if malware_info:
    lines.append(f"Malware: {'; '.join(list(set(malware_info))[:3])}.")

# Source
if ipinfo.get("org"):
    loc = f"{ipinfo.get('city','')}, {ipinfo.get('country','')}" if ipinfo.get('city') else ipinfo.get('country','')
    lines.append(f"Source: {ipinfo['org']} ({loc}).")

# Disclosure
lines.append("Data from SSH honeypot — not a production system.")

comment = " ".join(lines)

# Strip RFC 1918 / internal IPs from report — never leak internal addressing
import re
comment = re.sub(r'192\.168\.\d+\.\d+', '[internal]', comment)
comment = re.sub(r'10\.\d+\.\d+\.\d+', '[internal]', comment)
comment = re.sub(r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+', '[internal]', comment)

print(comment[:1024])
PYEOF
)

  # Determine categories
  # 18=brute force, 22=SSH, 23=malware, 15=hacking, 4=DDoS, 14=port scan
  CATEGORIES="18,22"
  if echo "$INTEL" | grep -qi "malware\|miner\|botnet\|trojan\|ransomware\|Downloaded"; then
    CATEGORIES="18,22,23"
  fi
  if echo "$INTEL" | grep -qi "rogue sshd\|backdoor\|rootkit\|processhider"; then
    CATEGORIES="$CATEGORIES,15"
  fi

  echo "[$IP] $INTEL"

  # URL-encode and send
  ENCODED_COMMENT=$(python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))" <<< "$INTEL" 2>/dev/null)

  curl -s -X POST https://api.abuseipdb.com/api/v2/report \
    -H "Key: $API_KEY" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "ip=$IP&categories=$CATEGORIES&comment=$ENCODED_COMMENT"

  echo "$IP" >> $REPORTED_FILE
  sleep 1
done

echo "Done - $(date)"
