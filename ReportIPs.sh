#!/bin/bash
# Report attacker IPs to AbuseIPDB with enriched intel from honeypot data
API_KEY="${ABUSEIPDB_API_KEY:-}"
REPORTED_FILE="/home/legs/reported_ips.txt"
ES_URL="http://localhost:9200"
INDEX=".ds-filebeat-8.19.8-*"

touch $REPORTED_FILE

# Get successful logins from last 24h (avoid re-reporting old ones)
curl -s "$ES_URL/$INDEX/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "term": {"honeypot.eventid": "cowrie.login.success"}
  },
  "aggs": {
    "unique_ips": {
      "terms": {"field": "src_ip", "size": 500}
    }
  }
}' | jq -r '.aggregations.unique_ips.buckets[].key' | sort -u | while read IP; do

  [[ -z "$IP" ]] && continue
  grep -q "$IP" $REPORTED_FILE && continue
  [[ "$IP" =~ ^192\.168\. ]] && continue
  [[ "$IP" =~ ^10\. ]] && continue
  [[ "$IP" =~ ^172\. ]] && continue

  # Gather intel for this IP
  INTEL=$(python3 << PYEOF
import json, requests

ip = "$IP"
es = "$ES_URL"
idx = "$INDEX"

parts = []

# Get credentials used
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 0,
    "query": {"bool": {"must": [
        {"term": {"src_ip": ip}},
        {"bool": {"should": [
            {"term": {"honeypot.eventid": "cowrie.login.success"}},
            {"term": {"honeypot.eventid": "cowrie.login.failed"}}
        ], "minimum_should_match": 1}}
    ]}},
    "aggs": {
        "usernames": {"terms": {"field": "honeypot.username", "size": 5}},
        "passwords": {"terms": {"field": "honeypot.password", "size": 5}},
        "total_attempts": {"value_count": {"field": "honeypot.eventid"}},
        "successes": {"filter": {"term": {"honeypot.eventid": "cowrie.login.success"}}}
    }
}, timeout=10)

if r.status_code == 200:
    d = r.json()
    aggs = d.get("aggregations", {})
    total = aggs.get("total_attempts", {}).get("value", 0)
    success = aggs.get("successes", {}).get("doc_count", 0)
    users = [b["key"] for b in aggs.get("usernames", {}).get("buckets", [])]
    passes = [b["key"] for b in aggs.get("passwords", {}).get("buckets", [])]
    parts.append(f"Brute force: {total} attempts, {success} successful")
    if users:
        parts.append(f"Users: {', '.join(users[:5])}")
    if passes:
        parts.append(f"Passwords: {', '.join(passes[:5])}")

# Get commands executed
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 5,
    "query": {"bool": {"must": [
        {"term": {"src_ip": ip}},
        {"term": {"honeypot.eventid": "cowrie.command.input"}}
    ]}},
    "_source": ["honeypot.input"],
    "sort": [{"@timestamp": "desc"}]
}, timeout=10)

if r.status_code == 200:
    cmds = [h["_source"].get("honeypot", {}).get("input", "")[:60] for h in r.json().get("hits", {}).get("hits", [])]
    cmds = [c for c in cmds if c]
    if cmds:
        parts.append(f"Commands: {'; '.join(cmds[:3])}")

# Get file downloads
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 3,
    "query": {"bool": {"must": [
        {"term": {"src_ip": ip}},
        {"bool": {"should": [
            {"term": {"honeypot.eventid": "cowrie.session.file_download"}},
            {"term": {"honeypot.eventid": "cowrie.session.file_upload"}}
        ], "minimum_should_match": 1}}
    ]}},
    "_source": ["honeypot.shasum", "honeypot.url"],
    "sort": [{"@timestamp": "desc"}]
}, timeout=10)

if r.status_code == 200:
    for h in r.json().get("hits", {}).get("hits", []):
        hp = h["_source"].get("honeypot", {})
        sha = hp.get("shasum", "")
        url = hp.get("url", "")
        if sha:
            parts.append(f"Malware dropped: {sha[:16]}...")
        if url:
            parts.append(f"Download URL: {url[:60]}")

# Check if this IP has malware analysis results
r = requests.post(f"{es}/malware-analysis/_search", json={
    "size": 1,
    "query": {"term": {"source.src_ip": ip}},
    "_source": ["classification", "severity", "sha256"]
}, timeout=5)

if r.status_code == 200 and r.json().get("hits", {}).get("total", {}).get("value", 0) > 0:
    hit = r.json()["hits"]["hits"][0]["_source"]
    parts.append(f"Malware: {hit.get('classification','?')} (severity: {hit.get('severity','?')})")

# Get tunnel requests
r = requests.post(f"{es}/{idx}/_search", json={
    "size": 3,
    "query": {"bool": {"must": [
        {"term": {"src_ip": ip}},
        {"term": {"honeypot.eventid": "cowrie.direct-tcpip.request"}}
    ]}},
    "_source": ["honeypot.dst_ip", "honeypot.dst_port"]
}, timeout=10)

if r.status_code == 200:
    tunnels = []
    for h in r.json().get("hits", {}).get("hits", []):
        hp = h["_source"].get("honeypot", {})
        dst = hp.get("dst_ip", "")
        port = hp.get("dst_port", "")
        if dst:
            tunnels.append(f"{dst}:{port}")
    if tunnels:
        parts.append(f"Tunnel attempts: {', '.join(tunnels[:3])}")

# Build comment
if not parts:
    parts.append("SSH honeypot - successful brute force login")

comment = " | ".join(parts)
# AbuseIPDB comment limit is 1024 chars
print(comment[:1024])
PYEOF
)

  # Determine categories
  # 18 = brute force, 22 = SSH, 23 = malware
  CATEGORIES="18,22"
  if echo "$INTEL" | grep -qi "malware\|dropped"; then
    CATEGORIES="18,22,23"
  fi
  if echo "$INTEL" | grep -qi "tunnel"; then
    CATEGORIES="$CATEGORIES,14"  # 14 = port scan / proxy
  fi

  echo "[$IP] $INTEL"

  # URL-encode the comment
  ENCODED_COMMENT=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$INTEL'))" 2>/dev/null || echo "SSH+honeypot+brute+force")

  curl -s -X POST https://api.abuseipdb.com/api/v2/report \
    -H "Key: $API_KEY" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "ip=$IP&categories=$CATEGORIES&comment=$ENCODED_COMMENT"

  echo "$IP" >> $REPORTED_FILE
  sleep 1
done

echo "Done - $(date)"
