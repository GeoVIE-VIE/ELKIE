#!/bin/bash
API_KEY="${ABUSEIPDB_API_KEY:-}"
REPORTED_FILE="/home/legs/reported_ips.txt"

touch $REPORTED_FILE

# Get successful logins from Cowrie
curl -s "http://localhost:9200/.ds-filebeat-8.19.8-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {
    "term": { "honeypot.eventid": "cowrie.login.success" }
  },
  "aggs": {
    "unique_ips": {
      "terms": { "field": "src_ip", "size": 500 }
    }
  }
}' | jq -r '.aggregations.unique_ips.buckets[].key' | sort -u | while read IP; do

  # Skip empty
  [[ -z "$IP" ]] && continue
  
  # Skip if already reported
  grep -q "$IP" $REPORTED_FILE && continue
  
  # Skip local IPs
  [[ "$IP" =~ ^192\.168\. ]] && continue
  [[ "$IP" =~ ^10\. ]] && continue
  
  echo "Reporting $IP"
  curl -s -X POST https://api.abuseipdb.com/api/v2/report \
    -H "Key: $API_KEY" \
    -d "ip=$IP&categories=18,22&comment=SSH honeypot - successful brute force"
  
  echo "$IP" >> $REPORTED_FILE
  sleep 1
done

echo "Done - $(date)"
