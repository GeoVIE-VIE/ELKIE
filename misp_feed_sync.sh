#!/bin/bash
# Daily MISP feed sync — pull fresh threat intel from all enabled feeds
# Run via cron: 0 4 * * * /home/legs/misp_feed_sync.sh >> /home/legs/misp_feed_sync.log 2>&1

MISP_KEY="${MISP_API_KEY:-}"
MISP_URL="https://localhost"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting MISP feed sync"

# Fetch all enabled feeds
FEEDS=$(curl -sk -H "Authorization: $MISP_KEY" -H "Accept: application/json" "$MISP_URL/feeds/index.json" 2>/dev/null)
echo "$FEEDS" | python3 -c "
import json, sys, requests, time, urllib3
urllib3.disable_warnings()

feeds = json.load(sys.stdin)
key = '$MISP_KEY'
url = '$MISP_URL'

for f in feeds:
    feed = f.get('Feed', {})
    if not feed.get('enabled'):
        continue
    fid = feed['id']
    name = feed['name']
    print(f'  Fetching: {name}...', flush=True)
    r = requests.post(f'{url}/feeds/fetchFromFeed/{fid}',
        headers={'Authorization': key, 'Accept': 'application/json'},
        verify=False, timeout=30)
    if r.status_code == 200:
        print(f'  -> Queued OK')
    else:
        print(f'  -> Error: {r.status_code}')
    time.sleep(2)

print('Feed sync complete.')
" 2>/dev/null

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Feed sync finished"
