#!/usr/bin/env python3
"""Recon Dashboard v2 — IP-level tracking, multi-source validation, change detection."""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import shodan
from flask import Flask, render_template, request, jsonify

from config import (SHODAN_API_KEY, COUNTRIES, SECTORS, TRACKED_SECTORS,
                     PRIORITY_COUNTRIES, DISCORD_WEBHOOK_URL)
from models import init_db, get_db

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('recon')

app = Flask(__name__)
api = shodan.Shodan(SHODAN_API_KEY)

SNAPSHOTS_DIR = Path('/home/kali/recon-dashboard/snapshots')
SNAPSHOTS_DIR.mkdir(exist_ok=True)

# ── Existing routes (preserved) ──────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', countries=COUNTRIES, sectors=SECTORS)

@app.route('/api/search')
def search():
    country = request.args.get('country', 'IR')
    sector = request.args.get('sector', 'all')
    custom = request.args.get('query', '')
    page = int(request.args.get('page', 1))
    facets_only = request.args.get('facets_only', 'false') == 'true'

    query = f'country:{country}'
    if sector != 'all' and sector in SECTORS:
        query += f' {SECTORS[sector]}'
    if custom:
        query += f' {custom}'

    try:
        if facets_only:
            result = api.count(query, facets=[('port', 20), ('org', 20), ('product', 20),
                                               ('os', 20), ('vuln', 20), ('city', 20)])
            return jsonify({'total': result['total'], 'facets': result.get('facets', {}), 'query': query})
        else:
            result = api.search(query, page=page)
            hosts = []
            for h in result.get('matches', []):
                loc = h.get('location', {})
                hosts.append({
                    'ip': h.get('ip_str', ''), 'port': h.get('port', ''),
                    'product': h.get('product', ''), 'version': h.get('version', ''),
                    'os': h.get('os', ''), 'org': h.get('org', ''),
                    'hostnames': h.get('hostnames', []),
                    'city': loc.get('city', ''),
                    'vulns': list(h.get('vulns', {}).keys()) if isinstance(h.get('vulns'), dict) else [],
                    'http_title': h.get('http', {}).get('title', ''),
                    'banner': (h.get('data', '') or '')[:200],
                    'timestamp': h.get('timestamp', ''),
                    'lat': loc.get('latitude'), 'lon': loc.get('longitude'),
                })
            return jsonify({'total': result['total'], 'hosts': hosts, 'query': query, 'page': page})
    except shodan.APIError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/host/<ip>')
def host_detail(ip):
    try:
        return jsonify(api.host(ip))
    except shodan.APIError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/snapshot')
def take_snapshot():
    country = request.args.get('country', 'IR')
    snapshot = {'timestamp': datetime.now(timezone.utc).isoformat(), 'country': country, 'sectors': {}}
    for sector, qp in SECTORS.items():
        q = f'country:{country}'
        if qp:
            q += f' {qp}'
        try:
            result = api.count(q)
            snapshot['sectors'][sector] = result['total']
            time.sleep(0.5)
        except:
            snapshot['sectors'][sector] = None
    fn = f"{country}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(SNAPSHOTS_DIR / fn, 'w') as f:
        json.dump(snapshot, f, indent=2)
    return jsonify(snapshot)

@app.route('/api/history')
def get_history():
    country = request.args.get('country', 'IR')
    snaps = []
    for f in sorted(SNAPSHOTS_DIR.glob(f'{country}_*.json')):
        with open(f) as fh:
            snaps.append(json.load(fh))
    return jsonify(snaps)

@app.route('/api/changes')
def get_changes_legacy():
    """Legacy count-based changes (old snapshots). Use /api/tracker/changes for IP-level."""
    country = request.args.get('country', 'IR')
    files = sorted(SNAPSHOTS_DIR.glob(f'{country}_*.json'))
    if len(files) < 2:
        return jsonify({'error': 'Need at least 2 snapshots'}), 400
    with open(files[-2]) as f:
        old = json.load(f)
    with open(files[-1]) as f:
        new = json.load(f)
    changes = []
    for sector in new['sectors']:
        oc, nc = old['sectors'].get(sector), new['sectors'].get(sector)
        if oc is not None and nc is not None:
            diff = nc - oc
            pct = (diff / oc * 100) if oc > 0 else 0
            changes.append({'sector': sector, 'old': oc, 'new': nc, 'diff': diff, 'pct': round(pct, 1)})
    changes.sort(key=lambda x: abs(x['diff']), reverse=True)
    return jsonify({'old_timestamp': old['timestamp'], 'new_timestamp': new['timestamp'], 'changes': changes})

# ── Intel routes (preserved) ─────────────────────────────────────────

from intel import get_all_intel, fetch_rss_feeds, fetch_gdelt, fetch_cisa_kev

@app.route('/intel')
def intel_page():
    return render_template('intel.html', countries=COUNTRIES)

@app.route('/api/intel')
def api_intel():
    country = request.args.get('country', None)
    query = request.args.get('query', None)
    hours = float(request.args.get('hours', 72))
    if country == 'ALL':
        country = None
    return jsonify(get_all_intel(country, query, hours))

@app.route('/api/intel/news')
def api_intel_news():
    country = request.args.get('country', None)
    hours = float(request.args.get('hours', 72))
    if country == 'ALL':
        country = None
    return jsonify(fetch_rss_feeds(country, hours))

@app.route('/api/intel/gdelt')
def api_intel_gdelt():
    country = request.args.get('country', None)
    query = request.args.get('query', None)
    hours = float(request.args.get('hours', 72))
    if country == 'ALL':
        country = None
    return jsonify(fetch_gdelt(country, query, hours))

@app.route('/api/intel/kev')
def api_intel_kev():
    return jsonify(fetch_cisa_kev())

# ── NEW: IP-level tracker routes ─────────────────────────────────────

@app.route('/api/tracker/status')
def tracker_status():
    """Scheduler status and last run info."""
    from scheduler import get_status
    status = get_status()
    db = get_db()
    last_snap = db.execute("SELECT timestamp, country, query_tag, host_count FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    last_change = db.execute("SELECT date, country, change_type, ip, port FROM changes ORDER BY id DESC LIMIT 1").fetchone()
    status['last_snapshot'] = dict(last_snap) if last_snap else None
    status['last_change'] = dict(last_change) if last_change else None
    return jsonify(status)

@app.route('/api/tracker/snapshots')
def tracker_snapshots():
    """List consolidated snapshots."""
    country = request.args.get('country')
    date = request.args.get('date')
    db = get_db()
    q = "SELECT * FROM consolidated WHERE 1=1"
    params = []
    if country:
        q += " AND country = ?"
        params.append(country)
    if date:
        q += " AND date = ?"
        params.append(date)
    q += " ORDER BY date DESC, country, query_tag LIMIT 200"
    rows = db.execute(q, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/tracker/snapshots/<int:cid>/hosts')
def tracker_snapshot_hosts(cid):
    """List hosts in a consolidated snapshot."""
    db = get_db()
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    rows = db.execute(
        "SELECT * FROM consolidated_hosts WHERE consolidated_id = ? ORDER BY confidence DESC LIMIT ? OFFSET ?",
        (cid, limit, offset),
    ).fetchall()
    total = db.execute("SELECT COUNT(*) as c FROM consolidated_hosts WHERE consolidated_id = ?", (cid,)).fetchone()['c']
    return jsonify({'total': total, 'hosts': [dict(r) for r in rows]})

@app.route('/api/tracker/changes')
def tracker_changes():
    """List IP-level changes with filters."""
    date = request.args.get('date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))
    country = request.args.get('country')
    change_type = request.args.get('type')
    min_conf = float(request.args.get('min_confidence', 0))
    db = get_db()
    q = "SELECT * FROM changes WHERE date = ?"
    params = [date]
    if country:
        q += " AND country = ?"
        params.append(country)
    if change_type:
        q += " AND change_type = ?"
        params.append(change_type)
    if min_conf > 0:
        q += " AND confidence >= ?"
        params.append(min_conf)
    q += " ORDER BY confidence DESC LIMIT 500"
    rows = db.execute(q, params).fetchall()

    # Summary stats
    all_changes = db.execute("SELECT change_type, COUNT(*) as c FROM changes WHERE date = ? GROUP BY change_type", (date,)).fetchall()
    stats = {r['change_type']: r['c'] for r in all_changes}

    return jsonify({'date': date, 'stats': stats, 'changes': [dict(r) for r in rows]})

@app.route('/api/tracker/host/<ip>/history')
def tracker_host_history(ip):
    """History of a specific IP across all consolidated snapshots."""
    db = get_db()
    rows = db.execute("""
        SELECT ch.*, c.date, c.query_tag, c.country
        FROM consolidated_hosts ch
        JOIN consolidated c ON ch.consolidated_id = c.id
        WHERE ch.ip = ?
        ORDER BY c.date DESC
        LIMIT 100
    """, (ip,)).fetchall()
    changes = db.execute("SELECT * FROM changes WHERE ip = ? ORDER BY date DESC LIMIT 50", (ip,)).fetchall()
    return jsonify({
        'ip': ip,
        'appearances': [dict(r) for r in rows],
        'changes': [dict(r) for r in changes],
    })

@app.route('/api/tracker/summary')
def tracker_summary():
    """Daily summary stats across all countries."""
    date = request.args.get('date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))
    db = get_db()

    by_country = db.execute("""
        SELECT country, change_type, COUNT(*) as c, AVG(confidence) as avg_conf
        FROM changes WHERE date = ?
        GROUP BY country, change_type
        ORDER BY country, change_type
    """, (date,)).fetchall()

    result = {}
    for r in by_country:
        cc = r['country']
        if cc not in result:
            result[cc] = {'country': cc, 'name': COUNTRIES.get(cc, cc)}
        result[cc][r['change_type']] = {'count': r['c'], 'avg_confidence': round(r['avg_conf'], 2)}

    # Nmap stats
    nmap_stats = db.execute(
        "SELECT nmap_state, COUNT(*) as c FROM changes WHERE date = ? AND nmap_verified = 1 GROUP BY nmap_state",
        (date,),
    ).fetchall()

    return jsonify({
        'date': date,
        'countries': list(result.values()),
        'nmap_verifications': {r['nmap_state']: r['c'] for r in nmap_stats},
    })

@app.route('/api/tracker/scan_now')
def tracker_scan_now():
    """Trigger an immediate scan for a country (reading 0 = ad-hoc)."""
    country = request.args.get('country', 'IR')
    sector = request.args.get('sector')
    if country not in COUNTRIES:
        return jsonify({'error': f'Unknown country: {country}'}), 400

    from collectors.shodan_collector import collect, collect_all
    if sector and sector in SECTORS:
        sid = collect(country, sector, 0)
        return jsonify({'snapshot_id': sid, 'country': country, 'sector': sector})
    else:
        collect_all(country, 0)
        return jsonify({'country': country, 'sectors': TRACKED_SECTORS, 'reading': 0})

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'timestamp': datetime.now(timezone.utc).isoformat()})

# ── Startup ──────────────────────────────────────────────────────────

with app.app_context():
    init_db()

def start_with_scheduler():
    from scheduler import start_scheduler
    start_scheduler()
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == '__main__':
    start_with_scheduler()
