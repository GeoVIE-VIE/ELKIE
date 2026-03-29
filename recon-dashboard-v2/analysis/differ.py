"""Snapshot consolidation and change detection."""
import logging
from datetime import datetime, timezone, timedelta

from models import get_db

log = logging.getLogger(__name__)


def consolidate_readings(date: str, query_tag: str, country: str) -> int | None:
    """Intersect the day's readings — only keep hosts seen in 2+ of 3 readings.
    Returns consolidated_id or None if insufficient data."""
    db = get_db()

    # Get all readings for this day/query/country
    snapshots = db.execute(
        "SELECT id, reading_number FROM snapshots "
        "WHERE date(timestamp) = ? AND query_tag = ? AND country = ? AND source = 'shodan'",
        (date, query_tag, country),
    ).fetchall()

    if len(snapshots) < 2:
        log.debug("Only %d readings for %s/%s on %s — skipping consolidation", len(snapshots), country, query_tag, date)
        return None

    snapshot_ids = [s['id'] for s in snapshots]
    num_readings = len(snapshot_ids)
    placeholders = ','.join('?' * len(snapshot_ids))

    # Count how many readings each (ip, port) appears in
    rows = db.execute(f"""
        SELECT ip, port, transport, product, org,
               COUNT(DISTINCT snapshot_id) as readings_present
        FROM hosts
        WHERE snapshot_id IN ({placeholders})
        GROUP BY ip, port
        HAVING readings_present >= 2
    """, snapshot_ids).fetchall()

    if not rows:
        log.info("No hosts survived intersection for %s/%s on %s", country, query_tag, date)
        return None

    now = datetime.now(timezone.utc).isoformat()

    # Upsert consolidated record
    db.execute(
        "INSERT INTO consolidated (date, query_tag, country, host_count, created_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(date, query_tag, country) DO UPDATE SET host_count = ?, created_at = ?",
        (date, query_tag, country, len(rows), now, len(rows), now),
    )
    consolidated_id = db.execute(
        "SELECT id FROM consolidated WHERE date = ? AND query_tag = ? AND country = ?",
        (date, query_tag, country),
    ).fetchone()['id']

    # Clear old consolidated hosts for this record
    db.execute("DELETE FROM consolidated_hosts WHERE consolidated_id = ?", (consolidated_id,))

    # Insert consolidated hosts
    for r in rows:
        confidence = r['readings_present'] / num_readings
        db.execute(
            "INSERT INTO consolidated_hosts "
            "(consolidated_id, ip, port, transport, product, org, readings_present, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (consolidated_id, r['ip'], r['port'], r['transport'],
             r['product'], r['org'], r['readings_present'], round(confidence, 2)),
        )

    db.commit()
    log.info("Consolidated %d hosts for %s/%s on %s (%d readings)",
             len(rows), country, query_tag, date, num_readings)
    return consolidated_id


def compute_changes(date: str, query_tag: str, country: str) -> list[dict]:
    """Compare today's consolidated snapshot with yesterday's. Returns list of changes."""
    db = get_db()
    yesterday = (datetime.strptime(date, '%Y-%m-%d') - timedelta(days=1)).strftime('%Y-%m-%d')

    today_id = db.execute(
        "SELECT id FROM consolidated WHERE date = ? AND query_tag = ? AND country = ?",
        (date, query_tag, country),
    ).fetchone()
    yesterday_id = db.execute(
        "SELECT id FROM consolidated WHERE date = ? AND query_tag = ? AND country = ?",
        (yesterday, query_tag, country),
    ).fetchone()

    if not today_id:
        return []

    today_id = today_id['id']

    # Build host sets keyed by (ip, port)
    today_hosts = {}
    for h in db.execute("SELECT * FROM consolidated_hosts WHERE consolidated_id = ?", (today_id,)):
        today_hosts[(h['ip'], h['port'])] = dict(h)

    yesterday_hosts = {}
    if yesterday_id:
        for h in db.execute("SELECT * FROM consolidated_hosts WHERE consolidated_id = ?", (yesterday_id['id'],)):
            yesterday_hosts[(h['ip'], h['port'])] = dict(h)

    if not yesterday_hosts:
        # First day — everything is "appeared" but don't flag it as changes
        log.info("No prior data for %s/%s — baseline established", country, query_tag)
        return []

    changes = []

    # Appeared: in today but not yesterday
    for key, host in today_hosts.items():
        if key not in yesterday_hosts:
            changes.append({
                'change_type': 'appeared',
                'ip': host['ip'], 'port': host['port'],
                'product': host['product'], 'org': host['org'],
                'confidence': host['confidence'],
            })

    # Disappeared: in yesterday but not today
    for key, host in yesterday_hosts.items():
        if key not in today_hosts:
            changes.append({
                'change_type': 'disappeared',
                'ip': host['ip'], 'port': host['port'],
                'product': host['product'], 'org': host['org'],
                'confidence': host['confidence'],
            })

    # Modified: same (ip, port) but different product
    for key in today_hosts.keys() & yesterday_hosts.keys():
        t, y = today_hosts[key], yesterday_hosts[key]
        if t['product'] != y['product'] and t['product'] and y['product']:
            changes.append({
                'change_type': 'modified',
                'ip': t['ip'], 'port': t['port'],
                'product': f"{y['product']} -> {t['product']}",
                'org': t['org'],
                'confidence': t['confidence'],
            })

    # Store changes in DB
    for c in changes:
        db.execute(
            "INSERT INTO changes (date, query_tag, country, change_type, ip, port, product, org, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (date, query_tag, country, c['change_type'], c['ip'], c['port'],
             c['product'], c['org'], c['confidence']),
        )
    db.commit()

    log.info("Changes for %s/%s on %s: %d appeared, %d disappeared, %d modified",
             country, query_tag, date,
             sum(1 for c in changes if c['change_type'] == 'appeared'),
             sum(1 for c in changes if c['change_type'] == 'disappeared'),
             sum(1 for c in changes if c['change_type'] == 'modified'))
    return changes
