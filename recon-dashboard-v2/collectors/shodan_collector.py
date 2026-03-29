"""Shodan IP-level host collector — replaces count-based snapshots."""
import hashlib
import json
import logging
import time
from datetime import datetime, timezone

import shodan

from config import SHODAN_API_KEY, SECTORS, SHODAN_RESULTS_PER_QUERY
from models import get_db

log = logging.getLogger(__name__)
api = shodan.Shodan(SHODAN_API_KEY)


def collect(country: str, query_tag: str, reading_number: int) -> int | None:
    """Run a Shodan search and store host-level results. Returns snapshot_id."""
    query_extra = SECTORS.get(query_tag, '')
    query = f"country:{country}"
    if query_extra:
        query += f" {query_extra}"

    db = get_db()
    now = datetime.now(timezone.utc).isoformat()

    # Create snapshot record
    cur = db.execute(
        "INSERT INTO snapshots (timestamp, source, query_tag, country, reading_number, host_count) "
        "VALUES (?, 'shodan', ?, ?, ?, 0)",
        (now, query_tag, country, reading_number),
    )
    snapshot_id = cur.lastrowid
    db.commit()

    try:
        result = api.search(query, page=1, limit=SHODAN_RESULTS_PER_QUERY, minify=True)
    except shodan.APIError as e:
        if 'upgrade' in str(e).lower() or 'rate' in str(e).lower():
            log.warning("Shodan rate limit on %s %s — backing off", country, query_tag)
            time.sleep(5)
            return snapshot_id
        log.warning("Shodan error for %s %s: %s", country, query_tag, e)
        return snapshot_id

    hosts = result.get('matches', [])
    rows = []
    for h in hosts:
        banner = (h.get('data', '') or '')[:500]
        rows.append((
            snapshot_id,
            h.get('ip_str', ''),
            h.get('port', 0),
            h.get('transport', 'tcp'),
            h.get('product', '') or '',
            h.get('version', '') or '',
            h.get('org', '') or '',
            str(h.get('asn', '') or ''),
            json.dumps(h.get('hostnames', []) or []),
            json.dumps(list((h.get('vulns', {}) or {}).keys())),
            hashlib.md5(banner.encode()).hexdigest() if banner else '',
        ))

    if rows:
        db.executemany(
            "INSERT INTO hosts (snapshot_id, ip, port, transport, product, version, org, asn, hostnames, vulns, banner_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    db.execute("UPDATE snapshots SET host_count = ? WHERE id = ?", (len(rows), snapshot_id))
    db.commit()

    log.info("Collected %d hosts for %s/%s (reading %d)", len(rows), country, query_tag, reading_number)
    return snapshot_id


def collect_all(country: str, reading_number: int, sectors: list[str] | None = None):
    """Collect all tracked sectors for a country."""
    from config import TRACKED_SECTORS
    targets = sectors or TRACKED_SECTORS
    for i, sector in enumerate(targets):
        try:
            collect(country, sector, reading_number)
        except Exception as e:
            log.error("Failed to collect %s/%s: %s", country, sector, e)
        if i < len(targets) - 1:
            time.sleep(1.2)  # rate limit
