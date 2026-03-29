"""Censys Platform API v3 host validation — cross-references Shodan findings."""
import logging
from datetime import datetime, timezone

import requests

from config import CENSYS_DAILY_BUDGET
from models import get_db

log = logging.getLogger(__name__)

# Censys Platform API v3
BASE_URL = "https://api.platform.censys.io/v3/global/asset/host"
ACCEPT_HEADER = "application/vnd.censys.api.v3.host.v1+json"


def _get_token():
    import os
    return os.environ.get('CENSYS_API_TOKEN', '')


def _budget_ok() -> bool:
    if not _get_token():
        return False
    db = get_db()
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    row = db.execute("SELECT count FROM censys_budget WHERE date = ?", (today,)).fetchone()
    used = row['count'] if row else 0
    return used < CENSYS_DAILY_BUDGET


def _increment_budget():
    db = get_db()
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    db.execute(
        "INSERT INTO censys_budget (date, count) VALUES (?, 1) "
        "ON CONFLICT(date) DO UPDATE SET count = count + 1",
        (today,),
    )
    db.commit()


def validate_host(ip: str) -> dict | None:
    """Check if a host exists in Censys via Platform API v3.
    Returns dict with ports/services or None on error/budget exceeded."""
    if not _budget_ok():
        log.debug("Censys budget exceeded or no token configured")
        return None

    token = _get_token()
    try:
        r = requests.get(
            f"{BASE_URL}/{ip}",
            headers={
                'Authorization': f'Bearer {token}',
                'Accept': ACCEPT_HEADER,
            },
            timeout=15,
        )
        _increment_budget()

        if r.status_code == 404:
            return {'found': False, 'ip': ip, 'ports': [], 'services': []}
        if r.status_code == 403:
            log.warning("Censys 403 for %s — may need higher tier for this host", ip)
            return None
        if r.status_code != 200:
            log.warning("Censys API error %d for %s: %s", r.status_code, ip, r.text[:200])
            return None

        data = r.json().get('result', {})
        resource = data.get('resource', data)
        services = resource.get('services', [])
        ports = [s.get('port') for s in services if s.get('port')]

        return {
            'found': True,
            'ip': ip,
            'ports': ports,
            'services': [
                {
                    'port': s.get('port'),
                    'service_name': s.get('service_name', ''),
                    'transport': s.get('transport_protocol', 'TCP'),
                }
                for s in services[:20]
            ],
            'autonomous_system': resource.get('autonomous_system', {}),
            'location': resource.get('location', {}),
        }
    except requests.RequestException as e:
        log.warning("Censys request failed for %s: %s", ip, e)
        return None
