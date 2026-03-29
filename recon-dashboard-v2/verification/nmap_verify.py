"""Non-intrusive nmap verification of disappeared hosts."""
import logging
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from config import MAX_NMAP_PER_DAY
from models import get_db

log = logging.getLogger(__name__)


def _budget_ok() -> bool:
    db = get_db()
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    row = db.execute("SELECT count FROM nmap_budget WHERE date = ?", (today,)).fetchone()
    used = row['count'] if row else 0
    return used < MAX_NMAP_PER_DAY


def _increment_budget():
    db = get_db()
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    db.execute(
        "INSERT INTO nmap_budget (date, count) VALUES (?, 1) "
        "ON CONFLICT(date) DO UPDATE SET count = count + 1",
        (today,),
    )
    db.commit()


def verify_host(ip: str, port: int, protocol: str = 'tcp') -> dict | None:
    """Run a targeted SYN scan on a single port. Returns state dict or None."""
    if not _budget_ok():
        log.debug("Nmap budget exceeded for today")
        return None

    # Validate inputs to prevent injection
    if not ip.replace('.', '').replace(':', '').isalnum():
        log.warning("Invalid IP for nmap: %s", ip)
        return None
    if not (1 <= port <= 65535):
        log.warning("Invalid port for nmap: %d", port)
        return None

    scan_type = '-sS' if protocol == 'tcp' else '-sU'
    cmd = [
        'nmap', scan_type, '-Pn',
        f'-p{port}',
        '--max-retries', '2',
        '--host-timeout', '30s',
        '-oX', '-',
        '--reason',
        ip,
    ]

    log.info("Nmap verify: %s:%d/%s", ip, port, protocol)
    _increment_budget()

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=45,
        )
    except subprocess.TimeoutExpired:
        return {'state': 'timeout', 'ip': ip, 'port': port, 'reason': 'scan timeout'}
    except FileNotFoundError:
        log.error("nmap not found — install it")
        return None

    # Parse XML output
    try:
        root = ET.fromstring(result.stdout)
        host_el = root.find('.//host')
        if host_el is None:
            return {'state': 'down', 'ip': ip, 'port': port, 'reason': 'no host response'}

        port_el = host_el.find(f'.//port[@portid="{port}"]')
        if port_el is None:
            return {'state': 'not_scanned', 'ip': ip, 'port': port, 'reason': 'port not in results'}

        state_el = port_el.find('state')
        state = state_el.get('state', 'unknown') if state_el is not None else 'unknown'
        reason = state_el.get('reason', '') if state_el is not None else ''

        service_el = port_el.find('service')
        service = service_el.get('name', '') if service_el is not None else ''

        return {
            'state': state,
            'reason': reason,
            'service': service,
            'ip': ip,
            'port': port,
        }
    except ET.ParseError:
        log.warning("Failed to parse nmap XML for %s:%d", ip, port)
        return {'state': 'parse_error', 'ip': ip, 'port': port, 'reason': result.stderr[:200]}
