"""Discord webhook notifications for daily change summaries."""
import logging
from datetime import datetime, timezone

import requests

from config import PRIORITY_COUNTRIES, COUNTRIES, MIN_CONFIDENCE
from models import get_db

log = logging.getLogger(__name__)


def send_daily_summary(webhook_url: str, date: str | None = None) -> bool:
    """Build and send a daily infrastructure change summary to Discord."""
    if not webhook_url:
        log.warning("No Discord webhook URL configured")
        return False

    if not date:
        date = datetime.now(timezone.utc).strftime('%Y-%m-%d')

    db = get_db()

    # Gather changes by country
    embeds = []
    total_appeared = total_disappeared = total_modified = 0

    for country in PRIORITY_COUNTRIES:
        rows = db.execute(
            "SELECT * FROM changes WHERE date = ? AND country = ? AND confidence >= ? "
            "ORDER BY confidence DESC",
            (date, country, MIN_CONFIDENCE),
        ).fetchall()

        if not rows:
            continue

        appeared = [r for r in rows if r['change_type'] == 'appeared']
        disappeared = [r for r in rows if r['change_type'] == 'disappeared']
        modified = [r for r in rows if r['change_type'] == 'modified']

        total_appeared += len(appeared)
        total_disappeared += len(disappeared)
        total_modified += len(modified)

        parts = []
        if appeared:
            top = appeared[:5]
            lines = [f"`{r['ip']}:{r['port']}` {r['product'] or '?'} ({r['org'] or '?'}) [{r['confidence']:.0%}]" for r in top]
            parts.append(f"**+{len(appeared)} appeared**\n" + "\n".join(lines))
            if len(appeared) > 5:
                parts[-1] += f"\n*...and {len(appeared)-5} more*"

        if disappeared:
            top = disappeared[:5]
            lines = []
            for r in top:
                nmap = ""
                if r['nmap_verified']:
                    nmap = f" nmap:{r['nmap_state']}"
                lines.append(f"`{r['ip']}:{r['port']}` {r['product'] or '?'}{nmap} [{r['confidence']:.0%}]")
            parts.append(f"**-{len(disappeared)} disappeared**\n" + "\n".join(lines))
            if len(disappeared) > 5:
                parts[-1] += f"\n*...and {len(disappeared)-5} more*"

        if modified:
            top = modified[:3]
            lines = [f"`{r['ip']}:{r['port']}` {r['product']}" for r in top]
            parts.append(f"**~{len(modified)} modified**\n" + "\n".join(lines))

        country_name = COUNTRIES.get(country, country)
        flag_map = {'IR': '\U0001f1ee\U0001f1f7', 'RU': '\U0001f1f7\U0001f1fa', 'CN': '\U0001f1e8\U0001f1f3',
                     'UA': '\U0001f1fa\U0001f1e6', 'KP': '\U0001f1f0\U0001f1f5', 'IL': '\U0001f1ee\U0001f1f1',
                     'SY': '\U0001f1f8\U0001f1fe'}
        flag = flag_map.get(country, '')

        body = "\n\n".join(parts)
        if len(body) > 900:
            body = body[:900] + "\n*...truncated*"

        embeds.append({
            'title': f"{flag} {country_name}",
            'description': body,
            'color': 0xFE8D2F if disappeared else 0x57F287,
        })

    if not embeds:
        log.info("No significant changes for %s — skipping Discord notification", date)
        return True

    # Summary embed
    summary = {
        'title': f"Daily Infrastructure Report — {date}",
        'description': (
            f"**{total_appeared}** new hosts | **{total_disappeared}** disappeared | **{total_modified}** modified\n"
            f"Tracking {len(PRIORITY_COUNTRIES)} countries, confidence threshold {MIN_CONFIDENCE:.0%}"
        ),
        'color': 0x5865F2,
        'footer': {'text': 'ELKIE Recon Tracker v2'},
    }

    # Discord allows max 10 embeds per message
    all_embeds = [summary] + embeds[:9]

    try:
        r = requests.post(webhook_url, json={'embeds': all_embeds}, timeout=10)
        if r.status_code in (200, 204):
            # Mark changes as notified
            db.execute("UPDATE changes SET notified = 1 WHERE date = ? AND confidence >= ?",
                       (date, MIN_CONFIDENCE))
            db.commit()
            log.info("Discord summary sent for %s (%d embeds)", date, len(all_embeds))
            return True
        else:
            log.warning("Discord webhook returned %d: %s", r.status_code, r.text[:200])
            return False
    except requests.RequestException as e:
        log.warning("Discord webhook failed: %s", e)
        return False
