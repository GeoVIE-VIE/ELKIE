"""APScheduler-based task scheduling for the recon pipeline."""
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from config import (PRIORITY_COUNTRIES, TRACKED_SECTORS, SNAPSHOT_HOURS_UTC,
                     CONSOLIDATE_HOUR_UTC, DISCORD_HOUR_UTC, DISCORD_WEBHOOK_URL,
                     MIN_CONFIDENCE)
from models import get_db, init_db

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler(daemon=True)


def _run_collection(reading_number: int):
    """Collect all priority countries for a reading."""
    from collectors.shodan_collector import collect_all
    log.info("=== Starting reading %d ===", reading_number)
    for country in PRIORITY_COUNTRIES:
        try:
            collect_all(country, reading_number)
        except Exception as e:
            log.error("Collection failed for %s reading %d: %s", country, reading_number, e)


def _run_consolidation():
    """Consolidate today's readings and compute changes."""
    from analysis.differ import consolidate_readings, compute_changes
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    log.info("=== Consolidating readings for %s ===", today)

    for country in PRIORITY_COUNTRIES:
        for sector in TRACKED_SECTORS:
            try:
                cid = consolidate_readings(today, sector, country)
                if cid:
                    compute_changes(today, sector, country)
            except Exception as e:
                log.error("Consolidation failed for %s/%s: %s", country, sector, e)


def _run_censys_validation():
    """Validate top changes with Censys."""
    from collectors.censys_collector import validate_host
    from analysis.confidence import score_change
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    db = get_db()

    # Get top unvalidated changes (appeared + disappeared, highest confidence first)
    changes = db.execute(
        "SELECT id, ip, port, change_type FROM changes "
        "WHERE date = ? AND nmap_verified IS NULL "
        "ORDER BY confidence DESC LIMIT 16",
        (today,),
    ).fetchall()

    log.info("=== Censys validation: %d candidates ===", len(changes))
    seen_ips = set()
    for c in changes:
        if c['ip'] in seen_ips:
            continue
        seen_ips.add(c['ip'])
        result = validate_host(c['ip'])
        if result is None:
            break  # budget exceeded
        score_change(c['id'], censys_result=result)


def _run_nmap_verification():
    """Verify disappeared hosts with nmap."""
    from verification.nmap_verify import verify_host
    from analysis.confidence import score_change
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    db = get_db()

    disappeared = db.execute(
        "SELECT id, ip, port FROM changes "
        "WHERE date = ? AND change_type = 'disappeared' AND nmap_verified IS NULL "
        "ORDER BY confidence DESC LIMIT 10",
        (today,),
    ).fetchall()

    log.info("=== Nmap verification: %d disappeared hosts ===", len(disappeared))
    for c in disappeared:
        result = verify_host(c['ip'], c['port'])
        if result is None:
            break  # budget exceeded
        score_change(c['id'], nmap_result=result)


def _run_discord_summary():
    """Send daily summary to Discord."""
    from notifications.discord import send_daily_summary
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    send_daily_summary(DISCORD_WEBHOOK_URL, today)


def start_scheduler():
    """Start all scheduled jobs."""
    init_db()

    # 3 collection readings per day (all times UTC)
    for i, hour in enumerate(SNAPSHOT_HOURS_UTC, 1):
        scheduler.add_job(
            _run_collection, CronTrigger(hour=hour, minute=0, timezone='UTC'),
            args=[i], id=f'collection_r{i}', replace_existing=True,
            name=f'Shodan collection reading {i}',
        )

    # Consolidation + diff at 19:00 UTC
    scheduler.add_job(
        _run_consolidation, CronTrigger(hour=CONSOLIDATE_HOUR_UTC, minute=0, timezone='UTC'),
        id='consolidation', replace_existing=True, name='Consolidate & diff',
    )

    # Censys validation at 19:30 UTC
    scheduler.add_job(
        _run_censys_validation, CronTrigger(hour=CONSOLIDATE_HOUR_UTC, minute=30, timezone='UTC'),
        id='censys_validation', replace_existing=True, name='Censys validation',
    )

    # Nmap verification at 19:45 UTC
    scheduler.add_job(
        _run_nmap_verification, CronTrigger(hour=CONSOLIDATE_HOUR_UTC, minute=45, timezone='UTC'),
        id='nmap_verification', replace_existing=True, name='Nmap verification',
    )

    # Discord summary at 20:00 UTC
    scheduler.add_job(
        _run_discord_summary, CronTrigger(hour=DISCORD_HOUR_UTC, minute=0, timezone='UTC'),
        id='discord_summary', replace_existing=True, name='Discord summary',
    )

    scheduler.start()
    log.info("Scheduler started with %d jobs", len(scheduler.get_jobs()))


def get_status() -> dict:
    """Get scheduler status for the API."""
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            'id': job.id,
            'name': job.name,
            'next_run': str(job.next_run_time) if job.next_run_time else None,
        })
    return {'running': scheduler.running, 'jobs': jobs}
