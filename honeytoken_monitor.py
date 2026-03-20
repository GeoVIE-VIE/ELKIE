#!/usr/bin/env python3
"""
Honeytoken Monitor — Canary Files & Credential Traps on Trusted Network

Deploys decoy files, fake credentials, and canary services on the trusted
network. If an attacker pivots from the honeypot subnet or compromises a
real machine, these traps fire instantly.

Honeytokens deployed:
  - Fake AWS/SSH/DB credential files in common locations
  - Canary DNS records (unique subdomains that alert on resolution)
  - Decoy files with inotify watches (alert on access)
  - Fake admin pages on unused ports

Usage:
    python3 honeytoken_monitor.py --deploy              # deploy all tokens
    python3 honeytoken_monitor.py --monitor              # watch for triggers
    python3 honeytoken_monitor.py --deploy --monitor     # deploy + watch
"""

import argparse
import hashlib
import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "")
LOG_FILE = "/home/legs/honeytoken_monitor.log"
STATE_FILE = "/home/legs/.honeytoken_state.json"
TOKEN_DIR = Path("/home/legs/.honeytokens")

# Honeytoken definitions
HONEYTOKENS = {
    "aws_credentials": {
        "path": "/home/legs/.aws/credentials",
        "content": """[default]
aws_access_key_id = AKIAIOSFODNN7HONEYPOT
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYTOKEN1
region = us-east-1
# Production account — DO NOT SHARE
""",
        "description": "Fake AWS credentials",
    },
    "ssh_private_key": {
        "path": "/home/legs/.ssh/honeypot_prod_key",
        "content": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
HONEYTOKENFAKEKEYHONEYTOKENFAKEKEYHONEYTOKENFAKEKEYHONEYTOKE
NFAKEKEYHONEYTOKENFAKEKEYHONEYTOKENFAKEKEYHONEYTOKENFAKEKEY
-----END OPENSSH PRIVATE KEY-----
""",
        "description": "Fake SSH key labeled as production",
    },
    "database_config": {
        "path": "/home/legs/database.yml",
        "content": """# Production database — last updated 2026-03-01
production:
  adapter: postgresql
  host: db-prod-01.internal.elkie.local
  port: 5432
  database: elkie_production
  username: admin_prod
  password: Pr0d_Sup3r_S3cr3t_2026!
  pool: 25
""",
        "description": "Fake database credentials",
    },
    "vpn_config": {
        "path": "/home/legs/.openvpn/corporate.ovpn",
        "content": """client
dev tun
proto udp
remote vpn.corporate-elkie.com 1194
resolv-retry infinite
nobind
auth-user-pass
# user: admin@elkie.com
# pass: VPN_Corporate_2026!
ca ca.crt
cert client.crt
key client.key
""",
        "description": "Fake VPN configuration",
    },
    "env_file": {
        "path": "/home/legs/projects/.env.production",
        "content": """# Production environment — NEVER COMMIT
DATABASE_URL=postgresql://admin:Pr0dDB_Pass2026!@db-prod.internal:5432/elkie
REDIS_URL=redis://:Redis_S3cret@cache-prod.internal:6379/0
API_SECRET_KEY=sk_live_HoneyToken_51Rqz3FAKE_KEY_DO_NOT_USE
STRIPE_SECRET=sk_live_HoneyToken_stripe_fake_key_2026
AWS_ACCESS_KEY=AKIAIOSFODNN7HONEYPOT
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYTOKEN2
SMTP_PASSWORD=MailGun_H0neyT0ken_2026
""",
        "description": "Fake production environment file",
    },
    "password_file": {
        "path": "/home/legs/Documents/passwords.txt",
        "content": """=== IMPORTANT PASSWORDS ===
Last updated: 2026-02-15

Router admin: admin / R0ut3r_Admin_2026!
NAS: admin / NAS_Backup_Pass2026!
Grafana: admin / Gr4fana_Pr0d_2026!
Proxmox: root / Prox_R00t_2026!
pfSense: admin / pfS3nse_FW_2026!
IPMI: admin / IPMI_Remote_2026!
iDRAC: root / iDRAC_Srv01_2026!
ESXi: root / ESXi_Host_2026!
""",
        "description": "Fake password list",
    },
    "bitcoin_wallet": {
        "path": "/home/legs/.bitcoin/wallet.dat.bak",
        "content": """# Bitcoin wallet backup — 2.3 BTC
# Seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
# Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
""",
        "description": "Fake Bitcoin wallet backup",
    },
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging():
    logger = logging.getLogger("honeytoken")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

# ---------------------------------------------------------------------------
# Deploy honeytokens
# ---------------------------------------------------------------------------

def deploy_tokens(logger):
    """Create all honeytoken files."""
    deployed = {}

    for name, token in HONEYTOKENS.items():
        path = Path(token["path"])
        path.parent.mkdir(parents=True, exist_ok=True)

        # Don't overwrite if already exists and is a real file
        if path.exists():
            # Check if it's our honeytoken by checking a marker
            marker_path = TOKEN_DIR / f"{name}.marker"
            if not marker_path.exists():
                logger.warning("Skipping %s — real file exists at %s", name, path)
                continue

        with open(path, "w") as f:
            f.write(token["content"])

        # Set realistic permissions
        if "ssh" in name or "key" in name:
            os.chmod(path, 0o600)
        elif "env" in name or "credential" in name or "password" in name:
            os.chmod(path, 0o644)

        # Record deployment marker
        TOKEN_DIR.mkdir(parents=True, exist_ok=True)
        marker = TOKEN_DIR / f"{name}.marker"
        with open(marker, "w") as f:
            json.dump({
                "deployed_at": datetime.now(timezone.utc).isoformat(),
                "path": str(path),
                "hash": hashlib.sha256(token["content"].encode()).hexdigest(),
            }, f)

        deployed[name] = str(path)
        logger.info("Deployed honeytoken: %s → %s", name, path)

    logger.info("Deployed %d honeytokens", len(deployed))
    return deployed


# ---------------------------------------------------------------------------
# Monitor honeytokens via inotifywait
# ---------------------------------------------------------------------------

def fire_alert(token_name: str, token_info: dict, event: str, logger):
    """Fire Discord alert when a honeytoken is triggered."""
    logger.warning("HONEYTOKEN TRIGGERED: %s — %s (%s)", token_name, event, token_info["path"])

    if not WEBHOOK_URL:
        return

    fields = [
        {"name": "Token", "value": f"`{token_name}`", "inline": True},
        {"name": "Event", "value": f"`{event}`", "inline": True},
        {"name": "File", "value": f"`{token_info['path']}`", "inline": False},
        {"name": "Description", "value": HONEYTOKENS.get(token_name, {}).get("description", ""), "inline": False},
    ]

    # Try to identify who accessed it
    try:
        result = subprocess.run(
            ["sudo", "ausearch", "-f", token_info["path"], "--format", "text"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            audit_lines = result.stdout.strip().splitlines()[-5:]
            fields.append({"name": "Audit Trail", "value": f"```\n{chr(10).join(audit_lines)}\n```", "inline": False})
    except Exception:
        pass

    # Check who's logged in
    try:
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        if result.stdout.strip():
            fields.append({"name": "Active Sessions", "value": f"```\n{result.stdout.strip()}\n```", "inline": False})
    except Exception:
        pass

    payload = {
        "embeds": [{
            "title": "\U0001f6a8 HONEYTOKEN TRIGGERED — Possible Intrusion",
            "description": f"A honeytoken file was accessed on the trusted network. This may indicate an attacker has pivoted from the honeypot subnet or compromised a real machine.",
            "color": 0xED4245,
            "fields": fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "Honeytoken Monitor \u2022 ELKIE SOC"},
            "author": {"name": "Honeytoken Monitor \u2014 Intrusion Detection"},
        }]
    }

    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=10)
    except Exception as e:
        logger.error("Discord alert failed: %s", e)


def monitor_tokens(logger):
    """Watch honeytoken files for access using inotifywait."""
    # Collect all deployed token paths
    paths = []
    token_map = {}  # path -> token_name

    for name, token in HONEYTOKENS.items():
        path = token["path"]
        marker = TOKEN_DIR / f"{name}.marker"
        if marker.exists() and Path(path).exists():
            paths.append(path)
            token_map[path] = name

    if not paths:
        logger.error("No honeytokens deployed. Run with --deploy first.")
        return

    logger.info("Monitoring %d honeytokens...", len(paths))

    # Check if inotifywait is available
    try:
        subprocess.run(["which", "inotifywait"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("inotifywait not found. Install: sudo apt-get install inotify-tools")
        logger.info("Falling back to polling mode...")
        _monitor_polling(paths, token_map, logger)
        return

    # Build inotifywait command
    cmd = [
        "inotifywait", "-m", "-q",
        "--format", "%w %e",
        "-e", "access,open,modify,delete",
    ] + paths

    logger.info("Starting inotifywait on %d files", len(paths))

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    running = True
    def handle_signal(signum, frame):
        nonlocal running
        running = False
        proc.terminate()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    while running:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue

        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue

        filepath, event = parts

        # Ignore our own monitoring
        if "inotifywait" in event.lower():
            continue

        token_name = token_map.get(filepath.strip(), "unknown")
        token_info = {"path": filepath.strip()}

        fire_alert(token_name, token_info, event.strip(), logger)

    logger.info("Honeytoken monitor stopped")


def _monitor_polling(paths, token_map, logger):
    """Fallback: poll file access times."""
    last_access = {}
    for p in paths:
        try:
            last_access[p] = os.stat(p).st_atime
        except Exception:
            pass

    running = True
    def handle_signal(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    while running:
        for p in paths:
            try:
                current_atime = os.stat(p).st_atime
                if p in last_access and current_atime > last_access[p]:
                    token_name = token_map.get(p, "unknown")
                    fire_alert(token_name, {"path": p}, "ACCESS (poll)", logger)
                last_access[p] = current_atime
            except Exception:
                pass
        time.sleep(5)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Honeytoken Monitor — Canary Trap System")
    parser.add_argument("--deploy", action="store_true", help="Deploy honeytokens")
    parser.add_argument("--monitor", action="store_true", help="Monitor for triggers")
    parser.add_argument("--list", action="store_true", help="List deployed tokens")
    parser.add_argument("--cleanup", action="store_true", help="Remove all honeytokens")
    args = parser.parse_args()

    logger = setup_logging()

    if args.list:
        for name, token in HONEYTOKENS.items():
            marker = TOKEN_DIR / f"{name}.marker"
            status = "DEPLOYED" if marker.exists() else "NOT DEPLOYED"
            print(f"  [{status}] {name}: {token['path']}")
        return

    if args.cleanup:
        for name, token in HONEYTOKENS.items():
            path = Path(token["path"])
            marker = TOKEN_DIR / f"{name}.marker"
            if marker.exists():
                path.unlink(missing_ok=True)
                marker.unlink(missing_ok=True)
                logger.info("Removed: %s", path)
        return

    if args.deploy:
        deploy_tokens(logger)

    if args.monitor:
        monitor_tokens(logger)

    if not args.deploy and not args.monitor and not args.list and not args.cleanup:
        parser.print_help()


if __name__ == "__main__":
    main()
