#!/usr/bin/env python3
"""
PortScan Defender — Auto-block IPs that rapidly scan multiple ports.

Watches conntrack/netfilter logs for IPs hitting many distinct destination
ports in a short window — the hallmark of Shodan/Censys-style mass scanners.
Adds them to an iptables blocklist and optionally reports to AbuseIPDB.

Runs as a systemd service on the T-Pot honeypot host.

Usage:
    python3 portscan_defender.py                    # normal mode
    python3 portscan_defender.py --dry-run          # log only, no iptables
    python3 portscan_defender.py --threshold 10     # block after 10 ports
"""

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WHITELIST_CIDRS = [
    "192.168.0.0/16",   # LAN
    "10.0.0.0/8",       # LAN
    "172.16.0.0/12",    # Docker / LAN
    "127.0.0.0/8",      # Loopback
]

# How to detect scanners
DEFAULT_PORT_THRESHOLD = 8       # IPs hitting >= N distinct ports in the window
DEFAULT_WINDOW_SECONDS = 60      # Time window to count ports
DEFAULT_POLL_INTERVAL = 10       # How often to check conntrack
DEFAULT_BLOCK_DURATION = 86400   # 24 hours

# AbuseIPDB config (set via env vars)
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/report"

# iptables chain name
CHAIN = "PORTSCAN_BLOCK"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ip_in_whitelist(ip: str) -> bool:
    """Check if IP is in a whitelisted CIDR range."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in WHITELIST_CIDRS:
            if addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False


def run_cmd(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    """Run a command and return (exit_code, output)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr
    except Exception as e:
        return -1, str(e)


def get_conntrack_entries() -> list[dict]:
    """Parse current conntrack table for TCP SYN connections."""
    rc, output = run_cmd(["conntrack", "-L", "-p", "tcp", "--state", "SYN_SENT,SYN_RECV,ESTABLISHED"], timeout=15)
    if rc != 0:
        # Fallback: parse ss output for external connections
        return get_ss_entries()

    entries = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        # Parse: tcp  6 ... src=1.2.3.4 dst=... sport=... dport=22
        src_match = re.search(r"src=(\d+\.\d+\.\d+\.\d+)", line)
        dport_match = re.search(r"dport=(\d+)", line)
        if src_match and dport_match:
            entries.append({
                "src_ip": src_match.group(1),
                "dport": int(dport_match.group(1)),
            })
    return entries


def get_ss_entries() -> list[dict]:
    """Fallback: parse ss for current connections."""
    rc, output = run_cmd(["ss", "-tn", "state", "established", "state", "syn-recv"])
    if rc != 0:
        return []

    entries = []
    for line in output.strip().split("\n")[1:]:  # skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        # Peer address is parts[4]: 1.2.3.4:12345
        peer = parts[4]
        local = parts[3]
        if ":" in peer and ":" in local:
            src_ip = peer.rsplit(":", 1)[0]
            dport = int(local.rsplit(":", 1)[1])
            entries.append({"src_ip": src_ip, "dport": dport})
    return entries


# ---------------------------------------------------------------------------
# Main Defender
# ---------------------------------------------------------------------------

class PortScanDefender:

    def __init__(self, args):
        self.port_threshold = args.threshold
        self.window_seconds = args.window
        self.poll_interval = args.poll_interval
        self.block_duration = args.block_duration
        self.dry_run = args.dry_run
        self.state_file = args.state_file
        self.running = True

        # State: {ip: set of (dport, timestamp)} for window tracking
        self.ip_ports: dict[str, list[tuple[int, float]]] = defaultdict(list)
        # Blocked IPs: {ip: unblock_timestamp}
        self.blocked: dict[str, float] = {}
        # Already-reported to AbuseIPDB this session
        self.reported: set[str] = set()

        self.logger = self._setup_logging(args.log_file)
        self._ensure_chain()
        self._load_state()

    def _setup_logging(self, log_file: str) -> logging.Logger:
        logger = logging.getLogger("portscan_defender")
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        fh = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)
        return logger

    def _ensure_chain(self):
        """Create iptables chain if it doesn't exist."""
        if self.dry_run:
            return
        run_cmd(["iptables", "-N", CHAIN])
        # Ensure jumps exist
        for parent in ["INPUT", "FORWARD", "DOCKER-USER"]:
            rc, _ = run_cmd(["iptables", "-C", parent, "-j", CHAIN])
            if rc != 0:
                run_cmd(["iptables", "-I", parent, "1", "-j", CHAIN])

    def _load_state(self):
        """Load persisted block list."""
        try:
            with open(self.state_file) as f:
                state = json.load(f)
            now = time.time()
            for ip, unblock_at in state.get("blocked", {}).items():
                if unblock_at > now:
                    self.blocked[ip] = unblock_at
                    if not self.dry_run:
                        # Re-apply rule
                        rc, _ = run_cmd(["iptables", "-C", CHAIN, "-s", ip, "-j", "DROP"])
                        if rc != 0:
                            run_cmd(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
            if self.blocked:
                self.logger.info("Restored %d active blocks from state", len(self.blocked))
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning("Failed to load state: %s", e)

    def _save_state(self):
        """Persist block list."""
        try:
            with open(self.state_file, "w") as f:
                json.dump({"blocked": self.blocked}, f)
        except Exception as e:
            self.logger.warning("Failed to save state: %s", e)

    def _block_ip(self, ip: str, port_count: int, ports: list[int]):
        """Add IP to iptables blocklist."""
        if ip in self.blocked:
            return

        unblock_at = time.time() + self.block_duration
        self.blocked[ip] = unblock_at

        port_sample = sorted(ports)[:15]
        self.logger.warning(
            "BLOCKED %s — scanned %d ports in %ds: %s (block expires: %s)",
            ip, port_count, self.window_seconds,
            ",".join(str(p) for p in port_sample),
            datetime.fromtimestamp(unblock_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        if not self.dry_run:
            run_cmd(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])

        # Report to AbuseIPDB
        if ABUSEIPDB_KEY and ip not in self.reported:
            self._report_abuseipdb(ip, port_count, port_sample)

        self._save_state()

    def _unblock_expired(self):
        """Remove expired blocks."""
        now = time.time()
        expired = [ip for ip, t in self.blocked.items() if t <= now]
        for ip in expired:
            del self.blocked[ip]
            if not self.dry_run:
                run_cmd(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
            self.logger.info("UNBLOCKED %s (block expired)", ip)
        if expired:
            self._save_state()

    def _report_abuseipdb(self, ip: str, port_count: int, ports: list[int]):
        """Report scanner to AbuseIPDB."""
        try:
            comment = f"Port scan detected: {port_count} ports probed in {self.window_seconds}s (ports: {','.join(str(p) for p in ports[:10])})"
            resp = requests.post(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                data={
                    "ip": ip,
                    "categories": "14",  # Port scan
                    "comment": comment,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                self.reported.add(ip)
                self.logger.info("Reported %s to AbuseIPDB", ip)
            else:
                self.logger.warning("AbuseIPDB report failed (%d): %s", resp.status_code, resp.text[:200])
        except Exception as e:
            self.logger.warning("AbuseIPDB report error: %s", e)

    def _prune_window(self):
        """Remove entries outside the time window."""
        cutoff = time.time() - self.window_seconds
        for ip in list(self.ip_ports.keys()):
            self.ip_ports[ip] = [(p, t) for p, t in self.ip_ports[ip] if t > cutoff]
            if not self.ip_ports[ip]:
                del self.ip_ports[ip]

    def poll(self):
        """One detection cycle."""
        now = time.time()
        entries = get_conntrack_entries()

        for e in entries:
            ip = e["src_ip"]
            dport = e["dport"]

            if ip_in_whitelist(ip) or ip in self.blocked:
                continue

            self.ip_ports[ip].append((dport, now))

        self._prune_window()

        # Check for scanners
        for ip, port_entries in list(self.ip_ports.items()):
            unique_ports = set(p for p, _ in port_entries)
            if len(unique_ports) >= self.port_threshold:
                self._block_ip(ip, len(unique_ports), list(unique_ports))
                del self.ip_ports[ip]

        self._unblock_expired()

    def run(self):
        self.logger.info(
            "PortScan Defender starting — threshold=%d ports/%ds, poll=%ds, block=%ds%s",
            self.port_threshold, self.window_seconds, self.poll_interval,
            self.block_duration, " [DRY RUN]" if self.dry_run else "",
        )

        while self.running:
            try:
                self.poll()
            except Exception as e:
                self.logger.error("Poll error: %s", e)
            time.sleep(self.poll_interval)

        self._save_state()
        self.logger.info("PortScan Defender stopped (%d active blocks)", len(self.blocked))

    def stop(self):
        self.running = False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="PortScan Defender — auto-block rapid port scanners")
    p.add_argument("--threshold", type=int, default=DEFAULT_PORT_THRESHOLD,
                   help=f"Block IPs scanning >= N ports (default: {DEFAULT_PORT_THRESHOLD})")
    p.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS,
                   help=f"Detection window in seconds (default: {DEFAULT_WINDOW_SECONDS})")
    p.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL,
                   help=f"Seconds between checks (default: {DEFAULT_POLL_INTERVAL})")
    p.add_argument("--block-duration", type=int, default=DEFAULT_BLOCK_DURATION,
                   help=f"Block duration in seconds (default: {DEFAULT_BLOCK_DURATION})")
    p.add_argument("--log-file", default="/var/log/portscan_defender.log")
    p.add_argument("--state-file", default="/var/lib/portscan_defender.json")
    p.add_argument("--dry-run", action="store_true", help="Log only, no iptables changes")
    args = p.parse_args()

    defender = PortScanDefender(args)

    def handle_signal(signum, frame):
        defender.logger.info("Received signal %d — stopping", signum)
        defender.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    defender.run()


if __name__ == "__main__":
    main()
