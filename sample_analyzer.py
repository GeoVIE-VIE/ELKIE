#!/usr/bin/env python3
"""
Sample Analyzer — Automated Malware Analysis Pipeline

Orchestrates malware sample analysis across the honeypot lab:
  1. Polls Elasticsearch for new file capture events (Cowrie/Dionaea)
  2. Fetches samples from T-Pot via SSH
  3. Submits to REMnux for static analysis (YARA, capa, floss, LLM)
  4. Indexes results in Elasticsearch
  5. Fires Discord alerts with threat intelligence

Security: ELK (trusted) initiates all connections to honeypot subnet.
REMnux never connects outbound to trusted network.
"""

import argparse
import json
import logging
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional
import urllib.parse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _env(key: str, default: str = "") -> str:
    """Get env var with fallback default."""
    return os.environ.get(key, default)

def _env_int(key: str, default: int) -> int:
    """Get env var as int with fallback default."""
    v = os.environ.get(key, "")
    return int(v) if v else default

def _env_bool(key: str, default: bool) -> bool:
    """Get env var as bool with fallback default."""
    v = os.environ.get(key, "")
    if not v:
        return default
    return v.lower() in ("1", "true", "yes")

# Base directory — all relative paths derive from this
ELKIE_HOME = Path(_env("ELKIE_HOME", "/home/legs"))

@dataclass
class Config:
    # Elasticsearch
    es_url: str = _env("ES_URL", "http://localhost:9200")
    es_index: str = _env("ES_FILEBEAT_INDEX", ".ds-filebeat-*")
    result_index: str = _env("ES_RESULT_INDEX", "malware-analysis")
    poll_interval: int = _env_int("POLL_INTERVAL", 60)
    webhook_url: Optional[str] = _env("DISCORD_WEBHOOK_URL") or None
    log_file: str = _env("LOG_FILE", str(ELKIE_HOME / "sample_analyzer.log"))
    state_file: str = _env("STATE_FILE", str(ELKIE_HOME / ".sample_analyzer_state.json"))
    grafana_url: Optional[str] = _env("GRAFANA_URL", "") or None
    grafana_dashboard_uid: Optional[str] = _env("GRAFANA_DASHBOARD_UID", "tpot-attack-overview")
    dry_run: bool = _env_bool("DRY_RUN", False)
    backfill_hours: int = _env_int("BACKFILL_HOURS", 0)
    verbosity: str = _env("VERBOSITY", "normal")
    # T-Pot SSH (jump host for honeypot subnet)
    tpot_host: str = _env("TPOT_IP", "192.168.40.3")
    tpot_port: int = _env_int("TPOT_SSH_PORT", 64295)
    tpot_user: str = _env("TPOT_SSH_USER", "lepots")
    # REMnux SSH (static malware analysis)
    remnux_host: str = _env("REMNUX_IP", "192.168.40.5")
    remnux_port: int = _env_int("REMNUX_SSH_PORT", 22)
    remnux_user: str = _env("REMNUX_SSH_USER", "nalyzer")
    remnux_inbox: str = _env("REMNUX_INBOX", f"/home/{_env('REMNUX_SSH_USER', 'nalyzer')}/inbox")
    remnux_results: str = _env("REMNUX_RESULTS", f"/home/{_env('REMNUX_SSH_USER', 'nalyzer')}/results")
    remnux_script: str = _env("REMNUX_SCRIPT", f"/home/{_env('REMNUX_SSH_USER', 'nalyzer')}/analyze_sample.sh")
    remnux_vmid: int = _env_int("VMID_REMNUX", 106)
    remnux_auto_start: bool = _env_bool("REMNUX_AUTO_START", True)
    # Sandbox (dynamic analysis / detonation)
    sandbox_host: str = _env("SANDBOX_IP", "192.168.40.6")
    sandbox_port: int = _env_int("SANDBOX_SSH_PORT", 22)
    sandbox_user: str = _env("SANDBOX_SSH_USER", "dettony")
    sandbox_vmid: int = _env_int("VMID_SANDBOX", 109)
    sandbox_snapshot: str = _env("SANDBOX_SNAPSHOT", "clean")
    sandbox_enabled: bool = _env_bool("SANDBOX_ENABLED", True)
    sandbox_timeout: int = _env_int("SANDBOX_TIMEOUT", 90)
    # Sacrificial VM (via T-Pot jump host)
    sacrificial_host: str = _env("SACRIFICIAL_IP", "192.168.40.99")
    sacrificial_port: int = _env_int("SACRIFICIAL_SSH_PORT", 22)
    sacrificial_user: str = _env("SACRIFICIAL_SSH_USER", "root")
    # Proxmox API
    pve_api_url: str = _env("PVE_API_URL", "https://192.168.99.160:8006")
    pve_node: str = _env("PROXMOX_NODE", "flexiserve")
    pve_token_id: str = _env("PVE_TOKEN_ID", "")
    pve_token_secret: str = _env("PVE_TOKEN_SECRET", "")
    # MISP
    misp_url: str = _env("MISP_URL", "https://localhost")
    misp_api_key: str = _env("MISP_API_KEY", "")
    # Sacrificial VM agent names (as they appear in ES auditd logs)
    sacrificial_agent_name: str = _env("SACRIFICIAL_AGENT_NAME", "ds-prod-web01")
    sacrificial_agent_alt: str = _env("SACRIFICIAL_AGENT_ALT", "prodction1")
    # LLM configuration
    llm_mode: str = _env("LLM_MODE", "api")           # api | local | none
    llm_api_model: str = _env("LLM_API_MODEL", "claude-sonnet-4-20250514")
    llm_local_url: str = _env("LLM_LOCAL_URL", "http://localhost:11434")
    llm_local_model: str = _env("LLM_LOCAL_MODEL", "llama3:8b")
    # Cover story (for DNS interception on sandbox)
    remnux_dns_ip: str = _env("REMNUX_IP", "192.168.40.5")
    # Limits
    sample_retention_days: int = _env_int("SAMPLE_RETENTION_DAYS", 30)
    analysis_timeout: int = _env_int("ANALYSIS_TIMEOUT", 300)
    max_sample_size: int = _env_int("MAX_SAMPLE_SIZE", 52428800)
    alert_confidence_threshold: int = _env_int("ALERT_CONFIDENCE_THRESHOLD", 20)
    # Ghidra MCP interactive analysis
    ghidra_mcp_enabled: bool = _env_bool("GHIDRA_MCP_ENABLED", True)
    ghidra_mcp_max_turns: int = _env_int("GHIDRA_MCP_MAX_TURNS", 15)
    ghidra_mcp_max_cost: float = float(_env("GHIDRA_MCP_MAX_COST", "0.50"))
    ghidra_mcp_bridge_port: int = _env_int("GHIDRA_MCP_BRIDGE_PORT", 8081)
    ghidra_mcp_ghidra_port: int = _env_int("GHIDRA_MCP_GHIDRA_PORT", 8080)

STAGING_DIR = Path(_env("STAGING_DIR", str(ELKIE_HOME / "sample_staging")))
ANALYSIS_SCRIPT_LOCAL = Path(str(ELKIE_HOME / "analyze_sample.sh"))

# Sample directories on T-Pot (inside /data + quarantine)
_tpot_user = _env("TPOT_SSH_USER", "lepots")
_tpot_dirs_env = _env("TPOT_SAMPLE_DIRS", "")
if _tpot_dirs_env:
    TPOT_SAMPLE_DIRS = [d.strip() for d in _tpot_dirs_env.split(",") if d.strip()]
else:
    TPOT_SAMPLE_DIRS = [
        f"/home/{_tpot_user}/tpotce/data/cowrie/downloads",
        f"/home/{_tpot_user}/tpotce/data/dionaea/binaries",
        f"/home/{_tpot_user}/tpotce/data/honeytrap/downloads",
        f"/home/{_tpot_user}/tpotce/data/adbhoney/downloads",
        "/opt/honeypot-quarantine/cowrie",
        "/opt/honeypot-quarantine/dionaea",
        "/opt/honeypot-quarantine/honeytrap",
        "/opt/honeypot-quarantine/adbhoney",
        "/opt/honeypot-quarantine/glutton",
        "/opt/honeypot-quarantine/glutton_shared",
    ]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def _safe_hash(h: str) -> str:
    """Validate and return a SHA256 hash, or raise ValueError. Prevents injection."""
    h = h.strip()
    if len(h) == 64 and all(c in '0123456789abcdef' for c in h):
        return h
    raise ValueError(f"Invalid SHA256 hash: {h[:20]}...")

def _safe_ip(ip: str) -> str:
    """Validate and return an IP address. Prevents injection."""
    import ipaddress
    return str(ipaddress.ip_address(ip.strip()))

# Auditd false positive patterns — bracket-wrapped names are fake kernel threads,
# common malware trick to hide in `ps` output.
_AUDITD_FP_PATTERNS = [
    re.compile(r'^\[.*\]$'),          # [kworker/1:0H], [kthreadd], etc.
    re.compile(r'^/proc/'),            # /proc paths aren't real executables
    re.compile(r'^/sys/'),             # sysfs paths
]

# Persistent false-positive list (path-based, loaded from file)
_FP_LIST_FILE = ELKIE_HOME / ".sample_analyzer_fp.json"

# ---------------------------------------------------------------------------
# Main daemon class
# ---------------------------------------------------------------------------

class SampleAnalyzer:

    def __init__(self, config: Config):
        self.cfg = config
        self.known_hashes: set = set()
        self._auditd_cooldown: dict[str, float] = {}  # path -> last_seen timestamp
        self._false_positives: dict[str, str] = {}     # path or hash -> reason
        self.last_timestamp: Optional[str] = None
        self.last_dir_scan: float = 0
        self.last_cleanup: float = 0
        self.running = True
        self.logger = self._setup_logging()
        self._tpot_pass = os.environ.get("TPOT_SSH_PASS", os.environ.get("TPOT_PASS", ""))
        self._remnux_pass = os.environ.get("REMNUX_SSH_PASS", os.environ.get("REMNUX_PASS", ""))
        self._vt_api_key = os.environ.get("VT_API_KEY", "")
        self._mb_api_key = os.environ.get("MB_API_KEY", "")
        self._anthropic_key = os.environ.get("CLAUDE_API_KEY", "")
        self._pve_token_id = self.cfg.pve_token_id
        self._pve_token_secret = self.cfg.pve_token_secret
        self._misp_api_key = self.cfg.misp_api_key

    # -- logging -----------------------------------------------------------

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("sample_analyzer")
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

        fh = RotatingFileHandler(self.cfg.log_file, maxBytes=10_000_000, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

        return logger

    # -- state persistence -------------------------------------------------

    def save_state(self):
        state = {
            "last_timestamp": self.last_timestamp,
            "known_hashes": list(self.known_hashes)[-10000:],
        }
        try:
            with open(self.cfg.state_file, "w") as f:
                json.dump(state, f)
        except Exception as e:
            self.logger.warning("Failed to save state: %s", e)

    def load_state(self):
        try:
            with open(self.cfg.state_file) as f:
                state = json.load(f)
            self.last_timestamp = state.get("last_timestamp")
            self.known_hashes = set(state.get("known_hashes", []))
            self.logger.info("Restored state — %d known hashes, resuming from %s",
                             len(self.known_hashes), self.last_timestamp)
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning("Failed to load state: %s", e)
        self._load_false_positives()

    # -- false positive management -----------------------------------------

    def _load_false_positives(self):
        """Load persistent false positive list from disk."""
        try:
            with open(_FP_LIST_FILE) as f:
                self._false_positives = json.load(f)
            if self._false_positives:
                self.logger.info("Loaded %d false positive entries", len(self._false_positives))
        except FileNotFoundError:
            self._false_positives = {}
        except Exception as e:
            self.logger.warning("Failed to load false positives: %s", e)
            self._false_positives = {}

    def _save_false_positives(self):
        """Persist false positive list to disk."""
        try:
            with open(_FP_LIST_FILE, "w") as f:
                json.dump(self._false_positives, f, indent=2)
        except Exception as e:
            self.logger.warning("Failed to save false positives: %s", e)

    def add_false_positive(self, key: str, reason: str):
        """Add a path or hash to the false positive list with a reason.
        key: file path (e.g. /tmp/VX0p2tL1wv) or SHA256 hash
        reason: why this is a false positive (e.g. 'landscape-sysinfo wrapper')
        """
        self._false_positives[key] = reason
        self._save_false_positives()
        self.logger.info("Added false positive: %s — %s", key, reason)

    def remove_false_positive(self, key: str):
        """Remove a path or hash from the false positive list."""
        if key in self._false_positives:
            del self._false_positives[key]
            self._save_false_positives()
            self.logger.info("Removed false positive: %s", key)

    def _is_false_positive_path(self, exe: str) -> bool:
        """Check if an executable path matches known false positive patterns."""
        # Check regex patterns (fake kernel threads, /proc, /sys)
        for pat in _AUDITD_FP_PATTERNS:
            if pat.match(exe):
                return True
        # Check persistent FP list (exact path match)
        if exe in self._false_positives:
            return True
        return False

    def _is_false_positive_hash(self, sha256: str) -> bool:
        """Check if a sample hash is in the false positive list."""
        return sha256 in self._false_positives

    def _auditd_on_cooldown(self, exe: str, cooldown_secs: int = 600) -> bool:
        """Suppress repeated auditd detections of the same path.
        Returns True if this path was seen within cooldown_secs (default 10 min)."""
        now = time.time()
        last_seen = self._auditd_cooldown.get(exe, 0)
        if now - last_seen < cooldown_secs:
            return True
        self._auditd_cooldown[exe] = now
        # Prune stale entries (older than 1 hour)
        stale = [k for k, v in self._auditd_cooldown.items() if now - v > 3600]
        for k in stale:
            del self._auditd_cooldown[k]
        return False

    # -- SSH/SCP helpers ---------------------------------------------------

    def _needs_jump(self, host: str) -> bool:
        """Check if host is on honeypot subnet and needs T-Pot jump host."""
        return host.startswith("192.168.40.") and host != self.cfg.tpot_host

    def _jump_arg(self) -> str:
        """Return the jump host argument for SSH."""
        return f"{self.cfg.tpot_user}@{self.cfg.tpot_host}:{self.cfg.tpot_port}"

    def _ssh_cmd(self, host: str, port: int, user: str, cmd: str,
                 password: str = "", timeout: int = 60) -> tuple[int, str, str]:
        """Execute command on remote host via SSH key auth (falls back to password).
        Automatically routes through T-Pot jump host for honeypot subnet."""
        ssh_args = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
        ]
        if self._needs_jump(host):
            ssh_args += ["-J", self._jump_arg()]
        ssh_args += ["-p", str(port), f"{user}@{host}", cmd]

        try:
            result = subprocess.run(
                ssh_args, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0 or "timeout" not in result.stderr.lower():
                return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.logger.warning("SSH command timed out after %ds: %s@%s: %s", timeout, user, host, cmd[:80])
            return -1, "", "timeout"
        except Exception as e:
            self.logger.error("SSH command failed: %s", e)
            return -1, "", str(e)

        # Key auth failed — fall back to password
        if password:
            ssh_args_pw = ["sshpass", "-p", password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
            ]
            if self._needs_jump(host):
                ssh_args_pw += ["-J", self._jump_arg()]
            ssh_args_pw += ["-p", str(port), f"{user}@{host}", cmd]
            try:
                result = subprocess.run(
                    ssh_args_pw, capture_output=True, text=True, timeout=timeout
                )
                return result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                self.logger.warning("SSH command timed out after %ds: %s@%s: %s", timeout, user, host, cmd[:80])
                return -1, "", "timeout"
            except Exception as e:
                return -1, "", str(e)

        return -1, "", "auth failed"

    def _scp_from(self, host: str, port: int, user: str, password: str,
                  remote_path: str, local_path: str, timeout: int = 120) -> bool:
        """Copy file from remote host. Routes through jump host for honeypot subnet.
        Uses ssh+cat instead of scp for jump host compatibility."""
        if self._needs_jump(host):
            # Use ssh+cat through jump host (SCP subsystem may not work)
            ssh_args = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=15",
                "-J", self._jump_arg(),
                "-p", str(port), f"{user}@{host}",
                f"cat {shlex.quote(remote_path)}",
            ]
            if password:
                ssh_args = ["sshpass", "-p", password] + ssh_args
            else:
                ssh_args.insert(3, "-o")
                ssh_args.insert(4, "BatchMode=yes")
            try:
                with open(local_path, "wb") as f:
                    result = subprocess.run(ssh_args, stdout=f, stderr=subprocess.PIPE, timeout=timeout)
                if result.returncode == 0 and Path(local_path).stat().st_size > 0:
                    return True
                Path(local_path).unlink(missing_ok=True)
            except (subprocess.TimeoutExpired, Exception):
                Path(local_path).unlink(missing_ok=True)
            return False

        # Direct SCP for non-honeypot hosts
        scp_args = [
            "scp", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
            "-P", str(port), f"{user}@{host}:{remote_path}", local_path,
        ]
        try:
            result = subprocess.run(scp_args, capture_output=True, text=True, timeout=timeout)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, Exception):
            pass

        if password:
            scp_args_pw = [
                "sshpass", "-p", password,
                "scp", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                "-P", str(port), f"{user}@{host}:{remote_path}", local_path,
            ]
            try:
                result = subprocess.run(scp_args_pw, capture_output=True, text=True, timeout=timeout)
                return result.returncode == 0
            except (subprocess.TimeoutExpired, Exception):
                pass

        return False

    def _scp_to(self, host: str, port: int, user: str, password: str,
                local_path: str, remote_path: str, timeout: int = 120) -> bool:
        """Copy file to remote host. Routes through jump host for honeypot subnet.
        Uses ssh+cat instead of scp for jump host compatibility."""
        if self._needs_jump(host):
            ssh_args = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=15",
                "-J", self._jump_arg(),
                "-p", str(port), f"{user}@{host}",
                f"cat > {shlex.quote(remote_path)}",
            ]
            if password:
                ssh_args = ["sshpass", "-p", password] + ssh_args
            else:
                ssh_args.insert(3, "-o")
                ssh_args.insert(4, "BatchMode=yes")
            try:
                with open(local_path, "rb") as f:
                    result = subprocess.run(ssh_args, stdin=f, capture_output=True, timeout=timeout)
                return result.returncode == 0
            except (subprocess.TimeoutExpired, Exception):
                pass
            return False

        # Direct SCP for non-honeypot hosts
        scp_args = [
            "scp", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
            "-P", str(port), local_path, f"{user}@{host}:{remote_path}",
        ]
        try:
            result = subprocess.run(scp_args, capture_output=True, text=True, timeout=timeout)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, Exception):
            pass

        if password:
            scp_args_pw = [
                "sshpass", "-p", password,
                "scp", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                "-P", str(port), local_path, f"{user}@{host}:{remote_path}",
            ]
            try:
                result = subprocess.run(scp_args_pw, capture_output=True, text=True, timeout=timeout)
                return result.returncode == 0
            except (subprocess.TimeoutExpired, Exception):
                pass

        return False

    def _sacrificial_ssh_cmd(self, cmd: str, timeout: int = 60) -> tuple[int, str, str]:
        """Execute command on sacrificial VM via T-Pot jump host."""
        jump = f"{self.cfg.tpot_user}@{self.cfg.tpot_host}:{self.cfg.tpot_port}"
        ssh_args = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15",
            "-o", "BatchMode=yes",
            "-J", jump,
            "-p", str(self.cfg.sacrificial_port),
            f"{self.cfg.sacrificial_user}@{self.cfg.sacrificial_host}",
            cmd,
        ]
        try:
            result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.logger.warning("Sacrificial VM SSH timed out after %ds: %s", timeout, cmd[:80])
            return -1, "", "timeout"
        except Exception as e:
            self.logger.error("Sacrificial VM SSH failed: %s", e)
            return -1, "", str(e)

    def _sacrificial_scp_from(self, remote_path: str, local_path: str, timeout: int = 120) -> bool:
        """Copy file from sacrificial VM via T-Pot jump host (uses ssh+cat, SCP subsystem unavailable)."""
        jump = f"{self.cfg.tpot_user}@{self.cfg.tpot_host}:{self.cfg.tpot_port}"
        ssh_args = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15",
            "-o", "BatchMode=yes",
            "-J", jump,
            "-p", str(self.cfg.sacrificial_port),
            f"{self.cfg.sacrificial_user}@{self.cfg.sacrificial_host}",
            f"cat {shlex.quote(remote_path)}",
        ]
        try:
            with open(local_path, "wb") as f:
                result = subprocess.run(ssh_args, stdout=f, stderr=subprocess.PIPE, timeout=timeout)
            if result.returncode == 0:
                return True
            # Clean up empty file on failure
            Path(local_path).unlink(missing_ok=True)
            return False
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.warning("Sacrificial VM SCP failed: %s", e)
            Path(local_path).unlink(missing_ok=True)
            return False

    # -- Attacker session correlation --------------------------------------

    def _correlate_attacker_session(self, sample_info: dict):
        """For sacrificial VM samples: find the attacker IP and download command.

        Queries ES auditd logs for:
        1. Recent wget/curl/tftp/scp/python downloads (the drop command)
        2. The SSH session that was active at the time (the attacker IP)
        """
        captured_at = sample_info.get("captured_at", "")
        sha256 = sample_info.get("sha256", "")
        filepath = sample_info.get("filepath", "")

        # Time window: look 5 minutes before the sample was captured
        time_filter = {"range": {"@timestamp": {"gte": "now-10m"}}}
        if captured_at:
            time_filter = {"range": {"@timestamp": {
                "gte": captured_at + "||-5m",
                "lte": captured_at + "||+1m",
            }}}

        # Query 1: Find download commands (wget, curl, tftp, python -c, etc.)
        try:
            dl_query = {
                "size": 10,
                "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"must": [
                    {"term": {"service.type": "auditd"}},
                    {"term": {"event.action": "execve"}},
                    {"bool": {"should": [
                        {"term": {"agent.name": self.cfg.sacrificial_agent_name}},
                        {"term": {"agent.name": self.cfg.sacrificial_agent_alt}},
                    ], "minimum_should_match": 1}},
                    time_filter,
                    {"bool": {"should": [
                        {"prefix": {"process.executable": "/usr/bin/wget"}},
                        {"prefix": {"process.executable": "/usr/bin/curl"}},
                        {"prefix": {"process.executable": "/usr/bin/tftp"}},
                        {"prefix": {"process.executable": "/usr/bin/scp"}},
                        {"prefix": {"process.executable": "/usr/bin/python"}},
                        {"prefix": {"process.executable": "/usr/bin/lwp-download"}},
                        {"prefix": {"process.executable": "/usr/bin/fetch"}},
                    ], "minimum_should_match": 1}},
                ]}},
                "_source": ["@timestamp", "process.executable", "process.args",
                            "process.pid", "process.ppid", "user.name"],
            }

            r = requests.post(
                f"{self.cfg.es_url}/.ds-filebeat-*/_search",
                json=dl_query, timeout=15,
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                if hits:
                    best = hits[0]["_source"]
                    proc = best.get("process", {})
                    args = proc.get("args", [])
                    exe = proc.get("executable", "")
                    cmd = f"{exe} {' '.join(args)}" if args else exe
                    sample_info["download_command"] = cmd[:500]
                    sample_info["download_timestamp"] = best.get("@timestamp", "")
                    sample_info["download_user"] = best.get("user", {}).get("name", "")
                    sample_info["download_pid"] = proc.get("pid", "")
                    self.logger.info("Correlated download command for %s: %s", sha256[:16], cmd[:100])
        except Exception as e:
            self.logger.debug("Download command correlation failed: %s", e)

        # Query 2: Find the SSH session — PAM auth or sshd accepted connection
        # Look for the attacker's source IP from auditd user_login or PAM events
        try:
            ssh_query = {
                "size": 5,
                "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"must": [
                    {"bool": {"should": [
                        {"term": {"agent.name": self.cfg.sacrificial_agent_name}},
                        {"term": {"agent.name": self.cfg.sacrificial_agent_alt}},
                    ], "minimum_should_match": 1}},
                    time_filter,
                    {"bool": {"should": [
                        # PAM honeypot auth events
                        {"term": {"event.action": "user_login"}},
                        {"term": {"event.action": "accepted"}},
                        # Auditd user_login records
                        {"exists": {"field": "source.ip"}},
                    ], "minimum_should_match": 1}},
                ]}},
                "_source": ["@timestamp", "source.ip", "source.geo",
                            "user.name", "event.action", "process.pid"],
            }

            r = requests.post(
                f"{self.cfg.es_url}/.ds-filebeat-*/_search",
                json=ssh_query, timeout=15,
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                for hit in hits:
                    src = hit["_source"]
                    src_ip = src.get("source", {}).get("ip", "")
                    if src_ip and not src_ip.startswith(("192.168.", "10.", "172.16.")):
                        sample_info["src_ip"] = src_ip
                        geo = src.get("source", {}).get("geo", {})
                        if isinstance(geo, dict):
                            sample_info["country"] = geo.get("country_name", "")
                        sample_info["attacker_user"] = src.get("user", {}).get("name", "")
                        self.logger.info("Correlated attacker IP for %s: %s (%s)",
                                         sha256[:16], src_ip, sample_info.get("country", "?"))
                        break
        except Exception as e:
            self.logger.debug("SSH session correlation failed: %s", e)

        # Query 3: Fallback — check PAM log on the VM directly via SSH
        if not sample_info.get("src_ip"):
            try:
                rc, pam_out, _ = self._sacrificial_ssh_cmd(
                    "grep 'Accepted\\|pam_honeypot.*success' /var/log/auth.log 2>/dev/null | tail -5",
                    timeout=10,
                )
                if rc == 0 and pam_out.strip():
                    # Extract IP from auth.log lines like: "Accepted password for root from 1.2.3.4 port 12345"
                    for line in reversed(pam_out.strip().splitlines()):
                        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not ip.startswith(("192.168.", "10.", "172.16.")):
                                sample_info["src_ip"] = ip
                                self.logger.info("Correlated attacker IP from auth.log for %s: %s",
                                                 sha256[:16], ip)
                                break
            except Exception as e:
                self.logger.debug("Auth.log correlation failed: %s", e)

    # -- Elasticsearch helpers ---------------------------------------------

    def _es_get(self, path: str, body: dict = None) -> Optional[dict]:
        try:
            if body:
                resp = requests.post(f"{self.cfg.es_url}/{path}", json=body, timeout=15)
            else:
                resp = requests.get(f"{self.cfg.es_url}/{path}", timeout=15)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    def _es_post(self, path: str, body: dict) -> Optional[dict]:
        try:
            resp = requests.post(
                f"{self.cfg.es_url}/{path}",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            self.logger.error("ES POST %s failed: %s", path, e)
            return None

    def _es_put(self, path: str, body: dict) -> Optional[dict]:
        try:
            resp = requests.put(
                f"{self.cfg.es_url}/{path}",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            return resp.json()
        except Exception as e:
            self.logger.error("ES PUT %s failed: %s", path, e)
            return None

    # -- Index setup -------------------------------------------------------

    def ensure_es_index(self):
        """Create malware-analysis index with proper mappings if it doesn't exist."""
        existing = self._es_get(f"{self.cfg.result_index}")
        if existing and "error" not in existing:
            self.logger.info("Index '%s' already exists", self.cfg.result_index)
            return

        mappings = {
            "mappings": {
                "properties": {
                    "sha256": {"type": "keyword"},
                    "md5": {"type": "keyword"},
                    "file_type": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "mime_type": {"type": "keyword"},
                    "file_size": {"type": "long"},
                    "is_pe": {"type": "boolean"},
                    "is_elf": {"type": "boolean"},
                    "analyzed_at": {"type": "date"},
                    "indexed_at": {"type": "date"},
                    "yara_matches": {"type": "keyword"},
                    "interesting_strings": {"type": "text"},
                    "floss_strings": {"type": "text"},
                    "capa_capabilities": {
                        "type": "nested",
                        "properties": {
                            "name": {"type": "keyword"},
                            "namespace": {"type": "keyword"},
                        }
                    },
                    "peframe": {"type": "object", "enabled": False},
                    "llm_summary": {"type": "text"},
                    "classification": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "analysis_version": {"type": "keyword"},
                    "source": {
                        "properties": {
                            "honeypot": {"type": "keyword"},
                            "src_ip": {"type": "ip"},
                            "country": {"type": "keyword"},
                            "session_id": {"type": "keyword"},
                            "captured_at": {"type": "date"},
                        }
                    },
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            }
        }

        result = self._es_put(self.cfg.result_index, mappings)
        if result and "acknowledged" in result:
            self.logger.info("Created index '%s'", self.cfg.result_index)
        else:
            self.logger.error("Failed to create index: %s", result)

    # -- Analysis script deployment ----------------------------------------

    def ensure_analysis_script(self):
        """Deploy analyze_sample.sh to REMnux if missing or outdated."""
        if not ANALYSIS_SCRIPT_LOCAL.exists():
            self.logger.error("Local analysis script not found: %s", ANALYSIS_SCRIPT_LOCAL)
            return False

        # Skip if REMnux is offline (will deploy when it starts for analysis)
        rc_test, _, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            "echo ok", password=self._remnux_pass, timeout=5,
        )
        if rc_test != 0:
            self.logger.info("REMnux offline — script will be deployed when VM starts for analysis")
            return True

        # Check if remote script exists and get its hash
        rc, remote_hash, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"sha256sum {self.cfg.remnux_script} 2>/dev/null | awk '{{print $1}}'",
            password=self._remnux_pass
        )
        local_hash = subprocess.run(
            ["sha256sum", str(ANALYSIS_SCRIPT_LOCAL)],
            capture_output=True, text=True
        ).stdout.split()[0] if ANALYSIS_SCRIPT_LOCAL.exists() else ""

        if rc == 0 and remote_hash.strip() == local_hash:
            self.logger.info("Analysis script on REMnux is up to date")
            return True

        # Ensure remote directories exist
        self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"mkdir -p {self.cfg.remnux_inbox} {self.cfg.remnux_results} /home/nalyzer/yara-rules",
            password=self._remnux_pass
        )

        # Deploy script
        ok = self._scp_to(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            self._remnux_pass,
            str(ANALYSIS_SCRIPT_LOCAL), self.cfg.remnux_script
        )
        if ok:
            self._ssh_cmd(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                f"chmod +x {self.cfg.remnux_script}",
                password=self._remnux_pass
            )
            self.logger.info("Deployed analysis script to REMnux")
            return True
        else:
            self.logger.error("Failed to deploy analysis script")
            return False

    # -- Sample discovery --------------------------------------------------

    def poll_for_new_samples(self) -> list[dict]:
        """Query ES for file capture events. Returns list of {sha256, src_ip, country, honeypot, captured_at, session_id}."""
        samples = []

        # Scan staging directory for new files (watchdog drops samples here)
        staging_samples = self._scan_staging_dir()
        samples.extend(staging_samples)

        # ES query for file events
        es_samples = self._poll_es_for_files()
        samples.extend(es_samples)

        # Auditd-driven: find unknown binaries executed on sacrificial VM
        auditd_samples = self._poll_auditd_execve()
        samples.extend(auditd_samples)

        # Periodic directory scan as fallback (every 5 minutes)
        now = time.time()
        if now - self.last_dir_scan > 300:
            dir_samples = self._scan_tpot_dirs()
            samples.extend(dir_samples)
            # Scan sacrificial VM filesystem for dropped files
            sac_samples = self._scan_sacrificial_vm()
            samples.extend(sac_samples)
            self.last_dir_scan = now

        return samples

    def _scan_staging_dir(self) -> list[dict]:
        """Scan local staging directory for samples dropped by watchdog."""
        samples = []
        for p in STAGING_DIR.iterdir():
            if not p.is_file():
                continue
            if len(p.name) != 64:
                continue
            if p.name in self.known_hashes:
                continue
            if p.stat().st_size < 1024:  # Skip files under 1KB (system caches, text files)
                continue
            self.logger.info("Staging: found new sample %s (%d bytes)", p.name[:16], p.stat().st_size)
            samples.append({
                "sha256": p.name,
                "src_ip": "",
                "country": "",
                "honeypot": "sacrificial-vm",
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "session_id": "",
            })
        return samples

    def _poll_es_for_files(self) -> list[dict]:
        """Poll ES for cowrie/dionaea file events."""
        query = {
            "size": 100,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "honeypot.eventid"}},
                    ],
                    "should": [
                        {"term": {"honeypot.eventid": "cowrie.session.file_download"}},
                        {"term": {"honeypot.eventid": "cowrie.session.file_upload"}},
                        {"term": {"honeypot.eventid": "dionaea.download.complete"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "_source": ["@timestamp", "honeypot", "source", "src_ip"],
        }

        if self.last_timestamp:
            query["query"]["bool"]["must"].append(
                {"range": {"@timestamp": {"gt": self.last_timestamp}}}
            )

        result = self._es_post(f"{self.cfg.es_index}/_search", query)
        if not result:
            return []

        samples = []
        hits = result.get("hits", {}).get("hits", [])
        for hit in hits:
            src = hit["_source"]
            hp = src.get("honeypot", {})
            if not isinstance(hp, dict):
                continue

            sha256 = hp.get("shasum", "")
            if not sha256 or len(sha256) != 64:
                continue

            src_ip = hp.get("src_ip", "") or src.get("src_ip", "")
            country = ""
            source_geo = src.get("source", {})
            if isinstance(source_geo, dict):
                geo = source_geo.get("geo", {})
                if isinstance(geo, dict):
                    country = geo.get("country_name", "")

            eventid = hp.get("eventid", "")
            honeypot = "cowrie" if "cowrie" in eventid else "dionaea"

            samples.append({
                "sha256": sha256,
                "src_ip": src_ip,
                "country": country,
                "honeypot": honeypot,
                "captured_at": src.get("@timestamp", ""),
                "session_id": hp.get("session", ""),
            })

            self.last_timestamp = src.get("@timestamp", self.last_timestamp)

        return samples

    def _scan_tpot_dirs(self) -> list[dict]:
        """SSH into T-Pot and list sample files directly as fallback."""
        samples = []
        for sample_dir in TPOT_SAMPLE_DIRS:
            rc, stdout, _ = self._ssh_cmd(
                self.cfg.tpot_host, self.cfg.tpot_port, self.cfg.tpot_user,
                f"find {sample_dir} -type f -mmin -60 -exec sha256sum {{}} \\; 2>/dev/null | head -50",
                password=self._tpot_pass,
                timeout=30,
            )
            if rc != 0 or not stdout.strip():
                continue

            honeypot = "cowrie" if "cowrie" in sample_dir else "dionaea"
            for line in stdout.strip().splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2 and len(parts[0]) == 64:
                    samples.append({
                        "sha256": parts[0],
                        "src_ip": "",
                        "country": "",
                        "honeypot": honeypot,
                        "captured_at": datetime.now(timezone.utc).isoformat(),
                        "session_id": "",
                    })

        return samples

    def _poll_auditd_execve(self) -> list[dict]:
        """Query ES for unknown binaries executed on sacrificial VM via auditd.
        This catches malware that drops anywhere on the filesystem."""
        # Standard system paths — anything executed outside these is suspicious
        system_paths = [
            '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/',
            '/usr/lib/', '/lib/', '/snap/', '/usr/local/bin/',
            '/usr/local/sbin/', '/usr/libexec/',
        ]

        try:
            query = {
                "size": 50,
                "query": {"bool": {"must": [
                    {"term": {"service.type": "auditd"}},
                    {"term": {"event.action": "execve"}},
                    {"bool": {"should": [
                        {"term": {"agent.name": self.cfg.sacrificial_agent_name}},
                        {"term": {"agent.name": self.cfg.sacrificial_agent_alt}},
                    ], "minimum_should_match": 1}},
                    {"exists": {"field": "process.executable"}},
                    {"range": {"@timestamp": {"gte": "now-30m"}}},
                ], "must_not": [
                    {"prefix": {"process.executable": "/usr/"}},
                    {"prefix": {"process.executable": "/bin/"}},
                    {"prefix": {"process.executable": "/sbin/"}},
                    {"prefix": {"process.executable": "/lib/"}},
                    {"prefix": {"process.executable": "/snap/"}},
                    # Also exclude by name for auditd entries without full path
                    {"terms": {"process.executable": [
                        "bash", "sh", "dash", "ps", "tr", "head", "tail", "cat", "cut",
                        "awk", "sed", "grep", "find", "ls", "readlink", "stat", "wc",
                        "mkdir", "chmod", "chown", "rm", "cp", "mv", "touch", "sleep",
                        "date", "echo", "env", "id", "whoami", "uname", "hostname",
                        "ss", "netstat", "ip", "ping", "nc", "curl", "wget",
                        "systemctl", "journalctl", "crontab", "iptables",
                        "python3", "python", "perl", "ruby", "node",
                        "sshd", "ssh", "scp", "sftp", "sudo", "su",
                        "auditctl", "auditd", "filebeat", "chronyc",
                        "dpkg", "apt", "apt-get",
                        "honeypot_guard", "honeypot_pam",
                    ]}},
                ]}},
                "_source": ["@timestamp", "process.executable", "process.args"],
                "sort": [{"@timestamp": "desc"}],
            }

            r = requests.post(
                f"{self.cfg.es_url}/.ds-filebeat-*/_search",
                json=query, timeout=15,
            )

            if r.status_code != 200:
                return []

            hits = r.json().get("hits", {}).get("hits", [])
            if not hits:
                return []

            # Deduplicate by executable path
            seen_paths = set()
            samples = []
            for h in hits:
                exe = h["_source"].get("process", {}).get("executable", "")
                if not exe or exe in seen_paths:
                    continue
                seen_paths.add(exe)

                # Skip if it's just a short name (system binary without path)
                if '/' not in exe:
                    continue
                # Skip known system paths and our own tools
                if any(exe.startswith(sp) for sp in system_paths):
                    continue
                if 'honeypot_guard' in exe or 'honeypot_pam' in exe or 'filebeat' in exe:
                    continue

                # --- False positive filtering ---
                if self._is_false_positive_path(exe):
                    continue

                # --- Cooldown: suppress repeated detections (10 min) ---
                if self._auditd_on_cooldown(exe):
                    continue

                self.logger.info("Auditd: suspicious binary executed: %s", exe)

                # SSH into the VM and hash the file
                rc, stdout, _ = self._sacrificial_ssh_cmd(
                    f"sha256sum {shlex.quote(exe)} 2>/dev/null",
                    timeout=10,
                )

                # Fallback: if file was self-deleted, try /proc/PID/exe
                if rc != 0 or not stdout.strip():
                    self.logger.info("Auditd: file gone, trying /proc/PID/exe fallback for %s", exe)
                    rc, stdout, _ = self._sacrificial_ssh_cmd(
                        f"pid=$(pgrep -f {shlex.quote(exe)} 2>/dev/null | head -1); "
                        f"if [ -n \"$pid\" ] && [ -e /proc/$pid/exe ]; then "
                        f"  sha256sum /proc/$pid/exe 2>/dev/null; "
                        f"fi",
                        timeout=15,
                    )
                    if rc != 0 or not stdout.strip():
                        self.logger.debug("Auditd: %s — file deleted and no live process found", exe)
                        continue

                parts = stdout.strip().split(maxsplit=1)
                if len(parts) != 2 or len(parts[0]) != 64:
                    continue

                sha256 = parts[0]

                # Check false positive list by hash
                if self._is_false_positive_hash(sha256):
                    self.logger.debug("Auditd: skipping FP hash %s (%s)", sha256[:16], exe)
                    continue

                if sha256 in self.known_hashes:
                    continue

                self.logger.info("Auditd: new malware candidate %s from %s", sha256[:16], exe)
                samples.append({
                    "sha256": sha256,
                    "src_ip": "",
                    "country": "",
                    "honeypot": "sacrificial-vm",
                    "captured_at": h["_source"].get("@timestamp", ""),
                    "session_id": "",
                    "filepath": exe,
                })

            return samples

        except Exception as e:
            self.logger.warning("Auditd execve poll failed: %s", e)
            return []

    def _scan_sacrificial_vm(self) -> list[dict]:
        """Scan sacrificial VM for files dropped by attackers (via T-Pot jump host).
        Focuses on common drop locations: /tmp, /dev/shm, /var/tmp, /root, /home, filesystem root."""
        samples = []
        # Targeted scan of attacker drop locations — no mtime limit since snapshots reset clocks
        rc, stdout, _ = self._sacrificial_ssh_cmd(
            "find /tmp /dev/shm /var/tmp /root /home /.* / -maxdepth 2 -type f "
            "-not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' "
            "-not -path '/snap/*' -not -path '/boot/*' "
            "-not -name '*.log' -not -name '*.json' -not -name '*.timer' "
            "-size +50c -size -50M "
            "-exec sha256sum {} \\; 2>/dev/null | head -50",
            timeout=30,
        )
        if rc == 0 and stdout.strip():
            for line in stdout.strip().splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2 and len(parts[0]) == 64:
                    filepath = parts[1]
                    # Skip system/decoy/known files (decoys from setup_honeypot_decoys.sh)
                    if any(skip in filepath for skip in [
                        '/proc/', '/sys/', '.bash_history', '.bashrc', '.profile',
                        '.ssh/', '.env', '.kube/', '.aws/', '.my.cnf', '.pgpass',
                        '.bitcoin/', 'crypto-bot/', '.vault-token',
                        '/opt/webapp/', '/opt/ansible/', '/var/lib/jenkins/',
                        '/var/lib/landscape/', '/var/lib/dpkg/', '/var/lib/apt/',
                        '/var/lib/systemd/', '/var/lib/chrony/', '/etc/',
                        'sshd.bak', 'honeypot_pam', 'honeypot_guard',
                        'sample_catcher', 'swap.img', '.sudo_as_admin',
                        '/var/lib/filebeat/', '/var/lib/snapd/',
                        # Decoy files planted by setup_honeypot_decoys.sh
                        '/root/scripts/', '/root/.my.cnf',
                        '/home/dbadmin/', '/home/devops/', '/home/jchen/',
                        '/home/mkovacs/', '/home/srao/',
                        'database.yml', 'secrets.yml', 'deploy.sh', 'backup.sh',
                        'seed_backup', 'docker-compose.yml', 'server.js',
                        'group_vars/', 'inventory/production',
                    ]):
                        continue
                    samples.append({
                        "sha256": parts[0],
                        "src_ip": "",
                        "country": "",
                        "honeypot": "sacrificial-vm",
                        "captured_at": datetime.now(timezone.utc).isoformat(),
                        "session_id": "",
                        "filepath": filepath,
                    })

        return samples

    # -- Sample processing pipeline ----------------------------------------

    def fetch_sample(self, sha256: str) -> Optional[Path]:
        """Fetch sample from T-Pot to local staging."""
        STAGING_DIR.mkdir(parents=True, exist_ok=True)
        local_path = STAGING_DIR / sha256

        if local_path.exists():
            return local_path

        # Search across all sample directories
        for sample_dir in TPOT_SAMPLE_DIRS:
            rc, stdout, _ = self._ssh_cmd(
                self.cfg.tpot_host, self.cfg.tpot_port, self.cfg.tpot_user,
                f"find {sample_dir} -type f -exec sha256sum {{}} \\; 2>/dev/null | grep -F {shlex.quote(sha256)} | head -1",
                password=self._tpot_pass,
                timeout=30,
            )
            if rc == 0 and sha256 in stdout:
                remote_path = stdout.strip().split(maxsplit=1)[1] if len(stdout.strip().split(maxsplit=1)) == 2 else ""
                if not remote_path:
                    continue

                # Check file size first
                rc2, size_out, _ = self._ssh_cmd(
                    self.cfg.tpot_host, self.cfg.tpot_port, self.cfg.tpot_user,
                    f"stat -c%s {shlex.quote(remote_path)} 2>/dev/null",
                    password=self._tpot_pass,
                )
                if rc2 == 0 and size_out.strip().isdigit():
                    size = int(size_out.strip())
                    if size > self.cfg.max_sample_size:
                        self.logger.warning("Sample %s too large (%d bytes), skipping", sha256[:16], size)
                        return None

                ok = self._scp_from(
                    self.cfg.tpot_host, self.cfg.tpot_port, self.cfg.tpot_user,
                    self._tpot_pass, remote_path, str(local_path)
                )
                if ok:
                    self.logger.info("Fetched sample %s from %s", sha256[:16], sample_dir)
                    return local_path

        # Also check sacrificial VM (via T-Pot jump host)
        scan_dirs = "/tmp /dev/shm /var/tmp /root /home"
        rc, stdout, _ = self._sacrificial_ssh_cmd(
            f"find {scan_dirs} -type f -exec sha256sum {{}} \\; 2>/dev/null | grep -F {shlex.quote(sha256)} | head -1",
            timeout=30,
        )
        if rc == 0 and sha256 in stdout:
            parts = stdout.strip().split(maxsplit=1)
            if len(parts) == 2:
                remote_path = parts[1]
                ok = self._sacrificial_scp_from(remote_path, str(local_path))
                if ok:
                    self.logger.info("Fetched sample %s from sacrificial VM", sha256[:16])
                    return local_path

        # Last resort: grab from /proc/PID/exe if the file self-deleted but process is alive
        self.logger.info("Trying /proc/PID/exe fallback for %s", sha256[:16])
        rc, stdout, _ = self._sacrificial_ssh_cmd(
            "for pid in /proc/[0-9]*/exe; do "
            "  h=$(sha256sum \"$pid\" 2>/dev/null) && "
            f"  echo \"$h\" | grep -qF {shlex.quote(sha256)} && "
            "  echo \"$pid\" && break; "
            "done",
            timeout=30,
        )
        if rc == 0 and stdout.strip():
            proc_path = stdout.strip()
            ok = self._sacrificial_scp_from(proc_path, str(local_path))
            if ok:
                self.logger.info("Fetched sample %s from %s (self-deleted binary)", sha256[:16], proc_path)
                return local_path

        self.logger.warning("Sample %s not found on T-Pot or sacrificial VM", sha256[:16])
        return None

    def _pre_screen_sample(self, sha256: str, local_path: Path) -> bool:
        """Quick local checks to reject obvious non-malware before full analysis.
        Returns True if the sample should proceed, False to skip."""
        try:
            size = local_path.stat().st_size
        except OSError:
            return False

        # Too small to be a real binary (< 512 bytes)
        if size < 512:
            self.logger.info("Pre-screen: skipping %s — too small (%d bytes)", sha256[:16], size)
            return False

        # Read magic bytes for file type detection
        try:
            with open(local_path, "rb") as f:
                header = f.read(512)
        except OSError:
            return False

        # Check if it's actually a text/script file masquerading as a binary
        # Allow shell scripts through — attackers do drop malicious scripts
        is_elf = header[:4] == b'\x7fELF'
        is_pe = header[:2] == b'MZ'
        is_script = header[:2] in (b'#!', b'#\n')

        # Pure text files with no shebang — likely config fragments, not malware
        if not is_elf and not is_pe and not is_script:
            try:
                # Check if entirely printable ASCII/UTF-8
                text_sample = header[:256].decode("utf-8", errors="strict")
                # If it decodes cleanly and has no binary chars, it's probably text
                non_printable = sum(1 for c in text_sample if ord(c) < 32 and c not in '\n\r\t')
                if non_printable == 0 and size < 10240:
                    self.logger.info("Pre-screen: skipping %s — plain text file (%d bytes)", sha256[:16], size)
                    return False
            except UnicodeDecodeError:
                pass  # Binary data — proceed

        # Empty or near-empty ELF (corrupted/truncated downloads)
        if is_elf and size < 1024:
            self.logger.info("Pre-screen: skipping %s — truncated ELF (%d bytes)", sha256[:16], size)
            return False

        return True

    def _ensure_remnux_running(self) -> bool:
        """Start REMnux VM if not running, wait for SSH."""
        if not self.cfg.remnux_auto_start or not self._pve_token_id:
            return True

        node = self.cfg.pve_node
        vmid = self.cfg.remnux_vmid

        # Check if already reachable via SSH
        rc, _, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            "echo ready", password=self._remnux_pass, timeout=5,
        )
        if rc == 0:
            return True

        # Check VM status via Proxmox
        status = self._pve_api("GET", f"/api2/json/nodes/{node}/qemu/{vmid}/status/current")
        vm_status = status.get("data", {}).get("status", "") if status else ""

        if vm_status != "running":
            self.logger.info("Starting REMnux VM (VMID %d)...", vmid)
            self._pve_api("POST", f"/api2/json/nodes/{node}/qemu/{vmid}/status/start")

        # Wait for SSH to become available
        for attempt in range(60):
            time.sleep(5)
            rc, _, _ = self._ssh_cmd(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                "echo ready", password=self._remnux_pass, timeout=5,
            )
            if rc == 0:
                self.logger.info("REMnux ready after %ds", (attempt + 1) * 5)
                # Deploy analysis script if needed
                self.ensure_analysis_script()
                return True

        self.logger.error("REMnux did not become reachable after 5 minutes")
        return False

    def _stop_remnux(self):
        """Shut down REMnux VM to save resources."""
        if not self.cfg.remnux_auto_start or not self._pve_token_id:
            return

        node = self.cfg.pve_node
        vmid = self.cfg.remnux_vmid

        self.logger.info("Shutting down REMnux VM to save resources")
        self._pve_api("POST", f"/api2/json/nodes/{node}/qemu/{vmid}/status/shutdown")

    def submit_for_analysis(self, sha256: str, local_path: Path) -> bool:
        """Upload sample to REMnux inbox and trigger analysis."""
        remote_sample = f"{self.cfg.remnux_inbox}/{sha256}"

        # Upload sample
        ok = self._scp_to(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            self._remnux_pass, str(local_path), remote_sample
        )
        if not ok:
            self.logger.error("Failed to upload sample %s to REMnux", sha256[:16])
            return False

        # Trigger analysis in background on REMnux (don't wait for completion)
        rc, stdout, stderr = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"nohup bash {self.cfg.remnux_script} {remote_sample} > /tmp/analysis_{sha256[:16]}.log 2>&1 &",
            password=self._remnux_pass,
            timeout=10,
        )

        self.logger.info("Analysis triggered in background for %s", sha256[:16])
        return True

    def wait_for_results(self, sha256: str) -> Optional[dict]:
        """Poll REMnux for analysis results — waits up to 20 minutes for LLM."""
        remote_result = f"{self.cfg.remnux_results}/{sha256}.json"
        max_wait = 1200  # 20 minutes — LLM on CPU is slow
        deadline = time.time() + max_wait
        self.logger.info("Waiting for results (up to %ds): %s", max_wait, sha256[:16])

        while time.time() < deadline:
            rc, stdout, _ = self._ssh_cmd(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                f"cat {remote_result} 2>/dev/null",
                password=self._remnux_pass,
                timeout=15,
            )
            if rc == 0 and stdout.strip():
                try:
                    return json.loads(stdout)
                except json.JSONDecodeError:
                    self.logger.warning("Invalid JSON in results for %s, retrying", sha256[:16])

            # Log progress — check if analysis script is still running
            if int(time.time()) % 60 < 15:  # every ~60s
                rc_check, ps_out, _ = self._ssh_cmd(
                    self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                    f"ps aux | grep -F 'analyze_sample' | grep -F {shlex.quote(sha256[:16])} | grep -v grep | head -1",
                    password=self._remnux_pass, timeout=5,
                )
                if rc_check == 0 and ps_out.strip():
                    elapsed = int(time.time() - (deadline - max_wait))
                    self.logger.info("  Still analyzing %s (%ds elapsed)...", sha256[:16], elapsed)

            time.sleep(15)

        # Check if script is still running — if so, add to pending for catch-up
        rc_check, ps_out, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"ps aux | grep -F 'analyze_sample' | grep -F {shlex.quote(sha256[:16])} | grep -v grep",
            password=self._remnux_pass, timeout=5,
        )
        if rc_check == 0 and ps_out.strip():
            self.logger.warning("Analysis still running for %s after %ds — will catch up later", sha256[:16], max_wait)
            self._add_pending(sha256)
        else:
            self.logger.warning("Analysis timed out and not running for %s", sha256[:16])

        return None

    # -- Pending results catch-up ------------------------------------------

    def _add_pending(self, sha256: str):
        """Track samples that timed out but are still being analyzed."""
        pending_file = ELKIE_HOME / ".pending_analysis.json"
        pending = []
        try:
            with open(pending_file) as f:
                pending = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        if sha256 not in pending:
            pending.append(sha256)
            with open(pending_file, "w") as f:
                json.dump(pending, f)

    def check_pending_results(self):
        """Check for results from samples that timed out — runs every poll cycle."""
        pending_file = ELKIE_HOME / ".pending_analysis.json"
        try:
            with open(pending_file) as f:
                pending = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return

        if not pending:
            return

        # Check if REMnux is reachable
        rc, _, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            "echo ok", password=self._remnux_pass, timeout=5,
        )
        if rc != 0:
            return

        completed = []
        for sha256 in pending:
            remote_result = f"{self.cfg.remnux_results}/{sha256}.json"
            rc, stdout, _ = self._ssh_cmd(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                f"cat {remote_result} 2>/dev/null",
                password=self._remnux_pass, timeout=15,
            )
            if rc == 0 and stdout.strip():
                try:
                    results = json.loads(stdout)
                except json.JSONDecodeError:
                    continue

                self.logger.info("CATCH-UP: Results ready for %s!", sha256[:16])

                # Check if still analyzing (LLM might still be running)
                rc_ps, ps_out, _ = self._ssh_cmd(
                    self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                    f"ps aux | grep -F 'analyze_sample' | grep -F {shlex.quote(sha256[:16])} | grep -v grep",
                    password=self._remnux_pass, timeout=5,
                )
                if rc_ps == 0 and ps_out.strip():
                    self.logger.info("  LLM still working on %s — waiting for completion", sha256[:16])
                    continue

                metadata = {
                    "honeypot": "cowrie",
                    "src_ip": "",
                    "country": "",
                    "session_id": f"catchup-{sha256[:8]}",
                    "captured_at": results.get("analyzed_at", ""),
                }

                # VT lookup
                vt = self.vt_lookup(sha256)
                if vt:
                    results["virustotal"] = vt

                # MISP
                misp_iocs = self.misp_check_iocs(results)
                if misp_iocs:
                    results["misp"] = misp_iocs
                self.misp_create_event(results, metadata)

                # Index
                self.index_results(sha256, results, metadata)

                # Similarity
                similar = self.find_similar_samples(results)
                if similar:
                    results["similar_samples"] = similar

                # PDF
                try:
                    from generate_report import generate_report as gen_pdf, build_styles
                    report_dir = Path(_env("REPORTS_DIR", str(ELKIE_HOME / "reports")))
                    report_dir.mkdir(parents=True, exist_ok=True)
                    gen_pdf(results, report_dir / f"{sha256[:16]}_report.pdf", build_styles())
                except Exception:
                    pass

                # Sigma
                try:
                    from generate_sigma_rules import generate_sigma_rules, save_rules
                    sigma_rules = generate_sigma_rules(results)
                    if sigma_rules:
                        save_rules(sigma_rules, sha256)
                except Exception:
                    pass

                # Discord
                self.fire_discord_alert(results, metadata)

                completed.append(sha256)
                self.known_hashes.add(sha256)
                self.logger.info("CATCH-UP complete for %s", sha256[:16])

        # Remove completed from pending
        if completed:
            remaining = [s for s in pending if s not in completed]
            with open(pending_file, "w") as f:
                json.dump(remaining, f)
            self.logger.info("Catch-up: %d completed, %d still pending", len(completed), len(remaining))

    # -- Sample similarity ------------------------------------------------

    def find_similar_samples(self, results: dict) -> list[dict]:
        """Compare ssdeep hash against all previously indexed samples."""
        ssdeep_hash = results.get("ssdeep")
        if not ssdeep_hash:
            return []

        # Fetch all ssdeep hashes from ES
        query_result = self._es_post(f"{self.cfg.result_index}/_search", {
            "size": 500,
            "_source": ["sha256", "ssdeep", "classification", "file_type"],
            "query": {"exists": {"field": "ssdeep"}},
        })
        if not query_result:
            return []

        hits = query_result.get("hits", {}).get("hits", [])
        if not hits:
            return []

        # Compare using ssdeep
        similar = []
        try:
            import ssdeep as ssdeep_lib
            for hit in hits:
                src = hit["_source"]
                other_hash = src.get("ssdeep", "")
                other_sha = src.get("sha256", "")
                if not other_hash or other_sha == results.get("sha256"):
                    continue
                try:
                    score = ssdeep_lib.compare(ssdeep_hash, other_hash)
                    if score > 0:
                        similar.append({
                            "sha256": other_sha,
                            "similarity": score,
                            "classification": src.get("classification", "unknown"),
                            "file_type": (src.get("file_type") or "")[:40],
                        })
                except Exception:
                    continue
        except ImportError:
            # ssdeep python module not on ELK — use subprocess
            for hit in hits:
                src = hit["_source"]
                other_hash = src.get("ssdeep", "")
                other_sha = src.get("sha256", "")
                if not other_hash or other_sha == results.get("sha256"):
                    continue
                try:
                    result = subprocess.run(
                        ["ssdeep", "-a", "-d", f"{ssdeep_hash}", f"{other_hash}"],
                        capture_output=True, text=True, timeout=5,
                    )
                    # ssdeep -a outputs score, parse it
                except Exception:
                    continue

        # Sort by similarity descending
        similar.sort(key=lambda x: -x["similarity"])
        return similar[:10]

    # -- Sample clustering -------------------------------------------------

    def cluster_samples(self, results: dict) -> dict:
        """Assign sample to behavioral clusters using multiple similarity signals."""
        sha256 = results.get("sha256", "")
        if not sha256:
            return {}

        # Collect signals to match against
        yara_matches = set(results.get("yara_matches", []))
        dns_queries = set((results.get("dynamic_analysis") or {}).get("dns_queries", []))
        c2_ips = set(ip["ip"] for ip in (results.get("c2_infrastructure") or {}).get("ips", []))
        cap_namespaces = set(c.get("namespace", "").split("/")[0]
                             for c in results.get("capa_capabilities", []) if c.get("namespace"))
        attack_techs = set(t["technique_id"] for t in results.get("attack_techniques", []))
        classification = results.get("classification", "unknown")

        if not (yara_matches or dns_queries or c2_ips):
            return {}

        # Query ES for candidate samples (recent, with overlapping signals)
        should_clauses = []
        if yara_matches:
            should_clauses.append({"terms": {"yara_matches": list(yara_matches)[:10]}})
        if dns_queries:
            should_clauses.append({"terms": {"dynamic_analysis.dns_queries": list(dns_queries)[:10]}})
        if classification != "unknown":
            should_clauses.append({"term": {"classification": classification}})

        if not should_clauses:
            return {}

        resp = self._es_get(f"{self.cfg.result_index}/_search", {
            "size": 200,
            "query": {"bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "must_not": [{"term": {"sha256": sha256}}],
            }},
            "_source": ["sha256", "classification", "yara_matches", "capa_capabilities",
                         "dynamic_analysis.dns_queries", "c2_infrastructure.ips",
                         "attack_techniques", "ssdeep"],
        })

        if not resp:
            return {}

        candidates = resp.get("hits", {}).get("hits", [])
        if not candidates:
            return {}

        # Score each candidate
        members = []
        for hit in candidates:
            src = hit["_source"]
            other_sha = src.get("sha256", "")
            score = 0
            shared = []

            # Shared YARA matches
            other_yara = set(src.get("yara_matches", []))
            overlap = yara_matches & other_yara
            if overlap:
                score += len(overlap) * 25
                shared.append(f"{len(overlap)} YARA")

            # Shared C2 domains
            other_dns = set(src.get("dynamic_analysis", {}).get("dns_queries", []) if isinstance(src.get("dynamic_analysis"), dict) else [])
            dns_overlap = dns_queries & other_dns
            if dns_overlap:
                score += len(dns_overlap) * 30
                shared.append(f"{len(dns_overlap)} C2 domains")

            # Same classification
            if classification != "unknown" and src.get("classification") == classification:
                score += 10
                shared.append(f"same class: {classification}")

            # Shared capa namespaces
            other_caps = set(c.get("namespace", "").split("/")[0]
                             for c in src.get("capa_capabilities", []) if isinstance(c, dict) and c.get("namespace"))
            cap_overlap = cap_namespaces & other_caps
            if len(cap_overlap) > 2:
                score += len(cap_overlap) * 5
                shared.append(f"{len(cap_overlap)} capa")

            if score >= 50:
                members.append({
                    "sha256": other_sha,
                    "similarity_score": min(score, 100),
                    "shared_signals": shared,
                    "classification": src.get("classification", "unknown"),
                })

        if not members:
            return {}

        members.sort(key=lambda m: -m["similarity_score"])
        members = members[:20]

        # Determine cluster label from majority classification
        class_counts = {}
        for m in members:
            c = m.get("classification", "unknown")
            if c != "unknown":
                class_counts[c] = class_counts.get(c, 0) + 1
        if classification != "unknown":
            class_counts[classification] = class_counts.get(classification, 0) + 1

        label = max(class_counts, key=class_counts.get) if class_counts else "unknown"

        # Check for specific family from YARA
        family = None
        for ym in yara_matches:
            yl = ym.lower()
            for fam in ["mirai", "gafgyt", "tsunami", "xmrig", "emotet", "trickbot", "redtail"]:
                if fam in yl:
                    family = fam
                    break
            if family:
                break

        cluster_label = f"{family.title()} Variant Cluster" if family else f"{label.title()} Cluster"

        cluster = {
            "cluster_id": f"cluster-{label}-{sha256[:12]}",
            "cluster_label": cluster_label,
            "cluster_size": len(members) + 1,
            "cluster_members": members,
        }

        self.logger.info("Cluster: %s (%d members, top score %d)",
                         cluster_label, len(members),
                         members[0]["similarity_score"] if members else 0)
        return cluster

    # -- C2 infrastructure mapping -----------------------------------------

    def map_c2_infrastructure(self, results: dict) -> dict:
        """Build C2 infrastructure graph from dynamic analysis network data."""
        dyn = results.get("dynamic_analysis") or {}
        if not dyn:
            return {}

        # Collect all domains
        domains = set()
        for d in dyn.get("dns_queries", []):
            if d and '.' in d:
                domains.add(d)
        for entry in dyn.get("tls_sni", []):
            sni = entry.get("sni", "")
            if sni and '.' in sni:
                domains.add(sni)
        for entry in dyn.get("http_requests", []):
            host = entry.get("host", "")
            if host and '.' in host:
                domains.add(host)

        # Collect all external IPs
        ips = {}
        for conn in dyn.get("outbound_connections", []):
            ip = conn.get("ip", "")
            if ip and not ip.startswith(("192.168.", "10.", "172.16.", "127.")):
                if ip not in ips:
                    ips[ip] = {"ip": ip, "ports": set(), "domains": set()}
                ips[ip]["ports"].add(conn.get("port", ""))
                if conn.get("hostname"):
                    ips[ip]["domains"].add(conn["hostname"])
                    domains.add(conn["hostname"])

        # Correlate TLS SNI with IPs
        for entry in dyn.get("tls_sni", []):
            ip = entry.get("ip", "")
            sni = entry.get("sni", "")
            if ip and ip in ips and sni:
                ips[ip]["domains"].add(sni)

        if not domains and not ips:
            return {}

        # Query ES for other samples that share C2 infrastructure
        shared_samples = set()
        sha256 = results.get("sha256", "")
        if domains:
            domain_list = list(domains)[:20]
            resp = self._es_get(f"{self.cfg.result_index}/_search", {
                "size": 50,
                "query": {"bool": {
                    "should": [{"terms": {"dynamic_analysis.dns_queries": domain_list}}],
                    "must_not": [{"term": {"sha256": sha256}}],
                }},
                "_source": ["sha256", "classification"],
            })
            if resp:
                for hit in resp.get("hits", {}).get("hits", []):
                    shared_samples.add(hit["_source"]["sha256"])

        # Build output
        domain_list = []
        for d in sorted(domains)[:30]:
            entry = {"domain": d}
            # Find which IPs serve this domain
            resolved = [ip for ip, info in ips.items() if d in info["domains"]]
            if resolved:
                entry["resolved_ips"] = resolved
            domain_list.append(entry)

        ip_list = []
        for ip, info in sorted(ips.items())[:30]:
            ip_list.append({
                "ip": ip,
                "ports": sorted(info["ports"]),
                "domains": sorted(info["domains"]),
            })

        c2 = {
            "domains": domain_list,
            "ips": ip_list,
            "shared_with_samples": sorted(shared_samples)[:20],
        }

        self.logger.info("C2 map: %d domains, %d IPs, %d shared samples",
                         len(domain_list), len(ip_list), len(shared_samples))
        return c2

    # -- ATT&CK technique mapping ------------------------------------------

    def map_attack_techniques(self, results: dict) -> list[dict]:
        """Map sample analysis results to MITRE ATT&CK techniques."""
        try:
            from generate_attack_navigator import map_sample_techniques
            return map_sample_techniques(results)
        except Exception as e:
            self.logger.warning("ATT&CK mapping failed: %s", e)
            return []

    # -- Results indexing --------------------------------------------------

    def index_results(self, sha256: str, results: dict, metadata: dict):
        """Index analysis results into Elasticsearch."""
        # Extract classification and severity from LLM summary
        classification, severity = self._extract_classification(results)

        doc = {
            **results,
            "classification": classification,
            "severity": severity,
            "indexed_at": datetime.now(timezone.utc).isoformat(),
            "source": {
                "honeypot": metadata.get("honeypot", "unknown"),
                "country": metadata.get("country", ""),
                "session_id": metadata.get("session_id", ""),
                "captured_at": metadata.get("captured_at", ""),
            },
        }

        # Only include src_ip if it's a valid IP (ES rejects empty strings for ip type)
        src_ip = metadata.get("src_ip", "")
        if src_ip:
            doc["source"]["src_ip"] = src_ip

        # Attacker session correlation (how the file was dropped)
        if metadata.get("download_command"):
            doc["source"]["download_command"] = metadata["download_command"]
        if metadata.get("download_timestamp"):
            doc["source"]["download_timestamp"] = metadata["download_timestamp"]
        if metadata.get("download_user"):
            doc["source"]["download_user"] = metadata["download_user"]
        if metadata.get("attacker_user"):
            doc["source"]["attacker_user"] = metadata["attacker_user"]

        result = self._es_put(
            f"{self.cfg.result_index}/_doc/{sha256}",
            doc
        )
        if result and ("result" in result or "_id" in result):
            self.logger.info("Indexed results for %s (classification=%s, severity=%s)",
                             sha256[:16], classification, severity)
        else:
            self.logger.error("Failed to index results for %s: %s", sha256[:16], result)

    def _extract_classification(self, results: dict) -> tuple[str, str]:
        """Extract classification, severity, and confidence from weighted signal scoring.

        Returns (classification, severity). Also injects 'confidence' and
        'confidence_signals' into `results` dict for indexing/alerting.
        """
        llm_summary = (results.get("llm_summary") or "").lower()
        yara_matches = [m.lower() for m in results.get("yara_matches", [])]
        combined_text = llm_summary + " " + " ".join(yara_matches)

        # --- Classification from keywords (unchanged logic) ---
        classification = "unknown"
        class_keywords = {
            "botnet": ["botnet", "mirai", "gafgyt", "hajime", "mozi", "tsunami"],
            "trojan": ["trojan", "rat", "remote access"],
            "miner": ["miner", "xmrig", "cryptominer", "monero", "stratum", "mining"],
            "ransomware": ["ransomware", "ransom", "encrypt", "locker"],
            "backdoor": ["backdoor", "reverse shell", "bind shell", "c2", "command and control"],
            "worm": ["worm", "self-propagat", "spreading"],
            "dropper": ["dropper", "downloader", "loader", "stager"],
        }
        for cls, keywords in class_keywords.items():
            if any(kw in combined_text for kw in keywords):
                classification = cls
                break

        # --- Weighted confidence scoring ---
        confidence = 0
        signals = []

        # Packing / compression indicators
        if results.get("unpacked") or results.get("decompressed"):
            confidence += 20
            signals.append("packed/compressed (+20)")

        # Stripped binary (no symbols)
        file_type = (results.get("file_type") or "").lower()
        if "stripped" in file_type:
            confidence += 10
            signals.append("stripped binary (+10)")

        # Statically linked
        if "statically linked" in file_type:
            confidence += 10
            signals.append("statically linked (+10)")

        # YARA matches
        yara_count = len(results.get("yara_matches", []))
        if yara_count > 0:
            yara_score = min(yara_count * 25, 50)
            confidence += yara_score
            signals.append(f"{yara_count} YARA matches (+{yara_score})")

        # VT detections
        vt = results.get("virustotal", {})
        if vt and vt.get("found"):
            detections = vt.get("detections", 0)
            if detections > 5:
                confidence += 40
                signals.append(f"VT {detections} detections (+40)")
            elif detections > 0:
                confidence += 20
                signals.append(f"VT {detections} detections (+20)")
        elif vt and not vt.get("found"):
            confidence += 15
            signals.append("not on VT — novel sample (+15)")

        # Obfuscated / FLOSS strings
        floss = results.get("floss_strings", [])
        if len(floss) > 5:
            confidence += 20
            signals.append(f"{len(floss)} FLOSS strings (+20)")

        # capa capabilities
        capa_count = len(results.get("capa_capabilities", []))
        if capa_count > 5:
            capa_score = min(capa_count * 3, 30)
            confidence += capa_score
            signals.append(f"{capa_count} capa capabilities (+{capa_score})")

        # Dynamic analysis signals
        dyn = results.get("dynamic_analysis") or {}
        if dyn:
            outbound = len(dyn.get("outbound_connections", []))
            if outbound > 0:
                net_score = min(outbound * 10, 30)
                confidence += net_score
                signals.append(f"{outbound} outbound connections (+{net_score})")
            new_files = len(dyn.get("new_files", []))
            if new_files > 0:
                file_score = min(new_files * 10, 20)
                confidence += file_score
                signals.append(f"{new_files} new files dropped (+{file_score})")
            tls_sni = len(dyn.get("tls_sni", []))
            if tls_sni > 0:
                confidence += min(tls_sni * 5, 15)
                signals.append(f"{tls_sni} TLS SNI domains (+{min(tls_sni * 5, 15)})")

        # LLM classification adds confidence
        if results.get("llm_summary"):
            confidence += 10
            signals.append("LLM analysis available (+10)")

        # Cap at 100
        confidence = min(confidence, 100)

        # --- Severity from confidence + keyword severity boosters ---
        if any(w in combined_text for w in ["critical", "severe", "destructive", "ransomware", "wiper"]):
            severity = "critical"
        elif confidence >= 70 or any(w in combined_text for w in ["high", "dangerous", "backdoor", "rat", "botnet"]):
            severity = "high"
        elif confidence >= 40 or any(w in combined_text for w in ["medium", "moderate", "miner"]):
            severity = "medium"
        else:
            severity = "low"

        # Boost severity if many YARA matches or capa capabilities
        if yara_count > 3:
            severity = max(severity, "high", key=lambda s: SEVERITY_ORDER.get(s, 0))
        if capa_count > 10:
            severity = max(severity, "high", key=lambda s: SEVERITY_ORDER.get(s, 0))

        # Inject confidence into results for indexing
        results["confidence"] = confidence
        results["confidence_signals"] = signals

        # Build human-readable confidence label
        if classification != "unknown":
            results["confidence_label"] = f"{classification.title()} (confidence: {confidence}%)"
        elif confidence >= 60:
            results["confidence_label"] = f"Likely malware (confidence: {confidence}%)"
        elif confidence >= 30:
            results["confidence_label"] = f"Suspicious (confidence: {confidence}%)"
        else:
            results["confidence_label"] = f"Unknown (confidence: {confidence}%)"

        return classification, severity

    # -- VirusTotal --------------------------------------------------------

    # -- Claude API analysis ------------------------------------------------

    # -- Deep analysis scoring + Ghidra decompilation ---------------------

    DEEP_ANALYSIS_STATE = ELKIE_HOME / ".deep_analysis_today.json"

    def _score_sample(self, results: dict) -> int:
        """Score a sample to determine if it deserves deep Ghidra decompilation."""
        score = 0
        score += len(results.get("capa_capabilities", [])) * 10
        score += len(results.get("yara_matches", [])) * 20
        score += min(len(results.get("interesting_strings", [])), 10) * 5
        if results.get("is_elf") or results.get("is_pe"):
            score += 10
        if results.get("file_size", 0) > 100000:
            score += 5
        ghidra = results.get("ghidra")
        if ghidra and isinstance(ghidra, dict):
            score += len(ghidra.get("suspicious_apis", [])) * 10
        dyn = results.get("dynamic_analysis", {})
        if dyn:
            score += min(len(dyn.get("outbound_connections", [])), 5) * 20
            score += min(len(dyn.get("new_files", [])), 3) * 10
            score += min(len(dyn.get("dns_queries", [])), 5) * 10
        vt = results.get("virustotal", {})
        if vt and vt.get("found") and vt.get("detections", 0) > 0:
            score += 25
        return score

    def _can_deep_analyze_today(self) -> bool:
        """Check if we've already done a deep analysis today (max 1/day)."""
        try:
            with open(self.DEEP_ANALYSIS_STATE) as f:
                state = json.load(f)
            last_date = state.get("date", "")
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            return last_date != today
        except (FileNotFoundError, json.JSONDecodeError):
            return True

    def _mark_deep_analyzed(self, sha256: str):
        """Record that we did a deep analysis today."""
        with open(self.DEEP_ANALYSIS_STATE, "w") as f:
            json.dump({
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "sha256": sha256,
            }, f)

    def deep_ghidra_analysis(self, sha256: str, results: dict) -> Optional[dict]:
        """Run deep Ghidra decompilation and feed to Claude for code-level analysis."""
        score = self._score_sample(results)
        self.logger.info("Sample %s deep analysis score: %d (threshold: 40)", sha256[:16], score)

        if score < 40:
            return None

        if not self._can_deep_analyze_today():
            self.logger.info("Deep analysis budget exhausted for today")
            return None

        if not (results.get("is_elf") or results.get("is_pe")):
            return None  # Only binaries

        self.logger.info("Running DEEP Ghidra decompilation for %s (score=%d)", sha256[:16], score)

        # Ensure sample is on REMnux
        remote_sample = f"{self.cfg.remnux_inbox}/{sha256}"
        local_sample = STAGING_DIR / sha256
        if local_sample.exists():
            self._scp_to(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                self._remnux_pass, str(local_sample), remote_sample
            )
        # Also deploy the deep extract script
        self._scp_to(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            self._remnux_pass, str(ELKIE_HOME / "ghidra_deep_extract.py"),
            f"/home/{self.cfg.remnux_user}/ghidra_deep_extract.py"
        )
        rc, _, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"mkdir -p /tmp/ghidra_deep; rm -rf /tmp/ghidra_deep/sample_{sha256[:16]}*; "
            f"SA_SHA256={sha256} timeout 300 /opt/ghidra/support/analyzeHeadless "
            f"/tmp/ghidra_deep sample_{sha256[:16]} "
            f"-import {remote_sample} "
            f"-postscript /home/nalyzer/ghidra_deep_extract.py "
            f"-deleteProject -analysisTimeoutPerFile 240 2>/dev/null",
            password=self._remnux_pass, timeout=320,
        )

        # Fetch deep results
        deep_result_path = f"/home/nalyzer/results/{sha256}_ghidra_deep.json"
        rc2, deep_json, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"cat {deep_result_path} 2>/dev/null",
            password=self._remnux_pass, timeout=15,
        )

        if rc2 != 0 or not deep_json.strip():
            self.logger.warning("Deep Ghidra extraction produced no output for %s", sha256[:16])
            return None

        try:
            deep_data = json.loads(deep_json)
        except json.JSONDecodeError:
            return None

        decompiled = deep_data.get("decompiled_functions", [])
        func_index = deep_data.get("function_index", [])
        if not decompiled and not func_index:
            return None

        self.logger.info("Extracted %d functions (%d decompiled) for %s",
                         len(func_index), len(decompiled), sha256[:16])

        if self.cfg.llm_mode == "none":
            return None

        api_key = self._anthropic_key
        if self.cfg.llm_mode == "api" and not api_key:
            return None

        try:
            import anthropic
        except ImportError:
            if self.cfg.llm_mode == "api":
                return None

        client = anthropic.Anthropic(api_key=api_key)
        total_cost = 0.0

        # ── PASS 1: Triage — send function index (metadata only, no C code) ──
        # Ask the LLM which functions warrant deep review based on names, sizes,
        # call graphs, and suspicious API usage.

        index_text = json.dumps(func_index[:200], indent=1)  # cap at 200 functions
        if len(index_text) > 15000:
            index_text = index_text[:15000] + "\n... truncated ..."

        triage_prompt = f"""You are triaging a binary captured from an SSH honeypot. Below is the function index — metadata for every non-thunk function extracted by Ghidra. NO decompiled code is included yet.

Your job: identify which functions warrant deep code review, and which can be skipped.

RULES:
- Select functions based on evidence: suspicious API calls, large size, interesting names, call graph position (functions called by many others, or that call suspicious APIs)
- Do NOT select compiler-generated functions (e.g. __libc_csu_init, _start, frame_dummy, register_tm_clones, deregister_tm_clones) unless they contain suspicious calls
- Explain WHY each function was selected — cite the specific evidence from the index
- If the binary has very few functions (<10 non-trivial), select all of them

Binary: {results.get('file_type','')} | {results.get('file_size',0)} bytes
Suspicious APIs found in binary: {deep_data.get('suspicious_apis', [])}
Total functions: {len(func_index)}

Respond as JSON:
{{
  "selected_functions": ["func_name_1", "func_name_2", ...],
  "triage_reasoning": {{
    "func_name_1": "why this function — e.g. calls connect+send, largest function, called by main",
    "func_name_2": "why this function — e.g. calls execve+fork, name suggests persistence"
  }},
  "skipped_summary": "brief note on what was skipped and why (e.g. '45 compiler/init stubs, 12 string helpers')"
}}

FUNCTION INDEX:
{index_text}"""

        try:
            triage_response = client.messages.create(
                model=self.cfg.llm_api_model,
                max_tokens=1500,
                messages=[{"role": "user", "content": triage_prompt}],
            )
            triage_text = triage_response.content[0].text
            triage_cost = (triage_response.usage.input_tokens * 3 / 1_000_000) + (triage_response.usage.output_tokens * 15 / 1_000_000)
            total_cost += triage_cost
            self.logger.info("Pass 1 triage: %d in / %d out tokens ($%.4f) for %s",
                             triage_response.usage.input_tokens, triage_response.usage.output_tokens,
                             triage_cost, sha256[:16])

            # Parse triage response
            triage_match = re.search(r'\{[\s\S]*\}', triage_text)
            if triage_match:
                triage_data = json.loads(triage_match.group())
            else:
                triage_data = {"selected_functions": []}
        except (json.JSONDecodeError, Exception) as e:
            self.logger.warning("Pass 1 triage failed for %s: %s — falling back to top 15 by size", sha256[:16], e)
            triage_data = {"selected_functions": [f["name"] for f in func_index[:15]],
                           "triage_reasoning": {"fallback": "triage pass failed, using top 15 by size"}}

        selected_names = set(triage_data.get("selected_functions", []))

        # If triage selected nothing useful, fall back to top 15 by size
        if not selected_names:
            selected_names = {f["name"] for f in func_index[:15]}
            triage_data["triage_reasoning"] = {"fallback": "no functions selected, using top 15 by size"}

        # ── PASS 2: Deep analysis — send decompiled C for selected functions ──

        # Build decompiled code for selected functions
        selected_funcs = [f for f in decompiled if f["name"] in selected_names]

        # If selected functions weren't found in decompiled (name mismatch), fall back
        if not selected_funcs:
            selected_funcs = decompiled[:15]

        functions_text = ""
        for func in selected_funcs[:25]:  # hard cap at 25 to stay within token budget
            functions_text += f"\n--- Function: {func['name']} ({func['size']} bytes) at {func['address']} ---\n"
            if func.get("suspicious_calls"):
                functions_text += f"// Suspicious API calls: {', '.join(func['suspicious_calls'])}\n"
            functions_text += func.get("c_code", "// no code") + "\n"

        # Include triage reasoning so the LLM knows why these were selected
        triage_reasoning_text = json.dumps(triage_data.get("triage_reasoning", {}), indent=1)[:2000]

        deep_prompt = f"""You are analyzing decompiled malware code from a honeypot-captured binary. These functions were selected from {len(func_index)} total functions based on a triage pass.

RULES:
- Report ONLY what the code demonstrates — do not speculate about capabilities not present in the decompiled output
- Cite specific code patterns, strings, constants, and API calls for every claim
- If decompilation is incomplete or unclear, say so — do not guess what missing code does
- Flag anything that warrants further investigation (obfuscated sections, encrypted data, indirect calls that couldn't be resolved)

Triage reasoning (why these functions were selected):
{triage_reasoning_text}

Binary info: {results.get('file_type','')} | {results.get('file_size',0)} bytes | Suspicious APIs: {deep_data.get('suspicious_apis',[])}

Provide your analysis as structured text covering:
1. **Function-by-function findings** — what each function does, citing specific code evidence
2. **Observed IOCs** — hardcoded IPs, domains, ports, paths, keys found IN the code
3. **MITRE ATT&CK techniques** — only those demonstrated by the code, with evidence
4. **Warrants further investigation** — what couldn't be determined from decompilation alone (encrypted configs, indirect jumps, packed sections, functions that failed to decompile)

SELECTED FUNCTIONS ({len(selected_funcs)} of {len(func_index)} total):
{functions_text}"""

        try:
            deep_response = client.messages.create(
                model=self.cfg.llm_api_model,
                max_tokens=4000,
                messages=[{"role": "user", "content": deep_prompt}],
            )
            analysis = deep_response.content[0].text
            deep_cost = (deep_response.usage.input_tokens * 3 / 1_000_000) + (deep_response.usage.output_tokens * 15 / 1_000_000)
            total_cost += deep_cost
            self.logger.info("Pass 2 deep analysis: %d in / %d out tokens ($%.4f) for %s",
                             deep_response.usage.input_tokens, deep_response.usage.output_tokens,
                             deep_cost, sha256[:16])
        except Exception as e:
            self.logger.error("Pass 2 deep analysis failed for %s: %s", sha256[:16], e)
            analysis = ""

        self._mark_deep_analyzed(sha256)

        return {
            "deep_analysis": analysis,
            "triage": triage_data,
            "functions_analyzed": len(selected_funcs),
            "functions_total": len(func_index),
            "decompiled_function_count": len(decompiled),
            "score": score,
            "cost": round(total_cost, 4),
        }

    # -- Ghidra MCP interactive analysis ------------------------------------

    # Tool definitions matching bridge_mcp_ghidra.py — subset of most useful
    # tools for automated malware analysis (skip rename/comment tools that
    # mutate Ghidra state, we only need read-only tools)
    GHIDRA_MCP_TOOLS = [
        {"name": "list_methods", "description": "List all function names with pagination.", "input_schema": {
            "type": "object", "properties": {"offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}}},
        {"name": "list_imports", "description": "List imported symbols with pagination.", "input_schema": {
            "type": "object", "properties": {"offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}}},
        {"name": "list_exports", "description": "List exported functions/symbols with pagination.", "input_schema": {
            "type": "object", "properties": {"offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}}},
        {"name": "list_segments", "description": "List memory segments.", "input_schema": {
            "type": "object", "properties": {"offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}}},
        {"name": "list_strings", "description": "List defined strings with addresses. Use filter param to search.", "input_schema": {
            "type": "object", "properties": {"offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 500}, "filter": {"type": "string"}}}},
        {"name": "decompile_function", "description": "Decompile a function by name, returns C code.", "input_schema": {
            "type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
        {"name": "decompile_function_by_address", "description": "Decompile function at a given hex address.", "input_schema": {
            "type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}},
        {"name": "disassemble_function", "description": "Get assembly for a function at address.", "input_schema": {
            "type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}},
        {"name": "search_functions_by_name", "description": "Search functions whose name contains substring.", "input_schema": {
            "type": "object", "properties": {"query": {"type": "string"}, "offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}, "required": ["query"]}},
        {"name": "get_xrefs_to", "description": "Get all cross-references TO an address.", "input_schema": {
            "type": "object", "properties": {"address": {"type": "string"}, "offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}, "required": ["address"]}},
        {"name": "get_xrefs_from", "description": "Get all cross-references FROM an address.", "input_schema": {
            "type": "object", "properties": {"address": {"type": "string"}, "offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}, "required": ["address"]}},
        {"name": "get_function_xrefs", "description": "Get all references to a function by name.", "input_schema": {
            "type": "object", "properties": {"name": {"type": "string"}, "offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}, "required": ["name"]}},
        {"name": "list_data_items", "description": "List defined data labels and values.", "input_schema": {
            "type": "object", "properties": {"offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}}},
        {"name": "list_namespaces", "description": "List all non-global namespaces.", "input_schema": {
            "type": "object", "properties": {"offset": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}}},
    ]

    # Map tool names to their MCP bridge HTTP endpoints and methods
    _MCP_TOOL_ROUTES = {
        "list_methods": ("GET", "methods"),
        "list_imports": ("GET", "imports"),
        "list_exports": ("GET", "exports"),
        "list_segments": ("GET", "segments"),
        "list_strings": ("GET", "strings"),
        "decompile_function": ("POST", "decompile"),
        "decompile_function_by_address": ("GET", "decompile_function"),
        "disassemble_function": ("GET", "disassemble_function"),
        "search_functions_by_name": ("GET", "searchFunctions"),
        "get_xrefs_to": ("GET", "xrefs_to"),
        "get_xrefs_from": ("GET", "xrefs_from"),
        "get_function_xrefs": ("GET", "function_xrefs"),
        "list_data_items": ("GET", "data"),
        "list_namespaces": ("GET", "namespaces"),
    }

    def _ghidra_mcp_call_tool(self, tunnel_port: int, tool_name: str, tool_input: dict) -> str:
        """Execute a Ghidra MCP tool call via the HTTP bridge through SSH tunnel."""
        route = self._MCP_TOOL_ROUTES.get(tool_name)
        if not route:
            return f"Unknown tool: {tool_name}"

        method, endpoint = route
        url = f"http://127.0.0.1:{tunnel_port}/{endpoint}"

        try:
            if method == "POST":
                # decompile_function takes raw string body
                if tool_name == "decompile_function":
                    r = requests.post(url, data=tool_input.get("name", "").encode("utf-8"), timeout=30)
                else:
                    r = requests.post(url, data=tool_input, timeout=30)
            else:
                r = requests.get(url, params=tool_input, timeout=30)

            if r.ok:
                text = r.text.strip()
                # Cap response to avoid blowing up context
                if len(text) > 12000:
                    text = text[:12000] + "\n... [truncated, use offset/limit to paginate]"
                return text
            else:
                return f"Error {r.status_code}: {r.text[:500]}"
        except requests.exceptions.ConnectionError:
            return "Error: Ghidra MCP bridge not reachable — server may have crashed"
        except Exception as e:
            return f"Request failed: {e}"

    def _start_ghidra_mcp(self, sha256: str) -> Optional[tuple[subprocess.Popen, int]]:
        """Start Ghidra headless with MCP server script on REMnux and set up SSH tunnel.
        Uses ghidra_mcp_server.py (Jython) which starts an HTTP server inside
        analyzeHeadless — no GUI or Xvfb needed.
        Returns (tunnel_process, local_port) or None on failure."""

        ghidra_port = self.cfg.ghidra_mcp_ghidra_port
        bridge_port = self.cfg.ghidra_mcp_bridge_port

        # Ensure sample is on REMnux
        remote_sample = f"{self.cfg.remnux_inbox}/{sha256}"
        local_sample = STAGING_DIR / sha256
        if local_sample.exists():
            self._scp_to(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                self._remnux_pass, str(local_sample), remote_sample
            )

        # Deploy the MCP server script
        self._scp_to(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            self._remnux_pass, str(ELKIE_HOME / "ghidra_mcp_server.py"),
            f"/home/{self.cfg.remnux_user}/ghidra_mcp_server.py"
        )

        # Kill any leftover Ghidra processes on REMnux
        self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            "pkill -f analyzeHeadless 2>/dev/null; sleep 1",
            password=self._remnux_pass, timeout=10,
        )

        # Start Ghidra headless with MCP server postscript
        # -scriptTimeout 0 prevents analyzeHeadless from killing the script
        # The script blocks serving HTTP until MCP_SERVER_TIMEOUT expires
        self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"rm -rf /tmp/ghidra_mcp_project; mkdir -p /tmp/ghidra_mcp_project; "
            f"MCP_SERVER_PORT={ghidra_port} MCP_SERVER_TIMEOUT=600 "
            f"nohup /opt/ghidra/support/analyzeHeadless /tmp/ghidra_mcp_project mcp_session "
            f"-import {remote_sample} "
            f"-postScript /home/{self.cfg.remnux_user}/ghidra_mcp_server.py "
            f"-scriptTimeout 0 "
            f"-analysisTimeoutPerFile 240 "
            f"> /tmp/ghidra_mcp.log 2>&1 &",
            password=self._remnux_pass, timeout=15,
        )

        # Wait for Ghidra MCP HTTP server to come up (analysis + script startup)
        self.logger.info("Waiting for Ghidra MCP HTTP server on REMnux:%d...", ghidra_port)
        for attempt in range(60):  # 120s max (analysis can take a while)
            rc, out, _ = self._ssh_cmd(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                f"curl -s http://127.0.0.1:{ghidra_port}/health 2>/dev/null",
                password=self._remnux_pass, timeout=5,
            )
            if rc == 0 and out.strip() == "ok":
                self.logger.info("Ghidra MCP server ready (attempt %d, ~%ds)", attempt + 1, attempt * 2)
                break
            time.sleep(2)
        else:
            self.logger.warning("Ghidra MCP server did not start — falling back to batch analysis")
            rc, log_out, _ = self._ssh_cmd(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                "tail -30 /tmp/ghidra_mcp.log 2>/dev/null",
                password=self._remnux_pass, timeout=5,
            )
            if log_out:
                self.logger.warning("Ghidra MCP log: %s", log_out.strip()[-500:])
            return None

        # Set up SSH tunnel: local bridge_port → REMnux ghidra_port
        tunnel_cmd = [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10", "-N",
            "-L", f"{bridge_port}:127.0.0.1:{ghidra_port}",
            "-J", f"{self.cfg.tpot_user}@{self.cfg.tpot_host}:{self.cfg.tpot_port}",
            "-p", str(self.cfg.remnux_port),
            f"{self.cfg.remnux_user}@{self.cfg.remnux_host}",
        ]
        tunnel = subprocess.Popen(tunnel_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

        # Verify tunnel works
        try:
            r = requests.get(f"http://127.0.0.1:{bridge_port}/health", timeout=5)
            if not r.ok:
                self.logger.warning("SSH tunnel test failed: %s", r.status_code)
                tunnel.kill()
                return None
        except Exception as e:
            self.logger.warning("SSH tunnel not working: %s", e)
            tunnel.kill()
            return None

        self.logger.info("Ghidra MCP tunnel established on local port %d", bridge_port)
        return tunnel, bridge_port

    def _stop_ghidra_mcp(self, tunnel: Optional[subprocess.Popen]):
        """Clean up Ghidra MCP session."""
        if tunnel:
            tunnel.kill()
            tunnel.wait()
        self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            "pkill -f analyzeHeadless 2>/dev/null; pkill -f bridge_mcp_ghidra 2>/dev/null; "
            "rm -rf /tmp/ghidra_mcp_project 2>/dev/null",
            password=self._remnux_pass, timeout=10,
        )

    def ghidra_mcp_analysis(self, sha256: str, results: dict) -> Optional[dict]:
        """Interactive Ghidra analysis via MCP — Claude explores the binary autonomously.
        Falls back to batch deep_ghidra_analysis if MCP setup fails."""

        if not self.cfg.ghidra_mcp_enabled:
            return self.deep_ghidra_analysis(sha256, results)

        score = self._score_sample(results)
        self.logger.info("Sample %s deep analysis score: %d (threshold: 40)", sha256[:16], score)
        if score < 40:
            return None
        if not self._can_deep_analyze_today():
            self.logger.info("Deep analysis budget exhausted for today")
            return None
        if not (results.get("is_elf") or results.get("is_pe")):
            return None

        self.logger.info("Starting Ghidra MCP interactive analysis for %s (score=%d)", sha256[:16], score)

        # Ensure REMnux is up
        if not self._ensure_remnux_running():
            return None

        # Start Ghidra + tunnel
        mcp_session = self._start_ghidra_mcp(sha256)
        if not mcp_session:
            self.logger.info("MCP setup failed — falling back to batch Ghidra analysis")
            return self.deep_ghidra_analysis(sha256, results)

        tunnel, local_port = mcp_session

        try:
            return self._run_mcp_agent_loop(sha256, results, local_port)
        finally:
            self._stop_ghidra_mcp(tunnel)

    def _run_mcp_agent_loop(self, sha256: str, results: dict, tunnel_port: int) -> Optional[dict]:
        """Run the Claude tool-use agent loop against Ghidra MCP."""
        try:
            import anthropic
        except ImportError:
            return None

        api_key = self._anthropic_key
        if not api_key:
            return None

        client = anthropic.Anthropic(api_key=api_key)
        total_cost = 0.0
        max_cost = self.cfg.ghidra_mcp_max_cost
        max_turns = self.cfg.ghidra_mcp_max_turns
        tool_calls_log = []

        # Build context from prior analysis stages
        context_parts = []
        if results.get("file_type"):
            context_parts.append(f"File: {results['file_type']} | {results.get('file_size', 0)} bytes")
        if results.get("yara_matches"):
            context_parts.append(f"YARA: {', '.join(results['yara_matches'][:10])}")
        if results.get("capa_capabilities"):
            context_parts.append(f"Capabilities: {', '.join(results['capa_capabilities'][:10])}")
        if results.get("interesting_strings"):
            context_parts.append(f"Strings: {', '.join(results['interesting_strings'][:15])}")
        dyn = results.get("dynamic_analysis", {})
        if dyn:
            if dyn.get("outbound_connections"):
                context_parts.append(f"Network: {json.dumps(dyn['outbound_connections'][:10])}")
            if dyn.get("dns_queries"):
                context_parts.append(f"DNS: {json.dumps(dyn['dns_queries'][:10])}")
        vt = results.get("virustotal", {})
        if vt and vt.get("found"):
            context_parts.append(f"VirusTotal: {vt.get('detections', 0)}/{vt.get('total', 0)} detections — {vt.get('popular_threat_name', 'unknown')}")

        system_prompt = """You are a malware reverse engineer analyzing a binary captured from an SSH honeypot.
You have access to Ghidra via MCP tools. Use them to systematically investigate the binary.

APPROACH:
1. Start with list_imports and list_strings to get an overview
2. Use list_methods to see all functions, then search_functions_by_name for interesting ones
3. Decompile suspicious functions and follow xrefs to trace execution flow
4. Look for: C2 addresses, encryption keys, persistence mechanisms, credential theft, anti-analysis

RULES:
- Only report what the code DEMONSTRATES — cite specific functions, addresses, strings
- Follow the evidence chain: import → xref → decompile → analyze
- When you find something interesting, follow xrefs to understand the full call chain
- Stop when you've covered all significant functionality or hit diminishing returns

BUDGET: You have limited tool calls. Be strategic — don't enumerate everything, focus on what matters.

When done, provide your final analysis as structured text."""

        prior_context = "\n".join(context_parts)
        user_msg = f"""Analyze this binary from our SSH honeypot. Prior analysis context:

{prior_context}

SHA256: {sha256}

Explore the binary using the Ghidra tools and provide a complete code-level threat assessment."""

        messages = [{"role": "user", "content": user_msg}]

        for turn in range(max_turns):
            if total_cost >= max_cost:
                self.logger.info("MCP analysis hit cost cap ($%.4f >= $%.2f) at turn %d",
                                 total_cost, max_cost, turn + 1)
                break

            try:
                response = client.messages.create(
                    model=self.cfg.llm_api_model,
                    max_tokens=4000,
                    system=system_prompt,
                    tools=self.GHIDRA_MCP_TOOLS,
                    messages=messages,
                )
            except Exception as e:
                self.logger.error("MCP agent loop API error at turn %d: %s", turn + 1, e)
                break

            # Track cost (Sonnet pricing)
            turn_cost = (response.usage.input_tokens * 3 / 1_000_000) + (response.usage.output_tokens * 15 / 1_000_000)
            total_cost += turn_cost

            # Check if Claude is done (no more tool calls)
            if response.stop_reason == "end_turn":
                # Extract final text analysis
                final_text = ""
                for block in response.content:
                    if hasattr(block, "text"):
                        final_text += block.text
                self.logger.info("MCP analysis complete — %d turns, $%.4f", turn + 1, total_cost)
                messages.append({"role": "assistant", "content": response.content})
                break

            # Process tool calls
            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
            if not tool_use_blocks:
                # Text-only response, Claude is done
                final_text = ""
                for block in response.content:
                    if hasattr(block, "text"):
                        final_text += block.text
                self.logger.info("MCP analysis complete (text only) — %d turns, $%.4f", turn + 1, total_cost)
                break

            # Append assistant message with tool use
            messages.append({"role": "assistant", "content": response.content})

            # Execute each tool call and build results
            tool_results = []
            for tool_block in tool_use_blocks:
                tool_name = tool_block.name
                tool_input = tool_block.input
                self.logger.info("MCP turn %d: %s(%s)", turn + 1, tool_name,
                                 json.dumps(tool_input)[:100])

                result_text = self._ghidra_mcp_call_tool(tunnel_port, tool_name, tool_input)
                tool_calls_log.append({
                    "turn": turn + 1,
                    "tool": tool_name,
                    "input": tool_input,
                    "output_length": len(result_text),
                })

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_block.id,
                    "content": result_text,
                })

            messages.append({"role": "user", "content": tool_results})

        else:
            # Exhausted all turns — ask for final summary
            self.logger.info("MCP analysis hit turn limit (%d), requesting summary", max_turns)
            messages.append({"role": "user", "content": [{"type": "text",
                "text": "You've used all available tool calls. Provide your final analysis now based on everything you've found."}]})
            try:
                final_resp = client.messages.create(
                    model=self.cfg.llm_api_model,
                    max_tokens=4000,
                    system=system_prompt,
                    messages=messages,
                )
                final_cost = (final_resp.usage.input_tokens * 3 / 1_000_000) + (final_resp.usage.output_tokens * 15 / 1_000_000)
                total_cost += final_cost
                final_text = ""
                for block in final_resp.content:
                    if hasattr(block, "text"):
                        final_text += block.text
            except Exception as e:
                self.logger.error("MCP final summary failed: %s", e)
                final_text = ""

        self._mark_deep_analyzed(sha256)

        if not final_text:
            return None

        return {
            "deep_analysis": final_text,
            "analysis_mode": "ghidra_mcp_interactive",
            "triage": {"mode": "mcp_interactive", "tool_calls": tool_calls_log},
            "functions_analyzed": len([t for t in tool_calls_log if "decompile" in t["tool"]]),
            "functions_total": 0,  # Unknown in MCP mode
            "decompiled_function_count": len([t for t in tool_calls_log if "decompile" in t["tool"]]),
            "score": self._score_sample(results),
            "cost": round(total_cost, 4),
            "mcp_turns": len(set(t["turn"] for t in tool_calls_log)),
            "mcp_tool_calls": len(tool_calls_log),
        }

    def claude_analyze(self, results: dict) -> Optional[dict]:
        """Call LLM for threat assessment and YARA rule generation."""
        if self.cfg.llm_mode == "none":
            return None

        if self.cfg.llm_mode == "local":
            return self._llm_analyze_local(results)

        api_key = self._anthropic_key
        if not api_key:
            return None

        try:
            import anthropic
        except ImportError:
            self.logger.warning("anthropic package not installed — skipping LLM analysis")
            return None

        sha256 = results.get("sha256", "?")
        self.logger.info("Calling Claude API for %s...", sha256[:16])

        # Build analysis prompt with ALL available evidence
        strings_text = "\n".join(results.get("interesting_strings", [])[:30])
        floss_text = "\n".join(results.get("floss_strings", [])[:20])
        capa_text = json.dumps(results.get("capa_capabilities", [])[:20], indent=2)
        ghidra_text = json.dumps(results.get("ghidra"), indent=2) if results.get("ghidra") else "N/A"
        yara_text = json.dumps(results.get("yara_matches", []))
        dyn = results.get("dynamic_analysis", {})
        dyn_text = ""
        if dyn:
            strace = dyn.get("strace") or {}
            dyn_text = f"""
Dynamic Analysis (Sandbox Detonation — {dyn.get('detonation_duration', '?')}s):
  DNS Queries: {json.dumps(dyn.get('dns_queries', [])[:20])}
  Outbound Connections: {json.dumps(dyn.get('outbound_connections', [])[:20])}
  TLS SNI (Server Name Indication): {json.dumps(dyn.get('tls_sni', [])[:15])}
  HTTP Requests: {json.dumps(dyn.get('http_requests', [])[:15])}
  JA3 TLS Fingerprints: {json.dumps(dyn.get('ja3_fingerprints', [])[:10])}
  New Files Created: {json.dumps(dyn.get('new_files', [])[:15])}
  Filesystem Changes: {json.dumps(dyn.get('filesystem_changes', {}))[:2000]}
  Process Tree (auditd): {json.dumps(dyn.get('process_tree', [])[:15], indent=2)[:2000]}
  Strace File Operations: {json.dumps(strace.get('file_operations', [])[:20])[:1000]}
  Strace Network Operations: {json.dumps(strace.get('network_operations', [])[:15])[:800]}
  Strace Process Operations: {json.dumps(strace.get('process_operations', [])[:15])[:800]}
  PCAP Size: {dyn.get('pcap_size', 0)} bytes
"""
        # VirusTotal / MalwareBazaar context if available
        vt = results.get("virustotal", {})
        vt_text = ""
        if vt:
            vt_text = f"""
VirusTotal:
  Detections: {vt.get('positives', '?')}/{vt.get('total', '?')}
  Detection Names: {json.dumps(vt.get('detection_names', [])[:10])}
"""
        mb = results.get("malwarebazaar", {})
        mb_text = ""
        if mb:
            mb_text = f"""
MalwareBazaar:
  Signature: {mb.get('signature', 'N/A')}
  Tags: {mb.get('tags', [])}
"""

        prompt = f"""You are a senior malware analyst writing a threat intelligence report. Analyze ALL evidence below from a honeypot-captured sample.

CRITICAL RULES:
- USE ALL EVIDENCE PROVIDED. If dynamic analysis data exists (PCAP, strace, connections, DNS, process tree), you MUST analyze it. Saying "no behavioral evidence" when dynamic data is present is WRONG.
- Every claim MUST cite specific evidence (e.g. "strace shows connect() to 185.x.x.x:4444", "PCAP contains 3 TCP SYN to port 443")
- Distinguish OBSERVED behavior (what it DID in sandbox) vs STATIC capabilities (what it COULD do based on code)
- If the 90-second detonation window may have been too short, note what might emerge with longer execution

THREAT HYPOTHESIS — you MUST take a stance on what this is:
- Is it a reverse shell, botnet implant, loader/dropper, C2 agent, cryptominer, ransomware, or recon tool?
- State your hypothesis with confidence level and the evidence chain that supports it
- If evidence is insufficient for a firm classification, state your best hypothesis with caveats

IP/DOMAIN CONTEXT — for every IP or domain found:
- Note if it's a known Tor exit node, VPN endpoint, bulletproof hosting, or CDN
- Note the port significance (4444=meterpreter, 3333=mining, 8080=proxy, etc.)
- Correlate with VT/MB data if available

Provide your response as JSON with these exact keys:
{{
  "classification": "one of: botnet, trojan, miner, ransomware, backdoor, worm, dropper, RAT, exploit-kit, unknown",
  "confidence": "one of: high, medium, low — with a brief reason (e.g. 'high — VT 45/70, YARA match, observed C2 traffic')",
  "severity": "one of: critical, high, medium, low",
  "malware_family": "specific family name if identifiable from VT/MB/strings/YARA, otherwise 'unknown'",
  "threat_hypothesis": "Your assessment of what this malware IS and what it's designed to do, with evidence chain. Take a stance — e.g. 'This is a Mirai-variant botnet implant: it connects to C2 on port 4444 (common for Mirai), contains /bin/sh string for command execution, and was dropped via SSH brute-force. The C2 IP 185.x.x.x is a known Tor exit node, suggesting anonymized infrastructure.'",
  "summary": "structured as: 1) BEHAVIORAL (what it DID during detonation — connections made, processes spawned, files created, DNS lookups), 2) STATIC (code capabilities from strings/capa/Ghidra — APIs called, embedded IPs/domains, encryption, persistence mechanisms), 3) NETWORK (all observed traffic — every connection, DNS query, TLS handshake, with protocol and port analysis), 4) IOCs (all extracted indicators with context — IPs with reputation, domains, file paths, mutex names, registry keys, C2 protocols)",
  "warrants_investigation": ["list of specific actionable items — e.g. 'IP 185.x.x.x needs AbuseIPDB/Shodan lookup for infrastructure mapping', 'encrypted config blob at offset 0x400 needs decryption', 'longer detonation needed to observe beacon interval'"],
  "mitre_attack": ["Txx.xxx — technique name — citing specific evidence"],
  "yara_rule": "A production YARA rule that reliably detects THIS specific malware family. MUST include: 1) meta block with description, author='ELKIE SOC', date, hash, 2) string patterns unique to this family (product names, C2 domains, unique error messages, API strings — NOT generic libc strings), 3) condition combining: magic bytes check (ELF/PE), file size range (within 2x of actual), AND string matches. Use 'nocase' for product/brand names. For Go binaries include '.gopclntab' or 'Go build ID'. For large binaries (>10MB) include filesize constraints. Do NOT match on generic strings like '/bin/sh', 'Connection refused', etc."
}}

--- EVIDENCE ---
SHA256: {results.get('sha256', '')}
MD5: {results.get('md5', '')}
File Type: {results.get('file_type', '')}
MIME: {results.get('mime_type', '')}
Size: {results.get('file_size', 0)} bytes
Is ELF: {results.get('is_elf', False)}
Is PE: {results.get('is_pe', False)}
ssdeep: {results.get('ssdeep', 'N/A')}

YARA Matches: {yara_text}

Interesting Strings:
{strings_text}

FLOSS Decoded Strings:
{floss_text}

capa Capabilities:
{capa_text}

Ghidra Analysis:
{ghidra_text}
{dyn_text}{vt_text}{mb_text}"""

        try:
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model=self.cfg.llm_api_model,
                max_tokens=3000,
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.content[0].text
            cost = (response.usage.input_tokens * 3 / 1_000_000) + (response.usage.output_tokens * 15 / 1_000_000)
            self.logger.info("Claude API: %d in / %d out tokens ($%.4f) for %s",
                             response.usage.input_tokens, response.usage.output_tokens, cost, sha256[:16])

            # Try to parse as JSON
            try:
                # Find JSON in response
                import re
                json_match = re.search(r'\{[\s\S]*\}', text)
                if json_match:
                    data = json.loads(json_match.group())
                    return data
            except json.JSONDecodeError:
                pass

            # Fallback: use raw text as summary
            return {"summary": text, "classification": None, "confidence": None,
                    "severity": None, "yara_rule": "", "warrants_investigation": ""}

        except Exception as e:
            self.logger.error("Claude API failed for %s: %s", sha256[:16], e)
            return None

    def _llm_analyze_local(self, results: dict) -> Optional[dict]:
        """Use local Ollama endpoint for threat assessment (no API key needed)."""
        try:
            # Build the same prompt as claude_analyze but send to local endpoint
            sha256 = results.get("sha256", "?")
            strings_text = "\n".join(results.get("interesting_strings", [])[:20])
            capa_text = json.dumps(results.get("capa_capabilities", [])[:15], indent=2)
            yara_text = json.dumps(results.get("yara_matches", []))
            dyn = results.get("dynamic_analysis", {})
            dyn_summary = ""
            if dyn:
                dyn_summary = f"DNS: {dyn.get('dns_queries', [])[:10]}, Connections: {dyn.get('outbound_connections', [])[:10]}, New files: {dyn.get('new_files', [])[:10]}"

            prompt = f"""Analyze this honeypot-captured sample. Report ONLY what evidence supports. Respond as JSON with keys: classification, confidence, severity, malware_family, summary, warrants_investigation, yara_rule.

SHA256: {sha256}
File Type: {results.get('file_type', '')}
Size: {results.get('file_size', 0)} bytes
YARA: {yara_text}
Strings: {strings_text[:2000]}
capa: {capa_text[:1500]}
Dynamic: {dyn_summary[:1500]}"""

            resp = requests.post(
                f"{self.cfg.llm_local_url}/api/generate",
                json={"model": self.cfg.llm_local_model, "prompt": prompt, "stream": False},
                timeout=120,
            )
            if resp.status_code != 200:
                self.logger.warning("Local LLM returned %d", resp.status_code)
                return None

            text = resp.json().get("response", "")
            json_match = re.search(r'\{[\s\S]*\}', text)
            if json_match:
                return json.loads(json_match.group())
            return {"summary": text, "classification": None, "confidence": None,
                    "severity": None, "yara_rule": "", "warrants_investigation": ""}
        except Exception as e:
            self.logger.warning("Local LLM analysis failed: %s", e)
            return None

    def claude_generate_sigma(self, results: dict) -> Optional[str]:
        """Generate a behavioral Sigma rule from dynamic analysis via LLM."""
        if self.cfg.llm_mode == "none":
            return None

        dyn = results.get("dynamic_analysis")
        if not dyn:
            return None

        api_key = self._anthropic_key
        if self.cfg.llm_mode == "api" and not api_key:
            return None

        sha256 = results.get("sha256", "?")
        classification = results.get("classification", "unknown")
        yara_matches = results.get("yara_matches", [])[:5]

        # Build behavioral context
        process_tree = json.dumps(dyn.get("process_tree", [])[:15], indent=2)[:2000]
        strace = dyn.get("strace") or {}
        file_ops = json.dumps(strace.get("file_operations", [])[:20])[:1000]
        net_ops = json.dumps(strace.get("network_operations", [])[:15])[:800]
        proc_ops = json.dumps(strace.get("process_operations", [])[:15])[:800]
        dns = ", ".join(dyn.get("dns_queries", [])[:10])
        new_files = ", ".join(dyn.get("new_files", [])[:10])

        prompt = f"""You are a Sigma rule author. Generate a Sigma detection rule in YAML that detects the BEHAVIORAL pattern of this Linux malware. Focus on process chains, file operations, and network patterns — not just IOCs.

Classification: {classification}
YARA matches: {', '.join(yara_matches)}

Process Tree:
{process_tree}

Strace File Operations:
{file_ops}

Strace Network Operations:
{net_ops}

Strace Process Operations:
{proc_ops}

DNS Queries: {dns}
Files Created: {new_files}

Requirements:
- Output exactly ONE Sigma rule as valid YAML — no multiple documents, no '---' separators
- Use logsource categories: process_creation, file_event, network_connection, or dns_query
- Include: title, status (experimental), description, logsource, detection, level, tags (MITRE ATT&CK)
- The rule should detect the BEHAVIOR, not specific hashes or IPs
- Output ONLY valid YAML, no explanation, no markdown fences"""

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model=self.cfg.llm_api_model,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.content[0].text.strip()
            cost = (response.usage.input_tokens * 3 / 1_000_000) + (response.usage.output_tokens * 15 / 1_000_000)
            self.logger.info("Sigma generation: %d in / %d out tokens ($%.4f)",
                             response.usage.input_tokens, response.usage.output_tokens, cost)

            # Strip markdown fences if present
            if text.startswith("```"):
                text = "\n".join(text.split("\n")[1:])
            if text.endswith("```"):
                text = "\n".join(text.split("\n")[:-1])

            # Validate YAML — handle multi-document (Claude sometimes outputs multiple rules separated by ---)
            import yaml
            valid_rules = []
            for doc in yaml.safe_load_all(text):
                if isinstance(doc, dict) and "title" in doc and "detection" in doc:
                    valid_rules.append(doc)

            if not valid_rules:
                self.logger.warning("Sigma generation: no valid rules in output")
                return None

            # Return the first valid rule as YAML text
            return yaml.dump(valid_rules[0], default_flow_style=False, sort_keys=False)

        except Exception as e:
            self.logger.warning("Sigma generation failed: %s", e)
            return None

    # -- VirusTotal --------------------------------------------------------

    def vt_lookup(self, sha256: str) -> Optional[dict]:
        """Look up a hash on VirusTotal. Returns detection info or None."""
        if not self._vt_api_key:
            return None

        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self._vt_api_key},
                timeout=15,
            )
            if resp.status_code == 404:
                self.logger.info("VT: %s not found (novel sample)", sha256[:16])
                return {"found": False, "sha256": sha256}
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                names = data.get("popular_threat_classification", {})
                suggested_label = names.get("suggested_threat_label", "")
                result = {
                    "found": True,
                    "sha256": sha256,
                    "detections": detections,
                    "total_engines": total,
                    "detection_ratio": f"{detections}/{total}",
                    "suggested_label": suggested_label,
                    "reputation": data.get("reputation", 0),
                    "first_submission": data.get("first_submission_date"),
                    "tags": data.get("tags", [])[:10],
                }
                self.logger.info("VT: %s — %d/%d detections (%s)",
                                 sha256[:16], detections, total, suggested_label or "unlabeled")
                return result
            else:
                self.logger.warning("VT lookup returned %d for %s", resp.status_code, sha256[:16])
                return None
        except Exception as e:
            self.logger.error("VT lookup failed for %s: %s", sha256[:16], e)
            return None

    # -- MalwareBazaar -----------------------------------------------------

    def mb_submit(self, sha256: str, local_path: Path, results: dict) -> Optional[dict]:
        """Submit a sample to MalwareBazaar if not already known there."""
        if not self._mb_api_key:
            return None

        # Check if already on MalwareBazaar
        try:
            resp = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": sha256},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "hash_not_found":
                    self.logger.info("MB: %s not found — submitting", sha256[:16])
                elif data.get("query_status") == "ok":
                    self.logger.info("MB: %s already known", sha256[:16])
                    return {"submitted": False, "already_known": True}
                else:
                    self.logger.info("MB: query status %s for %s", data.get("query_status"), sha256[:16])
        except Exception as e:
            self.logger.warning("MB lookup failed: %s", e)

        # Submit the sample
        try:
            # Build tags from analysis
            tags = []
            classification = results.get("classification", "")
            if classification and classification != "unknown":
                tags.append(classification)
            for yara in results.get("yara_matches", [])[:5]:
                tags.append(yara)

            with open(local_path, "rb") as f:
                resp = requests.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={
                        "query": "upload_sample",
                        "tags_list": ",".join(tags) if tags else "honeypot",
                        "anonymous": "0",
                    },
                    files={"file": (sha256, f, "application/octet-stream")},
                    headers={"API-KEY": self._mb_api_key},
                    timeout=60,
                )

            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status", "")
                if status in ("ok", "sample_already_known"):
                    self.logger.info("MB: submitted %s — %s", sha256[:16], status)
                    return {"submitted": status == "ok", "already_known": status == "sample_already_known"}
                else:
                    self.logger.warning("MB: submission status %s for %s: %s",
                                        status, sha256[:16], data.get("query_msg", ""))
            else:
                self.logger.warning("MB submit returned %d for %s", resp.status_code, sha256[:16])
        except Exception as e:
            self.logger.error("MB submission failed for %s: %s", sha256[:16], e)

        return None

    # -- MISP integration --------------------------------------------------

    def _misp_api(self, method: str, path: str, data: dict = None) -> Optional[dict]:
        """Call MISP REST API."""
        if not self._misp_api_key:
            return None
        url = f"{self.cfg.misp_url}{path}"
        headers = {
            "Authorization": self._misp_api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, verify=False, timeout=15)
            elif method == "POST":
                resp = requests.post(url, headers=headers, json=data, verify=False, timeout=15)
            else:
                return None
            if resp.status_code in (200, 201):
                return resp.json()
            else:
                self.logger.warning("MISP API %s %s returned %d", method, path, resp.status_code)
                return None
        except Exception as e:
            self.logger.error("MISP API %s %s failed: %s", method, path, e)
            return None

    def misp_check_iocs(self, results: dict) -> Optional[dict]:
        """Check if any IOCs from analysis are already known in MISP."""
        if not self._misp_api_key:
            return None

        sha256 = results.get("sha256", "")
        known_iocs = []

        # Check hash
        search = self._misp_api("POST", "/attributes/restSearch", {
            "value": sha256,
            "type": "sha256",
            "limit": 5,
        })
        if search and search.get("response", {}).get("Attribute"):
            attrs = search["response"]["Attribute"]
            known_iocs.append({
                "type": "sha256",
                "value": sha256[:16] + "...",
                "events": len(attrs),
                "first_seen": attrs[0].get("timestamp", ""),
            })

        # Check interesting IPs/domains from strings
        for s in results.get("interesting_strings", [])[:20]:
            # Quick IP check
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', s)
            if ip_match:
                ip = ip_match.group(1)
                if ip.startswith(("10.", "192.168.", "127.", "0.")):
                    continue
                search = self._misp_api("POST", "/attributes/restSearch", {
                    "value": ip,
                    "type": ["ip-src", "ip-dst"],
                    "limit": 3,
                })
                if search and search.get("response", {}).get("Attribute"):
                    attrs = search["response"]["Attribute"]
                    known_iocs.append({
                        "type": "ip",
                        "value": ip,
                        "events": len(attrs),
                    })

        # Check DNS queries from dynamic analysis
        dyn = results.get("dynamic_analysis", {})
        for domain in dyn.get("dns_queries", [])[:10]:
            search = self._misp_api("POST", "/attributes/restSearch", {
                "value": domain,
                "type": ["domain", "hostname"],
                "limit": 3,
            })
            if search and search.get("response", {}).get("Attribute"):
                attrs = search["response"]["Attribute"]
                known_iocs.append({
                    "type": "domain",
                    "value": domain,
                    "events": len(attrs),
                })

        if known_iocs:
            self.logger.info("MISP: found %d known IOCs for %s", len(known_iocs), sha256[:16])
            return {"known_iocs": known_iocs, "total_matches": len(known_iocs)}

        self.logger.info("MISP: no known IOCs for %s", sha256[:16])
        return {"known_iocs": [], "total_matches": 0}

    def misp_create_event(self, results: dict, metadata: dict):
        """Create a professional MISP event from analysis results."""
        if not self._misp_api_key:
            return

        sha256 = results.get("sha256", "")
        md5 = results.get("md5", "")
        classification = results.get("classification", "unknown")
        severity = results.get("severity", "medium")
        file_type = results.get("file_type", "unknown")
        file_size = results.get("file_size", 0)
        honeypot = metadata.get("honeypot", "unknown")
        src_ip = metadata.get("src_ip", "")
        country = metadata.get("country", "")

        threat_level = {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 3)

        # Build descriptive event info
        size_str = f"{file_size / 1024:.0f}KB" if file_size < 1048576 else f"{file_size / 1048576:.1f}MB"
        info_parts = [f"[{honeypot.upper()}]", classification.title(), f"({file_type.split(',')[0].strip()}, {size_str})"]
        if src_ip:
            info_parts.append(f"from {src_ip}")
            if country:
                info_parts.append(f"({country})")
        event_info = " ".join(info_parts)

        # Build tags — proper taxonomy tags
        tags = [
            {"name": "tlp:green"},
            {"name": "type:OSINT"},
            {"name": f"malware_classification:malware-category=\"{classification}\""},
        ]

        # Map classification to kill-chain phase
        kill_chain_map = {
            "botnet": "kill-chain:Actions on Objectives",
            "trojan": "kill-chain:Installation",
            "miner": "kill-chain:Actions on Objectives",
            "ransomware": "kill-chain:Actions on Objectives",
            "backdoor": "kill-chain:Installation",
            "worm": "kill-chain:Delivery",
            "dropper": "kill-chain:Delivery",
        }
        if classification in kill_chain_map:
            tags.append({"name": kill_chain_map[classification]})

        # Admiralty scale — reliability of source
        tags.append({"name": "admiralty-scale:source-reliability=\"b\""})  # Usually reliable (honeypot)
        tags.append({"name": "admiralty-scale:information-credibility=\"2\""})  # Probably true (automated analysis)

        # VT-based confidence
        vt = results.get("virustotal", {})
        if vt and vt.get("found"):
            detections = vt.get("detections", 0)
            if detections > 10:
                tags.append({"name": "admiralty-scale:information-credibility=\"1\""})  # Confirmed by VT
            if vt.get("suggested_label"):
                tags.append({"name": f"malware_classification:malware-category=\"{vt['suggested_label']}\""})

        event_data = {
            "Event": {
                "info": event_info,
                "threat_level_id": threat_level,
                "analysis": 2,  # completed
                "distribution": 0,  # org only
                "Tag": tags,
                "Attribute": [],
            }
        }

        attrs = event_data["Event"]["Attribute"]

        # --- Payload delivery ---
        attrs.append({"type": "sha256", "category": "Payload delivery", "value": sha256,
                       "to_ids": True, "comment": f"Sample hash ({classification})"})
        if md5:
            attrs.append({"type": "md5", "category": "Payload delivery", "value": md5, "to_ids": True})
        attrs.append({"type": "filename|sha256", "category": "Payload delivery",
                       "value": f"{sha256[:16]}|{sha256}", "to_ids": True,
                       "comment": file_type.split(",")[0].strip()})
        if file_size:
            attrs.append({"type": "size-in-bytes", "category": "Payload delivery",
                           "value": str(file_size), "to_ids": False})
        attrs.append({"type": "mime-type", "category": "Payload delivery",
                       "value": results.get("mime_type", "unknown"), "to_ids": False})

        # --- Network activity: source ---
        if src_ip:
            comment = f"Attacker delivering payload via {honeypot}"
            if country:
                comment += f" ({country})"
            attrs.append({"type": "ip-src", "category": "Network activity", "value": src_ip,
                           "to_ids": True, "comment": comment})

        # --- Antivirus detection ---
        for yara in results.get("yara_matches", []):
            attrs.append({"type": "yara", "category": "Payload delivery", "value": yara,
                           "to_ids": False, "comment": "YARA rule match"})

        if vt and vt.get("found"):
            attrs.append({"type": "link", "category": "External analysis",
                           "value": f"https://www.virustotal.com/gui/file/{sha256}",
                           "to_ids": False, "comment": f"VirusTotal: {vt['detection_ratio']} detections"})

        # MalwareBazaar link
        mb = results.get("malwarebazaar", {})
        if mb:
            attrs.append({"type": "link", "category": "External analysis",
                           "value": f"https://bazaar.abuse.ch/sample/{sha256}/",
                           "to_ids": False, "comment": "MalwareBazaar"})

        # --- Network IOCs from strings ---
        seen_iocs = set()
        for s in results.get("interesting_strings", []):
            url_match = re.search(r'https?://\S+', s)
            if url_match:
                url = url_match.group().rstrip(")'\"")
                if url not in seen_iocs:
                    seen_iocs.add(url)
                    attrs.append({"type": "url", "category": "Network activity", "value": url,
                                   "to_ids": True, "comment": "Extracted from sample strings"})
                continue
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', s)
            if ip_match:
                ip = ip_match.group(1)
                if not ip.startswith(("10.", "192.168.", "127.", "0.", "255.")) and ip not in seen_iocs:
                    seen_iocs.add(ip)
                    attrs.append({"type": "ip-dst", "category": "Network activity", "value": ip,
                                   "to_ids": True, "comment": "Extracted from sample strings"})

        # --- Dynamic analysis IOCs ---
        dyn = results.get("dynamic_analysis", {})
        for domain in dyn.get("dns_queries", []):
            if domain not in seen_iocs:
                seen_iocs.add(domain)
                attrs.append({"type": "domain", "category": "Network activity", "value": domain,
                               "to_ids": True, "comment": "DNS query during sandbox detonation"})
        for conn in dyn.get("outbound_connections", []):
            val = f"{conn['ip']}|{conn['port']}"
            if val not in seen_iocs:
                seen_iocs.add(val)
                attrs.append({"type": "ip-dst|port", "category": "Network activity", "value": val,
                               "to_ids": True, "comment": "Outbound connection during sandbox detonation"})
        if dyn.get("new_files"):
            for f in dyn["new_files"][:10]:
                attrs.append({"type": "filename", "category": "Artifacts dropped", "value": f,
                               "to_ids": False, "comment": "File created during sandbox detonation"})

        # --- capa capabilities as MITRE ATT&CK TTPs ---
        for cap in results.get("capa_capabilities", [])[:15]:
            ns = cap.get("namespace", "")
            name = cap.get("name", "")
            if ns:
                attrs.append({"type": "text", "category": "Other", "value": f"[{ns}] {name}",
                               "to_ids": False, "comment": "capa capability (MITRE ATT&CK)"})

        # --- C2 infrastructure as domain|ip composite attributes ---
        for entry in (results.get("c2_infrastructure") or {}).get("domains", [])[:10]:
            domain = entry.get("domain", "")
            for ip in entry.get("resolved_ips", [])[:3]:
                attrs.append({"type": "domain|ip", "category": "Network activity",
                               "value": f"{domain}|{ip}", "to_ids": True,
                               "comment": "C2 infrastructure mapping"})

        # --- ATT&CK technique tags (MISP galaxy format) ---
        for tech in results.get("attack_techniques", [])[:20]:
            tid = tech["technique_id"]
            src = tech.get("source", "")
            tags.append({"name": f"misp-galaxy:mitre-attack-pattern=\"{tid}\""})

        # --- LLM threat assessment ---
        if results.get("llm_summary"):
            attrs.append({"type": "comment", "category": "External analysis",
                           "value": f"LLM Threat Assessment (qwen2.5:14b):\n\n{results['llm_summary'][:5000]}",
                           "to_ids": False, "comment": "Automated LLM analysis"})

        # --- Auto-generated YARA rule ---
        gen_yara = results.get("generated_yara_rule", "")
        if gen_yara:
            attrs.append({"type": "yara", "category": "Payload delivery",
                           "value": gen_yara, "to_ids": True,
                           "comment": "Auto-generated YARA rule (LLM)"})

        # --- Capture metadata ---
        captured_at = metadata.get("captured_at", "")
        if captured_at:
            attrs.append({"type": "datetime", "category": "Other", "value": captured_at,
                           "to_ids": False, "comment": f"Captured by {honeypot} honeypot"})

        result = self._misp_api("POST", "/events/add", event_data)
        if result and result.get("Event", {}).get("id"):
            event_id = result["Event"]["id"]
            self.logger.info("MISP: created event #%s for %s (%s)", event_id, sha256[:16], event_info[:50])
        else:
            self.logger.error("MISP: failed to create event for %s: %s", sha256[:16], result)

    # -- Sandbox (dynamic analysis) ----------------------------------------

    def _pve_api(self, method: str, path: str, data: dict = None) -> Optional[dict]:
        """Call Proxmox API."""
        if not self._pve_token_id or not self._pve_token_secret:
            return None
        url = f"{self.cfg.pve_api_url}{path}"
        headers = {"Authorization": f"PVEAPIToken={self._pve_token_id}={self._pve_token_secret}"}
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, verify=False, timeout=30)
            elif method == "POST":
                resp = requests.post(url, headers=headers, json=data, verify=False, timeout=30)
            else:
                return None
            return resp.json()
        except Exception as e:
            self.logger.error("Proxmox API %s %s failed: %s", method, path, e)
            return None

    def _enrich_connections(self, connections: list) -> list:
        """Filter internal IPs and enrich external ones with geo/reputation."""
        enriched = []
        seen = set()

        for conn in connections:
            ip = conn.get("ip", "")
            port = conn.get("port", "")
            key = f"{ip}:{port}"

            # Skip internal/private IPs
            if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "127.", "0.")):
                continue
            # Skip duplicates
            if key in seen:
                continue
            seen.add(key)

            entry = {"ip": ip, "port": port}

            # Quick IPInfo lookup
            try:
                r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
                if r.status_code == 200:
                    info = r.json()
                    entry["hostname"] = info.get("hostname", "")
                    entry["city"] = info.get("city", "")
                    entry["country"] = info.get("country", "")
                    entry["org"] = info.get("org", "")
            except Exception:
                pass

            # Shodan InternetDB (free, no key needed)
            try:
                r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
                if r.status_code == 200:
                    shodan = r.json()
                    entry["shodan_ports"] = shodan.get("ports", [])
                    entry["shodan_tags"] = shodan.get("tags", [])
                    entry["shodan_hostnames"] = shodan.get("hostnames", [])
                    entry["shodan_vulns"] = shodan.get("vulns", [])[:5]
            except Exception:
                pass

            enriched.append(entry)
            time.sleep(0.3)  # Rate limit

        return enriched

    def _sandbox_ssh(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run command on sandbox VM via T-Pot jump host."""
        return self._ssh_cmd(self.cfg.sandbox_host, self.cfg.sandbox_port,
                             self.cfg.sandbox_user, cmd, timeout=timeout)

    def _sandbox_scp_to(self, local_path: str, remote_path: str, timeout: int = 60) -> bool:
        """Copy file to sandbox via T-Pot jump host."""
        return self._scp_to(self.cfg.sandbox_host, self.cfg.sandbox_port,
                            self.cfg.sandbox_user, "", local_path, remote_path, timeout=timeout)

    def _sandbox_scp_from(self, remote_path: str, local_path: str, timeout: int = 60) -> bool:
        """Copy file from sandbox via T-Pot jump host."""
        return self._scp_from(self.cfg.sandbox_host, self.cfg.sandbox_port,
                              self.cfg.sandbox_user, "", remote_path, local_path, timeout=timeout)

    def _sandbox_restore_snapshot(self) -> bool:
        """Restore sandbox VM to clean snapshot via Proxmox API."""
        vmid = self.cfg.sandbox_vmid
        snap = self.cfg.sandbox_snapshot
        node = self.cfg.pve_node

        self.logger.info("Restoring sandbox VM %d to snapshot '%s'", vmid, snap)

        # Stop VM first if running
        status = self._pve_api("GET", f"/api2/json/nodes/{node}/qemu/{vmid}/status/current")
        if status and status.get("data", {}).get("status") == "running":
            self._pve_api("POST", f"/api2/json/nodes/{node}/qemu/{vmid}/status/stop")
            # Wait for VM to stop
            for _ in range(30):
                time.sleep(2)
                s = self._pve_api("GET", f"/api2/json/nodes/{node}/qemu/{vmid}/status/current")
                if s and s.get("data", {}).get("status") == "stopped":
                    break

        # Rollback snapshot
        result = self._pve_api("POST", f"/api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snap}/rollback")
        if not result or "data" not in result:
            self.logger.error("Failed to rollback snapshot: %s", result)
            return False

        # Wait for rollback to complete, then start
        time.sleep(5)
        self._pve_api("POST", f"/api2/json/nodes/{node}/qemu/{vmid}/status/start")

        # Wait for VM to be reachable via SSH
        for attempt in range(30):
            time.sleep(3)
            rc, _, _ = self._sandbox_ssh("echo ready", timeout=5)
            if rc == 0:
                self.logger.info("Sandbox VM ready after restore (%ds)", (attempt + 1) * 3)
                return True

        self.logger.error("Sandbox VM not reachable after snapshot restore")
        return False

    def _parse_strace_log(self, strace_path: Path) -> dict:
        """Parse strace output for file, network, and process operations."""
        if not strace_path.exists():
            return {}

        try:
            content = strace_path.read_text(errors="replace")
        except OSError:
            return {}

        file_ops = []     # open, openat, creat, unlink, rename
        net_ops = []      # connect, bind, sendto
        proc_ops = []     # execve, clone, fork, kill
        seen_files = set()
        seen_nets = set()

        for line in content.splitlines():
            # File operations: openat(AT_FDCWD, "/etc/passwd", ...)
            m = re.match(r'(\d+)\s+(openat?|creat|unlink|rename)\(.*?"([^"]+)"', line)
            if m:
                pid, syscall, path = m.group(1), m.group(2), m.group(3)
                if path not in seen_files and not path.startswith(("/usr/lib", "/lib/x86_64", "/etc/ld")):
                    seen_files.add(path)
                    file_ops.append({"pid": pid, "syscall": syscall, "path": path})
                continue

            # Network: connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, ...)
            m = re.match(r'(\d+)\s+(connect|bind|sendto)\(.*?sin_port=htons\((\d+)\).*?inet_addr\("([^"]+)"\)', line)
            if m:
                pid, syscall, port, ip = m.group(1), m.group(2), m.group(3), m.group(4)
                key = f"{ip}:{port}"
                if key not in seen_nets:
                    seen_nets.add(key)
                    net_ops.append({"pid": pid, "syscall": syscall, "ip": ip, "port": port})
                continue

            # Process: execve("/bin/sh", ["sh", "-c", "..."], ...)
            m = re.match(r'(\d+)\s+(execve|clone|fork)\(.*?"?([^",\s]+)"?', line)
            if m:
                pid, syscall, target = m.group(1), m.group(2), m.group(3)
                proc_ops.append({"pid": pid, "syscall": syscall, "target": target[:200]})
                continue

        return {
            "file_operations": file_ops[:100],
            "network_operations": net_ops[:50],
            "process_operations": proc_ops[:50],
            "total_syscalls": len(content.splitlines()),
        }

    def _run_volatility(self, memdump_path: Path, sha256: str) -> dict:
        """Run volatility3 on REMnux to analyze a memory dump.

        Uploads dump to REMnux, runs pslist + netscan + malfind, returns parsed results.
        """
        if not memdump_path.exists() or memdump_path.stat().st_size < 1048576:
            return {}

        remote_dump = f"/home/{self.cfg.remnux_user}/inbox/{sha256}_memdump.lime"

        # Upload dump to REMnux
        if not self._scp_to(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            self._remnux_pass, str(memdump_path), remote_dump
        ):
            self.logger.warning("Failed to upload memory dump to REMnux")
            return {}

        vol_results = {}

        # Run volatility3 plugins
        plugins = {
            "pslist": "linux.pslist.PsList",
            "sockstat": "linux.sockstat.Sockstat",
            "malfind": "linux.malware.malfind.Malfind",
        }

        for name, plugin in plugins.items():
            rc, output, err = self._ssh_cmd(
                self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                f"vol3 -q -f {remote_dump} -r json {plugin} 2>/dev/null",
                password=self._remnux_pass, timeout=180,
            )
            if rc == 0 and output.strip():
                try:
                    parsed = json.loads(output)
                    # Serialize back to string for ES text field compatibility
                    vol_results[name] = json.dumps(parsed)[:5000]
                except json.JSONDecodeError:
                    vol_results[name] = output[:3000]
            else:
                self.logger.debug("vol3 %s returned rc=%d: %s", name, rc, (err or "")[:200])

        # Cleanup dump on REMnux
        self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"rm -f {remote_dump}",
            password=self._remnux_pass, timeout=10,
        )

        # Cleanup local dump (large file)
        try:
            memdump_path.unlink()
        except OSError:
            pass

        return vol_results

    def _parse_audit_process_tree(self, audit_log_path: Path) -> list:
        """Parse auditd log into a process execution tree.

        Returns a list of process entries with parent/child relationships and
        the commands each process executed.
        """
        if not audit_log_path.exists():
            return []

        try:
            content = audit_log_path.read_text(errors="replace")
        except OSError:
            return []

        processes = {}  # pid -> {ppid, exe, args, children, files}

        for line in content.splitlines():
            # Parse EXECVE syscall records from auditd
            # Format: type=SYSCALL ... pid=X ppid=Y exe="..." ...
            if "type=SYSCALL" in line and "EXECVE" in line:
                pid_m = re.search(r'\bpid=(\d+)', line)
                ppid_m = re.search(r'\bppid=(\d+)', line)
                exe_m = re.search(r'\bexe="([^"]*)"', line)
                comm_m = re.search(r'\bcomm="([^"]*)"', line)

                if pid_m:
                    pid = pid_m.group(1)
                    ppid = ppid_m.group(1) if ppid_m else "0"
                    exe = exe_m.group(1) if exe_m else (comm_m.group(1) if comm_m else "unknown")

                    if pid not in processes:
                        processes[pid] = {
                            "pid": pid,
                            "ppid": ppid,
                            "exe": exe,
                            "children": [],
                        }
                    else:
                        processes[pid]["exe"] = exe
                        processes[pid]["ppid"] = ppid

            # Parse EXECVE argument records for full command lines
            # Format: type=EXECVE ... a0="cmd" a1="arg1" ...
            elif "type=EXECVE" in line:
                args = []
                for arg_m in re.finditer(r'a\d+="([^"]*)"', line):
                    args.append(arg_m.group(1))
                # Also handle hex-encoded args: a0=2F62696E2F7368
                for arg_m in re.finditer(r'a\d+=([0-9A-Fa-f]+)(?:\s|$)', line):
                    try:
                        decoded = bytes.fromhex(arg_m.group(1)).decode("utf-8", errors="replace")
                        args.append(decoded)
                    except (ValueError, UnicodeDecodeError):
                        pass
                if args:
                    # Associate with the most recent PID we saw
                    # auditd groups related records by audit event ID
                    event_m = re.search(r'msg=audit\(\d+\.\d+:(\d+)\)', line)
                    if event_m:
                        event_id = event_m.group(1)
                        # Find the SYSCALL record with same event ID
                        for pid, proc in processes.items():
                            if proc.get("_event_id") == event_id:
                                proc["cmdline"] = " ".join(args)
                                break

            # Track event IDs for correlation
            if "type=SYSCALL" in line:
                event_m = re.search(r'msg=audit\(\d+\.\d+:(\d+)\)', line)
                pid_m = re.search(r'\bpid=(\d+)', line)
                if event_m and pid_m:
                    pid = pid_m.group(1)
                    if pid in processes:
                        processes[pid]["_event_id"] = event_m.group(1)

            # Track file creation/modification
            if "type=SYSCALL" in line and any(s in line for s in ["openat", "creat", "rename", "unlink"]):
                pid_m = re.search(r'\bpid=(\d+)', line)
                if pid_m:
                    pid = pid_m.group(1)
                    name_m = re.search(r'\bname="([^"]*)"', line)
                    if name_m and pid in processes:
                        if "files_touched" not in processes[pid]:
                            processes[pid]["files_touched"] = []
                        processes[pid]["files_touched"].append(name_m.group(1))

        # Build parent-child relationships
        for pid, proc in processes.items():
            ppid = proc.get("ppid", "0")
            if ppid in processes and ppid != pid:
                processes[ppid]["children"].append(pid)

        # Convert to list, clean up internal fields, limit size
        result = []
        for pid, proc in list(processes.items())[:100]:
            entry = {
                "pid": proc["pid"],
                "ppid": proc.get("ppid", "0"),
                "exe": proc.get("exe", "unknown"),
            }
            if proc.get("cmdline"):
                entry["cmdline"] = proc["cmdline"][:500]
            if proc.get("children"):
                entry["children"] = proc["children"]
            if proc.get("files_touched"):
                entry["files_touched"] = proc["files_touched"][:20]
            result.append(entry)

        return result

    def detonate_sample(self, sha256: str, local_path: Path) -> Optional[dict]:
        """Detonate a sample in the sandbox VM and collect behavioral data."""
        if not self.cfg.sandbox_enabled or not self._pve_token_id:
            return None

        self.logger.info("Starting dynamic analysis for %s", sha256[:16])

        # Step 1: Restore clean snapshot
        if not self._sandbox_restore_snapshot():
            return None

        # Step 2: Point DNS to INetSim on REMnux, set up DoT interception
        dns_ip = _safe_ip(self.cfg.remnux_dns_ip)
        self._sandbox_ssh(
            f"sudo bash -c 'rm -f /etc/resolv.conf && echo nameserver {shlex.quote(dns_ip)} > /etc/resolv.conf'",
            timeout=5,
        )
        # Intercept DNS-over-TLS (port 853) — socat strips TLS, forwards to INetSim plain DNS
        self._sandbox_ssh(
            "sudo bash -c '"
            "if command -v socat >/dev/null 2>&1; then "
            "  openssl req -x509 -newkey rsa:2048 -keyout /tmp/dot.key -out /tmp/dot.crt -days 1 -nodes -subj \"/CN=dns\" 2>/dev/null && "
            f"  nohup socat OPENSSL-LISTEN:853,reuseaddr,fork,cert=/tmp/dot.crt,key=/tmp/dot.key,verify=0 TCP:{dns_ip}:53 > /tmp/dot.log 2>&1 & "
            "fi'",
            timeout=10,
        )
        # Redirect DoT/DoH attempts to local interceptors
        self._sandbox_ssh(
            "sudo iptables -t nat -A OUTPUT -p tcp --dport 853 -j REDIRECT --to-port 853 2>/dev/null; "
            f"sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d 1.1.1.1 -j DNAT --to-destination {dns_ip}:80 2>/dev/null; "
            f"sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d 8.8.8.8 -j DNAT --to-destination {dns_ip}:80 2>/dev/null; "
            f"sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d 9.9.9.9 -j DNAT --to-destination {dns_ip}:80 2>/dev/null",
            timeout=5,
        )
        # Clear INetSim DNS log on REMnux so we only capture this detonation's queries
        self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            "sudo truncate -s 0 /var/log/inetsim/service.log 2>/dev/null",
            password=self._remnux_pass, timeout=5,
        )
        self._sandbox_ssh("sudo auditctl -D && sudo rm -f /var/log/audit/audit.log && sudo systemctl restart auditd", timeout=10)
        self._sandbox_ssh(
            f"sudo tcpdump -i any -w /home/{self.cfg.sandbox_user}/detonation/capture.pcap -c 10000 &",
            timeout=5,
        )

        # Step 2.5: Snapshot filesystem state before detonation for diffing
        rc_snap, fs_before, _ = self._sandbox_ssh(
            "sudo find / -xdev -not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' "
            "-not -path '/dev/*' -not -path '/tmp/ghidra*' "
            "-type f -printf '%T@ %m %s %p\\n' 2>/dev/null | sort",
            timeout=30,
        )
        fs_before_lines = set(fs_before.strip().splitlines()) if rc_snap == 0 and fs_before else set()

        # Step 3: Upload sample
        remote_sample = f"/home/{self.cfg.sandbox_user}/detonation/{sha256}"
        if not self._sandbox_scp_to(str(local_path), remote_sample):
            self.logger.error("Failed to upload sample to sandbox")
            return None

        # Step 4: Make executable and detonate under strace (backgrounded)
        self._sandbox_ssh(
            f"chmod +x {remote_sample} 2>/dev/null; "
            f"nohup strace -f -e trace=network,file,process "
            f"-o /home/{self.cfg.sandbox_user}/detonation/strace.log "
            f"timeout {self.cfg.sandbox_timeout} {remote_sample} > /dev/null 2>&1 &",
            timeout=10,
        )

        # Step 5: Wait for detonation period
        self.logger.info("Detonating %s — waiting %ds", sha256[:16], self.cfg.sandbox_timeout)
        time.sleep(self.cfg.sandbox_timeout)

        # Step 6: Collect results
        results_dir = STAGING_DIR / f"{sha256}_dynamic"
        results_dir.mkdir(parents=True, exist_ok=True)

        # Grab auditd logs
        self._sandbox_scp_from("/var/log/audit/audit.log", str(results_dir / "audit.log"))

        # Stop tcpdump and grab pcap
        self._sandbox_ssh("sudo pkill tcpdump", timeout=5)
        time.sleep(1)
        self._sandbox_scp_from(
            f"/home/{self.cfg.sandbox_user}/detonation/capture.pcap",
            str(results_dir / "capture.pcap"),
        )

        # Step 6.5: Grab strace log
        self._sandbox_scp_from(
            f"/home/{self.cfg.sandbox_user}/detonation/strace.log",
            str(results_dir / "strace.log"),
        )

        # Step 6.6: Memory dump with LiME
        memdump_path = results_dir / "memdump.lime"
        rc_lime, lime_out, lime_err = self._sandbox_ssh(
            f"sudo insmod /opt/lime.ko 'path=/home/{self.cfg.sandbox_user}/detonation/memdump.lime format=lime' 2>&1",
            timeout=30,
        )
        if rc_lime == 0:
            time.sleep(5)  # give LiME time to write
            self._sandbox_ssh("sudo rmmod lime 2>/dev/null", timeout=10)
            self._sandbox_scp_from(f"/home/{self.cfg.sandbox_user}/detonation/memdump.lime", str(memdump_path))
            self._sandbox_ssh(f"sudo rm -f /home/{self.cfg.sandbox_user}/detonation/memdump.lime", timeout=5)
            if memdump_path.exists():
                self.logger.info("Memory dump captured: %d MB", memdump_path.stat().st_size // 1048576)
        else:
            self.logger.warning("LiME load failed: %s", lime_err or lime_out)

        # Step 7: Collect process list, network connections, filesystem changes
        rc, ps_out, _ = self._sandbox_ssh("ps auxf", timeout=5)
        rc2, net_out, _ = self._sandbox_ssh("sudo ss -tulnp && echo '---' && sudo ss -anp", timeout=5)
        rc3, files_out, _ = self._sandbox_ssh(
            f"find /tmp /dev/shm /var/tmp /home/{self.cfg.sandbox_user} -newer {remote_sample} -type f 2>/dev/null",
            timeout=10,
        )

        # Step 7.5: Comprehensive filesystem diff — new, modified, deleted files
        fs_changes = {"new": [], "modified": [], "deleted": []}
        if fs_before_lines:
            rc_after, fs_after, _ = self._sandbox_ssh(
                "sudo find / -xdev -not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' "
                "-not -path '/dev/*' -not -path '/tmp/ghidra*' "
                "-type f -printf '%T@ %m %s %p\\n' 2>/dev/null | sort",
                timeout=30,
            )
            if rc_after == 0 and fs_after:
                fs_after_lines = set(fs_after.strip().splitlines())

                # Build path->metadata maps for comparison
                def parse_fs_line(line):
                    parts = line.split(" ", 3)
                    if len(parts) == 4:
                        return parts[3], line  # path -> full line
                    return None, None

                before_map = {}
                for line in fs_before_lines:
                    path, full = parse_fs_line(line)
                    if path:
                        before_map[path] = full

                after_map = {}
                for line in fs_after_lines:
                    path, full = parse_fs_line(line)
                    if path:
                        after_map[path] = full

                # New files (in after but not before)
                for path in after_map:
                    if path not in before_map:
                        fs_changes["new"].append(path)

                # Deleted files (in before but not after)
                for path in before_map:
                    if path not in after_map:
                        fs_changes["deleted"].append(path)

                # Modified files (same path, different metadata)
                for path in after_map:
                    if path in before_map and after_map[path] != before_map[path]:
                        fs_changes["modified"].append(path)

                # Limit each category
                fs_changes["new"] = fs_changes["new"][:50]
                fs_changes["modified"] = fs_changes["modified"][:50]
                fs_changes["deleted"] = fs_changes["deleted"][:50]

                self.logger.info("Filesystem diff: %d new, %d modified, %d deleted",
                                 len(fs_changes["new"]), len(fs_changes["modified"]),
                                 len(fs_changes["deleted"]))

        # Step 8: Parse auditd for executed commands
        rc4, audit_out, _ = self._sandbox_ssh(
            "sudo ausearch -k sandbox_exec --format text 2>/dev/null | head -200",
            timeout=10,
        )

        # Step 9: Parse pcap for DNS queries and connections
        dns_queries = []
        connections = []
        pcap_path = results_dir / "capture.pcap"
        if pcap_path.exists() and pcap_path.stat().st_size > 0:
            # Extract DNS queries
            try:
                dns_result = subprocess.run(
                    ["tshark", "-r", str(pcap_path), "-Y", "dns.qr == 0", "-T", "fields", "-e", "dns.qry.name"],
                    capture_output=True, text=True, timeout=15,
                )
                if dns_result.returncode == 0:
                    dns_queries = list(set(dns_result.stdout.strip().splitlines()))[:50]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Extract unique destination IPs
            try:
                conn_result = subprocess.run(
                    ["tshark", "-r", str(pcap_path), "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                     "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport"],
                    capture_output=True, text=True, timeout=15,
                )
                if conn_result.returncode == 0:
                    for line in conn_result.stdout.strip().splitlines():
                        parts = line.split("\t")
                        if len(parts) == 2:
                            connections.append({"ip": parts[0], "port": parts[1]})
                    connections = connections[:50]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Extract TLS SNI (Server Name Indication) — reveals actual C2 domains
            tls_sni = []
            try:
                sni_result = subprocess.run(
                    ["tshark", "-r", str(pcap_path), "-Y", "tls.handshake.type == 1",
                     "-T", "fields", "-e", "tls.handshake.extensions_server_name",
                     "-e", "ip.dst", "-e", "tcp.dstport"],
                    capture_output=True, text=True, timeout=15,
                )
                if sni_result.returncode == 0:
                    seen_sni = set()
                    for line in sni_result.stdout.strip().splitlines():
                        parts = line.split("\t")
                        if len(parts) >= 1 and parts[0] and parts[0] not in seen_sni:
                            seen_sni.add(parts[0])
                            entry = {"sni": parts[0]}
                            if len(parts) >= 2:
                                entry["ip"] = parts[1]
                            if len(parts) >= 3:
                                entry["port"] = parts[2]
                            tls_sni.append(entry)
                    tls_sni = tls_sni[:50]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Extract HTTP requests — host + URI
            http_requests = []
            try:
                http_result = subprocess.run(
                    ["tshark", "-r", str(pcap_path), "-Y", "http.request",
                     "-T", "fields", "-e", "http.host", "-e", "http.request.uri",
                     "-e", "http.request.method", "-e", "ip.dst"],
                    capture_output=True, text=True, timeout=15,
                )
                if http_result.returncode == 0:
                    for line in http_result.stdout.strip().splitlines():
                        parts = line.split("\t")
                        if len(parts) >= 2 and parts[0]:
                            entry = {"host": parts[0], "uri": parts[1]}
                            if len(parts) >= 3:
                                entry["method"] = parts[2]
                            if len(parts) >= 4:
                                entry["ip"] = parts[3]
                            http_requests.append(entry)
                    http_requests = http_requests[:50]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Extract JA3 TLS fingerprints (requires tshark with JA3 plugin)
            ja3_fingerprints = []
            try:
                ja3_result = subprocess.run(
                    ["tshark", "-r", str(pcap_path), "-Y", "tls.handshake.type == 1",
                     "-T", "fields", "-e", "tls.handshake.ja3"],
                    capture_output=True, text=True, timeout=15,
                )
                if ja3_result.returncode == 0:
                    ja3_fingerprints = list(set(
                        h.strip() for h in ja3_result.stdout.strip().splitlines() if h.strip()
                    ))[:20]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Step 10: Memory forensics — disabled (needs LiME kernel module for proper dumps)
        # /dev/mem only gives 1MB on modern kernels, producing garbage Volatility results.
        # TODO: Install LiME on sandbox, enable when GPU available for faster analysis.

        # Step 10: Collect INetSim DNS logs — real C2 domain lookups
        inetsim_dns = []
        rc_inet, inet_log, _ = self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            "grep 'DNS.*Query' /var/log/inetsim/service.log 2>/dev/null | tail -50",
            password=self._remnux_pass, timeout=10,
        )
        if rc_inet == 0 and inet_log.strip():
            for line in inet_log.strip().splitlines():
                # INetSim log format: timestamp type src query
                if "Query" in line:
                    inetsim_dns.append(line.strip())
            if inetsim_dns:
                self.logger.info("INetSim captured %d DNS queries", len(inetsim_dns))

        # Merge INetSim DNS with pcap DNS (dedup)
        all_dns = list(set(dns_queries))
        for line in inetsim_dns:
            # Extract domain from INetSim log line
            parts = line.split()
            for p in parts:
                if '.' in p and not p[0].isdigit() and len(p) > 4 and p not in all_dns:
                    all_dns.append(p)

        # Parse auditd into process execution tree
        process_tree = self._parse_audit_process_tree(results_dir / "audit.log")

        # Parse strace log for syscall-level IOCs
        strace_results = self._parse_strace_log(results_dir / "strace.log")

        # Run volatility3 on memory dump (sends to REMnux for analysis)
        vol_results = {}
        if memdump_path.exists() and memdump_path.stat().st_size > 1048576:
            vol_results = self._run_volatility(memdump_path, sha256)

        # Assemble dynamic analysis results
        dynamic_results = {
            "detonation_duration": self.cfg.sandbox_timeout,
            "processes": ps_out[:5000] if ps_out else "",
            "network_connections": net_out[:3000] if net_out else "",
            "new_files": files_out.strip().splitlines()[:50] if files_out else [],
            "executed_commands": audit_out[:5000] if audit_out else "",
            "dns_queries": all_dns,
            "inetsim_dns_log": inetsim_dns[:30],
            "outbound_connections": self._enrich_connections(connections),
            "tls_sni": tls_sni,
            "http_requests": http_requests,
            "ja3_fingerprints": ja3_fingerprints,
            "process_tree": process_tree,
            "filesystem_changes": fs_changes,
            "strace": strace_results,
            "memory_forensics": vol_results,
            "pcap_size": pcap_path.stat().st_size if pcap_path.exists() else 0,
            "audit_log_size": (results_dir / "audit.log").stat().st_size if (results_dir / "audit.log").exists() else 0,
        }

        self.logger.info("Dynamic analysis complete for %s — %d DNS, %d connections, %d TLS SNI, %d HTTP, %d new files, %d processes",
                         sha256[:16], len(all_dns), len(connections),
                         len(tls_sni), len(http_requests),
                         len(dynamic_results["new_files"]), len(process_tree))

        # Step 11: Restore clean snapshot (cleanup)
        self._sandbox_restore_snapshot()

        return dynamic_results

    # -- Discord alerting --------------------------------------------------

    def fire_discord_alert(self, results: dict, metadata: dict):
        """Send rich Discord embed with analysis results."""
        if not self.cfg.webhook_url:
            return

        sha256 = results.get("sha256", "unknown")
        classification, severity = self._extract_classification(results)
        file_type = results.get("file_type", "unknown")
        file_size = results.get("file_size", 0)
        src_ip = metadata.get("src_ip", "")
        country = metadata.get("country", "")
        honeypot = metadata.get("honeypot", "unknown")

        # Classification icons
        class_icons = {
            "botnet": "\U0001f916", "trojan": "\U0001f434", "miner": "\u26cf\ufe0f",
            "ransomware": "\U0001f512", "backdoor": "\U0001f6aa", "worm": "\U0001f41b",
            "dropper": "\U0001f4e6", "unknown": "\u2753",
        }
        icon = class_icons.get(classification, "\u2753")

        sev_colors = {"critical": 0xED4245, "high": 0xFE8D2F, "medium": 0xFEE75C, "low": 0x57F287}
        sev_icons = {"critical": "\U0001f6a8", "high": "\u26a0\ufe0f", "medium": "\U0001f7e1", "low": "\u2139\ufe0f"}
        color = sev_colors.get(severity, 0x5865F2)
        sev_icon = sev_icons.get(severity, "")

        flags = {
            "China": "\U0001f1e8\U0001f1f3", "Russia": "\U0001f1f7\U0001f1fa",
            "United States": "\U0001f1fa\U0001f1f8", "Brazil": "\U0001f1e7\U0001f1f7",
            "India": "\U0001f1ee\U0001f1f3", "Germany": "\U0001f1e9\U0001f1ea",
            "Taiwan": "\U0001f1f9\U0001f1fc", "France": "\U0001f1eb\U0001f1f7",
            "Netherlands": "\U0001f1f3\U0001f1f1", "South Korea": "\U0001f1f0\U0001f1f7",
        }
        flag = flags.get(country, "\U0001f310")

        # Size formatting
        if file_size >= 1048576:
            size_str = f"{file_size / 1048576:.1f} MB"
        elif file_size >= 1024:
            size_str = f"{file_size / 1024:.1f} KB"
        else:
            size_str = f"{file_size} B"

        # Description — include confidence label
        confidence_label = results.get("confidence_label", "")
        if confidence_label:
            desc = f"{icon} **{confidence_label}** captured by **{honeypot.title()}**"
        else:
            desc = f"{icon} **{classification.title()}** captured by **{honeypot.title()}**"
        if src_ip:
            desc += f" from `{src_ip}` ({flag} {country or 'Unknown'})"

        # Fields
        fields = [
            {"name": "SHA256", "value": f"`{sha256}`", "inline": False},
            {"name": "File Type", "value": f"`{file_type[:100]}`", "inline": True},
            {"name": "Size", "value": f"`{size_str}`", "inline": True},
            {"name": "Severity", "value": f"{sev_icon} **{severity.upper()}**", "inline": True},
        ]

        # Attacker drop context (how the file got there)
        dl_cmd = metadata.get("download_command", "")
        if dl_cmd:
            drop_parts = [f"**Command:** `{dl_cmd[:200]}`"]
            if metadata.get("download_user"):
                drop_parts.append(f"**User:** `{metadata['download_user']}`")
            if metadata.get("download_timestamp"):
                drop_parts.append(f"**Time:** {metadata['download_timestamp']}")
            fields.append({"name": "Drop Method", "value": "\n".join(drop_parts), "inline": False})

        # YARA matches
        yara_matches = results.get("yara_matches", [])
        if yara_matches:
            yara_text = "\n".join(f"\u2022 `{m}`" for m in yara_matches[:10])
            if len(yara_matches) > 10:
                yara_text += f"\n*\u2026and {len(yara_matches) - 10} more*"
            fields.append({"name": "YARA Matches", "value": yara_text, "inline": False})

        # capa capabilities
        capa = results.get("capa_capabilities", [])
        if capa:
            capa_text = "\n".join(f"\u2022 `{c.get('name', '')}`" for c in capa[:8])
            if len(capa) > 8:
                capa_text += f"\n*\u2026and {len(capa) - 8} more*"
            fields.append({"name": "Capabilities (capa)", "value": capa_text, "inline": False})

        # LLM summary
        llm_summary = results.get("llm_summary", "")
        if llm_summary:
            # Truncate for Discord embed limit
            if len(llm_summary) > 800:
                llm_summary = llm_summary[:800] + "\u2026"
            fields.append({"name": "LLM Threat Assessment", "value": llm_summary, "inline": False})

        # VirusTotal results
        vt = results.get("virustotal", {})
        if vt:
            if vt.get("found"):
                vt_text = f"**{vt['detection_ratio']}** engines detected"
                if vt.get("suggested_label"):
                    vt_text += f"\nLabel: `{vt['suggested_label']}`"
                if vt.get("tags"):
                    vt_text += f"\nTags: {', '.join(f'`{t}`' for t in vt['tags'][:5])}"
                fields.append({"name": "VirusTotal", "value": vt_text, "inline": True})
            else:
                fields.append({"name": "VirusTotal", "value": "**Not found** (novel sample)", "inline": True})

        # MalwareBazaar status
        mb = results.get("malwarebazaar", {})
        if mb:
            if mb.get("submitted"):
                mb_text = "**Submitted** (new to MalwareBazaar)"
            elif mb.get("already_known"):
                mb_text = "Already known"
            else:
                mb_text = "Submission attempted"
            fields.append({"name": "MalwareBazaar", "value": mb_text, "inline": True})

        # Dynamic analysis results
        dyn = results.get("dynamic_analysis", {})
        if dyn:
            dyn_parts = []
            if dyn.get("dns_queries"):
                dyn_parts.append("**DNS Queries:**\n" + "\n".join(f"\u2022 `{d}`" for d in dyn["dns_queries"][:5]))
            if dyn.get("outbound_connections"):
                conn_lines = []
                for c in dyn["outbound_connections"][:5]:
                    line = f"`{c['ip']}:{c['port']}`"
                    details = []
                    if c.get("hostname"):
                        details.append(c["hostname"])
                    if c.get("country"):
                        details.append(c["country"])
                    if c.get("org"):
                        details.append(c["org"])
                    if c.get("shodan_tags"):
                        details.extend(c["shodan_tags"])
                    if details:
                        line += f" ({', '.join(details[:3])})"
                    conn_lines.append(f"\u2022 {line}")
                dyn_parts.append("**Outbound Connections:**\n" + "\n".join(conn_lines))
            if dyn.get("new_files"):
                dyn_parts.append("**Files Created:**\n" + "\n".join(f"\u2022 `{f}`" for f in dyn["new_files"][:5]))
            if dyn_parts:
                dyn_text = "\n".join(dyn_parts)
                if len(dyn_text) > 1000:
                    dyn_text = dyn_text[:1000] + "\n\u2026"
                fields.append({"name": "Dynamic Analysis (Sandbox)", "value": dyn_text, "inline": False})

        # MISP correlation
        misp = results.get("misp", {})
        if misp and misp.get("known_iocs"):
            misp_lines = []
            for ioc in misp["known_iocs"][:5]:
                misp_lines.append(f"\u2022 `{ioc['value']}` ({ioc['type']}) — seen in {ioc['events']} event(s)")
            fields.append({"name": "MISP Correlations", "value": "\n".join(misp_lines), "inline": False})

        # Memory forensics
        dyn = results.get("dynamic_analysis", {})
        mem_forensics = dyn.get("memory_forensics", {}) if dyn else {}
        if mem_forensics:
            mem_parts = []
            malfind = mem_forensics.get("malfind", "")
            if malfind:
                mem_parts.append(f"**Malfind (injected code):**\n```\n{malfind[:300]}\n```")
            hidden = mem_forensics.get("hidden_modules", "")
            if hidden:
                mem_parts.append(f"**Hidden modules:** {hidden[:200]}")
            bash = mem_forensics.get("bash_history", "")
            if bash:
                mem_parts.append(f"**Bash history:**\n```\n{bash[:200]}\n```")
            if mem_parts:
                mem_text = "\n".join(mem_parts)
                if len(mem_text) > 900:
                    mem_text = mem_text[:900] + "\n\u2026"
                fields.append({"name": "Memory Forensics (Volatility)", "value": mem_text, "inline": False})

        # Sample similarity
        similar = results.get("similar_samples", [])
        if similar:
            sim_lines = []
            for s in similar[:5]:
                sim_lines.append(f"\u2022 **{s['similarity']}%** match — `{s['sha256'][:16]}...` ({s['classification']})")
            fields.append({"name": "Similar Samples (ssdeep)", "value": "\n".join(sim_lines), "inline": False})

        # Ghidra decompilation results
        ghidra = results.get("ghidra")
        if ghidra and isinstance(ghidra, dict):
            ghidra_parts = []
            ghidra_parts.append(f"**{ghidra.get('num_functions', 0)} functions** | {ghidra.get('executable_format', '?')} | {ghidra.get('language', '?')}")
            suspicious = ghidra.get("suspicious_apis", [])
            if suspicious:
                ghidra_parts.append("**Suspicious APIs:** " + ", ".join(f"`{a}`" for a in suspicious[:8]))
            top_funcs = ghidra.get("functions", [])[:5]
            if top_funcs:
                func_list = "\n".join(f"\u2022 `{f['name']}` ({f['size']}B)" for f in top_funcs)
                ghidra_parts.append("**Largest functions:**\n" + func_list)
            ghidra_text = "\n".join(ghidra_parts)
            if len(ghidra_text) > 800:
                ghidra_text = ghidra_text[:800] + "\u2026"
            fields.append({"name": "Ghidra Decompilation", "value": ghidra_text, "inline": False})

        # Auto-generated YARA rule
        gen_yara = results.get("generated_yara_rule", "")
        if gen_yara:
            yara_display = gen_yara[:800]
            if len(gen_yara) > 800:
                yara_display += "\n..."
            fields.append({"name": "Auto-Generated YARA Rule", "value": f"```yara\n{yara_display}\n```", "inline": False})

        # Auto-Generated Sigma Rule
        gen_sigma = results.get("generated_sigma_rule", "")
        if gen_sigma:
            sigma_display = gen_sigma[:800]
            if len(gen_sigma) > 800:
                sigma_display += "\n..."
            fields.append({"name": "Auto-Generated Sigma Rule", "value": f"```yaml\n{sigma_display}\n```", "inline": False})

        # Deep analysis (two-pass decompiled code review)
        deep = results.get("deep_analysis", "")
        if deep:
            funcs_analyzed = results.get("deep_analysis_functions_analyzed", 0)
            funcs_total = results.get("deep_analysis_functions_total", 0)
            deep_header = f"Deep Code Analysis ({funcs_analyzed}/{funcs_total} functions, score={results.get('deep_analysis_score',0)})"
            deep_display = deep[:900]
            if len(deep) > 900:
                deep_display += "\n..."
            fields.append({"name": deep_header, "value": deep_display, "inline": False})

        # Confidence and warrants investigation (from evidence-based assessment)
        warrants = results.get("warrants_investigation", "")
        if warrants:
            if isinstance(warrants, list):
                warrants_text = "\n".join(f"- {w}" for w in warrants[:8])
            else:
                warrants_text = str(warrants)[:600]
            fields.append({"name": "Warrants Further Investigation", "value": warrants_text, "inline": False})

        confidence = results.get("confidence", "")
        if confidence:
            fields.append({"name": "Confidence", "value": str(confidence)[:200], "inline": True})

        # Notable strings
        interesting = results.get("interesting_strings", [])
        if interesting:
            str_text = "\n".join(f"`{s[:80]}`" for s in interesting[:5])
            fields.append({"name": "Notable Strings", "value": str_text, "inline": False})

        # Investigation links
        intel_parts = [
            f"\u2022 [VirusTotal](https://www.virustotal.com/gui/file/{sha256})",
            f"\u2022 [MalwareBazaar](https://bazaar.abuse.ch/sample/{sha256}/)",
        ]
        if src_ip:
            intel_parts.append(f"\u2022 [AbuseIPDB](https://www.abuseipdb.com/check/{src_ip})")

        if self.cfg.grafana_url:
            dash_link = f"{self.cfg.grafana_url}/d/{self.cfg.grafana_dashboard_uid}"
            intel_parts.append(f"\u2022 [Grafana Dashboard]({dash_link})")

        fields.append({"name": "Investigate", "value": "\n".join(intel_parts), "inline": False})

        payload = {
            "embeds": [{
                "title": f"{sev_icon} Malware Captured: {classification.title()}",
                "description": desc,
                "color": color,
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": f"Sample Analyzer \u2022 {sha256[:16]}"},
                "author": {"name": "Sample Analyzer \u2014 Automated Malware Analysis"},
            }]
        }

        try:
            resp = requests.post(self.cfg.webhook_url, json=payload, timeout=10)
            if resp.status_code not in (200, 204):
                self.logger.warning("Discord webhook returned %d: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            self.logger.error("Discord webhook failed: %s", e)

    # -- Cleanup -----------------------------------------------------------

    def cleanup_old_samples(self):
        """Remove old samples from REMnux inbox and local staging."""
        now = time.time()
        if now - self.last_cleanup < 86400:  # daily
            return
        self.last_cleanup = now

        days = self.cfg.sample_retention_days

        # Clean REMnux inbox
        self._ssh_cmd(
            self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
            f"find {self.cfg.remnux_inbox} -type f -mtime +{days} -delete 2>/dev/null",
            password=self._remnux_pass,
        )

        # Clean local staging
        if STAGING_DIR.exists():
            cutoff = now - (days * 86400)
            for f in STAGING_DIR.iterdir():
                if f.is_file() and f.stat().st_mtime < cutoff:
                    f.unlink()
                    self.logger.info("Cleaned up staged sample: %s", f.name[:16])

        self.logger.info("Cleanup complete (retention=%d days)", days)

    # -- Dedup check -------------------------------------------------------

    def _is_already_analyzed(self, sha256: str) -> bool:
        """Check if sample has already been analyzed."""
        if sha256 in self.known_hashes:
            return True

        # Check ES
        result = self._es_get(f"{self.cfg.result_index}/_doc/{sha256}")
        if result and result.get("found"):
            self.known_hashes.add(sha256)
            return True

        return False

    # -- Main pipeline -----------------------------------------------------

    def process_sample(self, sample_info: dict) -> bool:
        """Full pipeline for a single sample: fetch → submit → collect → index → alert."""
        sha256 = sample_info["sha256"]

        if self._is_already_analyzed(sha256):
            self.logger.debug("Skipping already-analyzed sample: %s", sha256[:16])
            return False

        # Check false positive list (by hash or filepath)
        fp = sample_info.get("filepath", "")
        if self._is_false_positive_hash(sha256) or (fp and self._is_false_positive_path(fp)):
            reason = self._false_positives.get(sha256, self._false_positives.get(fp, "unknown"))
            self.logger.info("Skipping false positive %s — %s", sha256[:16], reason)
            self.known_hashes.add(sha256)
            return False

        self.logger.info("Processing new sample: %s (from %s via %s)",
                         sha256[:16], sample_info.get("src_ip", "?"), sample_info.get("honeypot", "?"))

        if self.cfg.dry_run:
            self.logger.info("DRY RUN — would process %s", sha256[:16])
            self.known_hashes.add(sha256)
            return True

        # Step 0: Ensure REMnux is running
        if not self._ensure_remnux_running():
            self.logger.error("REMnux not available, skipping %s", sha256[:16])
            return False

        # Step 0.5: Correlate attacker session (IP + download command) for sacrificial VM samples
        if sample_info.get("honeypot") == "sacrificial-vm" and not sample_info.get("src_ip"):
            self._correlate_attacker_session(sample_info)

        # Step 1: Fetch from T-Pot
        local_path = self.fetch_sample(sha256)
        if not local_path:
            self._stop_remnux()
            return False

        # Step 1.5: Pre-screen — reject obvious non-malware before burning resources
        if not self._pre_screen_sample(sha256, local_path):
            self.known_hashes.add(sha256)
            self._stop_remnux()
            return False

        # Step 2: Submit to REMnux
        ok = self.submit_for_analysis(sha256, local_path)
        if not ok:
            self.logger.warning("Submit failed for %s — marking known to prevent retry loop", sha256[:16])
            self.known_hashes.add(sha256)
            self.save_state()
            return False

        # Step 3: Wait for and collect results
        results = self.wait_for_results(sha256)
        if not results:
            self.logger.warning("No results received for %s — marking known to prevent retry loop", sha256[:16])
            self.known_hashes.add(sha256)
            self.save_state()
            return False

        # Step 4: Dynamic analysis FIRST (so LLM sees behavioral data)
        dynamic = self.detonate_sample(sha256, local_path)
        if dynamic:
            results["dynamic_analysis"] = dynamic

        # Step 5: VirusTotal lookup
        vt_result = self.vt_lookup(sha256)
        if vt_result:
            results["virustotal"] = vt_result

        # Step 5.5: MalwareBazaar submission
        mb_result = self.mb_submit(sha256, local_path, results)
        if mb_result:
            results["malwarebazaar"] = mb_result

        # Step 6: Claude API threat analysis — now has dynamic + VT + MB data
        claude_result = self.claude_analyze(results)
        if claude_result:
            results["llm_summary"] = claude_result.get("summary", "")
            results["generated_yara_rule"] = claude_result.get("yara_rule", "")
            if claude_result.get("classification"):
                results["classification"] = claude_result["classification"]
            if claude_result.get("severity"):
                results["severity"] = claude_result["severity"]
            if claude_result.get("confidence"):
                results["confidence"] = claude_result["confidence"]
            if claude_result.get("warrants_investigation"):
                results["warrants_investigation"] = claude_result["warrants_investigation"]
            if claude_result.get("malware_family"):
                results["malware_family"] = claude_result["malware_family"]
            if claude_result.get("mitre_attack"):
                results["mitre_attack"] = claude_result["mitre_attack"]
            if claude_result.get("threat_hypothesis"):
                results["threat_hypothesis"] = claude_result["threat_hypothesis"]

        # Step 7: Deep Ghidra analysis — MCP interactive (preferred) or batch fallback
        deep = self.ghidra_mcp_analysis(sha256, results)
        if deep:
            results["deep_analysis"] = deep.get("deep_analysis", "")
            results["deep_analysis_score"] = deep.get("score", 0)
            results["deep_analysis_cost"] = deep.get("cost", 0)
            results["deep_analysis_triage"] = deep.get("triage", {})
            results["deep_analysis_functions_analyzed"] = deep.get("functions_analyzed", 0)
            results["deep_analysis_functions_total"] = deep.get("functions_total", 0)
            results["deep_analysis_mode"] = deep.get("analysis_mode", "batch")
            mode = deep.get("analysis_mode", "batch")
            mcp_info = ""
            if mode == "ghidra_mcp_interactive":
                mcp_info = f", mcp_turns={deep.get('mcp_turns', 0)}, tool_calls={deep.get('mcp_tool_calls', 0)}"
            self.logger.info("Deep analysis complete for %s — mode=%s, %d functions decompiled, score=%d, cost=$%.4f%s",
                             sha256[:16], mode, deep.get("functions_analyzed", 0),
                             deep["score"], deep["cost"], mcp_info)

        # Step 8: C2 infrastructure mapping
        c2_map = self.map_c2_infrastructure(results)
        if c2_map:
            results["c2_infrastructure"] = c2_map

        # Step 8.5: ATT&CK technique mapping
        attack_techniques = self.map_attack_techniques(results)
        if attack_techniques:
            results["attack_techniques"] = attack_techniques
            self.logger.info("Mapped %d ATT&CK techniques for %s", len(attack_techniques), sha256[:16])

        # Step 9: MISP — check known IOCs and create event
        misp_iocs = self.misp_check_iocs(results)
        if misp_iocs:
            results["misp"] = misp_iocs
        self.misp_create_event(results, sample_info)

        # Step 10: Index in Elasticsearch
        self.index_results(sha256, results, sample_info)

        # Step 10.5: Sample similarity + clustering (must be after indexing)
        similar = self.find_similar_samples(results)
        if similar:
            results["similar_samples"] = similar
            self.logger.info("Found %d similar samples for %s (top: %d%% match)",
                             len(similar), sha256[:16], similar[0]["similarity"])

        cluster = self.cluster_samples(results)
        if cluster:
            results["cluster"] = cluster

        # Step 10: Generate PDF report
        try:
            from generate_report import generate_report as gen_pdf, build_styles
            report_dir = Path(_env("REPORTS_DIR", str(ELKIE_HOME / "reports")))
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"{sha256[:16]}_report.pdf"
            gen_pdf(results, report_path, build_styles())
            self.logger.info("PDF report generated: %s", report_path)
        except Exception as e:
            self.logger.warning("PDF report generation failed: %s", e)

        # Step 10.5: Copy PCAP and strace to reports dir for web access
        try:
            report_dir = Path(_env("REPORTS_DIR", str(ELKIE_HOME / "reports")))
            dyn_dir = STAGING_DIR / f"{sha256}_dynamic"
            if dyn_dir.exists():
                pcap_src = dyn_dir / "capture.pcap"
                strace_src = dyn_dir / "strace.log"
                if pcap_src.exists():
                    import shutil
                    shutil.copy2(pcap_src, report_dir / f"{sha256[:16]}_capture.pcap")
                if strace_src.exists():
                    import shutil
                    shutil.copy2(strace_src, report_dir / f"{sha256[:16]}_strace.log")
        except Exception as e:
            self.logger.warning("Failed to copy artifacts to reports: %s", e)

        # Step 11: Generate Sigma detection rules (template + LLM behavioral)
        try:
            from generate_sigma_rules import generate_sigma_rules, save_rules
            sigma_rules = generate_sigma_rules(results)

            # LLM-generated behavioral Sigma rule
            if results.get("dynamic_analysis"):
                llm_sigma = self.claude_generate_sigma(results)
                if llm_sigma:
                    sigma_rules.append(llm_sigma)
                    results["generated_sigma_rule"] = llm_sigma

            if sigma_rules:
                save_rules(sigma_rules, sha256)
                self.logger.info("Generated %d Sigma rules for %s (%s LLM)",
                                 len(sigma_rules), sha256[:16],
                                 "incl." if results.get("generated_sigma_rule") else "no")
        except Exception as e:
            self.logger.warning("Sigma rule generation failed: %s", e)

        # Step 12: Update ATT&CK Navigator layer
        try:
            from generate_attack_navigator import generate_layer
            layer = generate_layer()
            if layer:
                layer_path = Path(_env("REPORTS_DIR", str(ELKIE_HOME / "reports"))) / "attack_navigator_layer.json"
                with open(layer_path, "w") as f:
                    json.dump(layer, f, indent=2)
        except Exception as e:
            self.logger.warning("ATT&CK Navigator update failed: %s", e)

        # Step 13: Discord alert (suppress low-confidence noise)
        conf = results.get("confidence", 0)
        classification = results.get("classification", "unknown")
        if conf < self.cfg.alert_confidence_threshold and classification == "unknown":
            self.logger.info("Suppressing alert for %s — low confidence (%d%%) and unclassified", sha256[:16], conf)
        else:
            self.fire_discord_alert(results, sample_info)

        self.known_hashes.add(sha256)
        self.logger.info("Pipeline complete for %s", sha256[:16])

        # Shut down REMnux to save resources
        self._stop_remnux()

        return True

    # -- Main loop ---------------------------------------------------------

    def run(self):
        self.logger.info("Sample Analyzer starting — polling %s every %ds",
                         self.cfg.es_url, self.cfg.poll_interval)
        self.load_state()

        # Backfill
        if self.cfg.backfill_hours > 0:
            backfill_time = datetime.now(timezone.utc) - timedelta(hours=self.cfg.backfill_hours)
            self.last_timestamp = backfill_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            self.logger.info("Backfilling from %s", self.last_timestamp)
        elif not self.last_timestamp:
            start = datetime.now(timezone.utc) - timedelta(hours=1)
            self.last_timestamp = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            self.logger.info("No saved state — starting from %s", self.last_timestamp)

        # Startup tasks
        self.ensure_es_index()
        if not self.ensure_analysis_script():
            self.logger.warning("Could not deploy analysis script — will retry on next cycle")

        consecutive_errors = 0

        while self.running:
            try:
                samples = self.poll_for_new_samples()
                processed = 0

                for sample_info in samples:
                    if not self.running:
                        break
                    try:
                        if self.process_sample(sample_info):
                            processed += 1
                    except Exception as e:
                        self.logger.error("Error processing sample %s: %s",
                                          sample_info.get("sha256", "?")[:16], e)

                if processed > 0:
                    self.logger.info("Processed %d new samples this cycle", processed)
                    consecutive_errors = 0

                self.cleanup_old_samples()
                self.check_pending_results()
                self.save_state()

            except Exception as e:
                consecutive_errors += 1
                wait = min(30 * (2 ** consecutive_errors), 300)
                self.logger.error("Poll cycle error: %s — retrying in %ds", e, wait)
                time.sleep(wait)
                continue

            time.sleep(self.cfg.poll_interval)

        self.save_state()
        self.logger.info("Sample Analyzer stopped")

    def stop(self):
        self.running = False

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> Config:
    """Parse CLI args. All values default from env vars (via Config dataclass), then CLI overrides."""
    cfg = Config()  # picks up env vars automatically
    p = argparse.ArgumentParser(description="ELKIE SOC — Automated Malware Analysis Pipeline")
    p.add_argument("--es-url", default=cfg.es_url)
    p.add_argument("--es-index", default=cfg.es_index)
    p.add_argument("--result-index", default=cfg.result_index)
    p.add_argument("--poll-interval", type=int, default=cfg.poll_interval)
    p.add_argument("--webhook-url", default=cfg.webhook_url, help="Discord webhook URL")
    p.add_argument("--log-file", default=cfg.log_file)
    p.add_argument("--grafana-url", default=cfg.grafana_url)
    p.add_argument("--grafana-dashboard-uid", default=cfg.grafana_dashboard_uid)
    p.add_argument("--backfill", type=int, default=cfg.backfill_hours, dest="backfill_hours",
                   help="Backfill N hours on startup")
    p.add_argument("--dry-run", action="store_true", default=cfg.dry_run,
                   help="Process events but skip actual analysis/alerts")
    p.add_argument("--verbosity", default=cfg.verbosity, choices=["compact", "normal", "verbose"])
    # SSH targets (override env)
    p.add_argument("--tpot-host", default=cfg.tpot_host)
    p.add_argument("--tpot-port", type=int, default=cfg.tpot_port)
    p.add_argument("--tpot-user", default=cfg.tpot_user)
    p.add_argument("--remnux-host", default=cfg.remnux_host)
    p.add_argument("--remnux-port", type=int, default=cfg.remnux_port)
    p.add_argument("--remnux-user", default=cfg.remnux_user)
    p.add_argument("--sandbox-timeout", type=int, default=cfg.sandbox_timeout)
    p.add_argument("--llm-mode", default=cfg.llm_mode, choices=["api", "local", "none"])
    # Limits
    p.add_argument("--analysis-timeout", type=int, default=cfg.analysis_timeout)
    p.add_argument("--retention-days", type=int, default=cfg.sample_retention_days)

    args = p.parse_args()

    # CLI args override the env-populated Config
    cfg.es_url = args.es_url
    cfg.es_index = args.es_index
    cfg.result_index = args.result_index
    cfg.poll_interval = args.poll_interval
    cfg.webhook_url = args.webhook_url
    cfg.log_file = args.log_file
    cfg.grafana_url = args.grafana_url
    cfg.grafana_dashboard_uid = args.grafana_dashboard_uid
    cfg.backfill_hours = args.backfill_hours
    cfg.dry_run = args.dry_run
    cfg.verbosity = args.verbosity
    cfg.tpot_host = args.tpot_host
    cfg.tpot_port = args.tpot_port
    cfg.tpot_user = args.tpot_user
    cfg.remnux_host = args.remnux_host
    cfg.remnux_port = args.remnux_port
    cfg.remnux_user = args.remnux_user
    cfg.sandbox_timeout = args.sandbox_timeout
    cfg.llm_mode = args.llm_mode
    cfg.analysis_timeout = args.analysis_timeout
    cfg.sample_retention_days = args.retention_days

    return cfg

def main():
    config = parse_args()
    analyzer = SampleAnalyzer(config)

    def handle_signal(signum, frame):
        analyzer.logger.info("Received signal %d — stopping", signum)
        analyzer.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    analyzer.run()

if __name__ == "__main__":
    main()
