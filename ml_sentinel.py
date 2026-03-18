#!/usr/bin/env python3
"""
ML Sentinel — Machine-Learning-Enhanced Threat Detection for Honeypot + Sacrificial VM

Polls Elasticsearch for events from:
  - Honeypot containers (.ds-filebeat-*)  : cowrie sessions, dionaea, heralding, etc.
  - Sacrificial VM      (sacrificial-vm-*): auditd execve, auth, network events

Builds behavioral baselines with Isolation Forest, detects anomalies,
and fires Discord webhook alerts for severe/unusual activity.

Usage:
    python3 ml_sentinel.py                     # normal mode
    python3 ml_sentinel.py --train-only        # train baseline then exit
    python3 ml_sentinel.py --dry-run           # process but skip webhooks
    python3 ml_sentinel.py --backfill 24       # backfill 24 hours on start
"""

import argparse
import json
import logging
import math
import os
import pickle
import re
import signal
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import numpy as np
import requests
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    es_url: str = "http://localhost:9200"
    honeypot_index: str = ".ds-filebeat-*"
    vm_index: str = "sacrificial-vm-*"
    poll_interval: int = 30
    window_minutes: int = 5          # sliding window for feature extraction
    baseline_hours: int = 24         # hours of data to train baseline on
    retrain_interval: int = 3600     # retrain model every N seconds
    webhook_url: Optional[str] = None
    alert_threshold: float = -0.3    # isolation forest decision threshold (more negative = more anomalous)
    severity_threshold: str = "high" # minimum severity to alert on
    log_file: str = "/home/legs/ml_sentinel.log"
    model_dir: str = "/home/legs/ml_models"
    state_file: str = "/home/legs/.ml_sentinel_state.json"
    backfill_hours: int = 0
    train_only: bool = False
    dry_run: bool = False

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Suspicious patterns for rule-based scoring (supplements ML)
# ---------------------------------------------------------------------------

SUSPICIOUS_COMMANDS = [
    (re.compile(r"wget\s+.*\|\s*(sh|bash)|curl\s+.*\|\s*(sh|bash)", re.I), "download_execute", 25),
    (re.compile(r"wget\s+http|curl\s+(-[sOfL]+\s+)*http", re.I), "download", 10),
    (re.compile(r"/etc/shadow|/etc/passwd", re.I), "credential_access", 15),
    (re.compile(r"\.ssh/authorized_keys|ssh-keygen", re.I), "persistence_ssh", 20),
    (re.compile(r"crontab|/etc/cron", re.I), "persistence_cron", 15),
    (re.compile(r"chmod\s+\+s|chmod\s+4[0-7]{3}", re.I), "priv_escalation", 20),
    (re.compile(r"history\s+-c|unset\s+HISTFILE|rm\s+.*\.bash_history", re.I), "anti_forensics", 15),
    (re.compile(r"rm\s+(-rf?\s+)?/var/log", re.I), "log_destruction", 20),
    (re.compile(r"xmrig|stratum|minergate|pool\.", re.I), "cryptomining", 25),
    (re.compile(r"iptables|ufw|firewall-cmd", re.I), "firewall_tampering", 12),
    (re.compile(r"base64\s+-d|python.*-c.*exec|perl.*-e", re.I), "encoded_exec", 15),
    (re.compile(r"\bnc\b.*-[le]|\bncat\b|/dev/tcp|mkfifo", re.I), "reverse_shell", 25),
    (re.compile(r"useradd|adduser|passwd\s", re.I), "account_creation", 20),
    (re.compile(r"systemctl\s+(stop|disable)\s+(fail2ban|ufw|iptables|apparmor)", re.I), "security_disable", 20),
    (re.compile(r"\bdd\b.*of=/dev/sd|mkfs\.", re.I), "disk_wipe", 30),
]

# Suspicious VM executables (not standard system tools)
SUSPICIOUS_EXECUTABLES = re.compile(
    r"(\./)|(tmp/.+x$)|(/dev/shm/)|(perl\s+-e)|(python.*-c)|(nc\s)|(ncat)|(socat)|"
    r"(masscan)|(nmap)|(hydra)|(john)|(hashcat)|(nikto)|(sqlmap)|(metasploit)|"
    r"(msfconsole)|(msfvenom)|(\.elf$)|(\.sh$.*tmp)",
    re.I
)

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_honeypot_window_features(events: list) -> dict:
    """Extract features from a time window of honeypot events."""
    if not events:
        return None

    containers = Counter()
    protocols = Counter()
    event_types = Counter()
    src_ips = set()
    dest_ports = Counter()
    countries = Counter()
    commands = []
    login_successes = 0
    login_failures = 0
    file_events = 0
    tunnel_requests = 0

    for e in events:
        hp = e.get("honeypot", {}) or {}
        containers[e.get("container", {}).get("id", "unknown")] += 1
        protocols[e.get("protocol", "unknown")] += 1
        src_ip = hp.get("sourceIp") or hp.get("src_ip") or e.get("src_ip", "")
        if src_ip:
            src_ips.add(src_ip)
        dp = hp.get("destinationPort") or e.get("dest_port")
        if dp:
            dest_ports[str(dp)] += 1
        geo = e.get("source", {}).get("geo", {})
        if geo.get("country_name"):
            countries[geo["country_name"]] += 1

        eid = hp.get("eventid", "")
        event_types[eid] += 1
        if eid == "cowrie.login.success":
            login_successes += 1
        elif eid == "cowrie.login.failed":
            login_failures += 1
        elif eid == "cowrie.command.input":
            cmd = hp.get("input", "")
            if cmd:
                commands.append(cmd)
        elif "file_download" in eid or "file_upload" in eid:
            file_events += 1
        elif "direct-tcpip" in eid:
            tunnel_requests += 1

    # Command threat scoring
    cmd_threat_score = 0
    cmd_categories = set()
    for cmd in commands:
        for pattern, category, pts in SUSPICIOUS_COMMANDS:
            if pattern.search(cmd):
                cmd_threat_score += pts
                cmd_categories.add(category)

    total = len(events)
    return {
        # Volume features
        "total_events": total,
        "unique_src_ips": len(src_ips),
        "unique_dest_ports": len(dest_ports),
        "unique_countries": len(countries),
        "unique_containers": len(containers),
        # Ratios
        "events_per_ip": total / max(len(src_ips), 1),
        "cowrie_ratio": containers.get("cowrie", 0) / max(total, 1),
        "heralding_ratio": containers.get("heralding", 0) / max(total, 1),
        "dionaea_ratio": containers.get("dionaea", 0) / max(total, 1),
        # Auth features
        "login_successes": login_successes,
        "login_failures": login_failures,
        "login_success_ratio": login_successes / max(login_successes + login_failures, 1),
        # Interaction depth
        "command_count": len(commands),
        "unique_commands": len(set(commands)),
        "file_events": file_events,
        "tunnel_requests": tunnel_requests,
        # Threat features
        "cmd_threat_score": cmd_threat_score,
        "cmd_threat_categories": len(cmd_categories),
        # Port diversity (entropy)
        "port_entropy": _entropy(dest_ports),
        "country_entropy": _entropy(countries),
        # Metadata for alerting (not used as ML features)
        "_commands": commands,
        "_cmd_categories": cmd_categories,
        "_top_ips": src_ips,
        "_top_countries": countries.most_common(5),
        "_top_ports": dest_ports.most_common(5),
        "_containers": dict(containers),
    }


def extract_vm_window_features(events: list) -> dict:
    """Extract features from a time window of sacrificial VM auditd events."""
    if not events:
        return None

    actions = Counter()
    executables = Counter()
    command_lines = []
    users = Counter()
    suspicious_procs = 0
    network_events = 0

    for e in events:
        action = e.get("event", {}).get("action", "")
        if action:
            actions[action] += 1

        proc = e.get("process", {}) or {}
        exe = proc.get("executable", "")
        cmdline = proc.get("command_line", "")

        if exe:
            executables[exe] += 1
        if cmdline:
            command_lines.append(cmdline)
            if SUSPICIOUS_EXECUTABLES.search(cmdline):
                suspicious_procs += 1

        user = e.get("user", {})
        if isinstance(user, dict):
            eff = user.get("effective", {})
            if isinstance(eff, dict) and eff.get("name"):
                users[eff["name"]] += 1

        net = e.get("network", {})
        if isinstance(net, dict) and net.get("direction"):
            network_events += 1

    # Command threat scoring for VM
    vm_threat_score = 0
    vm_categories = set()
    for cmd in command_lines:
        for pattern, category, pts in SUSPICIOUS_COMMANDS:
            if pattern.search(cmd):
                vm_threat_score += pts
                vm_categories.add(category)

    total = len(events)
    execve_count = actions.get("execve", 0)

    return {
        "vm_total_events": total,
        "vm_execve_count": execve_count,
        "vm_unique_executables": len(executables),
        "vm_unique_users": len(users),
        "vm_suspicious_procs": suspicious_procs,
        "vm_network_events": network_events,
        "vm_auth_events": actions.get("authenticated", 0) + actions.get("logged-in", 0),
        "vm_execve_ratio": execve_count / max(total, 1),
        "vm_threat_score": vm_threat_score,
        "vm_threat_categories": len(vm_categories),
        "vm_executable_entropy": _entropy(executables),
        # Metadata
        "_vm_commands": command_lines[:50],
        "_vm_categories": vm_categories,
        "_vm_top_executables": executables.most_common(10),
        "_vm_actions": dict(actions),
    }


def _entropy(counter: Counter) -> float:
    """Shannon entropy of a counter."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    probs = [c / total for c in counter.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


# ML feature vector keys (must be stable for model compatibility)
HP_FEATURE_KEYS = [
    "total_events", "unique_src_ips", "unique_dest_ports", "unique_countries",
    "unique_containers", "events_per_ip", "cowrie_ratio", "heralding_ratio",
    "dionaea_ratio", "login_successes", "login_failures", "login_success_ratio",
    "command_count", "unique_commands", "file_events", "tunnel_requests",
    "cmd_threat_score", "cmd_threat_categories", "port_entropy", "country_entropy",
]

VM_FEATURE_KEYS = [
    "vm_total_events", "vm_execve_count", "vm_unique_executables", "vm_unique_users",
    "vm_suspicious_procs", "vm_network_events", "vm_auth_events", "vm_execve_ratio",
    "vm_threat_score", "vm_threat_categories", "vm_executable_entropy",
]

ALL_FEATURE_KEYS = HP_FEATURE_KEYS + VM_FEATURE_KEYS


def features_to_vector(hp_features: dict, vm_features: dict) -> np.ndarray:
    """Convert feature dicts to a numeric vector for ML."""
    vec = []
    for k in HP_FEATURE_KEYS:
        vec.append(hp_features.get(k, 0) if hp_features else 0)
    for k in VM_FEATURE_KEYS:
        vec.append(vm_features.get(k, 0) if vm_features else 0)
    return np.array(vec, dtype=np.float64)


# ---------------------------------------------------------------------------
# ML Model
# ---------------------------------------------------------------------------

class ThreatDetector:
    """Isolation Forest based anomaly detector for honeypot + VM activity."""

    def __init__(self, model_dir: str):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.trained_at: Optional[datetime] = None
        self.training_stats: dict = {}

    def _model_path(self) -> Path:
        return self.model_dir / "isolation_forest.pkl"

    def _scaler_path(self) -> Path:
        return self.model_dir / "scaler.pkl"

    def _stats_path(self) -> Path:
        return self.model_dir / "training_stats.json"

    def save(self):
        with open(self._model_path(), "wb") as f:
            pickle.dump(self.model, f)
        with open(self._scaler_path(), "wb") as f:
            pickle.dump(self.scaler, f)
        with open(self._stats_path(), "w") as f:
            json.dump(self.training_stats, f, indent=2, default=str)

    def load(self) -> bool:
        try:
            with open(self._model_path(), "rb") as f:
                self.model = pickle.load(f)
            with open(self._scaler_path(), "rb") as f:
                self.scaler = pickle.load(f)
            with open(self._stats_path()) as f:
                self.training_stats = json.load(f)
            self.trained_at = datetime.fromisoformat(self.training_stats.get("trained_at", ""))
            return True
        except Exception:
            return False

    def train(self, feature_vectors: list[np.ndarray]):
        """Train the isolation forest on historical feature vectors."""
        X = np.array(feature_vectors)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,   # expect ~5% of windows to be anomalous
            max_features=0.8,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.trained_at = datetime.now(timezone.utc)

        # Compute baseline stats for interpretability
        scores = self.model.decision_function(X_scaled)
        self.training_stats = {
            "trained_at": self.trained_at.isoformat(),
            "n_samples": len(feature_vectors),
            "n_features": X.shape[1],
            "feature_keys": ALL_FEATURE_KEYS,
            "score_mean": float(np.mean(scores)),
            "score_std": float(np.std(scores)),
            "score_min": float(np.min(scores)),
            "score_p5": float(np.percentile(scores, 5)),
            "feature_means": {k: float(v) for k, v in zip(ALL_FEATURE_KEYS, np.mean(X, axis=0))},
            "feature_stds": {k: float(v) for k, v in zip(ALL_FEATURE_KEYS, np.std(X, axis=0))},
        }

    def score(self, feature_vector: np.ndarray) -> float:
        """Return anomaly score. More negative = more anomalous."""
        if self.model is None or self.scaler is None:
            return 0.0
        X = self.scaler.transform(feature_vector.reshape(1, -1))
        return float(self.model.decision_function(X)[0])

    def get_feature_contributions(self, feature_vector: np.ndarray) -> list[tuple[str, float]]:
        """Identify which features deviate most from baseline (z-scores)."""
        if not self.training_stats.get("feature_means"):
            return []
        contributions = []
        means = self.training_stats["feature_means"]
        stds = self.training_stats["feature_stds"]
        for i, key in enumerate(ALL_FEATURE_KEYS):
            mean = means.get(key, 0)
            std = stds.get(key, 1)
            if std > 0:
                z = (feature_vector[i] - mean) / std
            else:
                z = 0
            contributions.append((key, float(z)))
        # Sort by absolute z-score descending
        contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        return contributions


# ---------------------------------------------------------------------------
# Main Sentinel
# ---------------------------------------------------------------------------

class MLSentinel:

    def __init__(self, config: Config):
        self.cfg = config
        self.detector = ThreatDetector(config.model_dir)
        self.last_hp_timestamp: Optional[str] = None
        self.last_vm_timestamp: Optional[str] = None
        self.last_train_time: float = 0
        self.running = True
        self.alert_cooldown: dict = {}  # ip -> last alert time
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("ml_sentinel")
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        fh = RotatingFileHandler(self.cfg.log_file, maxBytes=10_000_000, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)
        return logger

    # -- state persistence --------------------------------------------------

    def save_state(self):
        state = {
            "last_hp_timestamp": self.last_hp_timestamp,
            "last_vm_timestamp": self.last_vm_timestamp,
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
            self.last_hp_timestamp = state.get("last_hp_timestamp")
            self.last_vm_timestamp = state.get("last_vm_timestamp")
            self.logger.info("Restored state — HP from %s, VM from %s",
                             self.last_hp_timestamp, self.last_vm_timestamp)
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning("Failed to load state: %s", e)

    # -- elasticsearch queries ----------------------------------------------

    def _query_es(self, index: str, query: dict, size: int = 1000) -> list:
        """Fetch documents from ES."""
        body = {
            "size": size,
            "sort": [{"@timestamp": "asc"}],
            "query": query,
        }
        try:
            resp = requests.post(
                f"{self.cfg.es_url}/{index}/_search",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("hits", {}).get("hits", [])
        except Exception as e:
            self.logger.error("ES query failed on %s: %s", index, e)
            return []

    def fetch_honeypot_window(self, from_ts: str, to_ts: str) -> list:
        """Fetch honeypot events in a time window."""
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": from_ts, "lt": to_ts}}},
                ],
                "must_not": [
                    {"term": {"container.id": "suricata"}},
                    {"prefix": {"src_ip": "192.168."}},
                ]
            }
        }
        hits = self._query_es(self.cfg.honeypot_index, query, size=5000)
        return [h["_source"] for h in hits]

    def fetch_vm_window(self, from_ts: str, to_ts: str) -> list:
        """Fetch sacrificial VM events in a time window."""
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": from_ts, "lt": to_ts}}},
                    {"term": {"event.action.keyword": "execve"}},
                ]
            }
        }
        hits = self._query_es(self.cfg.vm_index, query, size=5000)
        return [h["_source"] for h in hits]

    # -- training -----------------------------------------------------------

    def train_baseline(self):
        """Train the isolation forest on historical data."""
        self.logger.info("Training ML baseline on last %d hours of data...", self.cfg.baseline_hours)

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=self.cfg.baseline_hours)
        window = timedelta(minutes=self.cfg.window_minutes)

        feature_vectors = []
        current = start
        windows_processed = 0

        while current + window <= now:
            from_ts = current.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            to_ts = (current + window).strftime("%Y-%m-%dT%H:%M:%S.000Z")

            hp_events = self.fetch_honeypot_window(from_ts, to_ts)
            vm_events = self.fetch_vm_window(from_ts, to_ts)

            hp_features = extract_honeypot_window_features(hp_events)
            vm_features = extract_vm_window_features(vm_events)

            vec = features_to_vector(hp_features, vm_features)
            feature_vectors.append(vec)

            windows_processed += 1
            current += window

            if windows_processed % 50 == 0:
                self.logger.info("  Processed %d windows (%d vectors)...",
                                 windows_processed, len(feature_vectors))

        if len(feature_vectors) < 10:
            self.logger.warning("Not enough data for training (%d windows). Need at least 10.",
                                len(feature_vectors))
            return False

        self.detector.train(feature_vectors)
        self.detector.save()
        self.last_train_time = time.time()

        stats = self.detector.training_stats
        self.logger.info(
            "Model trained: %d samples, score range [%.3f, %.3f], mean=%.3f",
            stats["n_samples"], stats["score_min"], stats["score_mean"] + 2 * stats["score_std"],
            stats["score_mean"]
        )
        return True

    # -- gridpot event detection ---------------------------------------------

    def fetch_gridpot_events(self, from_ts: str, to_ts: str) -> list:
        """Fetch GridPot ICS honeypot events."""
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": from_ts, "lt": to_ts}}},
                    {"term": {"container.id": "gridpot"}},
                ]
            }
        }
        hits = self._query_es(self.cfg.honeypot_index, query, size=500)
        return [h["_source"] for h in hits]

    def _check_gridpot_events(self, events: list):
        """Check gridpot events for high-severity actions and fire instant alerts."""
        for e in events:
            hp = e.get("honeypot", {}).get("honeypot", {}) or e.get("honeypot", {})
            eventid = hp.get("eventid", "")
            src_ip = e.get("src_ip", "unknown")
            ts = e.get("@timestamp", "")

            # Skip internal/docker IPs
            if src_ip.startswith("172.") or src_ip.startswith("192.168."):
                continue

            # Cooldown: don't spam same IP + event combo within 5 min
            cooldown_key = f"gp:{src_ip}:{eventid}"
            if cooldown_key in self.alert_cooldown:
                if time.time() - self.alert_cooldown[cooldown_key] < 300:
                    continue

            if "breaker_control" in eventid or "modbus_write" in eventid:
                self.alert_cooldown[cooldown_key] = time.time()
                self._fire_gridpot_alert("critical", "ICS BREAKER OPERATION", src_ip, ts, hp, e)

            elif "hmi_document_access" in eventid:
                self.alert_cooldown[cooldown_key] = time.time()
                self._fire_gridpot_alert("high", "SCADA DOCUMENT EXFILTRATION", src_ip, ts, hp, e)

            elif "hmi_login" in eventid:
                success = hp.get("success", False)
                if success:
                    self.alert_cooldown[cooldown_key] = time.time()
                    self._fire_gridpot_alert("high", "HMI LOGIN SUCCESS", src_ip, ts, hp, e)

            elif "dnp3_control" in eventid or "dnp3_restart" in eventid:
                self.alert_cooldown[cooldown_key] = time.time()
                self._fire_gridpot_alert("critical", "DNP3 CONTROL COMMAND", src_ip, ts, hp, e)

    # -- real-time detection ------------------------------------------------

    def detect(self):
        """Run one detection cycle on the current time window."""
        now = datetime.now(timezone.utc)
        window = timedelta(minutes=self.cfg.window_minutes)
        from_ts = (now - window).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        to_ts = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # GridPot instant alerts (checked every cycle regardless of ML)
        gp_events = self.fetch_gridpot_events(from_ts, to_ts)
        if gp_events:
            self._check_gridpot_events(gp_events)

        hp_events = self.fetch_honeypot_window(from_ts, to_ts)
        vm_events = self.fetch_vm_window(from_ts, to_ts)

        if not hp_events and not vm_events:
            return

        hp_features = extract_honeypot_window_features(hp_events)
        vm_features = extract_vm_window_features(vm_events)
        vec = features_to_vector(hp_features, vm_features)

        # ML anomaly score
        anomaly_score = self.detector.score(vec)

        # Rule-based threat score
        rule_score = 0
        if hp_features:
            rule_score += hp_features.get("cmd_threat_score", 0)
        if vm_features:
            rule_score += vm_features.get("vm_threat_score", 0)

        # Combined severity
        severity = self._compute_severity(anomaly_score, rule_score, hp_features, vm_features)

        if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(self.cfg.severity_threshold, 2):
            contributions = self.detector.get_feature_contributions(vec)
            self._fire_alert(
                severity=severity,
                anomaly_score=anomaly_score,
                rule_score=rule_score,
                hp_features=hp_features,
                vm_features=vm_features,
                contributions=contributions,
                window_start=from_ts,
                window_end=to_ts,
            )

        # Log summary
        hp_count = len(hp_events)
        vm_count = len(vm_events)
        gp_count = len(gp_events)
        self.logger.info(
            "Window %s: hp=%d vm=%d gp=%d anomaly=%.3f rules=%d severity=%s",
            from_ts[:19], hp_count, vm_count, gp_count, anomaly_score, rule_score, severity
        )

    def _compute_severity(self, anomaly_score: float, rule_score: int,
                          hp_features: Optional[dict], vm_features: Optional[dict]) -> str:
        """Combine ML anomaly score with rule-based scoring into a severity level."""
        # Start from rule-based severity
        if rule_score >= 50:
            base_severity = 3  # critical
        elif rule_score >= 25:
            base_severity = 2  # high
        elif rule_score >= 10:
            base_severity = 1  # medium
        else:
            base_severity = 0  # low

        # ML anomaly boost: very anomalous windows get bumped up
        if anomaly_score < -0.5:
            base_severity = max(base_severity, 3)  # critical anomaly
        elif anomaly_score < -0.3:
            base_severity = max(base_severity, 2)  # high anomaly
        elif anomaly_score < -0.15:
            base_severity = max(base_severity, 1)  # medium anomaly

        # Additional signals
        if hp_features:
            if hp_features.get("tunnel_requests", 0) > 0:
                base_severity = max(base_severity, 2)
            if hp_features.get("file_events", 0) > 0:
                base_severity = max(base_severity, 2)
            if hp_features.get("login_successes", 0) > 3:
                base_severity = max(base_severity, 2)

        if vm_features:
            if vm_features.get("vm_suspicious_procs", 0) > 3:
                base_severity = max(base_severity, 2)
            if vm_features.get("vm_auth_events", 0) > 5:
                base_severity = max(base_severity, 1)

        severity_names = {0: "low", 1: "medium", 2: "high", 3: "critical"}
        return severity_names.get(min(base_severity, 3), "low")

    # -- alerting -----------------------------------------------------------

    def _send_webhook(self, payload: dict):
        """Send a Discord webhook payload."""
        if self.cfg.dry_run or not self.cfg.webhook_url:
            return
        try:
            resp = requests.post(self.cfg.webhook_url, json=payload, timeout=10)
            if resp.status_code not in (200, 204):
                self.logger.warning("Webhook returned %d: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            self.logger.error("Webhook failed: %s", e)

    def _fire_gridpot_alert(self, severity: str, title: str, src_ip: str,
                            timestamp: str, hp_data: dict, raw_event: dict):
        """Fire an instant GridPot ICS alert with a clean embed."""
        self.logger.info("GRIDPOT ALERT [%s] %s from %s", severity.upper(), title, src_ip)
        if self.cfg.dry_run or not self.cfg.webhook_url:
            return

        color_map = {"critical": 0xED4245, "high": 0xFE8D2F, "medium": 0xFEE75C, "low": 0x57F287}
        icon_map = {"critical": "\U0001f6a8", "high": "\u26a0\ufe0f", "medium": "\U0001f7e1", "low": "\u2139\ufe0f"}
        color = color_map.get(severity, 0x5865F2)
        icon = icon_map.get(severity, "")

        eventid = hp_data.get("eventid", "")
        protocol = raw_event.get("protocol", "")

        # Build clean description
        desc_parts = []
        if "breaker" in eventid or "modbus_write" in eventid:
            breaker = hp_data.get("breaker", hp_data.get("action", ""))
            action = hp_data.get("action", "WRITE")
            desc_parts.append(f"An attacker **operated a circuit breaker** via {protocol.upper()}.")
            if breaker:
                desc_parts.append(f"Breaker: `{breaker}` | Action: `{action}`")
        elif "document" in eventid:
            filename = hp_data.get("filename", "unknown")
            desc_parts.append(f"An attacker **downloaded a sensitive document** from the SCADA HMI.")
            desc_parts.append(f"File: `{filename}`")
        elif "login" in eventid:
            user = hp_data.get("username", "?")
            pwd = hp_data.get("password", "?")
            desc_parts.append(f"An attacker **successfully authenticated** to the SCADA HMI.")
            desc_parts.append(f"Credentials: `{user}` / `{pwd}`")
        elif "dnp3" in eventid:
            fc = hp_data.get("function_code", "?")
            desc_parts.append(f"An attacker **sent a DNP3 control command** to the outstation.")
            desc_parts.append(f"Function Code: `{fc}`")

        description = "\n".join(desc_parts)

        fields = [
            {"name": "Source IP", "value": f"`{src_ip}`", "inline": True},
            {"name": "Protocol", "value": f"`{protocol.upper()}`", "inline": True},
            {"name": "Target", "value": "`SCADA-SRV-01`", "inline": True},
        ]

        if hp_data.get("user_agent"):
            fields.append({"name": "User Agent", "value": f"```{hp_data['user_agent'][:120]}```", "inline": False})

        payload = {
            "embeds": [{
                "title": f"{icon} {title}",
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": "GridPot ICS Honeypot  \u2022  Tri-State Regional Power Cooperative"},
                "author": {"name": "ML Sentinel  \u2014  ICS Threat Detection"},
            }]
        }
        self._send_webhook(payload)

    def _fire_alert(self, severity: str, anomaly_score: float, rule_score: int,
                    hp_features: Optional[dict], vm_features: Optional[dict],
                    contributions: list, window_start: str, window_end: str):
        """Format and send a clean ML anomaly/threat Discord alert."""
        self.logger.info(
            "ALERT [%s] anomaly=%.3f rules=%d window=%s",
            severity.upper(), anomaly_score, rule_score, window_start[:19]
        )

        if self.cfg.dry_run or not self.cfg.webhook_url:
            return

        color_map = {"critical": 0xED4245, "high": 0xFE8D2F, "medium": 0xFEE75C, "low": 0x57F287}
        icon_map = {"critical": "\U0001f6a8", "high": "\u26a0\ufe0f", "medium": "\U0001f7e1", "low": "\u2139\ufe0f"}
        color = color_map.get(severity, 0x5865F2)
        icon = icon_map.get(severity, "")

        is_anomaly = anomaly_score < self.cfg.alert_threshold
        label = "Behavioral Anomaly" if is_anomaly else "Threat Activity"

        # Build clean description
        desc_lines = [f"ML analysis detected **{label.lower()}** across the honeypot network."]
        if contributions:
            top = [(k, z) for k, z in contributions[:3] if abs(z) > 1.0]
            if top:
                factors = ", ".join(f"`{k}` ({z:+.1f}\u03c3)" for k, z in top)
                desc_lines.append(f"Key deviations: {factors}")
        description = "\n".join(desc_lines)

        # Compact metrics row
        fields = [
            {"name": "Anomaly Score", "value": f"`{anomaly_score:+.3f}`", "inline": True},
            {"name": "Threat Score", "value": f"`{rule_score}`", "inline": True},
            {"name": "Window", "value": f"`{window_start[11:19]} UTC`", "inline": True},
        ]

        # Honeypot summary — compact
        if hp_features:
            lines = []
            lines.append(f"\u2022 **{hp_features['total_events']:,}** events from **{hp_features['unique_src_ips']}** IPs across **{hp_features['unique_countries']}** countries")
            if hp_features['login_successes'] or hp_features['login_failures']:
                lines.append(f"\u2022 Auth: **{hp_features['login_successes']}** success / **{hp_features['login_failures']}** failed")
            if hp_features['command_count']:
                lines.append(f"\u2022 Commands: **{hp_features['command_count']}** ({hp_features['unique_commands']} unique)")
            if hp_features['file_events']:
                lines.append(f"\u2022 File transfers: **{hp_features['file_events']}**")
            if hp_features['tunnel_requests']:
                lines.append(f"\u2022 Tunnel requests: **{hp_features['tunnel_requests']}**")
            fields.append({"name": "Honeypot Network", "value": "\n".join(lines), "inline": False})

            if hp_features.get("_commands"):
                cmds = hp_features["_commands"][:8]
                cmd_text = "\n".join(cmds)
                if len(cmd_text) > 500:
                    cmd_text = cmd_text[:500] + "\n\u2026"
                fields.append({"name": "Captured Commands", "value": f"```bash\n{cmd_text}\n```", "inline": False})

            if hp_features.get("_top_countries"):
                flags = {"United States": "\U0001f1fa\U0001f1f8", "China": "\U0001f1e8\U0001f1f3", "Russia": "\U0001f1f7\U0001f1fa",
                         "Brazil": "\U0001f1e7\U0001f1f7", "India": "\U0001f1ee\U0001f1f3", "Germany": "\U0001f1e9\U0001f1ea",
                         "France": "\U0001f1eb\U0001f1f7", "Netherlands": "\U0001f1f3\U0001f1f1", "South Korea": "\U0001f1f0\U0001f1f7",
                         "Japan": "\U0001f1ef\U0001f1f5", "United Kingdom": "\U0001f1ec\U0001f1e7", "Taiwan": "\U0001f1f9\U0001f1fc"}
                countries = "  ".join(f"{flags.get(c, '\U0001f310')} {c} ({n:,})" for c, n in hp_features["_top_countries"][:4])
                fields.append({"name": "Top Origins", "value": countries, "inline": False})

        # VM summary — compact
        if vm_features and vm_features.get("vm_total_events", 0) > 0:
            vm_lines = []
            vm_lines.append(f"\u2022 **{vm_features['vm_execve_count']:,}** process executions, **{vm_features['vm_unique_executables']}** unique binaries")
            if vm_features['vm_suspicious_procs']:
                vm_lines.append(f"\u2022 **{vm_features['vm_suspicious_procs']}** suspicious processes detected")
            if vm_features['vm_network_events']:
                vm_lines.append(f"\u2022 **{vm_features['vm_network_events']}** network events")
            fields.append({"name": "Sacrificial VM", "value": "\n".join(vm_lines), "inline": False})

        payload = {
            "embeds": [{
                "title": f"{icon} {severity.upper()}: {label}",
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": "ML Sentinel  \u2022  Isolation Forest Anomaly Detection"},
                "author": {"name": "ML Sentinel  \u2014  Honeypot Threat Intelligence"},
            }]
        }
        self._send_webhook(payload)

    # -- main loop ----------------------------------------------------------

    def run(self):
        self.logger.info("ML Sentinel starting — polling %s every %ds",
                         self.cfg.es_url, self.cfg.poll_interval)
        self.load_state()

        # Load or train model
        if self.detector.load():
            self.logger.info("Loaded existing model (trained at %s, %d samples)",
                             self.detector.training_stats.get("trained_at"),
                             self.detector.training_stats.get("n_samples", 0))
            self.last_train_time = time.time()
        else:
            self.logger.info("No existing model found — training baseline...")
            if not self.train_baseline():
                self.logger.error("Training failed. Will retry after collecting more data.")

        if self.cfg.train_only:
            self.logger.info("Train-only mode — exiting.")
            return

        consecutive_errors = 0

        while self.running:
            try:
                self.detect()
                consecutive_errors = 0

                # Periodic retraining
                if time.time() - self.last_train_time > self.cfg.retrain_interval:
                    self.logger.info("Retraining model (periodic)...")
                    self.train_baseline()

                self.save_state()

            except Exception as e:
                consecutive_errors += 1
                wait = min(30 * (2 ** consecutive_errors), 300)
                self.logger.error("Detection cycle error: %s — retrying in %ds", e, wait)
                time.sleep(wait)
                continue

            time.sleep(self.cfg.poll_interval)

        self.logger.info("ML Sentinel stopped")

    def stop(self):
        self.running = False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> Config:
    p = argparse.ArgumentParser(description="ML Sentinel — ML-Enhanced Honeypot Threat Detection")
    p.add_argument("--es-url", default="http://localhost:9200")
    p.add_argument("--honeypot-index", default=".ds-filebeat-*")
    p.add_argument("--vm-index", default="sacrificial-vm-*")
    p.add_argument("--poll-interval", type=int, default=30)
    p.add_argument("--window-minutes", type=int, default=5)
    p.add_argument("--baseline-hours", type=int, default=24)
    p.add_argument("--retrain-interval", type=int, default=3600)
    p.add_argument("--webhook-url", default=None)
    p.add_argument("--alert-threshold", type=float, default=-0.3)
    p.add_argument("--severity-threshold", default="high", choices=["low", "medium", "high", "critical"])
    p.add_argument("--log-file", default="/home/legs/ml_sentinel.log")
    p.add_argument("--model-dir", default="/home/legs/ml_models")
    p.add_argument("--backfill", type=int, default=0, dest="backfill_hours")
    p.add_argument("--train-only", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    return Config(
        es_url=args.es_url,
        honeypot_index=args.honeypot_index,
        vm_index=args.vm_index,
        poll_interval=args.poll_interval,
        window_minutes=args.window_minutes,
        baseline_hours=args.baseline_hours,
        retrain_interval=args.retrain_interval,
        webhook_url=args.webhook_url,
        alert_threshold=args.alert_threshold,
        severity_threshold=args.severity_threshold,
        log_file=args.log_file,
        model_dir=args.model_dir,
        backfill_hours=args.backfill_hours,
        train_only=args.train_only,
        dry_run=args.dry_run,
    )


def main():
    config = parse_args()
    sentinel = MLSentinel(config)

    def handle_signal(signum, frame):
        sentinel.logger.info("Received signal %d — stopping", signum)
        sentinel.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    sentinel.run()


if __name__ == "__main__":
    main()
