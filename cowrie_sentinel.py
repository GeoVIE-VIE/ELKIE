#!/usr/bin/env python3
"""
Cowrie Sentinel — Honeypot Session Intelligence Daemon

Polls Elasticsearch for Cowrie honeypot events, reconstructs sessions,
scores attacker behavior, extracts IOCs, and alerts on high-value sessions.
"""

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    es_url: str = "http://localhost:9200"
    es_index: str = ".ds-filebeat-8.19.8-*"
    poll_interval: int = 30
    session_timeout: int = 900          # 15 min
    webhook_url: Optional[str] = None
    alert_threshold: str = "high"       # low / medium / high / critical
    log_file: str = "/home/legs/cowrie_sentinel.log"
    output_dir: str = "/home/legs/sentinel_alerts"
    state_file: str = "/home/legs/.sentinel_state.json"
    grafana_url: Optional[str] = "https://192.168.50.3:3000"
    grafana_auth: Optional[str] = None  # Basic auth header value
    grafana_dashboard_uid: Optional[str] = "tpot-attack-overview"
    backfill_hours: int = 0
    dry_run: bool = False
    verbosity: str = "normal"              # compact / normal / verbose

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

HIGH_VALUE_PATTERNS = [
    # (regex, category, points)
    (r"/etc/shadow", "credential_access", 15),
    (r"/etc/passwd", "credential_access", 10),
    (r"\.ssh/authorized_keys", "persistence", 15),
    (r"ssh-keygen", "persistence", 15),
    (r"crontab|/etc/cron", "persistence", 15),
    (r"systemctl\s+enable", "persistence", 12),
    (r"\.bashrc|\.profile|\.bash_profile", "persistence", 10),
    (r"wget\s+.*\|\s*(sh|bash)|curl\s+.*\|\s*(sh|bash)", "download_execute", 20),
    (r"wget\s+http|curl\s+(-[sOfL]+\s+)*http", "download", 10),
    (r"tftp\s|scp\s", "file_transfer", 10),
    (r"\bsudo\b|su\s+-", "privilege_escalation", 10),
    (r"chmod\s+\+s|chmod\s+4[0-7]{3}", "privilege_escalation", 15),
    (r"history\s+-c|unset\s+HISTFILE", "anti_forensics", 12),
    (r"rm\s+(-rf?\s+)?/var/log", "anti_forensics", 15),
    (r"\bnc\b|\bncat\b|/dev/tcp", "lateral_movement", 12),
    (r"\bssh\s+\S+@", "lateral_movement", 12),
    (r"xmrig|stratum|minergate|pool\.", "cryptomining", 20),
    (r"iptables|ufw|firewall-cmd", "firewall_tampering", 12),
    (r"setenforce\s+0|getenforce", "security_disable", 12),
    (r"base64\s+-d|python.*-c.*exec|perl.*-e", "encoded_execution", 12),
]

# Pre-compile
HIGH_VALUE_RE = [(re.compile(p, re.IGNORECASE), cat, pts) for p, cat, pts in HIGH_VALUE_PATTERNS]

URL_RE = re.compile(r"https?://[^\s'\";<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|cc|tk|ml|ga|cf|pw|biz|co)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class Session:
    session_id: str
    src_ip: str
    first_seen: str = ""
    last_seen: str = ""
    state: str = "CONNECTING"           # CONNECTING / AUTHENTICATING / ACTIVE / CLOSED / TIMED_OUT
    login_attempts: list = field(default_factory=list)
    commands: list = field(default_factory=list)
    files: list = field(default_factory=list)
    tunnel_requests: list = field(default_factory=list)
    country: Optional[str] = None
    score: int = 0
    classification: str = "unknown"
    alerted_at_level: Optional[str] = None
    client_version: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0
        try:
            t0 = datetime.fromisoformat(self.first_seen.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(self.last_seen.replace("Z", "+00:00"))
            return max((t1 - t0).total_seconds(), 0)
        except Exception:
            return 0

    @property
    def login_succeeded(self) -> bool:
        return any(a.get("success") for a in self.login_attempts)

# ---------------------------------------------------------------------------
# Main daemon class
# ---------------------------------------------------------------------------

class CowrieSentinel:

    def __init__(self, config: Config):
        self.cfg = config
        self.sessions: dict[str, Session] = {}      # key = (session_id, src_ip)
        self.alerted_sessions: set[str] = set()      # keep for 24h dedup
        self.last_timestamp: Optional[str] = None
        self.last_sort_values: Optional[list] = None
        self.running = True
        self.logger = self._setup_logging()
        self._ensure_output_dir()

    # -- logging -----------------------------------------------------------

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("cowrie_sentinel")
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

        fh = RotatingFileHandler(self.cfg.log_file, maxBytes=10_000_000, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

        return logger

    def _ensure_output_dir(self):
        Path(self.cfg.output_dir).mkdir(parents=True, exist_ok=True)

    # -- state persistence -------------------------------------------------

    def save_state(self):
        state = {
            "last_timestamp": self.last_timestamp,
            "last_sort_values": self.last_sort_values,
            "alerted_sessions": list(self.alerted_sessions)[-500:],
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
            self.last_sort_values = state.get("last_sort_values")
            self.alerted_sessions = set(state.get("alerted_sessions", []))
            self.logger.info("Restored state — resuming from %s", self.last_timestamp)
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning("Failed to load state: %s", e)

    # -- elasticsearch polling ---------------------------------------------

    def poll(self) -> int:
        """Fetch new cowrie events from ES. Returns count of events processed."""
        query = {
            "size": 500,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "honeypot.eventid"}},
                        {"prefix": {"honeypot.eventid": "cowrie."}},
                    ]
                }
            },
            "_source": ["@timestamp", "src_ip", "honeypot", "source"],
        }

        if self.last_timestamp:
            query["query"]["bool"]["must"].append(
                {"range": {"@timestamp": {"gt": self.last_timestamp}}}
            )

        if self.last_sort_values:
            query["search_after"] = self.last_sort_values

        total = 0
        while True:
            try:
                resp = requests.post(
                    f"{self.cfg.es_url}/{self.cfg.es_index}/_search",
                    json=query,
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                self.logger.error("ES poll failed: %s", e)
                break

            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                break

            for hit in hits:
                src = hit["_source"]
                self._process_event(src)
                total += 1

            last_hit = hits[-1]
            self.last_sort_values = last_hit.get("sort")
            self.last_timestamp = last_hit["_source"].get("@timestamp", self.last_timestamp)

            if len(hits) < 500:
                break

            query["search_after"] = self.last_sort_values

        return total

    # -- event processing --------------------------------------------------

    def _session_key(self, session_id: str, src_ip: str) -> str:
        return f"{session_id}:{src_ip}"

    def _get_or_create_session(self, session_id: str, src_ip: str, timestamp: str) -> Session:
        key = self._session_key(session_id, src_ip)
        if key not in self.sessions:
            self.sessions[key] = Session(session_id=session_id, src_ip=src_ip, first_seen=timestamp)
        sess = self.sessions[key]
        sess.last_seen = timestamp
        return sess

    def _process_event(self, src: dict):
        # honeypot fields come back as nested dict: {"honeypot": {"eventid": ..., "session": ...}}
        hp = src.get("honeypot", {}) if isinstance(src.get("honeypot"), dict) else {}
        eventid = hp.get("eventid", "")
        session_id = hp.get("session", "")
        src_ip = hp.get("src_ip", "") or src.get("src_ip", "")
        ts = src.get("@timestamp", "")

        if not session_id or not src_ip or not eventid:
            return

        sess = self._get_or_create_session(session_id, src_ip, ts)

        # Extract geo info from nested source.geo
        geo_src = src.get("source", {})
        if isinstance(geo_src, dict):
            geo = geo_src.get("geo", {})
            if isinstance(geo, dict) and geo.get("country_name"):
                sess.country = geo["country_name"]

        if eventid == "cowrie.session.connect":
            sess.state = "CONNECTING"
            if hp.get("version"):
                sess.client_version = hp["version"]

        elif eventid == "cowrie.client.version":
            if hp.get("version"):
                sess.client_version = hp["version"]

        elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
            sess.state = "AUTHENTICATING"
            username = hp.get("username", "")
            password = hp.get("password", "")
            success = eventid == "cowrie.login.success"
            sess.login_attempts.append({
                "username": username, "password": password, "success": success
            })
            if success:
                sess.state = "ACTIVE"

        elif eventid == "cowrie.command.input":
            sess.state = "ACTIVE"
            cmd = hp.get("input", "")
            if cmd:
                sess.commands.append(cmd)

        elif eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            direction = "download" if "download" in eventid else "upload"
            sess.files.append({
                "url": hp.get("url", ""),
                "sha256": hp.get("shasum", ""),
                "outfile": hp.get("outfile", ""),
                "direction": direction,
            })

        elif eventid == "cowrie.direct-tcpip.request":
            sess.tunnel_requests.append({
                "dest_ip": hp.get("destip", ""),
                "dest_port": hp.get("destport", ""),
            })

        elif eventid == "cowrie.session.closed":
            sess.state = "CLOSED"
            self._finalize_session(sess)

    # -- scoring -----------------------------------------------------------

    def _score_session(self, sess: Session) -> tuple[int, dict]:
        score = 0
        breakdown = {}

        # Auth scoring
        successes = sum(1 for a in sess.login_attempts if a.get("success"))
        failures = len(sess.login_attempts) - successes
        if successes > 0:
            score += 5
            breakdown["login_success"] = 5
        if failures > 10:
            score += 2
            breakdown["brute_force"] = 2
        if failures > 50:
            score += 3
            breakdown["aggressive_brute"] = 3

        # Command scoring
        if sess.commands:
            score += 10
            breakdown["commands_present"] = 10
        if len(sess.commands) > 5:
            score += 5
            breakdown["sustained_interaction"] = 5
        if len(sess.commands) > 20:
            score += 10
            breakdown["extended_recon"] = 10

        # High-value command patterns
        hv_total = 0
        for cmd in sess.commands:
            for pattern, category, pts in HIGH_VALUE_RE:
                if pattern.search(cmd):
                    hv_total += pts
        if hv_total:
            score += hv_total
            breakdown["high_value_commands"] = hv_total

        # Tunneling
        if sess.tunnel_requests:
            score += 20
            breakdown["tunnel_requests"] = 20

        # File transfers
        downloads = sum(1 for f in sess.files if f.get("direction") == "download")
        uploads = sum(1 for f in sess.files if f.get("direction") == "upload")
        if downloads:
            score += 15
            breakdown["file_downloads"] = 15
        if uploads:
            score += 10
            breakdown["file_uploads"] = 10

        # Duration
        dur = sess.duration_seconds
        if dur > 300:
            score += 10
            breakdown["long_session"] = 10
        elif dur > 60:
            score += 5
            breakdown["medium_session"] = 5

        # Credential diversity (stuffing signal)
        unique_creds = len(set((a["username"], a["password"]) for a in sess.login_attempts))
        if unique_creds > 5:
            score += 3
            breakdown["credential_diversity"] = 3

        sess.score = score
        return score, breakdown

    def _classify_session(self, sess: Session) -> str:
        has_commands = len(sess.commands) > 0
        has_success = sess.login_succeeded
        has_hv = any(
            pattern.search(cmd)
            for cmd in sess.commands
            for pattern, _, _ in HIGH_VALUE_RE
        )
        has_files = len(sess.files) > 0
        has_tunnels = len(sess.tunnel_requests) > 0

        if has_commands and (has_hv or has_files or has_tunnels):
            return "advanced_threat"
        if has_commands and has_success:
            return "interactive_attacker"
        if has_success and not has_commands:
            return "credential_stuffer"
        if len(sess.login_attempts) > 0 and not has_success:
            return "brute_forcer"
        return "scanner"

    def _get_severity(self, score: int) -> str:
        if score >= 40:
            return "critical"
        if score >= 25:
            return "high"
        if score >= 10:
            return "medium"
        return "low"

    # -- IOC extraction ----------------------------------------------------

    def _extract_iocs(self, sess: Session) -> dict:
        iocs = {
            "credentials": [],
            "urls": [],
            "ips": set(),
            "domains": set(),
            "file_hashes": [],
            "commands": list(sess.commands),
        }

        # Credentials
        seen_creds = set()
        for a in sess.login_attempts:
            pair = (a.get("username", ""), a.get("password", ""))
            if pair not in seen_creds:
                seen_creds.add(pair)
                iocs["credentials"].append({"username": pair[0], "password": pair[1], "success": a.get("success", False)})

        # From commands
        all_cmd_text = "\n".join(sess.commands)
        iocs["urls"] = list(set(URL_RE.findall(all_cmd_text)))
        found_ips = set(IP_RE.findall(all_cmd_text))
        # Exclude the attacker's own IP and common ones
        found_ips.discard(sess.src_ip)
        found_ips -= {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
        iocs["ips"] = list(found_ips)
        iocs["domains"] = list(set(DOMAIN_RE.findall(all_cmd_text)))

        # From file events
        for f in sess.files:
            if f.get("sha256"):
                iocs["file_hashes"].append(f["sha256"])
            if f.get("url"):
                iocs["urls"].append(f["url"])
                for m in DOMAIN_RE.findall(f["url"]):
                    iocs["domains"].append(m)

        iocs["urls"] = list(set(iocs["urls"]))
        iocs["domains"] = list(set(iocs["domains"]))

        return iocs

    def _check_high_value_commands(self, commands: list) -> list:
        hits = []
        seen = set()
        for cmd in commands:
            for pattern, category, pts in HIGH_VALUE_RE:
                if pattern.search(cmd):
                    key = (cmd, category)
                    if key not in seen:
                        seen.add(key)
                        hits.append({"command": cmd, "category": category, "points": pts})
        return hits

    # -- alerting ----------------------------------------------------------

    def _finalize_session(self, sess: Session):
        _, breakdown = self._score_session(sess)
        sess.classification = self._classify_session(sess)
        severity = self._get_severity(sess.score)
        self._evaluate_alert(sess, severity, breakdown)

    def _evaluate_alert(self, sess: Session, severity: str, breakdown: dict = None):
        threshold = SEVERITY_ORDER.get(self.cfg.alert_threshold, 2)
        sev_level = SEVERITY_ORDER.get(severity, 0)

        if sev_level < threshold:
            return

        # Dedup: don't re-alert at same or lower level
        if sess.alerted_at_level:
            prev_level = SEVERITY_ORDER.get(sess.alerted_at_level, 0)
            if sev_level <= prev_level:
                return

        key = self._session_key(sess.session_id, sess.src_ip)
        if key in self.alerted_sessions and not sess.alerted_at_level:
            return

        sess.alerted_at_level = severity
        self.alerted_sessions.add(key)

        alert = self._format_alert(sess, severity, breakdown)
        self._emit_alert(alert, sess)

    def _format_alert(self, sess: Session, severity: str, breakdown: dict = None) -> dict:
        hv_cmds = self._check_high_value_commands(sess.commands)
        iocs = self._extract_iocs(sess)

        dur = sess.duration_seconds
        if dur >= 3600:
            dur_str = f"{int(dur // 3600)}h {int((dur % 3600) // 60)}m"
        elif dur >= 60:
            dur_str = f"{int(dur // 60)}m {int(dur % 60)}s"
        else:
            dur_str = f"{int(dur)}s"

        return {
            "alert_id": f"sentinel-{sess.session_id}-{int(time.time())}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "classification": sess.classification,
            "score": sess.score,
            "session": {
                "id": sess.session_id,
                "src_ip": sess.src_ip,
                "country": sess.country,
                "first_seen": sess.first_seen,
                "last_seen": sess.last_seen,
                "duration": dur_str,
                "duration_seconds": dur,
                "client_version": sess.client_version,
            },
            "auth": {
                "attempts": len(sess.login_attempts),
                "successful": sess.login_succeeded,
                "credentials": iocs["credentials"],
            },
            "activity": {
                "commands": sess.commands,
                "command_count": len(sess.commands),
                "high_value_commands": hv_cmds,
                "files": sess.files,
                "tunnel_requests": sess.tunnel_requests,
            },
            "iocs": {
                "credentials": [(c["username"], c["password"]) for c in iocs["credentials"]],
                "urls": iocs["urls"],
                "ips": iocs["ips"],
                "domains": iocs["domains"],
                "file_hashes": iocs["file_hashes"],
            },
            "score_breakdown": breakdown or {},
        }

    def _emit_alert(self, alert: dict, sess: Session):
        severity = alert["severity"]
        classification = alert["classification"]
        src_ip = alert["session"]["src_ip"]
        country = alert["session"]["country"] or "Unknown"

        self.logger.info(
            "ALERT [%s] %s — %s (%s) score=%d cmds=%d duration=%s",
            severity.upper(), classification, src_ip, country,
            alert["score"], alert["activity"]["command_count"],
            alert["session"]["duration"],
        )

        # Write JSON file
        out_path = Path(self.cfg.output_dir) / f"{sess.session_id}.json"
        try:
            with open(out_path, "w") as f:
                json.dump(alert, f, indent=2, default=str)
            self.logger.info("Alert written to %s", out_path)
        except Exception as e:
            self.logger.error("Failed to write alert file: %s", e)

        if self.cfg.dry_run:
            self.logger.info("DRY RUN — skipping webhook and annotations")
            return

        # Webhook (Discord format)
        if self.cfg.webhook_url:
            self._post_webhook(alert)

        # Grafana annotation
        if self.cfg.grafana_url and self.cfg.grafana_auth:
            self._post_grafana_annotation(alert)

    def _post_webhook(self, alert: dict):
        severity = alert["severity"]
        src_ip = alert["session"]["src_ip"]
        country = alert["session"]["country"] or "Unknown"
        classification = alert["classification"].replace("_", " ").title()
        score = alert["score"]
        duration = alert["session"]["duration"]
        client_ver = alert["session"].get("client_version", "")
        alert_id = alert["alert_id"]
        verbosity = self.cfg.verbosity

        color_map = {"critical": 0xED4245, "high": 0xFE8D2F, "medium": 0xFEE75C, "low": 0x57F287}
        icon_map = {"critical": "\U0001f6a8", "high": "\u26a0\ufe0f", "medium": "\U0001f7e1", "low": "\u2139\ufe0f"}
        color = color_map.get(severity, 0x5865F2)
        icon = icon_map.get(severity, "")

        flags = {"China": "\U0001f1e8\U0001f1f3", "Russia": "\U0001f1f7\U0001f1fa", "United States": "\U0001f1fa\U0001f1f8",
                 "Brazil": "\U0001f1e7\U0001f1f7", "India": "\U0001f1ee\U0001f1f3", "Germany": "\U0001f1e9\U0001f1ea",
                 "Taiwan": "\U0001f1f9\U0001f1fc", "France": "\U0001f1eb\U0001f1f7", "Netherlands": "\U0001f1f3\U0001f1f1",
                 "South Korea": "\U0001f1f0\U0001f1f7", "United Kingdom": "\U0001f1ec\U0001f1e7", "Japan": "\U0001f1ef\U0001f1f5"}
        flag = flags.get(country, "\U0001f310")

        # Description
        desc_lines = [f"**{classification}** detected from `{src_ip}` ({flag} {country})."]
        if client_ver:
            desc_lines.append(f"Client: `{client_ver}`")
        description = "\n".join(desc_lines)

        # --- Compact mode: minimal phone-friendly embed ---
        if verbosity == "compact":
            fields = [
                {"name": "Threat Score", "value": f"`{score}`", "inline": True},
                {"name": "Duration", "value": f"`{duration}`", "inline": True},
                {"name": "Auth Attempts", "value": f"`{alert['auth']['attempts']}`", "inline": True},
            ]
            payload = {
                "embeds": [{
                    "title": f"{icon} {severity.upper()}: {classification}",
                    "description": description,
                    "color": color,
                    "fields": fields,
                    "timestamp": alert["timestamp"],
                    "footer": {"text": f"Cowrie Sentinel  \u2022  {alert_id}"},
                    "author": {"name": "Cowrie Sentinel  \u2014  SSH Honeypot Intelligence"},
                }]
            }
            self._send_webhook_payload(payload)
            return

        # --- Normal + Verbose modes ---
        cred_limit = 8 if verbosity == "normal" else None
        cmd_limit = 15 if verbosity == "normal" else None
        cmd_char_limit = 800 if verbosity == "normal" else 1800

        fields = [
            {"name": "Threat Score", "value": f"`{score}`", "inline": True},
            {"name": "Duration", "value": f"`{duration}`", "inline": True},
            {"name": "Auth Attempts", "value": f"`{alert['auth']['attempts']}`", "inline": True},
        ]

        # Credentials
        if alert["auth"]["credentials"]:
            creds = alert["auth"]["credentials"][:cred_limit] if cred_limit else alert["auth"]["credentials"]
            lines = []
            for c in creds:
                mark = "\u2705" if c.get("success") else "\u274c"
                lines.append(f"{mark} `{c['username']}:{c['password']}`")
            if cred_limit and len(alert["auth"]["credentials"]) > cred_limit:
                lines.append(f"*\u2026and {len(alert['auth']['credentials']) - cred_limit} more*")
            fields.append({"name": "Credentials Tried", "value": "\n".join(lines), "inline": False})

        # Commands
        if alert["activity"]["commands"]:
            cmds = alert["activity"]["commands"][:cmd_limit] if cmd_limit else alert["activity"]["commands"]
            cmd_text = "\n".join(cmds)
            if len(cmd_text) > cmd_char_limit:
                cmd_text = cmd_text[:cmd_char_limit] + "\n\u2026"
            fields.append({"name": "Commands Executed", "value": f"```bash\n{cmd_text}\n```", "inline": False})

        # Threat categories
        if alert["activity"]["high_value_commands"]:
            cats = set(h["category"].replace("_", " ").title() for h in alert["activity"]["high_value_commands"])
            fields.append({"name": "Threat Categories", "value": "  ".join(f"`{c}`" for c in cats), "inline": False})

        # File transfers (normal + verbose)
        if alert["activity"]["files"]:
            file_lines = []
            for f in alert["activity"]["files"]:
                direction = f.get("direction", "?").upper()
                url = f.get("url", "")
                sha = f.get("sha256", "")
                line = f"\u2022 **{direction}**"
                if url:
                    line += f" `{url}`"
                if sha:
                    line += f"\n  SHA256: `{sha}`"
                file_lines.append(line)
            fields.append({"name": "File Transfers", "value": "\n".join(file_lines), "inline": False})

        # Tunnel destinations (normal + verbose)
        if alert["activity"]["tunnel_requests"]:
            tun_lines = [f"\u2022 `{t['dest_ip']}:{t['dest_port']}`" for t in alert["activity"]["tunnel_requests"]]
            fields.append({"name": "Tunnel Destinations", "value": "\n".join(tun_lines), "inline": False})

        # IOCs — full hashes in normal+, extracted IPs
        ioc_parts = []
        if alert["iocs"]["urls"]:
            url_limit = 3 if verbosity == "normal" else None
            urls = alert["iocs"]["urls"][:url_limit] if url_limit else alert["iocs"]["urls"]
            ioc_parts.extend(f"\u2022 `{u}`" for u in urls)
        if alert["iocs"]["file_hashes"]:
            hash_limit = 3 if verbosity == "normal" else None
            hashes = alert["iocs"]["file_hashes"][:hash_limit] if hash_limit else alert["iocs"]["file_hashes"]
            ioc_parts.extend(f"\u2022 SHA256: `{h}`" for h in hashes)
        if alert["iocs"]["domains"]:
            dom_limit = 3 if verbosity == "normal" else None
            doms = alert["iocs"]["domains"][:dom_limit] if dom_limit else alert["iocs"]["domains"]
            ioc_parts.extend(f"\u2022 `{d}`" for d in doms)
        if alert["iocs"]["ips"]:
            ip_limit = 3 if verbosity == "normal" else None
            ips = alert["iocs"]["ips"][:ip_limit] if ip_limit else alert["iocs"]["ips"]
            ioc_parts.extend(f"\u2022 IP: `{ip}`" for ip in ips)
        if ioc_parts:
            fields.append({"name": "Indicators of Compromise", "value": "\n".join(ioc_parts), "inline": False})

        # --- Verbose-only fields ---
        if verbosity == "verbose":
            # Score breakdown
            breakdown = alert.get("score_breakdown", {})
            if breakdown:
                bd_lines = [f"`{k}`: **{v}** pts" for k, v in sorted(breakdown.items(), key=lambda x: -x[1])]
                fields.append({"name": "Score Breakdown", "value": "\n".join(bd_lines), "inline": False})

            # Session timeline
            fields.append({
                "name": "Session Timeline",
                "value": f"First seen: `{alert['session']['first_seen']}`\nLast seen: `{alert['session']['last_seen']}`\nDuration: `{alert['session']['duration']}` ({alert['session']['duration_seconds']:.0f}s)",
                "inline": False,
            })

            # Threat intel links
            intel_lines = [f"\u2022 [AbuseIPDB](https://www.abuseipdb.com/check/{src_ip}) | [Shodan](https://www.shodan.io/host/{src_ip})"]
            for ip in (alert["iocs"]["ips"] or [])[:3]:
                intel_lines.append(f"\u2022 `{ip}`: [AbuseIPDB](https://www.abuseipdb.com/check/{ip}) | [Shodan](https://www.shodan.io/host/{ip})")
            fields.append({"name": "Threat Intel", "value": "\n".join(intel_lines), "inline": False})

        # Grafana links: dashboard overview + Explore raw logs
        if self.cfg.grafana_url:
            first_seen = alert["session"].get("first_seen", "")
            last_seen = alert["session"].get("last_seen", "")
            time_params = ""
            try:
                from_ms = int(datetime.fromisoformat(first_seen.replace("Z", "+00:00")).timestamp() * 1000) - 300000
                to_ms = int(datetime.fromisoformat(last_seen.replace("Z", "+00:00")).timestamp() * 1000) + 300000
                time_params = f"&from={from_ms}&to={to_ms}"
            except Exception:
                pass

            links = []
            if self.cfg.grafana_dashboard_uid:
                dash_link = f"{self.cfg.grafana_url}/d/{self.cfg.grafana_dashboard_uid}?var-src_ip={src_ip}{time_params}"
                links.append(f"[Dashboard]({dash_link})")

            # Explore link: raw honeypot logs for this IP
            import urllib.parse
            explore_query = f"src_ip:{src_ip} OR honeypot.src_ip:{src_ip}"
            explore_params = urllib.parse.quote(json.dumps({
                "datasource": "ffffy3uxl7ri8b",
                "queries": [{"refId": "A", "query": explore_query, "timeField": "@timestamp",
                             "metrics": [{"id": "1", "type": "logs", "settings": {"limit": 200}}]}],
                "range": {"from": str(from_ms) if time_params else "now-1h", "to": str(to_ms) if time_params else "now"}
            }))
            explore_link = f"{self.cfg.grafana_url}/explore?orgId=1&left={explore_params}"
            links.append(f"[Raw Logs]({explore_link})")

            # Explore link: sacrificial VM auditd for this session window
            vm_explore_params = urllib.parse.quote(json.dumps({
                "datasource": "efffzddwcadq8e",
                "queries": [{"refId": "A", "query": "service.type:auditd AND event.action:execve", "timeField": "@timestamp",
                             "metrics": [{"id": "1", "type": "logs", "settings": {"limit": 200}}]}],
                "range": {"from": str(from_ms) if time_params else "now-1h", "to": str(to_ms) if time_params else "now"}
            }))
            vm_link = f"{self.cfg.grafana_url}/explore?orgId=1&left={vm_explore_params}"
            links.append(f"[VM Auditd]({vm_link})")

            fields.append({"name": "Investigate", "value": " | ".join(links), "inline": False})

        payload = {
            "embeds": [{
                "title": f"{icon} {severity.upper()}: {classification}",
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": alert["timestamp"],
                "footer": {"text": f"Cowrie Sentinel  \u2022  {alert_id}"},
                "author": {"name": "Cowrie Sentinel  \u2014  SSH Honeypot Intelligence"},
            }]
        }
        self._send_webhook_payload(payload)

    def _send_webhook_payload(self, payload: dict):
        try:
            resp = requests.post(self.cfg.webhook_url, json=payload, timeout=10)
            if resp.status_code not in (200, 204):
                self.logger.warning("Webhook returned %d: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            self.logger.error("Webhook failed: %s", e)

    def _post_grafana_annotation(self, alert: dict):
        severity = alert["severity"]
        classification = alert["classification"]
        src_ip = alert["session"]["src_ip"]
        score = alert["score"]
        cmd_count = alert["activity"]["command_count"]

        ts_ms = int(
            datetime.fromisoformat(alert["session"]["first_seen"].replace("Z", "+00:00")).timestamp() * 1000
        )

        text = f"{severity.upper()}: {classification} from {src_ip} — score {score}, {cmd_count} commands"
        if alert["activity"]["high_value_commands"]:
            cats = ", ".join(set(h["category"] for h in alert["activity"]["high_value_commands"]))
            text += f" [{cats}]"

        payload = {
            "dashboardUID": self.cfg.grafana_dashboard_uid,
            "time": ts_ms,
            "tags": ["cowrie", severity, classification],
            "text": text,
        }

        try:
            resp = requests.post(
                f"{self.cfg.grafana_url}/api/annotations",
                json=payload,
                headers={"Authorization": f"Basic {self.cfg.grafana_auth}"},
                timeout=10,
                verify=False,
            )
            if resp.status_code not in (200, 201):
                self.logger.warning("Grafana annotation returned %d: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            self.logger.error("Grafana annotation failed: %s", e)

    # -- session reaping ---------------------------------------------------

    def _reap_stale_sessions(self):
        now = datetime.now(timezone.utc)
        timeout = timedelta(seconds=self.cfg.session_timeout)
        stale_keys = []

        for key, sess in self.sessions.items():
            if sess.state in ("CLOSED", "TIMED_OUT"):
                stale_keys.append(key)
                continue
            try:
                last = datetime.fromisoformat(sess.last_seen.replace("Z", "+00:00"))
                if now - last > timeout:
                    sess.state = "TIMED_OUT"
                    self._finalize_session(sess)
                    stale_keys.append(key)
            except Exception:
                stale_keys.append(key)

        for key in stale_keys:
            self.sessions.pop(key, None)

    # -- main loop ---------------------------------------------------------

    def run(self):
        self.logger.info("Cowrie Sentinel starting — polling %s every %ds", self.cfg.es_url, self.cfg.poll_interval)
        self.load_state()

        if self.cfg.backfill_hours > 0:
            backfill_time = datetime.now(timezone.utc) - timedelta(hours=self.cfg.backfill_hours)
            self.last_timestamp = backfill_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            self.last_sort_values = None
            self.logger.info("Backfilling from %s", self.last_timestamp)
        elif not self.last_timestamp:
            # Default: start from 1 hour ago
            start = datetime.now(timezone.utc) - timedelta(hours=1)
            self.last_timestamp = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            self.logger.info("No saved state — starting from %s", self.last_timestamp)

        consecutive_errors = 0

        while self.running:
            try:
                count = self.poll()
                if count > 0:
                    self.logger.info("Processed %d events (%d active sessions)", count, len(self.sessions))
                    consecutive_errors = 0

                self._reap_stale_sessions()
                self.save_state()

            except Exception as e:
                consecutive_errors += 1
                wait = min(30 * (2 ** consecutive_errors), 300)
                self.logger.error("Poll cycle error: %s — retrying in %ds", e, wait)
                time.sleep(wait)
                continue

            time.sleep(self.cfg.poll_interval)

        # Shutdown: finalize remaining sessions
        self.logger.info("Shutting down — finalizing %d active sessions", len(self.sessions))
        for sess in list(self.sessions.values()):
            if sess.state not in ("CLOSED", "TIMED_OUT"):
                self._finalize_session(sess)
        self.save_state()
        self.logger.info("Cowrie Sentinel stopped")

    def stop(self):
        self.running = False

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> Config:
    p = argparse.ArgumentParser(description="Cowrie Sentinel — Honeypot Session Intelligence")
    p.add_argument("--es-url", default="http://localhost:9200")
    p.add_argument("--es-index", default=".ds-filebeat-8.19.8-*")
    p.add_argument("--poll-interval", type=int, default=30)
    p.add_argument("--session-timeout", type=int, default=900)
    p.add_argument("--webhook-url", default=None, help="Discord/Slack webhook URL")
    p.add_argument("--alert-threshold", default="high", choices=["low", "medium", "high", "critical"])
    p.add_argument("--log-file", default="/home/legs/cowrie_sentinel.log")
    p.add_argument("--output-dir", default="/home/legs/sentinel_alerts")
    p.add_argument("--grafana-url", default="https://192.168.50.3:3000")
    p.add_argument("--grafana-auth", default=None, help="Base64 user:pass for Grafana API")
    p.add_argument("--grafana-dashboard-uid", default="tpot-attack-overview")
    p.add_argument("--backfill", type=int, default=0, dest="backfill_hours", help="Backfill N hours on startup")
    p.add_argument("--dry-run", action="store_true", help="Process events but skip webhooks")
    p.add_argument("--verbosity", default="normal", choices=["compact", "normal", "verbose"],
                   help="Webhook detail level: compact (phone), normal, verbose (full)")
    args = p.parse_args()

    return Config(
        es_url=args.es_url,
        es_index=args.es_index,
        poll_interval=args.poll_interval,
        session_timeout=args.session_timeout,
        webhook_url=args.webhook_url,
        alert_threshold=args.alert_threshold,
        log_file=args.log_file,
        output_dir=args.output_dir,
        grafana_url=args.grafana_url,
        grafana_auth=args.grafana_auth,
        grafana_dashboard_uid=args.grafana_dashboard_uid,
        backfill_hours=args.backfill_hours,
        dry_run=args.dry_run,
        verbosity=args.verbosity,
    )

def main():
    config = parse_args()
    sentinel = CowrieSentinel(config)

    def handle_signal(signum, frame):
        sentinel.logger.info("Received signal %d — stopping", signum)
        sentinel.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    sentinel.run()

if __name__ == "__main__":
    main()
