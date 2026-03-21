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

@dataclass
class Config:
    es_url: str = "http://localhost:9200"
    es_index: str = ".ds-filebeat-8.19.8-*"
    result_index: str = "malware-analysis"
    poll_interval: int = 60
    webhook_url: Optional[str] = None
    log_file: str = "/home/legs/sample_analyzer.log"
    state_file: str = "/home/legs/.sample_analyzer_state.json"
    grafana_url: Optional[str] = "https://192.168.50.3:3000"
    grafana_dashboard_uid: Optional[str] = "tpot-attack-overview"
    dry_run: bool = False
    backfill_hours: int = 0
    verbosity: str = "normal"
    # T-Pot SSH
    tpot_host: str = "192.168.40.3"
    tpot_port: int = 64295
    tpot_user: str = "lepots"
    # REMnux SSH
    remnux_host: str = "192.168.40.5"
    remnux_port: int = 22
    remnux_user: str = "nalyzer"
    remnux_inbox: str = "/home/nalyzer/inbox"
    remnux_results: str = "/home/nalyzer/results"
    remnux_script: str = "/home/nalyzer/analyze_sample.sh"
    remnux_vmid: int = 106
    remnux_auto_start: bool = True       # auto-start/stop REMnux VM
    # Sandbox (dynamic analysis)
    sandbox_host: str = "192.168.40.6"
    sandbox_port: int = 22
    sandbox_user: str = "dettony"
    sandbox_vmid: int = 109
    sandbox_snapshot: str = "clean"
    sandbox_enabled: bool = True
    sandbox_timeout: int = 90          # detonation duration in seconds
    pve_api_url: str = "https://192.168.99.160:8006"
    pve_token_id: str = ""
    pve_token_secret: str = ""
    # MISP
    misp_url: str = "https://localhost"
    misp_api_key: str = ""
    # Limits
    sample_retention_days: int = 30
    analysis_timeout: int = 300
    max_sample_size: int = 52428800  # 50MB

STAGING_DIR = Path("/home/legs/sample_staging")
ANALYSIS_SCRIPT_LOCAL = Path("/home/legs/analyze_sample.sh")

# Sample directories on T-Pot (inside /data)
TPOT_SAMPLE_DIRS = [
    "/home/lepots/tpotce/data/cowrie/downloads",
    "/home/lepots/tpotce/data/dionaea/binaries",
    "/home/lepots/tpotce/data/honeytrap/downloads",
    "/home/lepots/tpotce/data/adbhoney/downloads",
]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Main daemon class
# ---------------------------------------------------------------------------

class SampleAnalyzer:

    def __init__(self, config: Config):
        self.cfg = config
        self.known_hashes: set = set()
        self.last_timestamp: Optional[str] = None
        self.last_dir_scan: float = 0
        self.last_cleanup: float = 0
        self.running = True
        self.logger = self._setup_logging()
        self._tpot_pass = os.environ.get("TPOT_PASS", "")
        self._remnux_pass = os.environ.get("REMNUX_PASS", "")
        self._vt_api_key = os.environ.get("VT_API_KEY", "")
        self._mb_api_key = os.environ.get("MB_API_KEY", "")
        self._pve_token_id = os.environ.get("PVE_TOKEN_ID", self.cfg.pve_token_id)
        self._pve_token_secret = os.environ.get("PVE_TOKEN_SECRET", self.cfg.pve_token_secret)
        if os.environ.get("PVE_API_URL"):
            self.cfg.pve_api_url = os.environ["PVE_API_URL"]
        if os.environ.get("SANDBOX_HOST"):
            self.cfg.sandbox_host = os.environ["SANDBOX_HOST"]
        if os.environ.get("SANDBOX_USER"):
            self.cfg.sandbox_user = os.environ["SANDBOX_USER"]
        if os.environ.get("SANDBOX_VMID"):
            self.cfg.sandbox_vmid = int(os.environ["SANDBOX_VMID"])
        if os.environ.get("SANDBOX_SNAPSHOT"):
            self.cfg.sandbox_snapshot = os.environ["SANDBOX_SNAPSHOT"]
        if os.environ.get("MISP_URL"):
            self.cfg.misp_url = os.environ["MISP_URL"]
        self._misp_api_key = os.environ.get("MISP_API_KEY", self.cfg.misp_api_key)

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

    # -- SSH/SCP helpers ---------------------------------------------------

    def _ssh_cmd(self, host: str, port: int, user: str, cmd: str,
                 password: str = "", timeout: int = 60) -> tuple[int, str, str]:
        """Execute command on remote host via SSH. Returns (returncode, stdout, stderr)."""
        ssh_args = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=no",
            "-p", str(port),
            f"{user}@{host}",
            cmd,
        ]
        try:
            result = subprocess.run(
                ssh_args, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.logger.warning("SSH command timed out after %ds: %s@%s: %s", timeout, user, host, cmd[:80])
            return -1, "", "timeout"
        except Exception as e:
            self.logger.error("SSH command failed: %s", e)
            return -1, "", str(e)

    def _scp_from(self, host: str, port: int, user: str, password: str,
                  remote_path: str, local_path: str, timeout: int = 120) -> bool:
        """Copy file from remote host to local path."""
        scp_args = [
            "sshpass", "-p", password,
            "scp", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-P", str(port),
            f"{user}@{host}:{remote_path}",
            local_path,
        ]
        try:
            result = subprocess.run(scp_args, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.logger.warning("SCP download timed out: %s:%s", host, remote_path)
            return False
        except Exception as e:
            self.logger.error("SCP download failed: %s", e)
            return False

    def _scp_to(self, host: str, port: int, user: str, password: str,
                local_path: str, remote_path: str, timeout: int = 120) -> bool:
        """Copy file from local path to remote host."""
        scp_args = [
            "sshpass", "-p", password,
            "scp", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-P", str(port),
            local_path,
            f"{user}@{host}:{remote_path}",
        ]
        try:
            result = subprocess.run(scp_args, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.logger.warning("SCP upload timed out: %s -> %s:%s", local_path, host, remote_path)
            return False
        except Exception as e:
            self.logger.error("SCP upload failed: %s", e)
            return False

    # -- Elasticsearch helpers ---------------------------------------------

    def _es_get(self, path: str) -> Optional[dict]:
        try:
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

        # ES query for file events
        es_samples = self._poll_es_for_files()
        samples.extend(es_samples)

        # Periodic directory scan as fallback (every 5 minutes)
        now = time.time()
        if now - self.last_dir_scan > 300:
            dir_samples = self._scan_tpot_dirs()
            samples.extend(dir_samples)
            self.last_dir_scan = now

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
                f"find {sample_dir} -type f -exec sha256sum {{}} \\; 2>/dev/null | grep '^{sha256}' | head -1",
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

        self.logger.warning("Sample %s not found on T-Pot", sha256[:16])
        return None

    def _ensure_remnux_running(self) -> bool:
        """Start REMnux VM if not running, wait for SSH."""
        if not self.cfg.remnux_auto_start or not self._pve_token_id:
            return True

        node = "flexiserve"
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

        node = "flexiserve"
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

            time.sleep(15)

        self.logger.warning("Timed out waiting for results after %ds: %s", max_wait, sha256[:16])
        return None

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
        }

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
        """Extract classification and severity from LLM summary or YARA matches."""
        classification = "unknown"
        severity = "medium"

        llm_summary = (results.get("llm_summary") or "").lower()
        yara_matches = [m.lower() for m in results.get("yara_matches", [])]

        # Classification from keywords
        class_keywords = {
            "botnet": ["botnet", "mirai", "gafgyt", "hajime", "mozi", "tsunami"],
            "trojan": ["trojan", "rat", "remote access"],
            "miner": ["miner", "xmrig", "cryptominer", "monero", "stratum", "mining"],
            "ransomware": ["ransomware", "ransom", "encrypt", "locker"],
            "backdoor": ["backdoor", "reverse shell", "bind shell", "c2", "command and control"],
            "worm": ["worm", "self-propagat", "spreading"],
            "dropper": ["dropper", "downloader", "loader", "stager"],
        }

        combined_text = llm_summary + " " + " ".join(yara_matches)
        for cls, keywords in class_keywords.items():
            if any(kw in combined_text for kw in keywords):
                classification = cls
                break

        # Severity from keywords
        if any(w in combined_text for w in ["critical", "severe", "destructive", "ransomware", "wiper"]):
            severity = "critical"
        elif any(w in combined_text for w in ["high", "dangerous", "backdoor", "rat", "botnet"]):
            severity = "high"
        elif any(w in combined_text for w in ["medium", "moderate", "miner"]):
            severity = "medium"
        elif any(w in combined_text for w in ["low", "benign", "adware"]):
            severity = "low"

        # Boost severity if many YARA matches or capa capabilities
        if len(results.get("yara_matches", [])) > 3:
            severity = max(severity, "high", key=lambda s: SEVERITY_ORDER.get(s, 0))
        if len(results.get("capa_capabilities", [])) > 10:
            severity = max(severity, "high", key=lambda s: SEVERITY_ORDER.get(s, 0))

        return classification, severity

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

    def _sandbox_ssh(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run command on sandbox VM via SSH key auth."""
        ssh_args = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-p", str(self.cfg.sandbox_port),
            f"{self.cfg.sandbox_user}@{self.cfg.sandbox_host}",
            cmd,
        ]
        try:
            result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as e:
            return -1, "", str(e)

    def _sandbox_scp_to(self, local_path: str, remote_path: str, timeout: int = 60) -> bool:
        """SCP file to sandbox via key auth."""
        scp_args = [
            "scp", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-P", str(self.cfg.sandbox_port),
            local_path,
            f"{self.cfg.sandbox_user}@{self.cfg.sandbox_host}:{remote_path}",
        ]
        try:
            result = subprocess.run(scp_args, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0
        except Exception:
            return False

    def _sandbox_scp_from(self, remote_path: str, local_path: str, timeout: int = 60) -> bool:
        """SCP file from sandbox via key auth."""
        scp_args = [
            "scp", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-P", str(self.cfg.sandbox_port),
            f"{self.cfg.sandbox_user}@{self.cfg.sandbox_host}:{remote_path}",
            local_path,
        ]
        try:
            result = subprocess.run(scp_args, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0
        except Exception:
            return False

    def _sandbox_restore_snapshot(self) -> bool:
        """Restore sandbox VM to clean snapshot via Proxmox API."""
        vmid = self.cfg.sandbox_vmid
        snap = self.cfg.sandbox_snapshot
        node = "flexiserve"

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

    def detonate_sample(self, sha256: str, local_path: Path) -> Optional[dict]:
        """Detonate a sample in the sandbox VM and collect behavioral data."""
        if not self.cfg.sandbox_enabled or not self._pve_token_id:
            return None

        self.logger.info("Starting dynamic analysis for %s", sha256[:16])

        # Step 1: Restore clean snapshot
        if not self._sandbox_restore_snapshot():
            return None

        # Step 2: Point DNS to INetSim on REMnux, clear auditd, start tcpdump
        self._sandbox_ssh(
            "sudo bash -c 'rm -f /etc/resolv.conf && echo nameserver 192.168.40.5 > /etc/resolv.conf'",
            timeout=5,
        )
        self._sandbox_ssh("sudo auditctl -D && sudo rm -f /var/log/audit/audit.log && sudo systemctl restart auditd", timeout=10)
        self._sandbox_ssh(
            f"sudo tcpdump -i any -w /home/{self.cfg.sandbox_user}/detonation/capture.pcap -c 10000 &",
            timeout=5,
        )

        # Step 3: Upload sample
        remote_sample = f"/home/{self.cfg.sandbox_user}/detonation/{sha256}"
        if not self._sandbox_scp_to(str(local_path), remote_sample):
            self.logger.error("Failed to upload sample to sandbox")
            return None

        # Step 4: Make executable and detonate (backgrounded, don't wait for it)
        self._sandbox_ssh(f"chmod +x {remote_sample} 2>/dev/null; nohup {remote_sample} > /dev/null 2>&1 &", timeout=10)

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

        # Step 7: Collect process list, network connections, filesystem changes
        rc, ps_out, _ = self._sandbox_ssh("ps auxf", timeout=5)
        rc2, net_out, _ = self._sandbox_ssh("sudo ss -tulnp && echo '---' && sudo ss -anp", timeout=5)
        rc3, files_out, _ = self._sandbox_ssh(
            f"find /tmp /dev/shm /var/tmp /home/{self.cfg.sandbox_user} -newer {remote_sample} -type f 2>/dev/null",
            timeout=10,
        )

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

        # Step 10: Memory dump + Volatility forensics
        memory_forensics = {}
        memdump_path = results_dir / "memdump.raw"
        try:
            vmid = self.cfg.sandbox_vmid
            node = "flexiserve"

            # Dump memory via Proxmox QEMU monitor (virsh dump equivalent)
            self.logger.info("Dumping sandbox memory (%s)...", sha256[:16])
            dump_result = self._pve_api("POST",
                f"/api2/json/nodes/{node}/qemu/{vmid}/monitor",
                {"command": f"dump-guest-memory -p /tmp/memdump_{vmid}.raw"})

            if dump_result is not None:
                time.sleep(5)  # Wait for dump to complete

                # Copy dump from Proxmox host to ELK
                # Since we can't SCP from Proxmox directly, copy via sandbox SSH
                # Alternative: use the sandbox itself to dump /proc/kcore or /dev/mem
                pass

            # Fallback: dump via /proc on the sandbox itself (requires root)
            self._sandbox_ssh(
                f"sudo dd if=/dev/mem of=/home/{self.cfg.sandbox_user}/detonation/memdump.raw bs=1M count=256 2>/dev/null || "
                f"sudo cat /proc/kcore > /home/{self.cfg.sandbox_user}/detonation/memdump.raw 2>/dev/null",
                timeout=30,
            )

            # SCP memory dump to local
            self._sandbox_scp_from(
                f"/home/{self.cfg.sandbox_user}/detonation/memdump.raw",
                str(memdump_path),
                timeout=60,
            )

            if memdump_path.exists() and memdump_path.stat().st_size > 0:
                self.logger.info("Memory dump collected: %d bytes", memdump_path.stat().st_size)

                # SCP to REMnux for Volatility analysis
                remnux_dump = f"/home/nalyzer/results/{sha256}_memdump.raw"
                self._scp_to(
                    self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                    self._remnux_pass, str(memdump_path), remnux_dump,
                )

                # Run Volatility plugins
                vol_plugins = {
                    "pslist": f"vol3 -f {remnux_dump} linux.pslist.PsList 2>/dev/null | head -50",
                    "malfind": f"vol3 -f {remnux_dump} linux.malfind.Malfind 2>/dev/null | head -50",
                    "lsof": f"vol3 -f {remnux_dump} linux.lsof.Lsof 2>/dev/null | head -30",
                    "bash_history": f"vol3 -f {remnux_dump} linux.bash.Bash 2>/dev/null | head -30",
                    "elfs": f"vol3 -f {remnux_dump} linux.elfs.Elfs 2>/dev/null | head -30",
                    "hidden_modules": f"vol3 -f {remnux_dump} linux.hidden_modules.Hidden_modules 2>/dev/null | head -20",
                    "network": f"vol3 -f {remnux_dump} linux.ip.Addr 2>/dev/null | head -20",
                }

                for plugin_name, cmd in vol_plugins.items():
                    rc, stdout, stderr = self._ssh_cmd(
                        self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                        cmd, password=self._remnux_pass, timeout=120,
                    )
                    if rc == 0 and stdout.strip():
                        memory_forensics[plugin_name] = stdout.strip()[:3000]
                        self.logger.info("  Volatility %s: %d lines", plugin_name, len(stdout.strip().splitlines()))

                # Cleanup remote dump
                self._ssh_cmd(
                    self.cfg.remnux_host, self.cfg.remnux_port, self.cfg.remnux_user,
                    f"rm -f {remnux_dump}", password=self._remnux_pass,
                )

                if memory_forensics:
                    self.logger.info("Memory forensics complete: %d plugins produced output", len(memory_forensics))

        except Exception as e:
            self.logger.warning("Memory forensics failed: %s", e)

        # Cleanup local memdump
        if memdump_path.exists():
            memdump_path.unlink()

        # Assemble dynamic analysis results
        dynamic_results = {
            "detonation_duration": self.cfg.sandbox_timeout,
            "processes": ps_out[:5000] if ps_out else "",
            "network_connections": net_out[:3000] if net_out else "",
            "new_files": files_out.strip().splitlines()[:50] if files_out else [],
            "executed_commands": audit_out[:5000] if audit_out else "",
            "dns_queries": dns_queries,
            "outbound_connections": connections,
            "pcap_size": pcap_path.stat().st_size if pcap_path.exists() else 0,
            "audit_log_size": (results_dir / "audit.log").stat().st_size if (results_dir / "audit.log").exists() else 0,
        }

        if memory_forensics:
            dynamic_results["memory_forensics"] = memory_forensics

        self.logger.info("Dynamic analysis complete for %s — %d DNS queries, %d connections, %d new files, %d vol plugins",
                         sha256[:16], len(dns_queries), len(connections),
                         len(dynamic_results["new_files"]), len(memory_forensics))

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

        # Description
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
                conns = [f"`{c['ip']}:{c['port']}`" for c in dyn["outbound_connections"][:5]]
                dyn_parts.append("**Outbound Connections:**\n" + "\n".join(f"\u2022 {c}" for c in conns))
            if dyn.get("new_files"):
                dyn_parts.append("**Files Created:**\n" + "\n".join(f"\u2022 `{f}`" for f in dyn["new_files"][:5]))
            if dyn_parts:
                dyn_text = "\n".join(dyn_parts)
                if len(dyn_text) > 900:
                    dyn_text = dyn_text[:900] + "\n\u2026"
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

        # Step 1: Fetch from T-Pot
        local_path = self.fetch_sample(sha256)
        if not local_path:
            self._stop_remnux()
            return False

        # Step 2: Submit to REMnux
        ok = self.submit_for_analysis(sha256, local_path)
        if not ok:
            return False

        # Step 3: Wait for and collect results
        results = self.wait_for_results(sha256)
        if not results:
            self.logger.warning("No results received for %s", sha256[:16])
            return False

        # Step 4: Dynamic analysis (sandbox detonation)
        dynamic = self.detonate_sample(sha256, local_path)
        if dynamic:
            results["dynamic_analysis"] = dynamic

        # Step 5: VirusTotal lookup
        vt_result = self.vt_lookup(sha256)
        if vt_result:
            results["virustotal"] = vt_result

        # Step 6: MalwareBazaar submission
        mb_result = self.mb_submit(sha256, local_path, results)
        if mb_result:
            results["malwarebazaar"] = mb_result

        # Step 7: MISP — check known IOCs and create event
        misp_iocs = self.misp_check_iocs(results)
        if misp_iocs:
            results["misp"] = misp_iocs
        self.misp_create_event(results, sample_info)

        # Step 8: Index in Elasticsearch
        self.index_results(sha256, results, sample_info)

        # Step 9: Sample similarity check (must be after indexing)
        similar = self.find_similar_samples(results)
        if similar:
            results["similar_samples"] = similar
            self.logger.info("Found %d similar samples for %s (top: %d%% match)",
                             len(similar), sha256[:16], similar[0]["similarity"])

        # Step 10: Generate PDF report
        try:
            from generate_report import generate_report as gen_pdf, build_styles
            report_dir = Path("/home/legs/reports")
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"{sha256[:16]}_report.pdf"
            gen_pdf(results, report_path, build_styles())
            self.logger.info("PDF report generated: %s", report_path)
        except Exception as e:
            self.logger.warning("PDF report generation failed: %s", e)

        # Step 11: Generate Sigma detection rules
        try:
            from generate_sigma_rules import generate_sigma_rules, save_rules
            sigma_rules = generate_sigma_rules(results)
            if sigma_rules:
                save_rules(sigma_rules, sha256)
                self.logger.info("Generated %d Sigma rules for %s", len(sigma_rules), sha256[:16])
        except Exception as e:
            self.logger.warning("Sigma rule generation failed: %s", e)

        # Step 12: Update ATT&CK Navigator layer
        try:
            from generate_attack_navigator import generate_layer
            layer = generate_layer()
            if layer:
                layer_path = Path("/home/legs/reports/attack_navigator_layer.json")
                with open(layer_path, "w") as f:
                    json.dump(layer, f, indent=2)
        except Exception as e:
            self.logger.warning("ATT&CK Navigator update failed: %s", e)

        # Step 13: Discord alert
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
    p = argparse.ArgumentParser(description="Sample Analyzer — Automated Malware Analysis Pipeline")
    p.add_argument("--es-url", default="http://localhost:9200")
    p.add_argument("--es-index", default=".ds-filebeat-8.19.8-*")
    p.add_argument("--result-index", default="malware-analysis")
    p.add_argument("--poll-interval", type=int, default=60)
    p.add_argument("--webhook-url", default=None, help="Discord webhook URL")
    p.add_argument("--log-file", default="/home/legs/sample_analyzer.log")
    p.add_argument("--grafana-url", default="https://192.168.50.3:3000")
    p.add_argument("--grafana-dashboard-uid", default="tpot-attack-overview")
    p.add_argument("--backfill", type=int, default=0, dest="backfill_hours", help="Backfill N hours on startup")
    p.add_argument("--dry-run", action="store_true", help="Process events but skip actual analysis/alerts")
    p.add_argument("--verbosity", default="normal", choices=["compact", "normal", "verbose"])
    # SSH targets
    p.add_argument("--tpot-host", default="192.168.40.3")
    p.add_argument("--tpot-port", type=int, default=64295)
    p.add_argument("--tpot-user", default="lepots")
    p.add_argument("--remnux-host", default="192.168.40.5")
    p.add_argument("--remnux-port", type=int, default=22)
    p.add_argument("--remnux-user", default="nalyzer")
    # Limits
    p.add_argument("--analysis-timeout", type=int, default=300)
    p.add_argument("--retention-days", type=int, default=30)

    args = p.parse_args()

    return Config(
        es_url=args.es_url,
        es_index=args.es_index,
        result_index=args.result_index,
        poll_interval=args.poll_interval,
        webhook_url=args.webhook_url,
        log_file=args.log_file,
        grafana_url=args.grafana_url,
        grafana_dashboard_uid=args.grafana_dashboard_uid,
        backfill_hours=args.backfill_hours,
        dry_run=args.dry_run,
        verbosity=args.verbosity,
        tpot_host=args.tpot_host,
        tpot_port=args.tpot_port,
        tpot_user=args.tpot_user,
        remnux_host=args.remnux_host,
        remnux_port=args.remnux_port,
        remnux_user=args.remnux_user,
        analysis_timeout=args.analysis_timeout,
        sample_retention_days=args.retention_days,
    )

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
