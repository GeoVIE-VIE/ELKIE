#!/usr/bin/env python3
"""
Outlook Sentinel — Email Threat Analysis & Junk Cleanup Daemon

Polls Microsoft Outlook inbox via Graph API, analyzes emails for threats:
  - Extracts URLs, sender domains, attachments
  - Checks against VirusTotal, MISP, abuse.ch feeds
  - Classifies: phishing, malware delivery, spam, scam, legitimate
  - Auto-moves junk to Junk Email folder
  - Alerts on Discord for actual phishing/malware with IOCs

Uses MSAL device code flow with cached refresh tokens.
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

import msal
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    poll_interval: int = 120              # seconds between inbox checks
    webhook_url: Optional[str] = None
    log_file: str = "/home/legs/outlook_sentinel.log"
    state_file: str = "/home/legs/.outlook_sentinel_state.json"
    token_cache_file: str = "/home/legs/.outlook_token_cache.json"
    dry_run: bool = False
    backfill_hours: int = 0
    verbosity: str = "normal"
    # Azure app
    client_id: str = "49d62aab-a482-4485-a5cb-9af0a33d250e"
    authority: str = "https://login.microsoftonline.com/common"
    scopes: list = field(default_factory=lambda: ["Mail.Read", "Mail.ReadWrite"])
    # Analysis
    vt_api_key: str = ""
    misp_url: str = "https://localhost"
    misp_api_key: str = ""
    # Thresholds
    auto_junk_threshold: float = 0.7     # score >= this → auto-move to junk
    alert_threshold: float = 0.5         # score >= this → Discord alert
    max_emails_per_cycle: int = 50       # prevent runaway on first backfill

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# ---------------------------------------------------------------------------
# Spam/phishing indicators
# ---------------------------------------------------------------------------

# Domains that legitimately use noreply@ — skip sender pattern scoring
WHITELISTED_SENDER_DOMAINS = {
    "linkedin.com", "redditmail.com", "reddit.com", "facebookmail.com",
    "twitter.com", "x.com", "instagram.com", "discord.com",
    "microsoft.com", "accountprotection.microsoft.com", "google.com",
    "apple.com", "amazon.com", "github.com", "paypal.com",
    "netflix.com", "spotify.com", "adobe.com", "zoom.us",
    "webull.com", "hilton.com", "harborfreight.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "vanguard.com", "fidelity.com", "schwab.com",
    "uber.com", "lyft.com", "doordash.com", "grubhub.com",
    "steam-chat.com", "steampowered.com", "epicgames.com",
    "twitch.tv", "youtube.com", "slack.com",
}

SPAM_SENDER_PATTERNS = [
    re.compile(r"@.*\.xyz$", re.I),
    re.compile(r"@.*\.top$", re.I),
    re.compile(r"@.*\.buzz$", re.I),
    re.compile(r"@.*\.club$", re.I),
    re.compile(r"@.*\.icu$", re.I),
    re.compile(r"@.*\.work$", re.I),
    re.compile(r"@.*\.click$", re.I),
    re.compile(r"@.*\.tk$", re.I),
    re.compile(r"@.*\.ml$", re.I),
    re.compile(r"@.*\.ga$", re.I),
    re.compile(r"@.*\.cf$", re.I),
]

PHISHING_SUBJECT_PATTERNS = [
    re.compile(r"(account|password|verify|suspend|unusual|unauthorized|security alert|action required)", re.I),
    re.compile(r"(confirm your|update your|validate your|unlock your)", re.I),
    re.compile(r"(you have won|congratulations|claim your|prize)", re.I),
    re.compile(r"(wire transfer|invoice|payment|receipt|statement)", re.I),
    re.compile(r"(urgent|immediate|within 24 hours|act now|limited time)", re.I),
]

PHISHING_BODY_PATTERNS = [
    re.compile(r"(click here|click below|click this link)", re.I),
    re.compile(r"(verify your identity|confirm your account|update your information)", re.I),
    re.compile(r"(social security|ssn|credit card|bank account|routing number)", re.I),
    re.compile(r"(bitcoin|cryptocurrency|crypto wallet|btc address)", re.I),
    re.compile(r"(dear customer|dear user|dear account holder|valued customer)", re.I),
    re.compile(r"(kindly|do the needful|revert back)", re.I),
]

SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # IP-based URLs
    re.compile(r"https?://[^/]*\.(xyz|top|buzz|club|icu|tk|ml|ga|cf|pw|work|click)/", re.I),
    re.compile(r"https?://bit\.ly/|https?://tinyurl\.com/|https?://t\.co/", re.I),  # URL shorteners
]

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
TRUSTED_DOMAINS = {
    "microsoft.com", "google.com", "apple.com", "amazon.com", "github.com",
    "paypal.com", "outlook.com", "live.com", "hotmail.com", "office.com",
    "linkedin.com", "facebook.com", "twitter.com", "youtube.com",
    "netflix.com", "spotify.com", "adobe.com", "zoom.us",
}

# ---------------------------------------------------------------------------
# Main daemon class
# ---------------------------------------------------------------------------

class OutlookSentinel:

    def __init__(self, config: Config):
        self.cfg = config
        self.last_timestamp: Optional[str] = None
        self.processed_ids: set = set()
        self.running = True
        self.logger = self._setup_logging()
        self._app: Optional[msal.PublicClientApplication] = None
        self._cache: Optional[msal.SerializableTokenCache] = None
        self._junk_folder_id: Optional[str] = None
        self.cfg.vt_api_key = os.environ.get("VT_API_KEY", self.cfg.vt_api_key)
        self.cfg.misp_api_key = os.environ.get("MISP_API_KEY", self.cfg.misp_api_key)
        if os.environ.get("MISP_URL"):
            self.cfg.misp_url = os.environ["MISP_URL"]

    # -- logging -----------------------------------------------------------

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("outlook_sentinel")
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
            "processed_ids": list(self.processed_ids)[-5000:],
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
            self.processed_ids = set(state.get("processed_ids", []))
            self.logger.info("Restored state — %d processed IDs, resuming from %s",
                             len(self.processed_ids), self.last_timestamp)
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning("Failed to load state: %s", e)

    # -- Microsoft Graph auth ----------------------------------------------

    def _init_msal(self):
        self._cache = msal.SerializableTokenCache()
        try:
            with open(self.cfg.token_cache_file) as f:
                self._cache.deserialize(f.read())
        except FileNotFoundError:
            self.logger.error("Token cache not found. Run outlook_auth.py first.")
            return False

        self._app = msal.PublicClientApplication(
            self.cfg.client_id,
            authority=self.cfg.authority,
            token_cache=self._cache,
        )
        return True

    def _get_token(self) -> Optional[str]:
        if not self._app:
            return None

        accounts = self._app.get_accounts()
        if not accounts:
            self.logger.error("No accounts in token cache. Re-run outlook_auth.py.")
            return None

        result = self._app.acquire_token_silent(self.cfg.scopes, account=accounts[0])
        if result and "access_token" in result:
            # Save refreshed cache
            if self._cache.has_state_changed:
                with open(self.cfg.token_cache_file, "w") as f:
                    f.write(self._cache.serialize())
            return result["access_token"]

        self.logger.error("Token refresh failed. Re-run outlook_auth.py.")
        return None

    def _graph_get(self, path: str) -> Optional[dict]:
        token = self._get_token()
        if not token:
            return None
        try:
            resp = requests.get(
                f"{GRAPH_BASE}{path}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json()
            self.logger.warning("Graph GET %s returned %d", path, resp.status_code)
            return None
        except Exception as e:
            self.logger.error("Graph GET %s failed: %s", path, e)
            return None

    def _graph_post(self, path: str, data: dict = None) -> Optional[dict]:
        token = self._get_token()
        if not token:
            return None
        try:
            resp = requests.post(
                f"{GRAPH_BASE}{path}",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=data or {},
                timeout=15,
            )
            if resp.status_code in (200, 201):
                return resp.json()
            self.logger.warning("Graph POST %s returned %d: %s", path, resp.status_code, resp.text[:200])
            return None
        except Exception as e:
            self.logger.error("Graph POST %s failed: %s", path, e)
            return None

    # -- Folder management -------------------------------------------------

    def _get_junk_folder_id(self) -> Optional[str]:
        if self._junk_folder_id:
            return self._junk_folder_id

        result = self._graph_get("/me/mailFolders?$filter=displayName eq 'Junk Email'")
        if result and result.get("value"):
            self._junk_folder_id = result["value"][0]["id"]
            return self._junk_folder_id

        # Fallback: try well-known name
        result = self._graph_get("/me/mailFolders/junkemail")
        if result and result.get("id"):
            self._junk_folder_id = result["id"]
            return self._junk_folder_id

        return None

    def _move_to_junk(self, message_id: str) -> bool:
        folder_id = self._get_junk_folder_id()
        if not folder_id:
            self.logger.warning("Could not find Junk folder")
            return False

        result = self._graph_post(
            f"/me/messages/{message_id}/move",
            {"destinationId": folder_id}
        )
        return result is not None

    # -- Email polling -----------------------------------------------------

    def poll_inbox(self) -> list[dict]:
        """Fetch new emails from inbox."""
        params = [
            "$top=" + str(self.cfg.max_emails_per_cycle),
            "$orderby=receivedDateTime asc",
            "$select=id,subject,from,receivedDateTime,bodyPreview,body,hasAttachments,internetMessageHeaders,isRead",
        ]

        if self.last_timestamp:
            params.append(f"$filter=receivedDateTime gt {self.last_timestamp}")

        query = "&".join(params)
        result = self._graph_get(f"/me/mailFolders/inbox/messages?{query}")
        if not result:
            return []

        messages = result.get("value", [])
        new_messages = []
        for msg in messages:
            msg_id = msg.get("id", "")
            if msg_id in self.processed_ids:
                continue
            new_messages.append(msg)
            self.last_timestamp = msg.get("receivedDateTime", self.last_timestamp)

        return new_messages

    # -- Email analysis ----------------------------------------------------

    def analyze_email(self, msg: dict) -> dict:
        """Analyze a single email and return threat assessment."""
        subject = msg.get("subject", "") or ""
        from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "") or ""
        from_name = msg.get("from", {}).get("emailAddress", {}).get("name", "") or ""
        body_preview = msg.get("bodyPreview", "") or ""
        body_content = msg.get("body", {}).get("content", "") or ""
        has_attachments = msg.get("hasAttachments", False)
        received = msg.get("receivedDateTime", "")

        # Extract sender domain
        sender_domain = from_addr.split("@")[1].lower() if "@" in from_addr else ""

        # Extract URLs from body
        urls = list(set(URL_RE.findall(body_content)))
        # Filter out Microsoft/safe URLs
        external_urls = []
        for url in urls:
            domain = re.search(r"https?://([^/]+)", url)
            if domain:
                d = domain.group(1).lower()
                # Skip known safe domains
                if any(d.endswith(t) for t in TRUSTED_DOMAINS):
                    continue
                if d.endswith(".microsoft.com") or d.endswith(".office.com"):
                    continue
            external_urls.append(url)

        # Check if sender is whitelisted
        is_whitelisted = any(sender_domain.endswith(d) for d in WHITELISTED_SENDER_DOMAINS) if sender_domain else False

        # Score the email
        score = 0.0
        reasons = []

        # Sender analysis — skip for whitelisted domains
        if not is_whitelisted:
            for pattern in SPAM_SENDER_PATTERNS:
                if pattern.search(from_addr):
                    score += 0.3
                    reasons.append(f"Suspicious sender TLD: {from_addr}")
                    break

            if sender_domain and sender_domain not in TRUSTED_DOMAINS:
                suspicious_tlds = {".xyz", ".top", ".buzz", ".club", ".icu", ".tk", ".ml", ".ga", ".cf", ".pw", ".work", ".click"}
                if any(sender_domain.endswith(tld) for tld in suspicious_tlds):
                    score += 0.3
                    reasons.append(f"Suspicious TLD: {sender_domain}")

        # Subject analysis
        subject_hits = 0
        for pattern in PHISHING_SUBJECT_PATTERNS:
            if pattern.search(subject):
                subject_hits += 1
        # Whitelisted senders need 2+ subject hits to score
        subject_threshold = 2 if is_whitelisted else 1
        if subject_hits >= subject_threshold:
            score += min(subject_hits * 0.1, 0.3)
            reasons.append(f"Phishing keywords in subject ({subject_hits} patterns)")

        # Body analysis
        body_hits = 0
        for pattern in PHISHING_BODY_PATTERNS:
            if pattern.search(body_content) or pattern.search(body_preview):
                body_hits += 1
        # Whitelisted senders need 3+ body hits to score
        body_threshold = 3 if is_whitelisted else 1
        if body_hits >= body_threshold:
            score += min(body_hits * 0.1, 0.3)
            reasons.append(f"Phishing keywords in body ({body_hits} patterns)")

        # URL analysis
        suspicious_urls = []
        for url in external_urls:
            for pattern in SUSPICIOUS_URL_PATTERNS:
                if pattern.search(url):
                    suspicious_urls.append(url)
                    break

        if suspicious_urls:
            score += min(len(suspicious_urls) * 0.15, 0.4)
            reasons.append(f"{len(suspicious_urls)} suspicious URLs")

        # Mismatch: display name vs actual sender
        if from_name and from_addr:
            known_brands = ["microsoft", "apple", "google", "amazon", "paypal", "netflix", "bank"]
            name_lower = from_name.lower()
            for brand in known_brands:
                if brand in name_lower and brand not in sender_domain:
                    score += 0.4
                    reasons.append(f"Brand impersonation: '{from_name}' from {sender_domain}")
                    break

        # Attachment + urgency = likely malware delivery
        if has_attachments and subject_hits > 0:
            score += 0.2
            reasons.append("Attachment with urgency signals")

        # Classify
        if score >= 0.6:
            classification = "phishing"
        elif score >= 0.4:
            classification = "spam"
        elif score >= 0.2:
            classification = "suspicious"
        else:
            classification = "legitimate"

        return {
            "message_id": msg.get("id", ""),
            "subject": subject,
            "from_address": from_addr,
            "from_name": from_name,
            "sender_domain": sender_domain,
            "received": received,
            "has_attachments": has_attachments,
            "urls": external_urls[:20],
            "suspicious_urls": suspicious_urls[:10],
            "score": round(score, 2),
            "classification": classification,
            "reasons": reasons,
            "body_preview": body_preview[:200],
        }

    # -- Threat intel enrichment -------------------------------------------

    def enrich_with_vt(self, analysis: dict) -> dict:
        """Check URLs against VirusTotal."""
        if not self.cfg.vt_api_key or not analysis.get("suspicious_urls"):
            return analysis

        vt_results = []
        for url in analysis["suspicious_urls"][:3]:  # Rate limit friendly
            try:
                # URL scan lookup
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": self.cfg.vt_api_key},
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    if malicious > 0:
                        vt_results.append({
                            "url": url[:80],
                            "detections": f"{malicious}/{total}",
                        })
                        analysis["score"] = min(analysis["score"] + 0.3, 1.0)
                        analysis["reasons"].append(f"VT: {url[:50]} flagged {malicious}/{total}")
                elif resp.status_code == 404:
                    pass  # URL not in VT
                time.sleep(0.5)  # Rate limit
            except Exception:
                pass

        if vt_results:
            analysis["vt_url_results"] = vt_results

        return analysis

    def enrich_with_misp(self, analysis: dict) -> dict:
        """Check sender domain and URLs against MISP."""
        if not self.cfg.misp_api_key:
            return analysis

        misp_hits = []
        # Check sender domain
        domain = analysis.get("sender_domain", "")
        if domain and domain not in TRUSTED_DOMAINS:
            try:
                resp = requests.post(
                    f"{self.cfg.misp_url}/attributes/restSearch",
                    headers={
                        "Authorization": self.cfg.misp_api_key,
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    json={"value": domain, "type": ["domain", "hostname"], "limit": 3},
                    verify=False,
                    timeout=10,
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("response", {}).get("Attribute", [])
                    if attrs:
                        misp_hits.append({"type": "domain", "value": domain, "events": len(attrs)})
                        analysis["score"] = min(analysis["score"] + 0.3, 1.0)
                        analysis["reasons"].append(f"MISP: sender domain '{domain}' is known IOC")
            except Exception:
                pass

        # Check suspicious URLs
        for url in analysis.get("suspicious_urls", [])[:3]:
            try:
                resp = requests.post(
                    f"{self.cfg.misp_url}/attributes/restSearch",
                    headers={
                        "Authorization": self.cfg.misp_api_key,
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    json={"value": url, "type": "url", "limit": 3},
                    verify=False,
                    timeout=10,
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("response", {}).get("Attribute", [])
                    if attrs:
                        misp_hits.append({"type": "url", "value": url[:60], "events": len(attrs)})
                        analysis["score"] = min(analysis["score"] + 0.3, 1.0)
            except Exception:
                pass

        if misp_hits:
            analysis["misp_hits"] = misp_hits

        # Re-classify after enrichment
        if analysis["score"] >= 0.6:
            analysis["classification"] = "phishing"
        elif analysis["score"] >= 0.4:
            analysis["classification"] = "spam"

        return analysis

    # -- Attachment analysis -----------------------------------------------

    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".msp",
        ".dll", ".ocx", ".cpl", ".inf", ".reg", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".iso", ".img",
        ".jar", ".py", ".rb", ".elf", ".sh", ".app", ".action",
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",  # macro-enabled Office
        ".zip", ".rar", ".7z", ".gz", ".tar", ".cab",  # archives (may contain malware)
    }

    SAFE_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
        ".pdf",  # generally safe but could be malicious
        ".txt", ".csv", ".log",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",  # non-macro Office
    }

    def _download_attachments(self, message_id: str) -> list[dict]:
        """Download attachments from a message via Graph API."""
        result = self._graph_get(f"/me/messages/{message_id}/attachments")
        if not result:
            return []

        attachments = []
        staging = Path("/home/legs/sample_staging")
        staging.mkdir(parents=True, exist_ok=True)

        for att in result.get("value", []):
            if att.get("@odata.type") != "#microsoft.graph.fileAttachment":
                continue

            name = att.get("name", "unknown")
            size = att.get("size", 0)
            content_bytes = att.get("contentBytes", "")

            if not content_bytes or size > 50 * 1024 * 1024:  # 50MB limit
                continue

            # Check extension
            ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            is_dangerous = ext in self.DANGEROUS_EXTENSIONS
            is_safe = ext in self.SAFE_EXTENSIONS

            import base64
            import hashlib
            raw = base64.b64decode(content_bytes)
            sha256 = hashlib.sha256(raw).hexdigest()

            # Save to staging
            local_path = staging / sha256
            with open(local_path, "wb") as f:
                f.write(raw)

            attachments.append({
                "name": name,
                "size": size,
                "sha256": sha256,
                "extension": ext,
                "is_dangerous": is_dangerous,
                "is_safe": is_safe,
                "local_path": str(local_path),
                "content_type": att.get("contentType", ""),
            })

            self.logger.info("  Downloaded attachment: %s (%s, %d bytes)", name, sha256[:16], size)

        return attachments

    def _analyze_attachment(self, attachment: dict) -> Optional[dict]:
        """Run attachment through the malware analysis pipeline."""
        sha256 = attachment["sha256"]
        local_path = Path(attachment["local_path"])
        name = attachment["name"]

        # Import sample_analyzer for the pipeline
        try:
            from sample_analyzer import SampleAnalyzer, Config as SAConfig
        except ImportError:
            self.logger.error("Could not import sample_analyzer — skipping attachment analysis")
            return None

        sa_cfg = SAConfig(
            webhook_url=None,  # We'll handle alerting ourselves
            dry_run=self.cfg.dry_run,
        )
        analyzer = SampleAnalyzer(sa_cfg)

        # Check VT first (quick, no SSH needed)
        vt_result = analyzer.vt_lookup(sha256)

        # Submit to REMnux for static analysis
        ok = analyzer.submit_for_analysis(sha256, local_path)
        if not ok:
            self.logger.warning("Failed to submit attachment %s to REMnux", name)
            return {"sha256": sha256, "name": name, "virustotal": vt_result, "static_analysis": None}

        # Wait for results
        results = analyzer.wait_for_results(sha256)

        # Dynamic analysis if it's a dangerous file type
        dynamic = None
        if attachment["is_dangerous"] and results:
            dynamic = analyzer.detonate_sample(sha256, local_path)

        analysis = {
            "sha256": sha256,
            "name": name,
            "virustotal": vt_result,
            "static_analysis": results,
            "dynamic_analysis": dynamic,
        }

        # Index in ES and create MISP event if we got results
        if results:
            metadata = {
                "honeypot": "outlook",
                "src_ip": "",
                "country": "",
                "session_id": "",
                "captured_at": "",
            }
            results["virustotal"] = vt_result
            if dynamic:
                results["dynamic_analysis"] = dynamic
            analyzer.index_results(sha256, results, metadata)
            analyzer.misp_create_event(results, metadata)

        return analysis

    # -- Actions -----------------------------------------------------------

    def process_email(self, msg: dict) -> Optional[dict]:
        """Full pipeline for one email."""
        analysis = self.analyze_email(msg)

        if analysis["classification"] == "legitimate" and analysis["score"] < 0.2:
            self.logger.debug("Legitimate: %s from %s", analysis["subject"][:40], analysis["from_address"])
            self.processed_ids.add(analysis["message_id"])
            return None

        # Enrich suspicious+ emails
        if analysis["score"] >= 0.2:
            analysis = self.enrich_with_vt(analysis)
            analysis = self.enrich_with_misp(analysis)

        self.logger.info("[%s] score=%.2f from=%s subj=%s",
                         analysis["classification"].upper(), analysis["score"],
                         analysis["from_address"], analysis["subject"][:50])

        if analysis["reasons"]:
            for r in analysis["reasons"][:3]:
                self.logger.info("  → %s", r)

        # Attachment analysis — download and analyze if email has attachments and is suspicious
        if analysis.get("has_attachments") and analysis["score"] >= 0.3:
            attachments = self._download_attachments(analysis["message_id"])
            if attachments:
                analysis["attachments"] = []
                for att in attachments:
                    if att["is_safe"] and analysis["score"] < 0.5:
                        self.logger.info("  Skipping safe attachment: %s", att["name"])
                        continue

                    self.logger.info("  Analyzing attachment: %s (%s)", att["name"], att["sha256"][:16])
                    att_result = self._analyze_attachment(att)
                    if att_result:
                        analysis["attachments"].append(att_result)

                        # Boost score if attachment is malicious
                        vt = att_result.get("virustotal", {})
                        if vt and vt.get("found") and vt.get("detections", 0) > 0:
                            analysis["score"] = min(analysis["score"] + 0.4, 1.0)
                            analysis["reasons"].append(f"Attachment '{att['name']}' flagged by VT: {vt.get('detection_ratio', '?')}")
                            analysis["classification"] = "phishing"

                        static = att_result.get("static_analysis", {})
                        if static and static.get("yara_matches"):
                            analysis["score"] = min(analysis["score"] + 0.3, 1.0)
                            analysis["reasons"].append(f"Attachment YARA: {', '.join(static['yara_matches'][:3])}")
                            analysis["classification"] = "phishing"

        # Auto-move to junk
        if analysis["score"] >= self.cfg.auto_junk_threshold and not self.cfg.dry_run:
            if self._move_to_junk(analysis["message_id"]):
                self.logger.info("  → Moved to Junk: %s", analysis["subject"][:50])
                analysis["action"] = "moved_to_junk"
            else:
                analysis["action"] = "move_failed"
        elif self.cfg.dry_run and analysis["score"] >= self.cfg.auto_junk_threshold:
            self.logger.info("  → DRY RUN: would move to Junk")
            analysis["action"] = "dry_run"
        else:
            analysis["action"] = "flagged"

        # Discord alert for phishing/malware
        if analysis["score"] >= self.cfg.alert_threshold:
            self.fire_discord_alert(analysis)

        self.processed_ids.add(analysis["message_id"])
        return analysis

    # -- Discord alerting --------------------------------------------------

    def fire_discord_alert(self, analysis: dict):
        """Send Discord alert for suspicious email."""
        if not self.cfg.webhook_url:
            return

        classification = analysis["classification"]
        score = analysis["score"]
        subject = analysis["subject"][:100]
        from_addr = analysis["from_address"]
        from_name = analysis.get("from_name", "")

        class_icons = {
            "phishing": "\U0001f3a3", "spam": "\U0001f4e7",
            "suspicious": "\u26a0\ufe0f", "legitimate": "\u2705",
        }
        icon = class_icons.get(classification, "\u2753")

        color_map = {"phishing": 0xED4245, "spam": 0xFE8D2F, "suspicious": 0xFEE75C}
        color = color_map.get(classification, 0x5865F2)

        desc = f"{icon} **{classification.title()}** email from `{from_addr}`"
        if from_name and from_name != from_addr:
            desc += f" (display: *{from_name}*)"

        fields = [
            {"name": "Subject", "value": f"`{subject}`", "inline": False},
            {"name": "Score", "value": f"`{score}`", "inline": True},
            {"name": "Action", "value": f"`{analysis.get('action', 'none')}`", "inline": True},
        ]

        # Reasons
        if analysis["reasons"]:
            reason_text = "\n".join(f"\u2022 {r}" for r in analysis["reasons"][:5])
            fields.append({"name": "Indicators", "value": reason_text, "inline": False})

        # Suspicious URLs
        if analysis.get("suspicious_urls"):
            url_text = "\n".join(f"\u2022 `{u[:70]}`" for u in analysis["suspicious_urls"][:5])
            fields.append({"name": "Suspicious URLs", "value": url_text, "inline": False})

        # VT results
        if analysis.get("vt_url_results"):
            vt_text = "\n".join(f"\u2022 `{r['url']}` — **{r['detections']}**" for r in analysis["vt_url_results"])
            fields.append({"name": "VirusTotal", "value": vt_text, "inline": False})

        # MISP hits
        if analysis.get("misp_hits"):
            misp_text = "\n".join(f"\u2022 `{h['value']}` ({h['type']}) — {h['events']} event(s)" for h in analysis["misp_hits"])
            fields.append({"name": "MISP Correlations", "value": misp_text, "inline": False})

        # Attachment analysis results
        for att in analysis.get("attachments", []):
            att_parts = [f"**{att.get('name', '?')}** (`{att.get('sha256', '?')[:16]}...`)"]

            vt = att.get("virustotal", {})
            if vt and vt.get("found"):
                att_parts.append(f"VT: **{vt.get('detection_ratio', '?')}** detections")
                if vt.get("suggested_label"):
                    att_parts.append(f"Label: `{vt['suggested_label']}`")
            elif vt and not vt.get("found"):
                att_parts.append("VT: **Not found** (novel)")

            static = att.get("static_analysis", {})
            if static:
                if static.get("yara_matches"):
                    att_parts.append(f"YARA: {', '.join(f'`{y}`' for y in static['yara_matches'][:3])}")
                if static.get("classification"):
                    att_parts.append(f"Classification: **{static.get('classification', 'unknown').title()}**")
                if static.get("llm_summary"):
                    summary = static["llm_summary"][:300]
                    if len(static["llm_summary"]) > 300:
                        summary += "\u2026"
                    att_parts.append(f"\n{summary}")

            dyn = att.get("dynamic_analysis", {})
            if dyn:
                if dyn.get("dns_queries"):
                    att_parts.append(f"DNS: {', '.join(f'`{d}`' for d in dyn['dns_queries'][:3])}")
                if dyn.get("outbound_connections"):
                    conns = [f"`{c['ip']}:{c['port']}`" for c in dyn["outbound_connections"][:3]]
                    att_parts.append(f"Connections: {', '.join(conns)}")

            att_text = "\n".join(att_parts)
            if len(att_text) > 900:
                att_text = att_text[:900] + "\n\u2026"
            fields.append({"name": "Attachment Analysis", "value": att_text, "inline": False})

            # Add investigation links for the attachment
            sha = att.get("sha256", "")
            if sha:
                links = f"\u2022 [VirusTotal](https://www.virustotal.com/gui/file/{sha}) | [MalwareBazaar](https://bazaar.abuse.ch/sample/{sha}/)"
                fields.append({"name": "Attachment Links", "value": links, "inline": False})

        # Body preview
        preview = analysis.get("body_preview", "")
        if preview:
            if len(preview) > 200:
                preview = preview[:200] + "\u2026"
            fields.append({"name": "Preview", "value": f"```{preview}```", "inline": False})

        payload = {
            "embeds": [{
                "title": f"{icon} Email Threat: {classification.title()}",
                "description": desc,
                "color": color,
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": f"Outlook Sentinel \u2022 {analysis['from_address']}"},
                "author": {"name": "Outlook Sentinel \u2014 Email Threat Analysis"},
            }]
        }

        try:
            resp = requests.post(self.cfg.webhook_url, json=payload, timeout=10)
            if resp.status_code not in (200, 204):
                self.logger.warning("Discord webhook returned %d", resp.status_code)
        except Exception as e:
            self.logger.error("Discord webhook failed: %s", e)

    # -- Main loop ---------------------------------------------------------

    def run(self):
        self.logger.info("Outlook Sentinel starting — polling every %ds", self.cfg.poll_interval)
        self.load_state()

        if not self._init_msal():
            self.logger.error("MSAL init failed — exiting")
            return

        # Test token
        token = self._get_token()
        if not token:
            self.logger.error("Could not acquire token — exiting")
            return

        self.logger.info("Authenticated — token OK")

        if self.cfg.backfill_hours > 0:
            backfill_time = datetime.now(timezone.utc) - timedelta(hours=self.cfg.backfill_hours)
            self.last_timestamp = backfill_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.logger.info("Backfilling from %s", self.last_timestamp)
        elif not self.last_timestamp:
            start = datetime.now(timezone.utc) - timedelta(hours=1)
            self.last_timestamp = start.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.logger.info("No saved state — starting from %s", self.last_timestamp)

        consecutive_errors = 0

        while self.running:
            try:
                messages = self.poll_inbox()
                processed = 0
                junked = 0

                for msg in messages:
                    if not self.running:
                        break
                    try:
                        result = self.process_email(msg)
                        if result:
                            processed += 1
                            if result.get("action") == "moved_to_junk":
                                junked += 1
                    except Exception as e:
                        self.logger.error("Error processing email: %s", e)

                if processed > 0:
                    self.logger.info("Processed %d suspicious emails (%d junked) this cycle", processed, junked)
                    consecutive_errors = 0

                self.save_state()

            except Exception as e:
                consecutive_errors += 1
                wait = min(30 * (2 ** consecutive_errors), 300)
                self.logger.error("Poll cycle error: %s — retrying in %ds", e, wait)
                time.sleep(wait)
                continue

            time.sleep(self.cfg.poll_interval)

        self.save_state()
        self.logger.info("Outlook Sentinel stopped")

    def stop(self):
        self.running = False

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> Config:
    p = argparse.ArgumentParser(description="Outlook Sentinel — Email Threat Analysis")
    p.add_argument("--poll-interval", type=int, default=120)
    p.add_argument("--webhook-url", default=None, help="Discord webhook URL")
    p.add_argument("--log-file", default="/home/legs/outlook_sentinel.log")
    p.add_argument("--backfill", type=int, default=0, dest="backfill_hours", help="Backfill N hours on startup")
    p.add_argument("--dry-run", action="store_true", help="Analyze but don't move emails")
    p.add_argument("--verbosity", default="normal", choices=["compact", "normal", "verbose"])
    p.add_argument("--auto-junk-threshold", type=float, default=0.7)
    p.add_argument("--alert-threshold", type=float, default=0.5)
    args = p.parse_args()

    return Config(
        poll_interval=args.poll_interval,
        webhook_url=args.webhook_url,
        log_file=args.log_file,
        backfill_hours=args.backfill_hours,
        dry_run=args.dry_run,
        verbosity=args.verbosity,
        auto_junk_threshold=args.auto_junk_threshold,
        alert_threshold=args.alert_threshold,
    )

def main():
    config = parse_args()
    sentinel = OutlookSentinel(config)

    def handle_signal(signum, frame):
        sentinel.logger.info("Received signal %d — stopping", signum)
        sentinel.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    sentinel.run()

if __name__ == "__main__":
    main()
