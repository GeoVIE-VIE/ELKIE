#!/usr/bin/env python3
"""
Honeypot PAM Authentication Module — Realistic SSH credential handling

Installed on the sacrificial VM as a PAM auth module via pam_exec.so.
Handles per-IP credential tracking, delayed responses, and realistic
failure counts before accepting a known password.

Features:
- Only accepts passwords from a known credential list
- Tracks per-IP state: remembers which password an IP used
- Rejects first N attempts (configurable, realistic behavior)
- Same IP must use the same password on subsequent connections
- Logs every attempt to a JSON file for Filebeat ingestion
- Rate limiting per IP

State file: /var/lib/honeypot/auth_state.json
Log file: /var/log/honeypot/auth.json (Filebeat ships to ES)
Credential list: /etc/honeypot/credentials.conf
"""

import json
import os
import sys
import time
import hashlib
import random
from datetime import datetime, timezone
from pathlib import Path

# --- Configuration ---
STATE_FILE = "/var/lib/honeypot/auth_state.json"
LOG_FILE = "/var/log/honeypot/auth.json"
CRED_FILE = "/etc/honeypot/credentials.conf"
MIN_FAILURES = 3       # Minimum failed attempts before allowing success
MAX_FAILURES = 20      # Maximum failures before allowing (randomized between min-max)
STATE_EXPIRY = 604800  # Forget IP state after 7 days

# --- Default credentials if config file missing ---
DEFAULT_CREDS = {
    "root": ["root", "toor", "password", "123456", "admin", "P@ssw0rd", "letmein", "changeme"],
    "admin": ["admin", "password", "admin123"],
    "ubuntu": ["ubuntu", "password"],
    "deploy": ["deploy", "deploy123"],
    "jenkins": ["jenkins", "jenkins123"],
    "postgres": ["postgres", "pgadmin"],
    "mysql": ["mysql", "root"],
    "git": ["git", "git123"],
    "test": ["test", "test123", "password"],
    "user": ["user", "user123", "password"],
    "ftpuser": ["ftpuser", "ftp123"],
    "www-data": ["www-data", "password"],
}

def load_credentials():
    """Load credential list from config file."""
    creds = {}
    try:
        with open(CRED_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 1)
                if len(parts) == 2:
                    user, passwd = parts
                    if user not in creds:
                        creds[user] = []
                    creds[user].append(passwd)
    except FileNotFoundError:
        pass
    return creds if creds else DEFAULT_CREDS

def load_state():
    """Load per-IP auth state."""
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
        # Expire old entries
        now = time.time()
        state = {ip: data for ip, data in state.items()
                 if now - data.get("last_seen", 0) < STATE_EXPIRY}
        return state
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_state(state):
    """Save per-IP auth state."""
    Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
    # Keep only last 10000 IPs
    if len(state) > 10000:
        sorted_ips = sorted(state.items(), key=lambda x: x[1].get("last_seen", 0))
        state = dict(sorted_ips[-10000:])
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def log_attempt(ip, username, password, success, reason):
    """Log auth attempt as JSON for Filebeat."""
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    eventid = "cowrie.login.success" if success else "cowrie.login.failed"
    entry = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "honeypot_event": "ssh_auth",
        "src_ip": ip,
        "username": username,
        "password": password,
        "auth_success": success,
        "auth_reason": reason,
        "container": {"name": "cowrie"},
        "honeypot": {
            "eventid": eventid,
            "username": username,
            "password": password,
        },
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def check_auth(ip, username, password):
    """
    Check if credentials should be accepted.
    Returns (accept: bool, reason: str)
    """
    creds = load_credentials()
    state = load_state()
    now = time.time()

    # Initialize IP state
    if ip not in state:
        state[ip] = {
            "attempts": 0,
            "failures": 0,
            "first_seen": now,
            "last_seen": now,
            "accepted_user": None,
            "accepted_pass": None,
            "required_failures": random.randint(MIN_FAILURES, MAX_FAILURES),
        }

    ip_state = state[ip]
    ip_state["attempts"] += 1
    ip_state["last_seen"] = now

    # Check if username exists in our credential list
    if username not in creds:
        ip_state["failures"] += 1
        save_state(state)
        log_attempt(ip, username, password, False, "unknown_user")
        return False, "unknown_user"

    # Check if password is in the allowed list for this user
    valid_passwords = creds[username]
    if password not in valid_passwords:
        ip_state["failures"] += 1
        save_state(state)
        log_attempt(ip, username, password, False, "wrong_password")
        return False, "wrong_password"

    # Password is valid — but should we accept yet?

    # If this IP previously logged in, only accept the SAME credentials
    if ip_state["accepted_user"] is not None:
        if username != ip_state["accepted_user"] or password != ip_state["accepted_pass"]:
            ip_state["failures"] += 1
            save_state(state)
            log_attempt(ip, username, password, False, "different_creds_same_ip")
            return False, "different_creds_same_ip"
        # Same creds as before — accept immediately (returning attacker)
        save_state(state)
        log_attempt(ip, username, password, True, "returning_attacker")
        return True, "returning_attacker"

    # First time this IP gets valid creds — enforce failure count
    if ip_state["failures"] < ip_state["required_failures"]:
        ip_state["failures"] += 1
        save_state(state)
        log_attempt(ip, username, password, False, f"need_more_failures ({ip_state['failures']}/{ip_state['required_failures']})")
        return False, "need_more_failures"

    # Enough failures — accept and remember this credential pair
    ip_state["accepted_user"] = username
    ip_state["accepted_pass"] = password
    save_state(state)
    log_attempt(ip, username, password, True, "first_success")
    return True, "first_success"

def main():
    """
    PAM module entry point.
    Called by pam_exec.so with:
      - PAM_RHOST env var = source IP
      - PAM_USER env var = username
      - Password on stdin
    Exit 0 = accept, Exit 1 = reject
    """
    username = os.environ.get("PAM_USER", "")
    ip = os.environ.get("PAM_RHOST", "unknown")
    pam_type = os.environ.get("PAM_TYPE", "")

    # Only handle auth, not account/session
    if pam_type != "auth":
        sys.exit(0)

    # Read password from stdin
    try:
        password = sys.stdin.readline().strip()
    except Exception:
        password = ""

    if not username or not password:
        sys.exit(1)

    # Add small delay for realism (real sshd takes 1-2s)
    time.sleep(random.uniform(0.5, 2.0))

    accepted, reason = check_auth(ip, username, password)

    if accepted:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
