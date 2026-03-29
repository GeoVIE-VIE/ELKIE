#!/usr/bin/env python3
"""
Session Correlator — Map attacker commands to IPs on the sacrificial VM.

Runs from ELK, SSHes to the sacrificial VM via jump host, and:
1. Reads auth.log for "Accepted password from IP" → gets sshd PID + session ID
2. Reads audit.log for EXECVE commands linked to those sessions (ppid chain)
3. Correlates: IP → session → commands → downloads → malware drops
4. Indexes structured attacker sessions to ES (not raw auditd — no spam)

Only ships actual attacker activity, pre-correlated. No guard noise, no system noise.

Usage:
    python3 session_correlator.py              # correlate last 6 hours
    python3 session_correlator.py --hours 24   # last 24 hours
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import requests
import urllib3
urllib3.disable_warnings()

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
SESSION_INDEX = "attacker-sessions"
JUMP_HOST = "lepots@192.168.40.3"
JUMP_PORT = "64295"
TARGET = "root@192.168.40.99"


def ssh_cmd(cmd, timeout=30):
    """Run command on sacrificial VM via jump host."""
    full_cmd = [
        "ssh", "-J", f"{JUMP_HOST}:{JUMP_PORT}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        TARGET, cmd
    ]
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except Exception as e:
        print(f"  SSH error: {e}")
        return ""


def es_index(doc_id, body):
    """Index a document."""
    resp = requests.put(
        f"{ES_URL}/{SESSION_INDEX}/_doc/{doc_id}",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    return resp.status_code in (200, 201)


def es_create_index():
    """Create index with mapping."""
    mapping = {
        "mappings": {
            "properties": {
                "attacker_ip": {"type": "ip"},
                "session_id": {"type": "keyword"},
                "sshd_pid": {"type": "keyword"},
                "login_time": {"type": "date"},
                "logout_time": {"type": "date"},
                "indexed_at": {"type": "date"},
                "session_duration_sec": {"type": "integer"},
                "credentials_tried": {"type": "keyword"},
                "commands": {"type": "text"},
                "command_count": {"type": "integer"},
                "executables": {"type": "keyword"},
                "download_urls": {"type": "keyword"},
                "download_domains": {"type": "keyword"},
                "dropped_files": {"type": "keyword"},
                "ssh_keys_installed": {"type": "boolean"},
                "cron_modified": {"type": "boolean"},
                "rootkit_attempted": {"type": "boolean"},
                "behavior_tags": {"type": "keyword"},
                "command_fingerprint": {"type": "keyword"},
                "country": {"type": "keyword"},
                "asn": {"type": "keyword"},
                "org": {"type": "keyword"},
            }
        }
    }
    requests.put(f"{ES_URL}/{SESSION_INDEX}", json=mapping, timeout=10)


def extract_sessions(hours=6):
    """SSH to sacrificial VM and extract correlated session data."""
    print(f"[*] Extracting sessions from last {hours} hours...")

    # Step 1: Get successful SSH logins with PID and IP
    auth_output = ssh_cmd(
        f"grep 'Accepted password' /var/log/auth.log 2>/dev/null | tail -500",
        timeout=15
    )
    if not auth_output:
        # Try syslog
        auth_output = ssh_cmd(
            f"grep 'Accepted password' /var/log/syslog 2>/dev/null | tail -500",
            timeout=15
        )

    # Supports both ISO 8601 (2026-03-28T20:17:54.548200-04:00) and traditional (Mar 28 19:41:05)
    login_pattern = re.compile(
        r'(\S+)\s+\S+\s+sshd\[(\d+)\]:\s+Accepted password for (\S+) from (\S+) port'
    )

    sessions = {}
    cutoff = datetime.now() - timedelta(hours=hours)

    for line in auth_output.splitlines():
        m = login_pattern.search(line)
        if not m:
            continue
        timestamp_str, pid, user, ip = m.groups()

        # Skip internal IPs
        if ip.startswith(("192.168.", "10.", "127.")):
            continue

        # Parse timestamp — try ISO 8601 first, then traditional
        try:
            # ISO: 2026-03-28T20:17:54.548200-04:00
            ts_clean = timestamp_str.split(".")[0]  # strip microseconds
            ts = datetime.fromisoformat(ts_clean.replace("T", " "))
            if ts < cutoff:
                continue
        except (ValueError, TypeError):
            try:
                ts = datetime.strptime(f"2026 {timestamp_str}", "%Y %b %d %H:%M:%S")
                if ts < cutoff:
                    continue
            except ValueError:
                continue

        sessions[pid] = {
            "attacker_ip": ip,
            "sshd_pid": pid,
            "login_time": ts.isoformat() + "Z",
            "user": user,
            "credentials_tried": [],
            "commands": [],
            "executables": set(),
            "download_urls": set(),
            "download_domains": set(),
            "dropped_files": set(),
            "ssh_keys_installed": False,
            "cron_modified": False,
            "rootkit_attempted": False,
            "behavior_tags": set(),
        }

    print(f"  Found {len(sessions)} external login sessions")
    if not sessions:
        return {}

    # Step 2: Get credential attempts (failed passwords before success)
    cred_output = ssh_cmd(
        f"grep -E 'Failed password|Invalid user' /var/log/auth.log 2>/dev/null | tail -1000",
        timeout=15
    )
    cred_pattern = re.compile(
        r'sshd\[(\d+)\]:\s+(?:Failed password for (?:invalid user )?(\S+)|Invalid user (\S+))\s+from\s+(\S+)'
    )
    for line in cred_output.splitlines():
        m = cred_pattern.search(line)
        if m:
            pid = m.group(1)
            user = m.group(2) or m.group(3)  # Failed password user or Invalid user
            ip = m.group(4)
            if not user:
                continue
            # Find the session for this IP
            for spid, sess in sessions.items():
                if sess["attacker_ip"] == ip:
                    if user not in sess["credentials_tried"]:
                        sess["credentials_tried"].append(user)

    # Step 3: Get EXECVE commands and correlate to attacker IPs
    # Strategy: sshd forks child sshd per connection. auth.log gives us parent sshd PID.
    # The child sshd PID spawns bash which spawns attacker commands.
    # We use a single SSH command to: get the full ppid tree from audit + correlate on-box.
    print("  Extracting and correlating attacker commands on-box...")

    # Build the sshd PID list for the remote script
    sshd_pid_list = ",".join(sessions.keys())

    # Pipe the correlation script via SSH stdin (SCP doesn't work through jump host)
    import tempfile
    script = f'''#!/usr/bin/env python3
import re, json, os, sys

sshd_pids = set({list(sessions.keys())!r})

pid_parent = {{}}
pid_info = {{}}

with open("/var/log/audit/audit.log") as f:
    for line in f:
        if "SYSCALL=execve" not in line:
            continue
        pid_m = re.search(r" pid=(\\d+)", line)
        ppid_m = re.search(r"ppid=(\\d+)", line)
        exe_m = re.search(r'exe="([^"]+)"', line)
        comm_m = re.search(r'comm="([^"]+)"', line)
        if not (pid_m and ppid_m and exe_m):
            continue
        pid, ppid = pid_m.group(1), ppid_m.group(1)
        exe = exe_m.group(1)
        comm = comm_m.group(1) if comm_m else ""
        if any(x in exe for x in ("honeypot", "filebeat", "auditd", "chronyd")):
            continue
        pid_parent[pid] = ppid
        pid_info[pid] = (exe, comm)

for p in os.listdir("/proc"):
    if p.isdigit():
        try:
            with open(f"/proc/{{p}}/stat") as f:
                parts = f.read().split()
                pid_parent[p] = parts[3]
        except:
            pass

def find_sshd(pid, depth=0):
    if depth > 15: return None
    if pid in sshd_pids: return pid
    parent = pid_parent.get(pid)
    if not parent or parent in ("0", "1") or parent == pid: return None
    return find_sshd(parent, depth + 1)

boring = {{"/usr/bin/env","/usr/bin/id","/usr/bin/uname","/usr/bin/whoami",
    "/usr/bin/hostname","/usr/bin/ls","/usr/bin/cat","/usr/bin/readlink",
    "/usr/bin/stat","/usr/bin/head","/usr/bin/tail","/usr/bin/wc",
    "/usr/bin/basename","/usr/bin/dirname","/usr/bin/tr","/usr/bin/cut",
    "/usr/bin/sort","/usr/bin/uniq","/usr/bin/tee","/usr/bin/true",
    "/usr/bin/false","/usr/bin/sleep","/usr/bin/date","/usr/bin/echo",
    "/usr/bin/test","/usr/bin/[","/usr/bin/grep","/usr/bin/awk",
    "/usr/bin/sed","/usr/bin/find","/usr/sbin/sshd","/usr/bin/bash",
    "/usr/bin/sh","/usr/bin/dash","/usr/bin/run-parts","/usr/bin/dpkg",
    "/usr/bin/apt-config","/usr/bin/gettext","/usr/bin/expr",
    "/usr/bin/gawk","/usr/bin/python3.12",
    "/usr/lib/update-notifier/update-motd-fsck-at-reboot",
    "/usr/lib/update-notifier/update-motd-reboot-required",
    "/usr/lib/update-notifier/update-motd-updates-available"}}

results = {{}}
for pid, (exe, comm) in pid_info.items():
    if exe in boring:
        continue
    sshd = find_sshd(pid)
    if sshd:
        results.setdefault(sshd, []).append({{"exe": exe, "comm": comm}})

print(json.dumps(results))
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script)
        local_script = f.name

    # Pipe script via SSH stdin — avoids SCP issues through jump host
    with open(local_script) as f:
        script_content = f.read()
    os.unlink(local_script)

    full_cmd = [
        "ssh", "-J", f"{JUMP_HOST}:{JUMP_PORT}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        TARGET, "python3 -"
    ]
    try:
        result = subprocess.run(full_cmd, input=script_content, capture_output=True, text=True, timeout=60)
        correlation_output = result.stdout
        if result.stderr:
            print(f"  Correlator stderr: {result.stderr[:200]}")
    except Exception as e:
        correlation_output = ""
        print(f"  Correlator error: {e}")

    # Parse the correlation results
    sshd_pids_set = set(sessions.keys())
    correlated = 0
    try:
        cmd_map = json.loads(correlation_output.strip())
    except (json.JSONDecodeError, ValueError):
        cmd_map = {}
        print(f"  WARNING: Could not parse correlation output")

    for sshd_pid, cmds in cmd_map.items():
        if sshd_pid not in sessions:
            continue
        sess = sessions[sshd_pid]
        for cmd in cmds:
            exe = cmd["exe"]
            comm = cmd["comm"]
            correlated += 1

            sess["executables"].add(exe)
            sess["commands"].append(f"{comm} ({exe})")

            # Detect interesting behaviors
            if "wget" in exe or "curl" in exe:
                sess["behavior_tags"].add("downloads_malware")
            if "chmod" in exe:
                sess["behavior_tags"].add("makes_executable")
            if "crontab" in exe or "cron" in comm:
                sess["cron_modified"] = True
                sess["behavior_tags"].add("persistence_cron")
            if exe.startswith("/tmp/") or exe.startswith("/."):
                sess["dropped_files"].add(exe)
                sess["behavior_tags"].add("executes_dropped_binary")
            if exe.startswith("/dev/shm/"):
                sess["dropped_files"].add(exe)
                sess["behavior_tags"].add("executes_from_shm")

    print(f"  Correlated {correlated} commands to {len([s for s in sessions.values() if s['commands']])} sessions")

    # Step 4: Get download URLs from audit EXECVE args (hex-encoded)
    print("  Extracting download URLs...")
    dl_output = ssh_cmd(
        r"""grep -B1 'type=EXECVE' /var/log/audit/audit.log 2>/dev/null | \
        grep -oP '(https?://[^\s"]+|http://[0-9.]+[^\s"]+)' | \
        sort -u | head -50""",
        timeout=15
    )
    for url in dl_output.splitlines():
        url = url.strip().rstrip("'\")")
        if not url or "192.168." in url or "127.0." in url:
            continue
        # Add to all sessions that downloaded (simplified — ideally would correlate by PID)
        domain = re.search(r'https?://([^/:]+)', url)
        for sess in sessions.values():
            if "downloads_malware" in sess["behavior_tags"]:
                sess["download_urls"].add(url)
                if domain:
                    sess["download_domains"].add(domain.group(1))

    return sessions


def enrich_sessions(sessions):
    """Add geo/ASN data and compute fingerprints."""
    seen_ips = {}
    for pid, sess in sessions.items():
        ip = sess["attacker_ip"]
        if ip in seen_ips:
            sess["country"] = seen_ips[ip].get("country", "")
            sess["asn"] = seen_ips[ip].get("asn", "")
            sess["org"] = seen_ips[ip].get("org", "")
            continue
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,countryCode,as,org",
                timeout=5,
            )
            if resp.status_code == 200:
                geo = resp.json()
                if geo.get("status") == "success":
                    sess["country"] = geo.get("countryCode", "")
                    sess["asn"] = geo.get("as", "").split()[0] if geo.get("as") else ""
                    sess["org"] = geo.get("org", "")
                    seen_ips[ip] = {"country": sess["country"], "asn": sess["asn"], "org": sess["org"]}
            time.sleep(0.3)
        except Exception:
            sess["country"] = ""
            sess["asn"] = ""
            sess["org"] = ""

    # Compute command fingerprints
    import hashlib
    for sess in sessions.values():
        cmds = sorted(set(sess["commands"]))
        if cmds:
            fp = hashlib.md5("|".join(cmds).encode()).hexdigest()[:12]
            sess["command_fingerprint"] = fp
        else:
            sess["command_fingerprint"] = ""


def index_sessions(sessions):
    """Index correlated sessions to ES."""
    es_create_index()
    indexed = 0
    for pid, sess in sessions.items():
        # Convert sets to lists
        doc = {
            "attacker_ip": sess["attacker_ip"],
            "session_id": f"{sess['attacker_ip']}_{pid}",
            "sshd_pid": pid,
            "login_time": sess["login_time"],
            "indexed_at": datetime.now(timezone.utc).isoformat(),
            "credentials_tried": sess["credentials_tried"][:10],
            "commands": "\n".join(sess["commands"][:50]),
            "command_count": len(sess["commands"]),
            "executables": sorted(sess["executables"])[:20],
            "download_urls": sorted(sess["download_urls"])[:10],
            "download_domains": sorted(sess["download_domains"])[:10],
            "dropped_files": sorted(sess["dropped_files"])[:10],
            "ssh_keys_installed": sess["ssh_keys_installed"],
            "cron_modified": sess["cron_modified"],
            "rootkit_attempted": sess["rootkit_attempted"],
            "behavior_tags": sorted(sess["behavior_tags"]),
            "command_fingerprint": sess.get("command_fingerprint", ""),
            "country": sess.get("country", ""),
            "asn": sess.get("asn", ""),
            "org": sess.get("org", ""),
        }

        doc_id = f"{sess['attacker_ip']}_{pid}_{sess['login_time'][:10]}"
        if es_index(doc_id, doc):
            indexed += 1

    print(f"[+] Indexed {indexed}/{len(sessions)} sessions to {SESSION_INDEX}")


def main():
    parser = argparse.ArgumentParser(description="Correlate attacker sessions on sacrificial VM")
    parser.add_argument("--hours", type=int, default=6, help="Hours to look back (default: 6)")
    parser.add_argument("--dry-run", action="store_true", help="Don't index, just print")
    args = parser.parse_args()

    sessions = extract_sessions(hours=args.hours)
    if not sessions:
        print("[!] No sessions found")
        return

    # Only enrich sessions that have actual commands (skip credential harvesters with no post-login)
    active_sessions = {pid: s for pid, s in sessions.items() if s["commands"]}
    passive_sessions = {pid: s for pid, s in sessions.items() if not s["commands"]}

    print(f"\n  Active sessions (post-login commands): {len(active_sessions)}")
    print(f"  Passive sessions (login + disconnect):  {len(passive_sessions)}")

    if active_sessions:
        print(f"\n[*] Enriching {len(active_sessions)} active sessions with geo data...")
        enrich_sessions(active_sessions)

    # Print active sessions
    for pid, sess in sorted(active_sessions.items(), key=lambda x: -len(x[1]["commands"])):
        tags = ", ".join(sorted(sess["behavior_tags"])) if sess["behavior_tags"] else "recon_only"
        print(f"\n  {sess['attacker_ip']} (PID {pid}) — {len(sess['commands'])} commands")
        print(f"    Country: {sess.get('country','?')}  ASN: {sess.get('asn','?')}  Org: {sess.get('org','?')}")
        print(f"    Tags: {tags}")
        print(f"    Creds tried: {', '.join(sess['credentials_tried'][:5])}")
        if sess["download_urls"]:
            print(f"    Downloads: {', '.join(sorted(sess['download_urls'])[:3])}")
        if sess["dropped_files"]:
            print(f"    Dropped: {', '.join(sorted(sess['dropped_files'])[:3])}")
        print(f"    Commands: {'; '.join(sess['commands'][:8])}")

    # Index all sessions (active ones with commands, passive ones as credential harvesters)
    all_sessions = {**active_sessions, **passive_sessions}
    if not args.dry_run:
        print(f"\n[*] Indexing to Elasticsearch...")
        index_sessions(all_sessions)

    print(f"\n[+] Done. {len(active_sessions)} active + {len(passive_sessions)} passive sessions.")


if __name__ == "__main__":
    main()
