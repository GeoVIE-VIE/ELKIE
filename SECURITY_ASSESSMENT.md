# ELKIE Security Assessment

## Executive Summary

This audit reviewed the full ELKIE codebase — Python daemons, shell scripts, Docker/Ansible
deployment, web interfaces, and infrastructure configuration. The platform processes
**attacker-controlled data from honeypots**, making input validation and isolation critical.

**Overall security posture: Concerning for production use.**

Found **8 critical**, **15 high**, **12 medium**, and **8 low** severity issues across
the codebase. The most dangerous findings involve command injection in the malware analysis
pipeline and unauthenticated Elasticsearch exposure.

---

## CRITICAL Findings

### C1. Command Injection in sample_analyzer.py via Attacker-Controlled Data

**Severity: CRITICAL | CVSS: 9.8**

The core malware analysis pipeline passes attacker-influenced data (SHA256 hashes,
file paths, usernames) into shell commands without proper escaping. SHA256 values
originate from Elasticsearch documents populated by honeypot events that attackers control.

**Vulnerable patterns** (sample_analyzer.py):
```python
# Line ~1152 — SHA256 from ES injected into grep via shell
f"find {sample_dir} -type f -exec sha256sum {{}} \\; 2>/dev/null | grep '^{sha256}' | head -1"

# Line ~1329 — SHA256 in bash command argument
f"nohup bash {self.cfg.remnux_script} {remote_sample} > /tmp/analysis_{sha256[:16]}.log 2>&1 &"

# Line ~3701 — DNS IP in sudo bash -c
f"sudo bash -c 'rm -f /etc/resolv.conf && echo nameserver {dns_ip} > /etc/resolv.conf'"
```

**Exploitation**: An attacker who controls a honeypot sample's metadata in ES can inject
shell commands that execute on the ELK analysis server — the most trusted host in the
architecture.

**Fix**: Use `shlex.quote()` on all interpolated values, or refactor to array-form
`subprocess.run()` calls without `shell=True`.

---

### C2. Elasticsearch Has No Authentication or Authorization

**Severity: CRITICAL | CVSS: 9.8**

Both Docker Compose files disable all Elasticsearch security:
```yaml
# deploy/docker-compose.yml AND elk/docker-compose.yml
xpack.security.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
```

Port 9200 is exposed on `${ELK_IP:-0.0.0.0}` — if the env var is unset, ES binds to
**all interfaces**. Anyone who can reach port 9200 gets full read/write/delete access to:
- All honeypot logs (attacker IPs, credentials, commands)
- Malware analysis results and IOCs
- Campaign correlation data
- ML model outputs

The nginx ingest proxy on port 5044 blocks reads from the honeypot subnet, but this
doesn't protect against access from the LAN, management VLAN, or any compromised host
on the trusted network.

**Fix**: Enable `xpack.security.enabled: true`, create ES users with least-privilege
roles, bind to specific interfaces only.

---

### C3. Unsafe Pickle Deserialization in ml_sentinel.py

**Severity: CRITICAL | CVSS: 9.1**

```python
# ml_sentinel.py ~line 339
with open(self._model_path(), "rb") as f:
    self.model = pickle.load(f)    # Arbitrary code execution
with open(self._scaler_path(), "rb") as f:
    self.scaler = pickle.load(f)   # Arbitrary code execution
```

If an attacker gains write access to `/home/legs/ml_models/` (weak permissions, shared
filesystem, or supply chain), they can replace the pickle files with payloads that execute
arbitrary Python code when the ML sentinel restarts.

**Fix**: Use `safetensors`, `joblib` with explicit dtype whitelisting, or JSON-based
model serialization.

---

### C4. Race Condition in PAM State File Bypasses Brute-Force Protection

**Severity: CRITICAL | CVSS: 8.8**

```python
# honeypot_pam.py — no locking between load and save
state = load_state()     # Read JSON from disk
# ... modify state ...
save_state(state)        # Write JSON to disk — overwrites concurrent changes
```

The custom PAM module is called concurrently by multiple SSH connections. Without file
locking, simultaneous connections can race on the state file, resetting each other's
failure counters. An attacker with parallel connections can bypass the randomized
brute-force threshold entirely.

**Fix**: Use `fcntl.flock()` or atomic rename (`write to temp, rename over original`).

---

### C5. Command Injection in ReportIPs.sh via Attacker IP Addresses

**Severity: CRITICAL | CVSS: 8.5**

```bash
# ReportIPs.sh ~line 40 — attacker IP directly in Python string
ip = "$IP"  # Shell variable interpolated into Python code
```

Attacker IPs from Elasticsearch are interpolated directly into inline Python code
within a bash script. An IP like `1.2.3.4"; import os; os.system("rm -rf /"); #` would
execute arbitrary commands.

**Fix**: Pass IPs as command-line arguments or stdin, validate IP format with regex
before use.

---

### C6. Plaintext Passwords Logged to Elasticsearch

**Severity: CRITICAL | CVSS: 7.5**

```python
# honeypot_pam.py ~line 104
entry = {
    "username": username,
    "password": password,    # Cleartext → JSON → Filebeat → Elasticsearch
    "auth_success": success,
}
```

Every SSH authentication attempt logs the cleartext password to a JSON file, which
Filebeat ships to Elasticsearch. This creates a searchable database of every password
attackers try — including any real credentials they may test.

**Fix**: Hash or mask passwords before logging (`password[:2] + "***"`).

---

### C7. Default Credentials in Production Services

**Severity: CRITICAL | CVSS: 7.4**

Multiple services fall back to default passwords when env vars aren't set:
```yaml
# deploy/docker-compose.yml
GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASS:-changeme}

# misp/docker-compose.yml
MISP_MYSQL_PASSWORD=${MISP_MYSQL_PASSWORD:-changeme}
MISP_ADMIN_PASSPHRASE=${MISP_ADMIN_PASSPHRASE:-changeme}
command: redis-server --requirepass redispassword  # Hardcoded
```

**Fix**: Remove all default passwords; fail to start if required secrets are missing.

---

### C8. Unvalidated Attacker Data Flows Through Entire Pipeline

**Severity: CRITICAL | CVSS: 7.2**

All sentinel daemons trust Elasticsearch data without validation. Attacker-controlled
fields (IPs, usernames, passwords, commands, file paths) from honeypot events flow
directly into:
- Shell commands (command injection — C1, C5)
- Log messages (log injection)
- Grafana URL construction (URL injection)
- Discord webhook embeds (content injection)
- PDF report generation
- Python `repr()` in embedded scripts (code injection)

There is no central input validation or sanitization layer.

**Fix**: Add validation functions for each data type (IPs, hashes, paths, commands)
and apply at the ES data ingestion boundary in each sentinel.

---

## HIGH Findings

### H1. SSH StrictHostKeyChecking Disabled Everywhere

All SSH connections disable host key verification:
```python
# sample_analyzer.py, session_correlator.py, etc.
"ssh", "-o", "StrictHostKeyChecking=no"
```
```bash
# check_sacrificial.sh, deploy.sh
SSH_OPTS="-o StrictHostKeyChecking=no"
```

Enables MITM attacks on the honeypot subnet. An attacker who compromises any host
on the subnet can intercept analysis commands and sample transfers.

### H2. SSH Passwords Visible in Process List

```python
ssh_args_pw = ["sshpass", "-p", password, "ssh", ...]
```

`sshpass` passes the password as a command-line argument, visible in `ps aux` output
and process accounting logs. Any user on the ELK host can harvest SSH credentials.

### H3. No TLS on Elasticsearch or Filebeat Communication

All ES traffic is HTTP. Filebeat ships logs unencrypted over the network. Log data
(including attacker credentials, commands, and analysis results) is visible to anyone
with network access.

### H4. Session Correlator Embeds Attacker Data in Python Script

```python
# session_correlator.py — attacker-controlled PIDs embedded in code
script = f'''
sshd_pids = set({list(sessions.keys())!r})
'''
```

While `repr()` provides some escaping, attacker-influenced session IDs flow into
Python code executed on the sacrificial VM.

### H5. Unquoted Shell Variables in Multiple Scripts

`check_sacrificial.sh`, `ReportIPs.sh`, `deploy.sh`, and `scanner_block.sh` use
unquoted variable expansion in command contexts, enabling word splitting and
glob expansion attacks.

### H6. ip-api.com Queried Over HTTP (Not HTTPS)

```python
# session_correlator.py
resp = requests.get(f"http://ip-api.com/json/{ip}?fields=...")
```

GeoIP data fetched over plaintext HTTP. MITM can inject false geolocation data
to mislead analysts.

### H7. No CSRF Protection on SOC Portal

The SOC portal `sessions.html` makes POST requests to the ES proxy with no CSRF
tokens. An attacker who knows the portal URL can forge requests via a malicious page.

### H8. XSS Risk in SOC Portal

While basic escaping exists (`esc()` function), attacker commands are injected into
HTML via string concatenation. A defense-in-depth approach should use
`textContent`/`createElement` instead of innerHTML.

### H9. Docker Containers Have No Resource Limits

No `deploy_resources` limits in any Docker Compose file. A runaway container
(or attacker-triggered OOM) can take down the entire host.

### H10. Grafana Allows Embedding Without Frame Protection

```yaml
GF_SECURITY_ALLOW_EMBEDDING=true
```

Combined with no SameSite cookie attribute, this enables clickjacking attacks
against authenticated Grafana sessions.

### H11. Symlink/TOCTOU Race in Sample Staging

Files are written to `STAGING_DIR` then checked. Between write and check, a local
attacker could replace the file with a symlink to exfiltrate or corrupt data.

### H12. API Keys Loaded Into Memory Without Protection

All API keys (Claude, VT, MISP, AbuseIPDB, Shodan, Proxmox) are stored as plain
Python strings. Memory dumps, core files, or exception tracebacks could leak them.

### H13. Ghidra MCP Server Has No Authentication

```python
# ghidra_mcp_server.py — HTTP server with no auth
PORT = int(os.environ.get("MCP_SERVER_PORT", "8080"))
```

Anyone who can reach port 8080 on REMnux can decompile functions, list strings,
and explore binaries loaded in Ghidra.

### H14. No Audit Trail for Analyst Actions

No logging of who accessed which dashboard, acknowledged which alert, or queried
which data. Required for SOC compliance (SOC 2, ISO 27001).

### H15. Log Injection Across All Daemons

Attacker-controlled data (usernames, passwords, commands, IPs) is logged via
Python's `logging` module with `%s` formatting. While Python's logger doesn't
interpret format strings, the log output can contain newlines, ANSI escapes,
and JSON-breaking characters that confuse log parsers and SIEM tools.

---

## MEDIUM Findings

| ID | Finding | Location |
|----|---------|----------|
| M1 | State files created without explicit permissions (umask-dependent) | All sentinels |
| M2 | No input length limits on ES data (memory exhaustion possible) | All sentinels |
| M3 | Ansible playbooks don't use Vault for secrets | deploy/ansible/ |
| M4 | Self-signed TLS certs without certificate pinning | deploy/nginx/ssl-gen.sh |
| M5 | No backup automation for ES data volumes | deploy/docker-compose.yml |
| M6 | Config paths (`remnux_inbox`, `remnux_script`) unquoted in commands | sample_analyzer.py |
| M7 | No minimum file size validation (zero-byte samples processed) | sample_analyzer.py |
| M8 | Broad exception catching masks errors (`except Exception`) | All sentinels |
| M9 | Decoy credentials use realistic AWS key format (AKIA prefix) | setup_honeypot_decoys.sh |
| M10 | No integrity checking on deployed scripts | deploy/deploy.sh |
| M11 | nginx root path allows non-GET methods to proxy to ES | deploy/nginx/nginx.conf |
| M12 | Flask recon dashboard is single-threaded (DoS risk) | recon-dashboard-v2/app.py |

---

## LOW Findings

| ID | Finding | Location |
|----|---------|----------|
| L1 | Python `random` module used for security-relevant values | honeypot_pam.py |
| L2 | SSH public key committed to repository | deploy_key_to_sacrificial.sh |
| L3 | No connection limits on Ghidra MCP HTTP server | ghidra_mcp_server.py |
| L4 | Overly broad TLD regex could match internal domains | cowrie_sentinel.py |
| L5 | No Grafana SameSite cookie attribute | deploy/docker-compose.yml |
| L6 | Redis password visible in Docker process list | misp/docker-compose.yml |
| L7 | File descriptor held during slow SSH transfers | sample_analyzer.py |
| L8 | No GPG signature verification on scripts | All shell scripts |

---

## Attack Scenarios

### Scenario 1: Honeypot-to-ELK Pivot via Command Injection

1. Attacker drops a malware sample on Cowrie with a crafted filename
2. Cowrie logs the event to Elasticsearch with attacker-controlled metadata
3. `sample_analyzer.py` polls ES, retrieves the event, passes the SHA256/filename
   into a shell command without escaping
4. Attacker's injected command executes on the ELK server — the most privileged host
5. Attacker now has access to all API keys, ES data, and the trusted network

**Likelihood: HIGH** — The attack surface is the core analysis pipeline that processes
every sample automatically.

### Scenario 2: Elasticsearch Data Exfiltration

1. Attacker on LAN (or any compromised host) discovers ES on port 9200
2. No authentication: `curl http://192.168.50.3:9200/malware-analysis/_search?size=10000`
3. Exfiltrates all malware analysis results, attacker TTPs, campaign clusters
4. Uses this intelligence to understand which attacks were detected and adapt

**Likelihood: HIGH** — ES is exposed with zero auth on the network.

### Scenario 3: PAM Race Condition Bypass

1. Attacker opens 50 parallel SSH connections to the sacrificial VM
2. Race condition in state file corrupts failure counters
3. Attacker bypasses brute-force protection, gains access on first attempt
4. Explores decoy environment, exfiltrates honeytoken data
5. Downloads and analyzes monitoring scripts to understand detection capabilities

**Likelihood: MEDIUM** — Requires parallel connections but is easily automated.

### Scenario 4: ML Model Poisoning via Pickle Replacement

1. Attacker compromises any service running as the same user as `ml_sentinel.py`
2. Replaces `/home/legs/ml_models/isolation_forest.pkl` with a malicious pickle
3. On next restart or retrain, `pickle.load()` executes arbitrary code
4. Attacker has persistent access even after the initial vector is patched

**Likelihood: LOW-MEDIUM** — Requires prior access but provides persistent backdoor.

---

## Remediation Priority

### Immediate (This Week)

| Priority | Action | Impact |
|----------|--------|--------|
| P0 | Enable `xpack.security` on Elasticsearch | Blocks unauthenticated access |
| P0 | Add `shlex.quote()` to all shell-interpolated values in sample_analyzer.py | Blocks command injection |
| P0 | Fix ReportIPs.sh IP injection (validate format: `^[0-9.]+$`) | Blocks command injection |
| P0 | Add `fcntl.flock()` to honeypot_pam.py state file operations | Fixes race condition |
| P1 | Replace `pickle.load()` with safe alternative in ml_sentinel.py | Blocks code execution |
| P1 | Bind ES to specific IP, not 0.0.0.0 | Reduces exposure surface |
| P1 | Remove default passwords from Docker Compose files | Prevents default cred access |

### Short Term (2 Weeks)

| Priority | Action | Impact |
|----------|--------|--------|
| P2 | Enable SSH `StrictHostKeyChecking` and maintain known_hosts | Blocks MITM |
| P2 | Replace `sshpass` with key-only authentication | Removes credential exposure |
| P2 | Add CSRF tokens to SOC portal | Blocks cross-site request forgery |
| P2 | Add input validation for IPs, hashes, and paths at ES query boundary | Defense in depth |
| P2 | Enable TLS for ES and Filebeat communication | Encrypts data in transit |
| P2 | Add Docker resource limits to all containers | Prevents DoS |
| P2 | Hash passwords before logging in honeypot_pam.py | Reduces credential exposure |

### Medium Term (1 Month)

| Priority | Action | Impact |
|----------|--------|--------|
| P3 | Add authentication to Ghidra MCP server | Blocks unauthorized RE access |
| P3 | Implement Ansible Vault for all secrets | Secure secret management |
| P3 | Add audit logging for analyst actions | Compliance readiness |
| P3 | Implement log sanitization layer | Blocks log injection |
| P3 | Add certificate pinning for internal TLS | Stronger MITM protection |
| P3 | Set explicit file permissions (0600) on all state files | Blocks local reads |

---

## Summary

The most dangerous pattern in ELKIE is that **attacker-controlled data from honeypots
flows through shell commands without sanitization**. This is the architectural equivalent
of a SQL injection — the system designed to observe attackers can be used by attackers
to compromise the observer.

The second major concern is **Elasticsearch with no authentication**. This is the central
nervous system of the SOC — all intelligence, all analysis, all credentials pass through
it — and it's wide open to anyone on the network.

The good news: the VLAN segmentation and ingest-only proxy show security-conscious
design intent. The issues are implementation gaps, not architectural flaws. The P0
fixes above can be applied in a day and dramatically improve the security posture.
