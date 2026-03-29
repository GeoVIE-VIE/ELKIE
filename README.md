# ELKIE — Home Network Security Operations Platform

A full-stack security operations platform running on a Dell R640 (96 cores, 128GB RAM) home lab, built around ELK (Elasticsearch, Kibana), honeypots, automated malware analysis, threat intelligence, and a sacrificial SSH honeypot with custom PAM authentication.

## Architecture

```
    Internet
       │
       │ Port 22 (NAT)
       ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                           pfSense (192.168.0.1)                                │
│                     Gateway / Firewall / NAT / NTP                             │
└──┬──────────────┬──────────────┬──────────────┬──────────────┬─────────────────┘
   │              │              │              │              │
 VLAN 0        VLAN 2        VLAN 40        VLAN 50        VLAN 99
  LAN           Kali       Honeypot Net   Trusted Net     Mgmt Net
192.168.0.x   192.168.2.x  192.168.40.x   192.168.50.x   192.168.99.x
   │              │              │              │              │
   │         ┌────▼────┐        │              │         ┌────▼─────────────┐
   │         │  Kali   │        │              │         │    Proxmox       │
   │         │  .2.160 │        │              │         │  192.168.99.160  │
   │         │ Shodan  │        │              │         │                  │
   │         │ Recon   │        │              │         │  Dell R640       │
   │         └─────────┘        │              │         │  96 cores        │
   │                            │              │         │  128GB RAM       │
   │                            │              │         │                  │
   │                            │              │         │  VM lifecycle    │
   │                            │              │         │  API :8006       │
   │                            │              │         │  Snapshots       │
   │                            │              │         │  Auto start/stop │
   │                            │              │         └──────────────────┘
   │                            │              │                 ▲
   │                            │              │                 │ API :8006
   │                            │         ┌────▼─────────────────┴─────────┐
   │                            │         │    ELK Stack (192.168.50.3)    │
   │                            │         │                                │
   │                            │         │  Elasticsearch + Kibana        │
   │                            │         │  Grafana (78-panel dashboard)  │
   │                            │         │                                │
   │                            │         │  ┌──────────────────────────┐  │
   │                            │         │  │   Sentinel Daemons       │  │
   │                            │         │  │ • Sample Analyzer        │  │
   │                            │         │  │ • Cowrie Sentinel        │  │
   │                            │         │  │ • ML Sentinel            │  │
   │                            │         │  │ • Outlook Sentinel       │  │
   │                            │         │  │ • Honeytoken Monitor     │  │
   │                            │         │  └──────────────────────────┘  │
   │                            │         │                                │
   │                            │         │  ┌──────────────────────────┐  │
   │                            │         │  │ Docker Containers        │  │
   │                            │         │  │ • MISP (Threat Intel)    │  │
   │                            │         │  │ • OpenCTI (Graph Intel)  │  │
   │                            │         │  └──────────────────────────┘  │
   │                            │         │                                │
   │                            │         │  SOC Portal (:9090)            │
   │                            │         │  PDF Reports (:9090/reports)   │
   │                            │         └──────┬─────────────────────────┘
   │                            │                │
   │                            │        SSH :64295 (key auth)
   │                            │                │
   │                       ┌────▼────────────────▼──────────┐
   │                       │       T-Pot (192.168.40.3)      │
   │                       │                                  │
   │                       │  Cowrie (SSH :22, shell mode)    │
   │                       │  Dionaea (FTP :21, MySQL :3306)  │
   │                       │  Tanner/Snare (HTTP :80)         │
   │                       │  H0neytr4p (HTTPS :443)          │
   │                       │  + 15 more honeypots             │
   │                       │                                  │
   │                       │  Jump host for sacrificial VM    │
   │                       └────────┬───────────┬─────────────┘
   │                                │           │
   │                         SSH :22│    SSH :22│
   │                                │           │
   │              ┌─────────────────▼┐   ┌──────▼──────────┐
   │              │  Sacrificial VM   │   │    REMnux       │
   │              │  192.168.40.99    │   │  192.168.40.5   │
   │              │                   │   │                 │
   │              │  Custom PAM Auth  │   │  YARA, capa     │
   │              │  Per-IP brute sim │   │  floss, strings │
   │              │  3-100 failures   │   ��  UPX 5.0 unpack │
   │              │  7-day IP memory  │   │  Ghidra MCP     │
   │              │                   │   │  (headless HTTP  │
   │              │  20 fake users    │   │   server for     │
   │              │  Crypto wallets   │   │   interactive    │
   │              │                   │   │   RE via Claude) │
   │              │                   │   │  Auto start/stop│
   │              │                   │   │  via Proxmox API│
   │              │  AWS/K8s creds    │
   │              │  Jenkins configs  │   ┌─────────────────┐
   │              │  Webapp .env      │   │    Sandbox      │
   │              │                   │   │  192.168.40.6   │
   │              │  Filebeat → ES    │   │                 │
   │              │  Auditd logging   │   │  Detonation VM  │
   │              └───────────────────┘   │  90s execution  │
   │                                      │  pcap + auditd  │
   │                                      │  Auto-restore   │
   │                                      │  via Proxmox API│
   │                                      └─────────────────┘
   │
┌──▼──────────────────────┐
│   Home Network Devices   │
│  TrueNAS, IoT, phones,  │
│  cameras, smart bulbs    │
│  Suricata IDS monitoring │
└──────────────────────────┘
```

### Network Security Model

- **ELK (trusted net)** initiates all connections — honeypot subnet never connects back
- **Elasticsearch isolation** — honeypot subnet has no access to ES :9200. Logs ship through an nginx ingest-only proxy on :5044 that allows `POST`/`PUT` (writes) and blocks all reads (`_search`, `_cat`, `_cluster`). Even with shell access on a honeypot, attackers cannot query logs or map the internal network
- **Sacrificial VM** accessed only via T-Pot jump host (`ssh -J`)
- **REMnux** auto-started/stopped via Proxmox API — only runs during analysis
- **Sandbox** snapshot restored after every detonation
- **pfSense** NATs external SSH to sacrificial VM for real attacker traffic

## Components

### Sample Analyzer (`sample_analyzer.py`)

Automated malware analysis pipeline — the core of the platform. Orchestrates a 10-step pipeline:

1. **Capture** — ES file events (Cowrie/Dionaea) + auditd execve monitoring + sacrificial VM filesystem scan + T-Pot directory scan + `/proc/PID/exe` fallback for self-deleting malware
2. **Fetch** — Pulls samples from T-Pot (SCP) or sacrificial VM (`ssh+cat` through jump host), with `/proc/PID/exe` recovery for deleted binaries
3. **Static Analysis** — Submits to REMnux via SSH: YARA rules, capa (MITRE ATT&CK mapping), FLOSS (string deobfuscation), UPX 5.0 unpacking, strings extraction
4. **Dynamic Analysis** — Sandbox VM detonation: restores Proxmox snapshot, uploads sample, executes for 90s under strace, captures pcap + auditd + filesystem diff + INetSim DNS logs, memory dump via LiME, restores clean snapshot
5. **VirusTotal + MalwareBazaar** — Hash lookup for detection ratio/vendor labels, auto-submits novel samples to abuse.ch
6. **Claude API Threat Assessment** — LLM analysis with full behavioral evidence (runs AFTER dynamic analysis): threat hypothesis with evidence chain, IP/domain reputation context, MITRE ATT&CK mapping, auto-generated YARA rules
7. **Ghidra MCP Interactive Analysis** — Scored trigger (>40 points, max 1/day): Claude autonomously explores binary via Ghidra headless HTTP API — decompiles functions, follows xrefs, traces call chains (15-turn agent loop, ~$0.20/sample)
8. **MISP/OpenCTI** — Creates events with full IOC set, checks against threat intel feeds
9. **Reporting** — PDF report, Discord webhook alert, Elasticsearch indexing, Sigma detection rules, ATT&CK Navigator heatmap
10. **False Positive Filtering** — Persistent allowlist + regex patterns (fake kernel threads, decoy files), 10-min auditd cooldown for repeated detections

### Sacrificial VM Honeypot

A realistic-looking "production server" that attackers SSH into after brute-forcing:

- **Custom PAM module** (`honeypot_pam.py`) — replaces standard SSH auth
  - Per-IP credential memory: remembers what worked for returning attackers
  - Randomized failure threshold (3-100 attempts per IP) simulates realistic brute force
  - 7-day IP state retention
  - JSON auth logging → Filebeat → Elasticsearch
- **Decoy environment** (`setup_honeypot_decoys.sh`) — 20 user accounts, bash histories with "leaked" passwords, fake AWS/K8s/Vault credentials, cryptocurrency wallet configs, Jenkins secrets, webapp .env files, nginx configs, cron jobs, systemd services
- **Monitoring** — Auditd tracks all commands, Filebeat ships everything to ES, Grafana dashboard shows auth attempts, successful logins, top passwords, process activity

### Sentinel Daemons

All sentinels follow the same pattern: dataclass Config, argparse CLI, RotatingFileHandler, signal handling, state persistence, poll loop with exponential backoff, Discord webhook alerts.

| Daemon | Purpose |
|--------|---------|
| `sample_analyzer.py` | Malware analysis pipeline (10-step, see above) |
| `cowrie_sentinel.py` | Cowrie session reconstruction, behavioral scoring, IOC extraction |
| `ml_sentinel.py` | Isolation Forest anomaly detection across honeypot + sacrificial VM |
| `outlook_sentinel.py` | Email threat analysis via Microsoft Graph API |
| `honeytoken_monitor.py` | Canary file access detection on sacrificial VM |

### REMnux Static Analysis (`analyze_sample.sh`)

Bash script deployed to REMnux VM:

- SHA256/MD5 hashing, file type identification
- UPX 5.0 unpacking (tries `upx5` then `upx`) with size change logging
- `strings` — extracts URLs, IPs, paths, crypto keywords, C2 indicators
- `yara` — scans against ratdecoders rules + custom rules
- `capa` — capability analysis mapped to MITRE ATT&CK
- `floss` — deobfuscated/decoded strings for packed samples
- `peframe` — PE-only: imports, sections, packer detection
- Outputs JSON to `/home/nalyzer/results/<sha256>.json`

### Threat Intelligence

- **MISP** — Docker deployment with feeds: CIRCL OSINT, Botvrij.eu, abuse.ch URLhaus, Feodo Tracker, MalwareBazaar
- **OpenCTI** — Graph-based intel with connectors: MISP, MITRE ATT&CK, AbuseIPDB, CVE
- **Shodan Recon Dashboard v2** — IP-level host tracking (not counts) with 3x daily readings, intersection averaging to eliminate Shodan's 15-25% variance, Censys Platform API v3 cross-validation, nmap SYN verification of disappeared hosts, automated Discord change summaries
- **Campaign Clustering** — Groups attacker IPs by shared malware, SSH keys, download URLs, and subnet proximity

### Supporting Scripts

| Script | Purpose |
|--------|---------|
| `rebuild_honeypot_dashboard.py` | Rebuilds 78-panel Grafana dashboard via API |
| `setup_honeypot_decoys.sh` | Populates sacrificial VM with realistic decoy files |
| `setup_sacrificial_honeypot.sh` | Deploys PAM auth module to sacrificial VM |
| `deploy_key_to_sacrificial.sh` | SSH key deployment for sacrificial VM access |
| `generate_report.py` | PDF threat report generation per sample |
| `generate_sigma_rules.py` | Auto-generates Sigma detection rules |
| `generate_attack_navigator.py` | MITRE ATT&CK Navigator heatmap |
| `ReportIPs.sh` | Reports attacker IPs to AbuseIPDB (cron, every 6h) |

| `shodan_recon.py` | Country infrastructure recon with Shodan API |
| `campaign_clusterer.py` | Clusters attacker IPs by shared malware/SSH keys/URLs (cron, daily) |
| `session_correlator.py` | Maps post-login commands to attacker IPs via auditd (cron, 2h) |
| `ghidra_mcp_server.py` | Jython HTTP server for headless Ghidra MCP — decompile, xrefs, strings |

### Recon Dashboard v2 (`recon-dashboard-v2/`)

Flask app on Kali (192.168.2.160:5000) with IP-level infrastructure tracking:

- **3x daily Shodan collection** (02:00, 10:00, 18:00 UTC) — 7 countries x 12 sectors = 252 queries/day
- **Intersection averaging** — only hosts seen in 2+ of 3 readings survive consolidation, eliminating Shodan's variance
- **Censys cross-validation** — Platform API v3 host lookups confirm changes (8/day budget)
- **Nmap verification** — SYN scan on specific ports for disappeared hosts (10/day budget)
- **Change detection** — appeared/disappeared/modified with confidence scoring
- **Discord daily summary** — per-country change report at 20:00 UTC
- **Threat intel feeds** — 21 RSS sources + GDELT + CISA KEV with bias detection and cross-corroboration

### Cisco Lab (`cisco_lab/`)

GNS3-based networking lab on dedicated VM (192.168.30.10):

- 120 scenarios (CCNA + CCNP): OSPF, BGP, EIGRP, MPLS, VRF, DMVPN, GRE, security hardening
- `labctl` CLI for scenario management, snapshots, router console access
- Web UI with mobile-friendly interface
- CSR1000v routers (R1-R4) with automatic topology configuration

## Elasticsearch Indices

| Index | Retention | Purpose |
|-------|-----------|---------|
| `.ds-filebeat-8.19.9-*` | 30 days (ILM) | Honeypot raw events + sacrificial VM auth/auditd |
| `.ds-suricata-*` | 14 days (ILM) | Suricata IDS alerts (46M+ events) |
| `malware-analysis` | Forever | Analyzed malware samples with full results |
| `campaign-clusters` | Forever | Attacker campaign groupings |
| `attacker-sessions` | Forever | Post-login command correlation |

## Grafana Dashboards

### Honeypot Threat Overview (`rebuild_honeypot_dashboard.py`)
78 panels across 8 sections:
- **Overview** — Total events, unique attackers, top source countries
- **Cowrie SSH** — Sessions, commands, credentials, file downloads
- **Dionaea** — FTP/MySQL exploit attempts, payload captures
- **Web Honeypots** — Tanner (HTTP) + H0neytr4p (HTTPS) traffic
- **Attacker Intelligence** — IP reputation, geo distribution, TTPs
- **Malware Samples** — Analysis results, classifications, YARA matches
- **Sacrificial VM — SSH Honeypot** — Auth attempts, successful logins, top passwords, auth reasons
- **Sacrificial VM — Auditd** — Process activity, executables, network connections

### Home Network Monitor (local only — not tracked in git)
Suricata IDS monitoring with device IP filter, event type filtering, network overview, DNS/HTTP/TLS traffic analysis, and security alerts.

## SOC Portal

Web portal at `:9090` (nginx) with quick-access cards for:
- Grafana, MISP, OpenCTI, Kibana
- Malware PDF reports (browseable at `/reports/`)
- Shodan recon dashboard (Kali)
- Proxmox hypervisor management

## Service Management

```bash
# Check all sentinels
systemctl status cowrie-sentinel ml-sentinel sample-analyzer outlook-sentinel

# Restart a sentinel
sudo systemctl restart sample-analyzer

# View logs
journalctl -u sample-analyzer -f

# MISP + OpenCTI
cd ~/misp && sudo docker compose ps
cd ~/opencti && sudo docker compose ps

# Rebuild Grafana dashboard
GRAFANA_TOKEN=<token> python3 rebuild_honeypot_dashboard.py
```

## Infrastructure

| Host | IP | Role |
|------|----|------|
| ELK | 192.168.50.3 | Elasticsearch, Kibana, Grafana, sentinels, MISP, OpenCTI |
| T-Pot | 192.168.40.3 | Honeypot suite (Cowrie, Dionaea, etc.), jump host |
| Sacrificial VM | 192.168.40.99 | SSH honeypot with PAM auth + decoys |
| REMnux | 192.168.40.5 | Static malware analysis (auto start/stop) |
| Sandbox | 192.168.40.6 | Dynamic analysis / detonation (auto snapshot restore) |
| Kali | 192.168.2.160 | Shodan recon dashboard v2, threat intel feeds |
| Cisco Lab | 192.168.30.10 | GNS3 networking lab, 120 scenarios, web UI |
| Proxmox | 192.168.99.160 | Hypervisor — VM lifecycle via API |
| pfSense | 192.168.0.1 | Gateway, firewall, NAT, NTP |

## Discord Alerts

All sentinels post to a shared Discord webhook with rich embeds including:
- Severity-coded colors and icons
- Country flags for attacker geolocation
- Investigation links (Grafana, VirusTotal, MalwareBazaar, AbuseIPDB)
- Auto-generated YARA rules and MITRE ATT&CK mappings
- Verbosity modes: compact (phone), normal, verbose
