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
   │                            │         │  │ • Traffic Noise Gen      │  │
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
   │              │  3-100 failures   │   │  UPX 5.0 unpack │
   │              │  7-day IP memory  │   │  Ghidra (deep)  │
   │              │                   │   │  Auto start/stop│
   │              │  20 fake users    │   │  via Proxmox API│
   │              │  Crypto wallets   │   └─────────────────┘
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

1. **Capture** — Polls ES for Cowrie/Dionaea file events + directory scan fallback + sacrificial VM scan via T-Pot jump host
2. **Fetch** — Pulls samples from T-Pot (SCP) or sacrificial VM (`ssh+cat` through jump host)
3. **Static Analysis** — Submits to REMnux via SSH: YARA rules, capa (MITRE ATT&CK mapping), FLOSS (string deobfuscation), UPX 5.0 unpacking, strings extraction
4. **Deep Ghidra Decompilation** — Scored trigger (>40 points, max 1/day): decompiles top 20 functions by size into readable C code
5. **Claude API Threat Assessment** — LLM analysis ($0.01/sample): classification, severity, IOCs, TTPs, auto-generated YARA rules
6. **Dynamic Analysis** — Sandbox VM detonation: restores Proxmox snapshot, uploads sample, executes for 90s, captures pcap + auditd + INetSim DNS logs, restores clean snapshot
7. **VirusTotal** — Hash lookup for detection ratio and vendor labels
8. **MalwareBazaar** — Auto-submits novel samples to abuse.ch with classification tags
9. **MISP/OpenCTI** — Creates events with full IOC set, checks against threat intel feeds
10. **Reporting** — PDF report generation, Discord webhook alert, Elasticsearch indexing

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
| `traffic_noise.py` | Privacy traffic generator (318K+ search queries) |
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
- **Shodan Recon** — Country infrastructure scanning with daily snapshots (Flask dashboard on Kali)

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
| `search_queries.py` | 318K+ template-based search query generation for traffic noise |
| `shodan_recon.py` | Country infrastructure recon with Shodan API |

## Elasticsearch Indices

| Index | Retention | Purpose |
|-------|-----------|---------|
| `.ds-filebeat-8.19.9-*` | 30 days (ILM) | Honeypot raw events + sacrificial VM auth/auditd |
| `.ds-suricata-*` | 14 days (ILM) | Suricata IDS alerts (46M+ events) |
| `malware-analysis` | Forever | Analyzed malware samples with full results |
| `traffic-noise` | 30 days | Privacy traffic generator logs |

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

### Home Network Monitor (`grafana-dashboard.json`)
Suricata IDS monitoring with device IP filter (hostname-mapped), event type filtering, and honeypot subnet isolation.

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
| Kali | 192.168.2.160 | Shodan recon dashboard |
| Proxmox | 192.168.99.160 | Hypervisor — VM lifecycle via API |
| pfSense | 192.168.0.1 | Gateway, firewall, NAT, NTP |

## Discord Alerts

All sentinels post to a shared Discord webhook with rich embeds including:
- Severity-coded colors and icons
- Country flags for attacker geolocation
- Investigation links (Grafana, VirusTotal, MalwareBazaar, AbuseIPDB)
- Auto-generated YARA rules and MITRE ATT&CK mappings
- Verbosity modes: compact (phone), normal, verbose
