# ELKIE — Home Network Security Operations Platform

A full-stack security operations platform running on a home lab, built around ELK (Elasticsearch, Logstash, Kibana), honeypots, automated malware analysis, and threat intelligence.

## Architecture

```
                         ┌──────────────────────────────────────┐
                         │         ELK Stack (192.168.50.3)     │
                         │                                      │
                         │  Elasticsearch + Kibana + Grafana    │
                         │                                      │
                         │  ┌───────────────────────────────┐   │
                         │  │     Sentinel Daemons          │   │
                         │  │  • Cowrie Sentinel            │   │
                         │  │  • ML Sentinel                │   │
                         │  │  • Sample Analyzer            │   │
                         │  │  • Outlook Sentinel           │   │
                         │  │  • Portscan Defender          │   │
                         │  └───────────────────────────────┘   │
                         │                                      │
                         │  ┌───────────────────────────────┐   │
                         │  │  MISP (Docker)                │   │
                         │  │  Threat Intel Platform        │   │
                         │  └───────────────────────────────┘   │
                         └───────┬──────────┬──────────┬────────┘
                                 │          │          │
                    SSH :64295   │  SSH :22 │  SSH :22 │
                                 │          │          │
                    ┌────────────▼┐  ┌──────▼──────┐  ┌▼─────────────┐
                    │   T-Pot     │  │   REMnux    │  │   Sandbox    │
                    │ 192.168.40.3│  │ 192.168.40.5│  │ 192.168.40.6 │
                    │             │  │             │  │              │
                    │ Cowrie      │  │ YARA, capa  │  │ Detonation   │
                    │ Dionaea     │  │ floss, LLM  │  │ auditd+pcap  │
                    │ Honeytrap   │  │ (qwen2.5)   │  │ Auto-restore │
                    │ + 20 more   │  │             │  │ via Proxmox  │
                    └─────────────┘  └─────────────┘  └──────────────┘
                     Honeypot Subnet (192.168.40.0/24) — Isolated
```

**Security model:** ELK (trusted network) initiates all connections. Honeypot subnet machines never connect back to the trusted network.

## Components

### Sentinel Daemons

All sentinels follow the same pattern: dataclass Config, argparse CLI, RotatingFileHandler, signal handling, state persistence, poll loop with exponential backoff, Discord webhook alerts.

#### Cowrie Sentinel (`cowrie_sentinel.py`)
Polls Elasticsearch for Cowrie SSH honeypot events, reconstructs attacker sessions, scores behavior, extracts IOCs, and alerts on high-value sessions.

- Session reconstruction from login → commands → file downloads → disconnect
- Behavioral scoring (credential stuffing, persistence, lateral movement, crypto mining, etc.)
- Classification: scanner, brute_forcer, credential_stuffer, interactive_attacker, advanced_threat
- Severity levels: low / medium / high / critical
- IOC extraction: credentials, URLs, IPs, domains, file hashes
- Grafana annotations for session timeline correlation

#### ML Sentinel (`ml_sentinel.py`)
Machine-learning-enhanced threat detection using Isolation Forest for anomaly detection across honeypot and sacrificial VM events.

- Behavioral baselines with scikit-learn Isolation Forest
- Feature extraction from sliding time windows
- Rule-based scoring supplementing ML (download-execute, reverse shells, disk wipe, etc.)
- Periodic model retraining
- Dual data source: honeypot containers + sacrificial VM auditd

#### Sample Analyzer (`sample_analyzer.py`)
Automated malware analysis pipeline — the core of the platform. Orchestrates a 9-step pipeline:

1. **Capture** — Polls ES for Cowrie/Dionaea file events + T-Pot directory scan fallback
2. **Fetch** — SCPs samples from T-Pot to local staging
3. **Static Analysis** — Submits to REMnux via SSH: YARA rules, capa (MITRE ATT&CK mapping), FLOSS (string deobfuscation), strings extraction, Ollama qwen2.5:14b LLM threat summary
4. **Dynamic Analysis** — Sandbox VM detonation: restores Proxmox snapshot via API, uploads sample, executes for 90s, captures pcap + auditd, collects process lists/network connections/new files, restores clean snapshot
5. **VirusTotal** — Hash lookup for detection ratio and vendor labels
6. **MalwareBazaar** — Auto-submits novel samples to abuse.ch with classification tags
7. **MISP** — Checks all IOCs against threat intel feeds, creates event with full IOC set
8. **Index** — Stores results in `malware-analysis` Elasticsearch index
9. **Discord Alert** — Rich embed with classification, YARA matches, capa capabilities, LLM assessment, VT detections, sandbox behavioral data, MISP correlations, investigation links

#### Outlook Sentinel (`outlook_sentinel.py`)
Email threat analysis via Microsoft Graph API. Monitors Outlook inbox in real-time.

- Sender reputation scoring (suspicious TLDs, brand impersonation detection)
- Phishing keyword analysis in subject and body
- URL extraction and suspicious URL pattern matching
- VirusTotal URL lookups for flagged URLs
- MISP IOC correlation for sender domains and URLs
- Whitelisted sender domains (LinkedIn, Reddit, banks, etc.) with higher thresholds
- Auto-moves emails scoring >= 0.7 to Junk Email folder (never deletes)
- Discord alerts for emails scoring >= 0.5
- OAuth device code flow with cached refresh tokens

#### Portscan Defender (`portscan_defender.py`)
Detects port scanning activity and triggers automated blocking.

### REMnux Static Analysis (`analyze_sample.sh`)
Bash script deployed to REMnux VM that runs the full static analysis toolkit:

- SHA256/MD5 hashing, file type identification
- `strings` — extracts URLs, IPs, paths, crypto keywords, C2 indicators
- `yara` — scans against ratdecoders rules + custom rules
- `capa` — capability analysis mapped to MITRE ATT&CK
- `floss` — deobfuscated/decoded strings for packed samples
- `peframe` — PE-only: imports, sections, packer detection
- **Ollama LLM** — feeds all results to qwen2.5:14b for classification, severity, IOCs, TTPs
- Outputs JSON to `/home/nalyzer/results/<sha256>.json`
- Idempotent, max 50MB samples, graceful degradation if tools unavailable

### MISP — Threat Intelligence Platform

Docker deployment (`misp/docker-compose.yml`) providing centralized IOC management:

- **Feeds:** CIRCL OSINT, Botvrij.eu, abuse.ch URLhaus, Feodo Tracker, MalwareBazaar
- **Integration:** Sample analyzer creates events and checks IOCs on every sample
- **Correlation:** Connects dots across samples over time
- **Stack:** misp-core, MariaDB 11, Redis 7, misp-modules

### Supporting Scripts

| Script | Purpose |
|--------|---------|
| `outlook_auth.py` | One-time OAuth device code flow for Outlook |
| `scanner_block.sh` | Port scanner blocking |
| `ReportIPs.sh` | Reports attacker IPs to AbuseIPDB (cron, every 6h) |

## Elasticsearch Indices

| Index | Retention | Purpose |
|-------|-----------|---------|
| `.ds-filebeat-8.19.8-*` | 30 days (ILM) | Honeypot raw events |
| `sacrificial-vm-*` | 14 days (ILM) | Sacrificial VM auditd/auth logs |
| `.ds-suricata-*` | 14 days (ILM) | Suricata IDS alerts |
| `malware-analysis` | Forever | Analyzed malware samples |

## Service Management

```bash
# Check all sentinels
systemctl status cowrie-sentinel ml-sentinel sample-analyzer outlook-sentinel

# Restart a sentinel
sudo systemctl restart sample-analyzer

# View logs
journalctl -u sample-analyzer -f

# MISP
cd ~/misp && sudo docker compose ps
```

## Grafana Dashboards

- **grafana-dashboard.json** — Home network monitoring (Suricata)
- **honeypot-grafana-dashboard.json** — Honeypot attack monitoring

### Dashboard Features

- Network overview, events over time, DNS queries, HTTP/TLS traffic
- Geographic attack maps (requires geo_point mapping)
- Top attackers, targeted ports, credential analysis
- Commands executed, malware downloads, attacker OS fingerprinting

## Filebeat & Suricata Configuration

- **Filebeat.yml** — Main config (optimized for 28GB RAM, 8 CPUs)
- **deploy-filebeat-config.sh** — Deployment script
- **elasticsearch-index-template.json** — Suricata field mappings
- **honeypot-elasticsearch-index-template.json** — Honeypot data mappings

### Supported T-Pot Honeypot Types

Cowrie, Dionaea, Suricata, p0f, SentryPeer, FATT, Tanner/Snare, Heralding, H0neytr4p, Conpot, Honeytrap, ADBHoney, CiscoASA, Wordpot, Miniprint

## Discord Alerts

All sentinels post to a shared Discord webhook with rich embeds including:
- Severity-coded colors and icons
- Country flags for attacker geolocation
- Investigation links (Grafana, VirusTotal, MalwareBazaar, AbuseIPDB)
- Verbosity modes: compact (phone), normal, verbose
