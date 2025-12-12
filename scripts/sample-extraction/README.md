# Honeypot Sample Extraction & Analysis

Safely extract and analyze malware samples from T-Pot honeypot containers.

## Safety Features

- **noexec filesystem**: Samples stored on a dedicated mount with `noexec,nosuid,nodev`
- **Immediate permission removal**: Execute bits stripped immediately on extraction
- **Dedicated user**: Runs as unprivileged `honeypot-analyst` user
- **Chain of custody**: Full logging with hashes and timestamps
- **Size limits**: Configurable max file size to prevent storage attacks
- **Duplicate detection**: SHA256-based deduplication

## Quick Start

### 1. Setup Quarantine Directory

```bash
# Run as root - creates secure noexec filesystem
sudo ./setup-quarantine.sh
```

This creates:
- `/opt/honeypot-quarantine/` - Mounted with `noexec,nosuid,nodev`
- `honeypot-analyst` user for running extractions
- Proper directory structure for each honeypot type

### 2. Install Extraction Script

```bash
# Copy script to quarantine directory
sudo cp extract-samples.sh /opt/honeypot-quarantine/scripts/
sudo chmod +x /opt/honeypot-quarantine/scripts/extract-samples.sh
sudo chown honeypot-analyst: /opt/honeypot-quarantine/scripts/extract-samples.sh
```

### 3. Setup Systemd Timer (Automated Extraction)

```bash
# Install service and timer
sudo cp honeypot-extraction.service /etc/systemd/system/
sudo cp honeypot-extraction.timer /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable honeypot-extraction.timer
sudo systemctl start honeypot-extraction.timer

# Check status
sudo systemctl status honeypot-extraction.timer
sudo systemctl list-timers | grep honeypot
```

### 4. Manual Extraction

```bash
# Run extraction manually
sudo -u honeypot-analyst /opt/honeypot-quarantine/scripts/extract-samples.sh

# Or with custom settings
sudo -u honeypot-analyst \
    EXTRACTION_WINDOW=120 \
    MAX_FILE_SIZE=52428800 \
    /opt/honeypot-quarantine/scripts/extract-samples.sh
```

## Elasticsearch Integration

### Install Ingest Pipeline

```bash
# Using curl
curl -X PUT "localhost:9200/_ingest/pipeline/honeypot-samples" \
    -H "Content-Type: application/json" \
    -d @honeypot-samples-pipeline.json

# Or via Kibana Dev Tools - copy contents of honeypot-samples-pipeline.json
```

### Configure Filebeat

Add the contents of `filebeat-samples.yml` to your Filebeat configuration:

```bash
# Append to existing config
cat filebeat-samples.yml >> /etc/filebeat/filebeat.yml

# Or use as module
cp filebeat-samples.yml /etc/filebeat/inputs.d/honeypot-samples.yml
```

## Sample Analysis

### Install Dependencies

```bash
# YARA for malware detection
sudo apt install yara

# Get YARA rules (example: Yara-Rules project)
sudo git clone https://github.com/Yara-Rules/rules.git /opt/yara-rules

# Optional: ssdeep for fuzzy hashing
sudo apt install ssdeep

# Optional: inotify-tools for watch mode
sudo apt install inotify-tools
```

### Analyze Samples

```bash
# Analyze single sample by path
./analyze-sample.sh /opt/honeypot-quarantine/cowrie/2024/01/15/abc123...

# Analyze by SHA256 hash
./analyze-sample.sh e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# Batch analyze all unanalyzed samples
./analyze-sample.sh --batch

# Watch mode - analyze samples as they arrive
./analyze-sample.sh --watch
```

### VirusTotal Integration

```bash
# Set API key (get free key at virustotal.com)
export VT_API_KEY="your_api_key_here"

# Run analysis with VT lookup
./analyze-sample.sh /path/to/sample
```

## Directory Structure

```
/opt/honeypot-quarantine/
├── cowrie/
│   └── 2024/01/15/
│       ├── <sha256_hash>        # The sample (named by hash)
│       └── <sha256_hash>.name   # Original filename
├── dionaea/
├── glutton/
├── honeytrap/
├── tanner/
├── temp/                        # Temporary extraction area
├── archive/                     # Old samples
├── catalog.json                 # Full catalog of all samples
└── scripts/
    └── extract-samples.sh

/var/log/honeypot-extraction/
├── extraction.log               # Extraction activity log
├── samples.jsonl                # Sample metadata (for Filebeat)
└── analysis.jsonl               # Analysis results
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `QUARANTINE_BASE` | `/opt/honeypot-quarantine` | Base quarantine directory |
| `LOG_DIR` | `/var/log/honeypot-extraction` | Log directory |
| `EXTRACTION_WINDOW` | `60` | Extract files modified in last N minutes |
| `MAX_FILE_SIZE` | `104857600` | Max file size in bytes (100MB) |
| `RETENTION_DAYS` | `30` | Days to keep samples |
| `CLEANUP_OLD` | `false` | Enable automatic cleanup |
| `VT_API_KEY` | (none) | VirusTotal API key |
| `YARA_RULES_DIR` | `/opt/yara-rules` | YARA rules directory |

## T-Pot Container Paths

| Container | Sample Path | Type |
|-----------|-------------|------|
| cowrie | `/home/cowrie/cowrie-git/var/lib/cowrie/downloads` | SSH/Telnet downloads |
| dionaea | `/opt/dionaea/var/dionaea/binaries` | Malware binaries |
| glutton | `/var/lib/glutton` | Connection payloads |
| honeytrap | `/opt/honeytrap/var/attacks` | Attack data |
| tanner | `/opt/tanner/data` | Web attack files |

## Grafana Dashboard

The sample metadata can be visualized in Grafana using the Elasticsearch data source. Query examples:

```
# Count samples by honeypot type
honeypot.type:cowrie

# Find ELF executables
file.classification:executable

# Samples with YARA matches
_exists_:yara_matches

# VirusTotal detections
virustotal.malicious:>0
```

## Security Considerations

1. **Never mount quarantine with execute permissions**
2. **Don't analyze samples on production systems** - use isolated VMs
3. **Keep YARA rules updated** for better detection
4. **Monitor disk usage** - attackers may try to fill storage
5. **Rotate logs and samples** to manage storage
6. **Review before sharing** - samples may contain credentials

## Troubleshooting

### Extraction fails silently
```bash
# Check if containers are running
docker ps | grep -E 'cowrie|dionaea|honeytrap'

# Check permissions
ls -la /var/run/docker.sock
groups honeypot-analyst
```

### No samples being extracted
```bash
# Check container paths exist
docker exec cowrie ls -la /home/cowrie/cowrie-git/var/lib/cowrie/downloads/

# Increase extraction window
EXTRACTION_WINDOW=1440 ./extract-samples.sh  # Last 24 hours
```

### Permission denied
```bash
# Ensure user is in docker group
sudo usermod -aG docker honeypot-analyst

# Verify mount options
mount | grep quarantine
```
