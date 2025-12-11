# ELKIE - Filebeat Configuration for Suricata Logs

This repository contains the optimized Filebeat configuration for ingesting Suricata logs from pfSense into Elasticsearch.

## Files

- **Filebeat.yml** - Main Filebeat configuration (optimized for 28GB RAM, 8 CPUs, 10Gbps network)
- **Syslog-NG-Config.txt** - Syslog-NG configuration reference
- **deploy-filebeat-config.sh** - Deployment script
- **elasticsearch-index-template.json** - Index template for Suricata field mappings (geo_point, etc.)
- **grafana-dashboard.json** - Home network monitoring dashboard (Suricata)
- **honeypot-elasticsearch-index-template.json** - Index template for honeypot data (filebeat-8.19.8*)
- **honeypot-grafana-dashboard.json** - Dedicated honeypot monitoring dashboard

## Quick Fix for Current Issue

The Filebeat service is failing because it's using an old configuration with `grok` processor (not available). This repository contains the fixed configuration using `dissect` instead.

### Deploy the Fix

```bash
cd /home/user/ELKIE
sudo bash deploy-filebeat-config.sh
```

### Manual Deployment

If you prefer to deploy manually:

```bash
# Backup existing config
sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup

# Deploy new config
sudo cp Filebeat.yml /etc/filebeat/filebeat.yml

# Test configuration
sudo filebeat test config

# Restart service
sudo systemctl restart filebeat

# Monitor logs
sudo journalctl -u filebeat -f
```

## Configuration Details

The configuration handles JSON logs from Suricata via syslog-ng with the following processors:

1. **decode_json_fields** - Parses the JSON directly from the message field
2. **drop_fields** - Cleans up the original message field

**Note**: Syslog-NG must be configured with `template("$MESSAGE\n")` to send raw JSON without headers.

### GeoIP Enrichment Setup

The Filebeat config uses an Elasticsearch ingest pipeline for GeoIP enrichment. Create it before starting Filebeat:

```bash
curl -X PUT "localhost:9200/_ingest/pipeline/suricata-geoip" -H 'Content-Type: application/json' -d'
{
  "description": "Add GeoIP data to Suricata logs",
  "processors": [
    {
      "geoip": {
        "field": "src_ip",
        "target_field": "source.geo",
        "ignore_missing": true
      }
    },
    {
      "geoip": {
        "field": "dest_ip",
        "target_field": "destination.geo",
        "ignore_missing": true
      }
    }
  ]
}
'
```

This adds geographic data (country, city, coordinates) to your Suricata events for map visualizations.

### Index Template for Geo_Point Mapping

For map visualizations to work properly, the `source.geo.location` and `destination.geo.location` fields must be mapped as `geo_point`. Create this index template before ingesting data:

```bash
curl -X PUT "localhost:9200/_index_template/suricata-template" \
  -H 'Content-Type: application/json' \
  -d @elasticsearch-index-template.json
```

**Note**: Existing indices won't be affected. To apply the new mapping, either:
- Wait for new daily indices to be created (next day)
- Or delete and recreate the current index: `curl -X DELETE "localhost:9200/suricata-$(date +%Y.%m.%d)"`

## Grafana Dashboard

Import the included `grafana-dashboard.json` for a complete home network monitoring dashboard.

### Dashboard Features

- **Network Overview**: Total events, unique IPs, protocols distribution
- **Events Over Time**: Time series visualization of network activity
- **DNS Queries**: Top visited domains with device filtering
- **HTTP/TLS Traffic**: Website and application monitoring
- **Geographic Map**: Traffic source/destination visualization (requires geo_point mapping)
- **Honeypot Monitor**: Activity on subnet 192.168.40.0/24
- **Security Alerts**: Suricata IDS alert monitoring

### Import Dashboard

1. Open Grafana → Dashboards → Import
2. Upload `grafana-dashboard.json` or paste its contents
3. Select your Elasticsearch datasource
4. Click Import

**Note**: The dashboard is configured for datasource UID `af68payzal7nkd`. Update if your datasource UID is different.

### Performance Optimizations

- **Queue**: 128K events in-memory buffer (~2-3GB RAM)
- **Workers**: 8 (using all CPUs)
- **Bulk size**: 5000 events per batch
- **Max connections**: 100 concurrent TCP connections
- **Max message size**: 50MB per message

## Monitoring

- **Metrics endpoint**: http://localhost:5066/stats
- **Logs**: `sudo journalctl -u filebeat -f`
- **Service status**: `sudo systemctl status filebeat`

## Troubleshooting

### Service won't start

Check the logs:
```bash
sudo journalctl -u filebeat -n 50 --no-pager
```

### Test configuration

```bash
sudo filebeat test config -c /etc/filebeat/filebeat.yml
```

### Reset service restart limit

If you see "Start request repeated too quickly":
```bash
sudo systemctl reset-failed filebeat
sudo systemctl start filebeat
```

## T-Pot Honeypot Monitoring Setup

The honeypot dashboard visualizes data from T-Pot honeypot systems using the `.ds-filebeat-8.19.8-*` data stream pattern.

### Step 1: Create the Ingest Pipeline

The ingest pipeline parses JSON from the message field and normalizes fields across all T-Pot honeypot types.

**Option A: Using Kibana Dev Tools** (recommended)
Copy and paste the contents of `honeypot-ingest-pipeline-devtools.txt` into Kibana Dev Tools.

**Option B: Using curl**
```bash
curl -X PUT "localhost:9200/_ingest/pipeline/tpot-honeypot" \
  -H 'Content-Type: application/json' \
  -d @honeypot-ingest-pipeline.json
```

### Step 2: Apply the Index Template

The index template references the ingest pipeline and defines proper field mappings:

```bash
curl -X PUT "localhost:9200/_index_template/honeypot-template" \
  -H 'Content-Type: application/json' \
  -d @honeypot-elasticsearch-index-template.json
```

### Step 3: Reindex Existing Data (Optional)

To apply the pipeline to existing data, reindex to a new index:

```bash
POST _reindex
{
  "source": {
    "index": ".ds-filebeat-8.19.8-*"
  },
  "dest": {
    "index": "honeypot-processed",
    "pipeline": "tpot-honeypot"
  }
}
```

Or update T-Pot's Filebeat config to use the pipeline for new data:
```yaml
output.elasticsearch:
  pipeline: tpot-honeypot
```

### Step 4: Add Honeypot Datasource in Grafana

1. Go to **Configuration → Data Sources → Add data source**
2. Select **Elasticsearch**
3. Configure:
   - **Name**: `Elasticsearch - Honeypot`
   - **URL**: `http://localhost:9200`
   - **Index name**: `.ds-filebeat-8.19.8-*` (or `honeypot-processed` if reindexed)
   - **Time field**: `@timestamp`
   - **Version**: Select your ES version
4. Click **Save & Test**

### Step 5: Import Honeypot Dashboard

1. Open Grafana → **Dashboards → Import**
2. Upload `honeypot-grafana-dashboard.json`
3. Select your honeypot Elasticsearch datasource
4. Click **Import**

### Honeypot Dashboard Features

- **Overview Stats**: Total events, unique attackers, countries, targeted ports, login attempts, malware downloads
- **Attack Timeline**: Time series of honeypot activity by honeypot type
- **Geographic Map**: Visual map showing attacker origins
- **Top Attackers**: IPs with most connection attempts, including country and ASN info
- **Targeted Ports**: Most scanned/attacked ports with service name mappings
- **Credential Analysis**: Top usernames and passwords attempted (normalized across all honeypots)
- **Commands Executed**: Commands run by attackers in honeypot sessions
- **Malware Downloads**: URLs and SHA256 hashes of downloaded malware (with VirusTotal links)
- **Attacker OS**: OS fingerprinting from p0f
- **Raw Events**: Recent events table for detailed analysis

### Supported T-Pot Honeypot Types

The pipeline parses and normalizes fields from all T-Pot honeypots:
- **Cowrie** (SSH/Telnet): usernames, passwords, commands, sessions, file downloads
- **Dionaea** (multi-protocol): connection types, credentials, download URLs
- **Suricata** (IDS): alerts, signatures, categories, severity
- **p0f** (passive fingerprinting): OS detection, network distance
- **SentryPeer** (VoIP): SIP methods, called numbers
- **FATT** (fingerprinting): JA3/JA3S hashes, HASSH
- **Tanner/Snare** (web): request paths, attack detection
- **Heralding** (credential): usernames, passwords, protocols
- **H0neytr4p** (HTTP): request URIs, user agents
- **Conpot** (ICS/SCADA): data types, requests
- **Honeytrap**: payloads, services
- **ADBHoney** (Android Debug Bridge): commands
- **CiscoASA**: credentials
- **Wordpot** (WordPress): attacked paths, plugins, themes
- **Miniprint** (printer): print data

### Normalized Fields

The pipeline creates consistent field names across all honeypots:
- `honeypot_type` - The honeypot container name
- `src_ip`, `dest_ip` - Normalized source/destination IPs
- `src_port`, `dest_port` - Normalized ports
- `username`, `password` - Credentials from any honeypot
- `command` - Commands executed
- `download_url`, `file_hash` - Malware info
- `request_path` - Web paths attacked
- `os_fingerprint` - OS detection
- `event_type` - Event type/method
- `geoip.*` - GeoIP data for attacker locations

## Recent Fixes

- **Dec 11, 2025**: Added comprehensive T-Pot ingest pipeline for parsing all honeypot JSON formats
- **Dec 11, 2025**: Updated dashboard to use normalized fields (works across all T-Pot honeypots)
- **Dec 11, 2025**: Added dedicated honeypot Grafana dashboard with credential analysis, commands, malware tracking
- **Dec 11, 2025**: Added honeypot Elasticsearch index template for filebeat-8.19.8* pattern
- **Dec 11, 2025**: Updated main dashboard to use configurable honeypot subnet variable
- **Dec 8, 2025**: Added Elasticsearch index template for geo_point mapping (map visualizations)
- **Dec 8, 2025**: Added Grafana dashboard for home network monitoring
- **Dec 8, 2025**: Added GeoIP enrichment via Elasticsearch ingest pipeline
- **Dec 8, 2025**: Simplified config to decode JSON directly (removed dissect processor)
- **Dec 8, 2025**: Updated syslog-ng to send raw JSON with `template("$MESSAGE\n")`
- **Dec 7, 2025**: Fixed `dissect` tokenizer to parse full syslog format with priority and timestamp
- **Dec 7, 2025**: Replaced `grok` processor with `dissect` (grok not available in this Filebeat version)
- **Dec 7, 2025**: Created automated deployment script and documentation

## Expected Performance

- **Input**: 50,000-100,000 events/second
- **RAM usage**: 3-5GB
- **CPU usage**: 10-30%
- **Network**: 100-500 Mbps
- **Drop rate**: < 0.1%
