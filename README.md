# ELKIE - Filebeat Configuration for Suricata Logs

This repository contains the optimized Filebeat configuration for ingesting Suricata logs from pfSense into Elasticsearch.

## Files

- **Filebeat.yml** - Main Filebeat configuration (optimized for 28GB RAM, 8 CPUs, 10Gbps network)
- **Syslog-NG-Config.txt** - Syslog-NG configuration reference
- **deploy-filebeat-config.sh** - Deployment script

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

This adds geographic data (country, city, coordinates) to your Suricata events for map visualizations in Kibana.

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

## Recent Fixes

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
