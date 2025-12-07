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

1. **dissect** - Extracts JSON payload from syslog message format
2. **decode_json_fields** - Parses the JSON payload
3. **drop_fields** - Cleans up temporary fields

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

- **Dec 7, 2024**: Replaced `grok` processor with `dissect` (grok not available in this Filebeat version)
- **Dec 7, 2024**: Fixed JSON extraction to handle syslog-ng format

## Expected Performance

- **Input**: 50,000-100,000 events/second
- **RAM usage**: 3-5GB
- **CPU usage**: 10-30%
- **Network**: 100-500 Mbps
- **Drop rate**: < 0.1%
