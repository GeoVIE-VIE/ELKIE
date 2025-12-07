#!/bin/bash
# Deploy Filebeat configuration and restart service

set -e

echo "=== Deploying Filebeat Configuration ==="

# Backup existing config
if [ -f /etc/filebeat/filebeat.yml ]; then
    echo "Backing up existing configuration..."
    sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup.$(date +%Y%m%d_%H%M%S)
fi

# Create directory if it doesn't exist
sudo mkdir -p /etc/filebeat

# Copy new configuration
echo "Deploying new configuration..."
sudo cp Filebeat.yml /etc/filebeat/filebeat.yml

# Set proper permissions
sudo chmod 644 /etc/filebeat/filebeat.yml
sudo chown root:root /etc/filebeat/filebeat.yml

# Test configuration
echo "Testing Filebeat configuration..."
if sudo filebeat test config -c /etc/filebeat/filebeat.yml; then
    echo "✓ Configuration is valid"
else
    echo "✗ Configuration test failed!"
    exit 1
fi

# Restart Filebeat service
echo "Restarting Filebeat service..."
sudo systemctl restart filebeat

# Wait a moment for service to start
sleep 2

# Check service status
echo "Checking Filebeat service status..."
sudo systemctl status filebeat --no-pager

echo ""
echo "=== Deployment Complete ==="
echo "Monitor logs with: sudo journalctl -u filebeat -f"
