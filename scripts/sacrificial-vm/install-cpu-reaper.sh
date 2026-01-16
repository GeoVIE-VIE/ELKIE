#!/bin/bash
# =============================================================================
# Install CPU Reaper on Sacrificial VM
# =============================================================================
# Blocks cryptocurrency miners and high-CPU processes from attackers.
#
# Usage:
#   scp install-cpu-reaper.sh cpu-reaper.sh cpu-reaper.banned cpu-reaper.service sacrificial-vm:/tmp/
#   ssh sacrificial-vm 'sudo bash /tmp/install-cpu-reaper.sh'
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          CPU Reaper - Miner Blocker Installation               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root${NC}"
    exit 1
fi

# Find files (either in same directory or /tmp)
find_file() {
    local name="$1"
    for path in "$SCRIPT_DIR/$name" "/tmp/$name" "./$name"; do
        if [[ -f "$path" ]]; then
            echo "$path"
            return 0
        fi
    done
    echo ""
    return 1
}

REAPER_SCRIPT="$(find_file "cpu-reaper.sh")"
REAPER_SERVICE="$(find_file "cpu-reaper.service")"
REAPER_BANNED="$(find_file "cpu-reaper.banned")"

if [[ -z "$REAPER_SCRIPT" ]]; then
    echo -e "${RED}Error: cpu-reaper.sh not found${NC}"
    exit 1
fi

echo -e "${BLUE}[1/4] Installing cpu-reaper script...${NC}"
cp "$REAPER_SCRIPT" /usr/local/bin/cpu-reaper
chmod +x /usr/local/bin/cpu-reaper
echo -e "${GREEN}  ✓ Installed to /usr/local/bin/cpu-reaper${NC}"

echo -e "${BLUE}[2/4] Installing banned patterns list...${NC}"
if [[ -n "$REAPER_BANNED" ]]; then
    cp "$REAPER_BANNED" /etc/cpu-reaper.banned
    echo -e "${GREEN}  ✓ Installed to /etc/cpu-reaper.banned${NC}"
else
    echo -e "${YELLOW}  ⚠ No banned list found, creating empty file${NC}"
    touch /etc/cpu-reaper.banned
fi

echo -e "${BLUE}[3/4] Installing systemd service...${NC}"
if [[ -n "$REAPER_SERVICE" ]]; then
    cp "$REAPER_SERVICE" /etc/systemd/system/cpu-reaper.service
else
    # Create inline if file not found
    cat > /etc/systemd/system/cpu-reaper.service << 'EOF'
[Unit]
Description=CPU Reaper - Kill cryptocurrency miners
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cpu-reaper
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi
echo -e "${GREEN}  ✓ Installed systemd service${NC}"

echo -e "${BLUE}[4/4] Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable cpu-reaper
systemctl restart cpu-reaper

sleep 2

if systemctl is-active --quiet cpu-reaper; then
    echo -e "${GREEN}  ✓ CPU Reaper is running${NC}"
else
    echo -e "${RED}  ✗ Failed to start. Check: journalctl -u cpu-reaper${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          CPU Reaper Installed Successfully!                    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Configuration:"
echo "  Script:     /usr/local/bin/cpu-reaper"
echo "  Banned:     /etc/cpu-reaper.banned"
echo "  Log:        /var/log/cpu-reaper.json"
echo "  Service:    cpu-reaper.service"
echo ""
echo "Commands:"
echo "  Status:     systemctl status cpu-reaper"
echo "  Logs:       journalctl -u cpu-reaper -f"
echo "  Kill log:   tail -f /var/log/cpu-reaper.json | jq ."
echo ""
echo "To add banned patterns:"
echo "  echo 'newminer' >> /etc/cpu-reaper.banned"
echo ""
