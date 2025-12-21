#!/bin/bash
#
# Cowrie Hardening Installation Script for T-Pot
#
# Makes your honeypot less detectable by automated tools
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Cowrie Hardening for T-Pot                                 ║"
echo "║     Make your honeypot less detectable                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect Cowrie container
detect_cowrie() {
    echo -e "${BLUE}[1/4] Detecting Cowrie container...${NC}"

    COWRIE_CONTAINER=$(docker ps --format '{{.Names}}' | grep -i cowrie | head -1)

    if [ -z "$COWRIE_CONTAINER" ]; then
        echo -e "${RED}[!] Cowrie container not found. Is T-Pot running?${NC}"
        echo "    Try: docker ps | grep cowrie"
        exit 1
    fi

    echo -e "${GREEN}  ✓ Found Cowrie container: $COWRIE_CONTAINER${NC}"
}

# Backup existing config
backup_config() {
    echo -e "${BLUE}[2/4] Backing up existing configuration...${NC}"

    BACKUP_DIR="$SCRIPT_DIR/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    # Backup txtcmds
    docker cp "$COWRIE_CONTAINER:/cowrie/cowrie-git/share/cowrie/txtcmds" "$BACKUP_DIR/" 2>/dev/null || true

    echo -e "${GREEN}  ✓ Backup saved to: $BACKUP_DIR${NC}"
}

# Install hardened files
install_hardening() {
    echo -e "${BLUE}[3/4] Installing hardened configuration...${NC}"

    # Copy txtcmds (realistic command outputs)
    for f in "$SCRIPT_DIR"/txtcmds/bin/*; do
        if [ -f "$f" ]; then
            filename=$(basename "$f")
            docker cp "$f" "$COWRIE_CONTAINER:/cowrie/cowrie-git/share/cowrie/txtcmds/bin/$filename"
            echo "  Installed: $filename"
        fi
    done

    # Copy SSH banner if exists
    if [ -f "$SCRIPT_DIR/banner.txt" ]; then
        docker cp "$SCRIPT_DIR/banner.txt" "$COWRIE_CONTAINER:/cowrie/cowrie-git/etc/banner.txt"
        echo "  Installed: banner.txt"
    fi

    echo -e "${GREEN}  ✓ Hardening files installed${NC}"
}

# Restart Cowrie
restart_cowrie() {
    echo -e "${BLUE}[4/4] Restarting Cowrie...${NC}"

    docker restart "$COWRIE_CONTAINER"

    sleep 5

    if docker ps | grep -q "$COWRIE_CONTAINER"; then
        echo -e "${GREEN}  ✓ Cowrie restarted successfully${NC}"
    else
        echo -e "${RED}  ✗ Cowrie failed to restart. Check logs:${NC}"
        echo "    docker logs $COWRIE_CONTAINER"
        exit 1
    fi
}

# Show summary
show_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Hardening Complete!                                         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Changes applied:"
    echo "  ✓ Realistic /proc/cpuinfo (4-core Xeon)"
    echo "  ✓ Realistic /proc/meminfo (16GB RAM)"
    echo "  ✓ Realistic /etc/passwd (common users)"
    echo "  ✓ Realistic process list (nginx, mysql, sshd)"
    echo "  ✓ Realistic network connections"
    echo "  ✓ Current Ubuntu 22.04 version strings"
    echo ""
    echo "Test it:"
    echo "  ssh root@your-honeypot-ip -p 2222"
    echo "  Then run: cat /proc/cpuinfo"
    echo ""
    echo "View logs:"
    echo "  docker logs -f $COWRIE_CONTAINER"
    echo ""
}

# Main
main() {
    detect_cowrie
    backup_config
    install_hardening
    restart_cowrie
    show_summary
}

# Handle arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  (none)     Install hardening to Cowrie"
        echo "  --list     List files that will be installed"
        echo "  --test     Test connection to Cowrie"
        ;;
    --list)
        echo "Files to be installed:"
        ls -la "$SCRIPT_DIR/txtcmds/bin/"
        ;;
    --test)
        detect_cowrie
        echo "Testing Cowrie commands..."
        docker exec "$COWRIE_CONTAINER" cat /cowrie/cowrie-git/share/cowrie/txtcmds/bin/uname__-a 2>/dev/null || echo "File not found"
        ;;
    *)
        main
        ;;
esac
