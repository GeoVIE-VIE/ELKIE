#!/bin/bash
#===============================================================================
# Setup Quarantine Directory with Safety Measures
# Run this once to prepare the secure sample storage
#===============================================================================

set -euo pipefail

QUARANTINE_DIR="${1:-/opt/honeypot-quarantine}"
QUARANTINE_USER="${2:-honeypot-analyst}"
QUARANTINE_SIZE="${3:-10G}"

echo "=========================================="
echo "Honeypot Quarantine Setup"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Create dedicated user for sample analysis
if ! id "$QUARANTINE_USER" &>/dev/null; then
    echo "[+] Creating quarantine user: $QUARANTINE_USER"
    useradd -r -s /usr/sbin/nologin -d "$QUARANTINE_DIR" "$QUARANTINE_USER"
else
    echo "[*] User $QUARANTINE_USER already exists"
fi

# Add current user to the group for access
if [[ -n "${SUDO_USER:-}" ]]; then
    usermod -aG "$QUARANTINE_USER" "$SUDO_USER"
    echo "[+] Added $SUDO_USER to $QUARANTINE_USER group"
fi

# Create quarantine directory
echo "[+] Creating quarantine directory: $QUARANTINE_DIR"
mkdir -p "$QUARANTINE_DIR"

# Option 1: Create a dedicated filesystem (most secure)
# This creates a loopback file that can be mounted with noexec
QUARANTINE_IMAGE="$QUARANTINE_DIR.img"

if [[ ! -f "$QUARANTINE_IMAGE" ]]; then
    echo "[+] Creating dedicated filesystem for quarantine ($QUARANTINE_SIZE)"

    # Create sparse file
    truncate -s "$QUARANTINE_SIZE" "$QUARANTINE_IMAGE"

    # Format as ext4
    mkfs.ext4 -F -L "quarantine" "$QUARANTINE_IMAGE"

    echo "[+] Created quarantine filesystem: $QUARANTINE_IMAGE"
fi

# Mount with security options
echo "[+] Mounting quarantine filesystem with noexec,nosuid,nodev"

# Unmount if already mounted
umount "$QUARANTINE_DIR" 2>/dev/null || true

# Mount with restrictive options
mount -o loop,noexec,nosuid,nodev,noatime "$QUARANTINE_IMAGE" "$QUARANTINE_DIR"

# Add to fstab for persistence
FSTAB_ENTRY="$QUARANTINE_IMAGE $QUARANTINE_DIR ext4 loop,noexec,nosuid,nodev,noatime 0 2"
if ! grep -q "$QUARANTINE_DIR" /etc/fstab; then
    echo "$FSTAB_ENTRY" >> /etc/fstab
    echo "[+] Added to /etc/fstab"
fi

# Create subdirectories
echo "[+] Creating directory structure"
mkdir -p "$QUARANTINE_DIR"/{cowrie,dionaea,glutton,honeytrap,tanner,temp,archive}

# Set ownership and permissions
echo "[+] Setting permissions"
chown -R "$QUARANTINE_USER:$QUARANTINE_USER" "$QUARANTINE_DIR"
chmod 750 "$QUARANTINE_DIR"
chmod 750 "$QUARANTINE_DIR"/*

# Create log directory
LOG_DIR="/var/log/honeypot-extraction"
mkdir -p "$LOG_DIR"
chown "$QUARANTINE_USER:$QUARANTINE_USER" "$LOG_DIR"
chmod 750 "$LOG_DIR"

# Verify mount options
echo ""
echo "=========================================="
echo "Verification"
echo "=========================================="
echo ""
mount | grep "$QUARANTINE_DIR"
echo ""
ls -la "$QUARANTINE_DIR"
echo ""

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Quarantine directory: $QUARANTINE_DIR"
echo "Mount options: noexec,nosuid,nodev (prevents execution)"
echo "Owner: $QUARANTINE_USER"
echo ""
echo "To run extraction manually:"
echo "  sudo -u $QUARANTINE_USER /path/to/extract-samples.sh"
echo ""
echo "To check mount:"
echo "  mount | grep quarantine"
echo ""
