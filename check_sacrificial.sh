#!/bin/bash
# Watchdog: scan for malware drops, check access, restore if locked out
# Config: source .env or .sample_analyzer_env for variables

# Source environment
ELKIE_HOME="${ELKIE_HOME:-/home/legs}"
source "$ELKIE_HOME/.sample_analyzer_env" 2>/dev/null
source "$ELKIE_HOME/.env" 2>/dev/null

# Config — all from env with sane defaults
LOG="${ELKIE_HOME}/sacrificial_watchdog.log"
STAGING="${STAGING_DIR:-$ELKIE_HOME/sample_staging}"
TPOT_USER="${TPOT_SSH_USER:-lepots}"
TPOT_HOST="${TPOT_IP:-192.168.40.3}"
TPOT_PORT="${TPOT_SSH_PORT:-64295}"
SACRIFICIAL_USER="${SACRIFICIAL_SSH_USER:-root}"
SACRIFICIAL_HOST="${SACRIFICIAL_IP:-192.168.40.99}"
PVE_URL="${PROXMOX_API_URL:-https://192.168.99.160:8006}"
PVE_NODE="${PROXMOX_NODE:-flexiserve}"
PVE_VMID="${VMID_SACRIFICIAL:-107}"
PVE_TOKEN="${PVE_API_TOKEN:-}"

SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10"
JUMP="-J ${TPOT_USER}@${TPOT_HOST}:${TPOT_PORT}"
TARGET="${SACRIFICIAL_USER}@${SACRIFICIAL_HOST}"

mkdir -p "$STAGING"

# Step 1: Check if we can access the VM
RESULT=$(ssh $SSH_OPTS $JUMP $TARGET "echo OK" 2>&1)

if [ "$RESULT" = "OK" ]; then
    # Step 2: Pull from quarantine dir (sample_catcher.sh captures malware in real-time)
    FILES=$(ssh $SSH_OPTS $JUMP $TARGET "
        find /opt/.quarantine -type f \
            -size +1k -size -50M \
            -exec sha256sum {} \; 2>/dev/null
    " 2>/dev/null)

    if [ -n "$FILES" ]; then
        echo "$(date) - Found files on sacrificial VM:" >> "$LOG"
        echo "$FILES" >> "$LOG"

        # Pull each file
        while IFS= read -r line; do
            HASH=$(echo "$line" | awk '{print $1}')
            FPATH=$(echo "$line" | awk '{print $2}')
            [ -z "$HASH" ] && continue
            [ ${#HASH} -ne 64 ] && continue

            # Skip if already staged
            [ -f "$STAGING/$HASH" ] && continue

            echo "$(date) - Pulling $HASH from $FPATH" >> "$LOG"
            ssh $SSH_OPTS $JUMP $TARGET "cat $(printf '%q' "$FPATH")" > "$STAGING/$HASH" 2>/dev/null

            if [ -s "$STAGING/$HASH" ]; then
                PULLED_HASH=$(sha256sum "$STAGING/$HASH" | awk '{print $1}')
                if [ "$PULLED_HASH" = "$HASH" ]; then
                    echo "$(date) - Captured sample $HASH ($(stat -c%s "$STAGING/$HASH") bytes) from $FPATH" >> "$LOG"
                else
                    rm -f "$STAGING/$HASH"
                fi
            else
                rm -f "$STAGING/$HASH"
            fi
        done <<< "$FILES"
    fi

    echo "$(date) - Sacrificial VM OK" >> "$LOG"
else
    echo "$(date) - Sacrificial VM locked out. Restoring snapshot..." >> "$LOG"

    # Restore snapshot via Proxmox API
    curl -sk -X POST -H "Authorization: $PVE_TOKEN" \
      "${PVE_URL}/api2/json/nodes/${PVE_NODE}/qemu/${PVE_VMID}/snapshot/clean/rollback" > /dev/null 2>&1

    sleep 30

    # Force NTP sync after restore
    ssh $SSH_OPTS $JUMP $TARGET "chronyc makestep" 2>/dev/null

    echo "$(date) - Snapshot restored and NTP synced" >> "$LOG"
fi
