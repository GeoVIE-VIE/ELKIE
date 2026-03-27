#!/bin/bash
# Watchdog: scan for malware drops, check access, restore if locked out
LOG="/home/legs/sacrificial_watchdog.log"
STAGING="/home/legs/sample_staging"
SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10"
JUMP="-J lepots@192.168.40.3:64295"
TARGET="root@192.168.40.99"
source /home/legs/.sample_analyzer_env 2>/dev/null
PVE_TOKEN="${PVE_API_TOKEN:-}"

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
      "https://192.168.99.160:8006/api2/json/nodes/flexiserve/qemu/107/snapshot/clean/rollback" > /dev/null 2>&1

    sleep 30

    # Force NTP sync after restore
    ssh $SSH_OPTS $JUMP $TARGET "chronyc makestep" 2>/dev/null

    echo "$(date) - Snapshot restored and NTP synced" >> "$LOG"
fi
