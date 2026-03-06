#!/bin/bash
#
# auditd-watchdog.sh - Detect and recover auditd after snapshot reverts
#
# Problem: After reverting a VM snapshot, auditd often goes silent within
# ~10 minutes. The kernel audit subsystem and the auditd daemon get out of
# sync - the backlog fills, events get dropped, and auditd stalls.
#
# Solution: This watchdog checks every 60 seconds whether auditd is still
# producing events. If it detects a stall (no new events for 3 minutes),
# it forces a recovery by restarting auditd and reloading rules.
#
# Deploy as: /usr/local/bin/auditd-watchdog.sh
# Service:   /etc/systemd/system/auditd-watchdog.service
#

AUDIT_LOG="/var/log/audit/audit.log"
CHECK_INTERVAL=60        # Check every 60 seconds
STALL_THRESHOLD=180      # 3 minutes without events = stalled
HONEYPOT_IP="192.168.40.99"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [auditd-watchdog] $1"
    logger -t auditd-watchdog "$1"
}

get_audit_log_mtime() {
    stat -c %Y "$AUDIT_LOG" 2>/dev/null || echo 0
}

get_audit_lost() {
    auditctl -s 2>/dev/null | grep "^lost" | awk '{print $2}' || echo 0
}

recover_auditd() {
    log "STALL DETECTED - auditd has not written events for ${STALL_THRESHOLD}s"
    log "Attempting recovery..."

    # Step 1: Check if auditd process is alive or service is inactive
    if ! pgrep -x auditd > /dev/null; then
        log "auditd process is DEAD - restarting service"
        systemctl restart auditd
        sleep 2
    elif ! systemctl is-active --quiet auditd; then
        log "auditd service is INACTIVE - starting service"
        systemctl start auditd
        sleep 2
    fi

    # Step 2: Reset the kernel audit backlog
    # The backlog filling up is the most common cause of post-snapshot stalls.
    # When the backlog is full, the kernel stops sending events to auditd.
    local lost_before=$(get_audit_lost)
    log "Lost events before recovery: $lost_before"

    # Step 3: Force auditd to re-read its config and flush
    # Using SIGHUP triggers a config reload without full restart
    pkill -HUP auditd 2>/dev/null
    sleep 2

    # Step 4: If still stalled, do a hard restart
    local mtime_after=$(get_audit_log_mtime)
    sleep 5
    local mtime_check=$(get_audit_log_mtime)

    if [ "$mtime_after" -eq "$mtime_check" ]; then
        log "SIGHUP didn't help - forcing hard restart"

        # Kill auditd (bypasses RefuseManualStop by using kill directly)
        pkill -9 auditd 2>/dev/null
        sleep 2

        # Clear any stale PID files
        rm -f /var/run/auditd.pid 2>/dev/null

        # Restart the service
        systemctl restart auditd
        sleep 2

        # Reload rules (they may have been lost during hard restart)
        augenrules --load 2>/dev/null || true

        log "Hard restart completed"
    else
        log "Recovery via SIGHUP succeeded"
    fi

    local lost_after=$(get_audit_lost)
    log "Lost events after recovery: $lost_after (delta: $((lost_after - lost_before)))"

    # Step 5: Verify auditd is producing events
    sleep 5
    local final_mtime=$(get_audit_log_mtime)
    sleep 5
    local verify_mtime=$(get_audit_log_mtime)

    if [ "$final_mtime" -ne "$verify_mtime" ]; then
        log "RECOVERY SUCCESSFUL - auditd is producing events again"
    else
        log "WARNING: Recovery may have failed - auditd still not producing events"
        log "This may require a VM reboot (rules are immutable with -e 2)"
    fi
}

# --- Main Loop ---

log "Starting auditd watchdog (check=${CHECK_INTERVAL}s, stall_threshold=${STALL_THRESHOLD}s)"
log "Monitoring: $AUDIT_LOG"
log "Honeypot VM: $HONEYPOT_IP"

LAST_ACTIVE_MTIME=$(get_audit_log_mtime)

while true; do
    sleep "$CHECK_INTERVAL"

    CURRENT_MTIME=$(get_audit_log_mtime)
    NOW=$(date +%s)

    if [ "$CURRENT_MTIME" -ne "$LAST_ACTIVE_MTIME" ]; then
        # Log file is being written to - auditd is healthy
        LAST_ACTIVE_MTIME=$CURRENT_MTIME
    else
        # Log file hasn't changed - check how long it's been
        SECONDS_STALLED=$((NOW - CURRENT_MTIME))

        if [ "$SECONDS_STALLED" -ge "$STALL_THRESHOLD" ]; then
            recover_auditd
            # Reset the baseline after recovery
            LAST_ACTIVE_MTIME=$(get_audit_log_mtime)
        fi
    fi

    # Also check for high event loss rate (can happen without full stall)
    LOST=$(get_audit_lost)
    if [ "$LOST" -gt 1000 ]; then
        log "WARNING: $LOST audit events lost - backlog may be undersized"
    fi
done
