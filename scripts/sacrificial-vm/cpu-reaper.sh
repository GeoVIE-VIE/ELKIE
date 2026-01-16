#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CPU Reaper - Kill cryptocurrency miners and high-CPU processes
# =============================================================================
#
# Features:
# 1. Instant kill for banned process names/patterns (ANY process, not just SSH)
# 2. Sustained high-CPU kill (only SSH-spawned processes for safety)
# 3. JSON logging for Elasticsearch/Filebeat integration
# 4. Binary hashing before kill for forensics
#
# Install:
#   cp cpu-reaper.sh /usr/local/bin/cpu-reaper
#   chmod +x /usr/local/bin/cpu-reaper
#   cp cpu-reaper.service /etc/systemd/system/
#   systemctl enable --now cpu-reaper
#
# =============================================================================

# Configuration
THRESHOLD="${CPU_REAPER_THRESHOLD:-90}"        # %CPU threshold
DURATION="${CPU_REAPER_DURATION:-30}"          # seconds sustained before kill
INTERVAL="${CPU_REAPER_INTERVAL:-5}"           # seconds between checks
BANNED_FILE="${CPU_REAPER_BANNED:-/etc/cpu-reaper.banned}"
LOG_FILE="${CPU_REAPER_LOG:-/var/log/cpu-reaper.json}"
ONLY_SSH_FOR_CPU="${CPU_REAPER_ONLY_SSH:-1}"   # SSH check only for CPU threshold kills

# Protected processes - never kill these
PROTECTED_PROCS="sshd auditd systemd filebeat suricata journald rsyslogd"

declare -A seen

# =============================================================================
# Logging
# =============================================================================

log_json() {
    local action="$1"
    local pid="$2"
    local reason="$3"
    local comm="${4:-}"
    local cmdline="${5:-}"
    local cpu="${6:-0}"
    local exe="${7:-}"
    local sha256="${8:-}"

    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

    printf '{"@timestamp":"%s","event":"cpu_reaper","action":"%s","pid":%d,"reason":"%s","comm":"%s","cmdline":"%s","cpu_percent":%s,"exe":"%s","sha256":"%s"}\n' \
        "$timestamp" "$action" "$pid" "$reason" "$comm" "$cmdline" "$cpu" "$exe" "$sha256" >> "$LOG_FILE"
}

# =============================================================================
# Helper functions
# =============================================================================

has_sshd_ancestor() {
    local p="$1"
    while [[ "$p" -gt 1 ]]; do
        local comm
        comm="$(ps -o comm= -p "$p" 2>/dev/null | tr -d ' ' || true)"
        [[ "$comm" == "sshd" ]] && return 0
        p="$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ' || true)"
        [[ -z "${p:-}" ]] && break
    done
    return 1
}

cmdline_of() {
    tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | head -c 500 || true
}

comm_of() {
    ps -o comm= -p "$1" 2>/dev/null | tr -d ' ' || true
}

exe_of() {
    readlink -f "/proc/$1/exe" 2>/dev/null || true
}

hash_exe() {
    local exe="$1"
    if [[ -f "$exe" && -r "$exe" ]]; then
        sha256sum "$exe" 2>/dev/null | cut -d' ' -f1 || true
    fi
}

is_protected() {
    local comm="$1"
    for proc in $PROTECTED_PROCS; do
        [[ "$comm" == "$proc" ]] && return 0
    done
    return 1
}

is_banned() {
    [[ -f "$BANNED_FILE" ]] || return 1
    local pid="$1"
    local cmd comm exe

    cmd="$(cmdline_of "$pid")"
    comm="$(comm_of "$pid")"
    exe="$(exe_of "$pid")"

    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        pattern="${pattern//$'\r'/}"
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*# ]] && continue

        # Case-insensitive matching
        if [[ "${cmd,,}" == *"${pattern,,}"* ]] || \
           [[ "${comm,,}" == *"${pattern,,}"* ]] || \
           [[ "${exe,,}" == *"${pattern,,}"* ]]; then
            return 0
        fi
    done < "$BANNED_FILE"

    return 1
}

get_matched_pattern() {
    [[ -f "$BANNED_FILE" ]] || return
    local pid="$1"
    local cmd comm exe

    cmd="$(cmdline_of "$pid")"
    comm="$(comm_of "$pid")"
    exe="$(exe_of "$pid")"

    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        pattern="${pattern//$'\r'/}"
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*# ]] && continue

        if [[ "${cmd,,}" == *"${pattern,,}"* ]] || \
           [[ "${comm,,}" == *"${pattern,,}"* ]] || \
           [[ "${exe,,}" == *"${pattern,,}"* ]]; then
            echo "$pattern"
            return
        fi
    done < "$BANNED_FILE"
}

kill_pid() {
    local pid="$1"
    local reason="$2"
    local comm cmdline cpu exe sha256

    comm="$(comm_of "$pid")"
    cmdline="$(cmdline_of "$pid" | tr '"' "'" | tr '\n' ' ')"
    cpu="$(ps -o pcpu= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0")"
    exe="$(exe_of "$pid")"
    sha256="$(hash_exe "$exe")"

    # Log before kill
    log_json "kill" "$pid" "$reason" "$comm" "$cmdline" "$cpu" "$exe" "$sha256"

    # Kill process and children
    pkill -9 -P "$pid" 2>/dev/null || true
    kill -9 "$pid" 2>/dev/null || true

    unset "seen[$pid]" 2>/dev/null || true

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Killed PID $pid ($comm) - $reason"
}

# =============================================================================
# Scan all processes for banned patterns (regardless of ancestry)
# =============================================================================

scan_banned_processes() {
    local pid comm

    # Get all process PIDs
    for pid in /proc/[0-9]*; do
        pid="${pid##*/}"
        [[ "$pid" -le 1 ]] && continue
        [[ -d "/proc/$pid" ]] || continue

        comm="$(comm_of "$pid")"

        # Skip protected processes
        is_protected "$comm" && continue

        # Check if banned
        if is_banned "$pid"; then
            local pattern
            pattern="$(get_matched_pattern "$pid")"
            kill_pid "$pid" "banned_pattern:$pattern"
        fi
    done
}

# =============================================================================
# Scan high-CPU processes (SSH ancestry required for safety)
# =============================================================================

scan_high_cpu_processes() {
    while read -r pid pcpu; do
        [[ -z "${pid:-}" ]] && continue
        [[ "$pid" -le 1 ]] && continue
        [[ -d "/proc/$pid" ]] || continue

        local comm
        comm="$(comm_of "$pid")"

        # Skip protected processes
        is_protected "$comm" && continue

        # For CPU-based kills, require SSH ancestry (safety measure)
        if [[ "$ONLY_SSH_FOR_CPU" -eq 1 ]]; then
            has_sshd_ancestor "$pid" || continue
        fi

        # Track sustained high CPU
        seen[$pid]=$(( ${seen[$pid]:-0} + INTERVAL ))

        if [[ ${seen[$pid]} -ge $DURATION ]]; then
            kill_pid "$pid" "sustained_cpu:${pcpu}%_for_${seen[$pid]}s"
        fi
    done < <(ps -eo pid,pcpu --no-headers | awk -v t="$THRESHOLD" '$2+0 > t+0 {print $1, $2}')
}

# =============================================================================
# Main
# =============================================================================

echo "CPU Reaper starting..."
echo "  Threshold: ${THRESHOLD}% CPU for ${DURATION}s"
echo "  Banned file: $BANNED_FILE"
echo "  Log file: $LOG_FILE"
echo "  SSH-only for CPU kills: $ONLY_SSH_FOR_CPU"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Ensure banned file exists
if [[ ! -f "$BANNED_FILE" ]]; then
    echo "Warning: Banned file not found at $BANNED_FILE"
fi

while true; do
    # Scan ALL processes for banned patterns (miners often daemonize)
    scan_banned_processes

    # Scan high-CPU processes (with SSH ancestry check for safety)
    scan_high_cpu_processes

    # Clean up dead PIDs from tracking
    for p in "${!seen[@]}"; do
        if [[ ! -d "/proc/$p" ]]; then
            unset "seen[$p]" 2>/dev/null || true
        fi
    done

    sleep "$INTERVAL"
done
