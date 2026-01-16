#!/bin/bash
# =============================================================================
# CPU Reaper - One-file installer for Sacrificial VM
# =============================================================================
# Copy this entire file to the sacrificial VM and run:
#   sudo bash deploy-cpu-reaper.sh
# =============================================================================

set -e

echo "Installing CPU Reaper..."

# -----------------------------------------------------------------------------
# Create the main script
# -----------------------------------------------------------------------------
cat > /usr/local/bin/cpu-reaper << 'REAPER_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

THRESHOLD="${CPU_REAPER_THRESHOLD:-90}"
DURATION="${CPU_REAPER_DURATION:-30}"
INTERVAL="${CPU_REAPER_INTERVAL:-5}"
BANNED_FILE="${CPU_REAPER_BANNED:-/etc/cpu-reaper.banned}"
LOG_FILE="${CPU_REAPER_LOG:-/var/log/cpu-reaper.json}"
ONLY_SSH_FOR_CPU="${CPU_REAPER_ONLY_SSH:-1}"
PROTECTED_PROCS="sshd auditd systemd filebeat suricata journald rsyslogd"

declare -A seen

log_json() {
    local action="$1" pid="$2" reason="$3" comm="${4:-}" cmdline="${5:-}" cpu="${6:-0}" exe="${7:-}" sha256="${8:-}"
    printf '{"@timestamp":"%s","event":"cpu_reaper","action":"%s","pid":%d,"reason":"%s","comm":"%s","cmdline":"%s","cpu_percent":%s,"exe":"%s","sha256":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "$action" "$pid" "$reason" "$comm" "$cmdline" "$cpu" "$exe" "$sha256" >> "$LOG_FILE"
}

has_sshd_ancestor() {
    local p="$1"
    while [[ "$p" -gt 1 ]]; do
        local comm; comm="$(ps -o comm= -p "$p" 2>/dev/null | tr -d ' ' || true)"
        [[ "$comm" == "sshd" ]] && return 0
        p="$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ' || true)"
        [[ -z "${p:-}" ]] && break
    done
    return 1
}

cmdline_of() { tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | head -c 500 || true; }
comm_of() { ps -o comm= -p "$1" 2>/dev/null | tr -d ' ' || true; }
exe_of() { readlink -f "/proc/$1/exe" 2>/dev/null || true; }
hash_exe() { [[ -f "$1" && -r "$1" ]] && sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true; }

is_protected() {
    local comm="$1"
    for proc in $PROTECTED_PROCS; do [[ "$comm" == "$proc" ]] && return 0; done
    return 1
}

is_banned() {
    [[ -f "$BANNED_FILE" ]] || return 1
    local pid="$1" cmd comm exe
    cmd="$(cmdline_of "$pid")"; comm="$(comm_of "$pid")"; exe="$(exe_of "$pid")"
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        pattern="${pattern//$'\r'/}"
        [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
        [[ "${cmd,,}" == *"${pattern,,}"* || "${comm,,}" == *"${pattern,,}"* || "${exe,,}" == *"${pattern,,}"* ]] && return 0
    done < "$BANNED_FILE"
    return 1
}

get_matched_pattern() {
    [[ -f "$BANNED_FILE" ]] || return
    local pid="$1" cmd comm exe
    cmd="$(cmdline_of "$pid")"; comm="$(comm_of "$pid")"; exe="$(exe_of "$pid")"
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        pattern="${pattern//$'\r'/}"
        [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
        [[ "${cmd,,}" == *"${pattern,,}"* || "${comm,,}" == *"${pattern,,}"* || "${exe,,}" == *"${pattern,,}"* ]] && echo "$pattern" && return
    done < "$BANNED_FILE"
}

kill_pid() {
    local pid="$1" reason="$2" comm cmdline cpu exe sha256
    comm="$(comm_of "$pid")"; cmdline="$(cmdline_of "$pid" | tr '"' "'" | tr '\n' ' ')"
    cpu="$(ps -o pcpu= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0")"
    exe="$(exe_of "$pid")"; sha256="$(hash_exe "$exe")"
    log_json "kill" "$pid" "$reason" "$comm" "$cmdline" "$cpu" "$exe" "$sha256"
    pkill -9 -P "$pid" 2>/dev/null || true; kill -9 "$pid" 2>/dev/null || true
    unset "seen[$pid]" 2>/dev/null || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Killed PID $pid ($comm) - $reason"
}

scan_banned_processes() {
    for pid in /proc/[0-9]*; do
        pid="${pid##*/}"; [[ "$pid" -le 1 || ! -d "/proc/$pid" ]] && continue
        comm="$(comm_of "$pid")"; is_protected "$comm" && continue
        is_banned "$pid" && kill_pid "$pid" "banned_pattern:$(get_matched_pattern "$pid")"
    done
}

scan_high_cpu_processes() {
    while read -r pid pcpu; do
        [[ -z "${pid:-}" || "$pid" -le 1 || ! -d "/proc/$pid" ]] && continue
        comm="$(comm_of "$pid")"; is_protected "$comm" && continue
        [[ "$ONLY_SSH_FOR_CPU" -eq 1 ]] && ! has_sshd_ancestor "$pid" && continue
        seen[$pid]=$(( ${seen[$pid]:-0} + INTERVAL ))
        [[ ${seen[$pid]} -ge $DURATION ]] && kill_pid "$pid" "sustained_cpu:${pcpu}%_for_${seen[$pid]}s"
    done < <(ps -eo pid,pcpu --no-headers | awk -v t="$THRESHOLD" '$2+0 > t+0 {print $1, $2}')
}

echo "CPU Reaper starting... (threshold=${THRESHOLD}%, duration=${DURATION}s)"
mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"
[[ ! -f "$BANNED_FILE" ]] && echo "Warning: $BANNED_FILE not found"

while true; do
    scan_banned_processes
    scan_high_cpu_processes
    for p in "${!seen[@]}"; do [[ ! -d "/proc/$p" ]] && unset "seen[$p]" || true; done
    sleep "$INTERVAL"
done
REAPER_SCRIPT

chmod +x /usr/local/bin/cpu-reaper

# -----------------------------------------------------------------------------
# Create banned patterns list
# -----------------------------------------------------------------------------
cat > /etc/cpu-reaper.banned << 'BANNED_LIST'
# Cryptocurrency miners
xmrig
xmr-stak
minerd
cgminer
bfgminer
cpuminer
ethminer
claymore
phoenixminer
gminer
nbminer
lolminer
t-rex
teamredminer
nanominer
srbminer
ccminer
nicehash

# Mining patterns
cryptonight
-o stratum
stratum+tcp
stratum+ssl
pool.minexmr
pool.supportxmr
nanopool.org
2miners.com
--algo=rx
--algo=cn
--randomx
--donate-level

# Known malicious
kinsing
kdevtmpfsi
dbused
solrd
kerberods
khugepageds
pamdicks
config.json.xmrig
# NOTE: Do NOT add generic patterns like "systemd-", "[kworker", ".sshd" (no slash), etc.
# Those will match legitimate system processes and break things.

# Botnets
tsunami
mirai
gafgyt
bashlite
xorddos
BANNED_LIST

# -----------------------------------------------------------------------------
# Create systemd service
# -----------------------------------------------------------------------------
cat > /etc/systemd/system/cpu-reaper.service << 'SERVICE_FILE'
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
SERVICE_FILE

# -----------------------------------------------------------------------------
# Enable and start
# -----------------------------------------------------------------------------
systemctl daemon-reload
systemctl enable cpu-reaper
systemctl restart cpu-reaper

sleep 2
if systemctl is-active --quiet cpu-reaper; then
    echo "✓ CPU Reaper installed and running"
    echo "  Logs: journalctl -u cpu-reaper -f"
    echo "  Kills: tail -f /var/log/cpu-reaper.json"
else
    echo "✗ Failed to start. Check: journalctl -u cpu-reaper"
    exit 1
fi
