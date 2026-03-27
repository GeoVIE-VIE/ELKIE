#!/bin/bash
# ============================================================================
# ELKIE SOC — One-Command Deployment
# ============================================================================
# Usage:
#   ./deploy.sh                          # Interactive mode
#   ./deploy.sh --env /path/to/.env      # Use existing env file
#   ./deploy.sh --check                  # Validate environment only
#   ./deploy.sh --component analyzer     # Deploy single component
#
# Components: analyzer, dashboards, watchdog, reports, all
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${GREEN}[ELKIE]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step() { echo -e "\n${BLUE}=== $* ===${NC}"; }

# ── Argument parsing ────────────────────────────────────────────────────────

ENV_FILE=""
CHECK_ONLY=false
COMPONENT="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env)       ENV_FILE="$2"; shift 2 ;;
        --check)     CHECK_ONLY=true; shift ;;
        --component) COMPONENT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--env FILE] [--check] [--component NAME]"
            echo "Components: analyzer, dashboards, watchdog, reports, all"
            exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Load environment ────────────────────────────────────────────────────────

if [ -n "$ENV_FILE" ]; then
    if [ ! -f "$ENV_FILE" ]; then
        err "Env file not found: $ENV_FILE"
        exit 1
    fi
    source "$ENV_FILE"
elif [ -f "$PROJECT_DIR/.env" ]; then
    source "$PROJECT_DIR/.env"
elif [ -f "$PROJECT_DIR/.sample_analyzer_env" ]; then
    source "$PROJECT_DIR/.sample_analyzer_env"
else
    warn "No .env file found. Using defaults + existing environment."
    warn "Copy .env.example to .env and configure: cp .env.example .env"
fi

# Apply defaults for anything not set
export ELKIE_HOME="${ELKIE_HOME:-$PROJECT_DIR}"
export ES_URL="${ES_URL:-http://localhost:9200}"
export ES_RESULT_INDEX="${ES_RESULT_INDEX:-malware-analysis}"
export STAGING_DIR="${STAGING_DIR:-$ELKIE_HOME/sample_staging}"
export REPORTS_DIR="${REPORTS_DIR:-$ELKIE_HOME/reports}"

# ── Validation ──────────────────────────────────────────────────────────────

validate_env() {
    step "Validating environment"
    local errors=0

    # Required files
    for f in sample_analyzer.py analyze_sample.sh ghidra_deep_extract.py check_sacrificial.sh ReportIPs.sh; do
        if [ -f "$PROJECT_DIR/$f" ]; then
            log "Found $f"
        else
            err "Missing $f"
            ((errors++))
        fi
    done

    # Check ES connectivity
    if curl -sf "${ES_URL}/_cluster/health" > /dev/null 2>&1; then
        log "Elasticsearch reachable at ${ES_URL}"
    else
        warn "Elasticsearch not reachable at ${ES_URL} — may need to start it first"
    fi

    # Check required tools
    for tool in python3 jq curl ssh tshark; do
        if command -v "$tool" > /dev/null 2>&1; then
            log "Found $tool"
        else
            warn "Missing $tool — some features may not work"
        fi
    done

    # Check Python dependencies
    python3 -c "import requests" 2>/dev/null && log "Python requests OK" || warn "pip install requests"
    python3 -c "import yaml" 2>/dev/null && log "Python PyYAML OK" || warn "pip install pyyaml"

    # Check API keys
    [ -n "${CLAUDE_API_KEY:-}" ] && log "Claude API key set" || warn "CLAUDE_API_KEY not set — LLM analysis disabled"
    [ -n "${VT_API_KEY:-}" ] && log "VirusTotal API key set" || warn "VT_API_KEY not set — VT lookups disabled"
    [ -n "${DISCORD_WEBHOOK_URL:-}" ] && log "Discord webhook set" || warn "DISCORD_WEBHOOK_URL not set — no alerts"
    [ -n "${ABUSEIPDB_API_KEY:-}" ] && log "AbuseIPDB key set" || warn "ABUSEIPDB_API_KEY not set — no IP reporting"

    # Check SSH connectivity to T-Pot jump host
    if [ -n "${TPOT_IP:-}" ]; then
        if ssh -o BatchMode=yes -o ConnectTimeout=5 -p "${TPOT_SSH_PORT:-64295}" \
               "${TPOT_SSH_USER:-lepots}@${TPOT_IP}" "echo OK" 2>/dev/null | grep -q OK; then
            log "T-Pot jump host reachable"
        else
            warn "Cannot reach T-Pot at ${TPOT_IP}:${TPOT_SSH_PORT:-64295}"
        fi
    fi

    if [ "$errors" -gt 0 ]; then
        err "$errors critical errors found"
        return 1
    fi
    log "Validation passed"
}

# ── Component deployers ─────────────────────────────────────────────────────

deploy_directories() {
    step "Creating directories"
    mkdir -p "$STAGING_DIR" "$REPORTS_DIR"
    log "Created $STAGING_DIR"
    log "Created $REPORTS_DIR"
}

deploy_es_index() {
    step "Setting up Elasticsearch index template"
    curl -sf -X PUT "${ES_URL}/${ES_RESULT_INDEX}" \
        -H 'Content-Type: application/json' \
        -d '{
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "sha256": {"type": "keyword"},
                    "md5": {"type": "keyword"},
                    "classification": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "confidence": {"type": "integer"},
                    "malware_family": {"type": "keyword"},
                    "file_type": {"type": "text"},
                    "file_size": {"type": "long"},
                    "indexed_at": {"type": "date"},
                    "source": {
                        "properties": {
                            "src_ip": {"type": "ip"},
                            "honeypot": {"type": "keyword"},
                            "country": {"type": "keyword"},
                            "session_id": {"type": "keyword"},
                            "captured_at": {"type": "date"},
                            "download_command": {"type": "text"},
                            "download_user": {"type": "keyword"},
                            "attacker_user": {"type": "keyword"}
                        }
                    }
                }
            }
        }' 2>/dev/null && log "Index ${ES_RESULT_INDEX} ready" \
        || warn "Index may already exist (OK)"
}

deploy_analyzer_service() {
    step "Deploying sample-analyzer systemd service"

    cat > /tmp/sample-analyzer.service << UNIT
[Unit]
Description=ELKIE SOC — Sample Analyzer Pipeline
After=network.target elasticsearch.service
Wants=elasticsearch.service

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=-${PROJECT_DIR}/.env
EnvironmentFile=-${PROJECT_DIR}/.sample_analyzer_env
ExecStart=/usr/bin/python3 ${PROJECT_DIR}/sample_analyzer.py
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT

    if sudo cp /tmp/sample-analyzer.service /etc/systemd/system/ 2>/dev/null; then
        sudo systemctl daemon-reload
        sudo systemctl enable sample-analyzer.service
        log "Service installed: sample-analyzer.service"
        log "Start with: sudo systemctl start sample-analyzer"
    else
        warn "Could not install systemd service (no sudo?). Manual start:"
        log "  source .env && python3 sample_analyzer.py"
    fi
}

deploy_watchdog_cron() {
    step "Deploying watchdog cron job"
    local cron_line="*/30 * * * * cd ${PROJECT_DIR} && bash check_sacrificial.sh"

    if crontab -l 2>/dev/null | grep -q "check_sacrificial"; then
        log "Watchdog cron already exists"
    else
        (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
        log "Added watchdog cron (every 30 min)"
    fi
}

deploy_abuseipdb_cron() {
    step "Deploying AbuseIPDB reporting cron"
    local cron_line="0 */6 * * * cd ${PROJECT_DIR} && bash ReportIPs.sh >> ${ELKIE_HOME}/abuseipdb.log 2>&1"

    if crontab -l 2>/dev/null | grep -q "ReportIPs"; then
        log "AbuseIPDB cron already exists"
    else
        (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
        log "Added AbuseIPDB reporting cron (every 6 hours)"
    fi
}

deploy_analysis_script() {
    step "Deploying analysis script to REMnux"
    local remnux_user="${REMNUX_SSH_USER:-nalyzer}"
    local remnux_host="${REMNUX_IP:-}"
    local tpot_jump="${TPOT_SSH_USER:-lepots}@${TPOT_IP:-}:${TPOT_SSH_PORT:-64295}"

    if [ -z "$remnux_host" ]; then
        warn "REMNUX_IP not set — skipping REMnux deployment"
        return
    fi

    # Deploy via jump host
    local ssh_cmd="ssh -o StrictHostKeyChecking=no -J $tpot_jump ${remnux_user}@${remnux_host}"

    $ssh_cmd "mkdir -p ~/inbox ~/results ~/yara-rules" 2>/dev/null && log "Created REMnux directories"

    # Copy analysis script and Ghidra extractor
    for script in analyze_sample.sh ghidra_deep_extract.py; do
        cat "$PROJECT_DIR/$script" | $ssh_cmd "cat > ~/$script && chmod +x ~/$script" 2>/dev/null \
            && log "Deployed $script to REMnux" \
            || warn "Failed to deploy $script"
    done
}

deploy_dashboards() {
    step "Deploying Grafana dashboards"
    if [ -n "${GRAFANA_TOKEN:-}" ]; then
        python3 "$PROJECT_DIR/rebuild_honeypot_dashboard.py" \
            && log "Grafana dashboard rebuilt" \
            || warn "Dashboard rebuild failed"
    else
        warn "GRAFANA_TOKEN not set — skipping dashboard deployment"
    fi
}

# ── Main ────────────────────────────────────────────────────────────────────

echo -e "${BLUE}"
echo "  _____ _     _  _____ _____   ____   ___   ____"
echo " | ____| |   | |/ /_ _| ____| / ___| / _ \\ / ___|"
echo " |  _| | |   | ' / | ||  _|   \\___ \\| | | | |    "
echo " | |___| |___| . \\ | || |___   ___) | |_| | |___ "
echo " |_____|_____|_|\\_\\___|_____| |____/ \\___/ \\____|"
echo -e "${NC}"
echo "  Automated Honeypot SOC — Deployment Tool"
echo ""

validate_env || { $CHECK_ONLY && exit 1 || warn "Continuing despite validation warnings..."; }
$CHECK_ONLY && { log "Check complete."; exit 0; }

case "$COMPONENT" in
    analyzer)
        deploy_directories
        deploy_es_index
        deploy_analyzer_service
        ;;
    dashboards)
        deploy_dashboards
        ;;
    watchdog)
        deploy_watchdog_cron
        ;;
    reports)
        deploy_abuseipdb_cron
        ;;
    all)
        deploy_directories
        deploy_es_index
        deploy_analyzer_service
        deploy_watchdog_cron
        deploy_abuseipdb_cron
        deploy_analysis_script
        deploy_dashboards
        ;;
    *)
        err "Unknown component: $COMPONENT"
        exit 1
        ;;
esac

step "Deployment complete"
log "Next steps:"
log "  1. Review and edit .env file"
log "  2. Start the analyzer: sudo systemctl start sample-analyzer"
log "  3. Monitor: journalctl -u sample-analyzer -f"
log "  4. Check Discord for alerts"
