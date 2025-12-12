#!/bin/bash
#===============================================================================
# Honeypot Sample Analysis Script
# Analyzes extracted samples with YARA rules and optional VirusTotal lookup
#
# Usage:
#   ./analyze-sample.sh <sample_path_or_sha256>
#   ./analyze-sample.sh --batch                    # Analyze all unanalyzed samples
#   ./analyze-sample.sh --watch                    # Watch for new samples
#===============================================================================

set -euo pipefail

QUARANTINE_BASE="${QUARANTINE_BASE:-/opt/honeypot-quarantine}"
YARA_RULES_DIR="${YARA_RULES_DIR:-/opt/yara-rules}"
ANALYSIS_LOG="${ANALYSIS_LOG:-/var/log/honeypot-extraction/analysis.jsonl}"
VT_API_KEY="${VT_API_KEY:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

#===============================================================================
# Analysis Functions
#===============================================================================

analyze_with_yara() {
    local filepath="$1"
    local results=""

    if [[ ! -d "$YARA_RULES_DIR" ]]; then
        echo "null"
        return
    fi

    if ! command -v yara &>/dev/null; then
        echo "null"
        return
    fi

    # Run YARA against all rules
    results=$(find "$YARA_RULES_DIR" -name "*.yar" -o -name "*.yara" | \
        xargs -I {} yara -w {} "$filepath" 2>/dev/null | \
        jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo "[]")

    echo "$results"
}

check_virustotal() {
    local sha256="$1"

    if [[ -z "$VT_API_KEY" ]]; then
        echo '{"error": "No API key configured"}'
        return
    fi

    local response
    response=$(curl -s --max-time 30 \
        "https://www.virustotal.com/api/v3/files/$sha256" \
        -H "x-apikey: $VT_API_KEY" 2>/dev/null || echo '{"error": "request failed"}')

    # Extract key info
    local stats
    stats=$(echo "$response" | jq -c '{
        malicious: .data.attributes.last_analysis_stats.malicious,
        suspicious: .data.attributes.last_analysis_stats.suspicious,
        undetected: .data.attributes.last_analysis_stats.undetected,
        harmless: .data.attributes.last_analysis_stats.harmless,
        popular_threat_name: .data.attributes.popular_threat_classification.suggested_threat_label,
        first_seen: .data.attributes.first_submission_date,
        tags: .data.attributes.tags
    }' 2>/dev/null || echo '{"error": "parse failed"}')

    echo "$stats"
}

get_strings_summary() {
    local filepath="$1"
    local min_length=6

    if ! command -v strings &>/dev/null; then
        echo "[]"
        return
    fi

    # Extract interesting strings (URLs, IPs, commands, etc.)
    strings -n "$min_length" "$filepath" 2>/dev/null | \
        grep -E '(http[s]?://|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|/bin/|/etc/|wget|curl|chmod|sh -c|bash|nc |ncat|\.onion|password|root@|admin)' | \
        head -50 | \
        jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo "[]"
}

analyze_sample() {
    local input="$1"
    local filepath=""
    local sha256=""

    # Determine if input is path or hash
    if [[ -f "$input" ]]; then
        filepath="$input"
        sha256=$(sha256sum "$filepath" | cut -d' ' -f1)
    elif [[ ${#input} -eq 64 ]]; then
        sha256="$input"
        # Find file by hash
        filepath=$(find "$QUARANTINE_BASE" -name "$sha256" -type f 2>/dev/null | head -1)
        if [[ -z "$filepath" ]]; then
            echo -e "${RED}[ERROR]${NC} Sample not found: $sha256"
            return 1
        fi
    else
        echo -e "${RED}[ERROR]${NC} Invalid input: $input"
        return 1
    fi

    echo -e "${BLUE}[*]${NC} Analyzing: $sha256"
    echo -e "${BLUE}[*]${NC} Path: $filepath"

    # Get basic info
    local file_type file_size
    file_type=$(file -b "$filepath" 2>/dev/null || echo "unknown")
    file_size=$(stat -c%s "$filepath" 2>/dev/null || stat -f%z "$filepath" 2>/dev/null)

    echo -e "${GREEN}[+]${NC} Type: $file_type"
    echo -e "${GREEN}[+]${NC} Size: $file_size bytes"

    # YARA analysis
    echo -e "${BLUE}[*]${NC} Running YARA rules..."
    local yara_results
    yara_results=$(analyze_with_yara "$filepath")

    if [[ "$yara_results" != "null" && "$yara_results" != "[]" ]]; then
        echo -e "${YELLOW}[!]${NC} YARA matches:"
        echo "$yara_results" | jq -r '.[]' 2>/dev/null | while read -r match; do
            echo -e "    ${RED}→${NC} $match"
        done
    else
        echo -e "${GREEN}[+]${NC} No YARA matches"
    fi

    # VirusTotal lookup
    if [[ -n "$VT_API_KEY" ]]; then
        echo -e "${BLUE}[*]${NC} Checking VirusTotal..."
        local vt_results
        vt_results=$(check_virustotal "$sha256")

        local malicious suspicious
        malicious=$(echo "$vt_results" | jq -r '.malicious // 0')
        suspicious=$(echo "$vt_results" | jq -r '.suspicious // 0')

        if [[ "$malicious" != "null" && "$malicious" -gt 0 ]]; then
            echo -e "${RED}[!]${NC} VirusTotal: $malicious malicious, $suspicious suspicious"
            local threat_name
            threat_name=$(echo "$vt_results" | jq -r '.popular_threat_name // "unknown"')
            echo -e "${RED}[!]${NC} Threat: $threat_name"
        else
            echo -e "${GREEN}[+]${NC} VirusTotal: No detections (or not yet scanned)"
        fi
    fi

    # Interesting strings
    echo -e "${BLUE}[*]${NC} Extracting interesting strings..."
    local strings_results
    strings_results=$(get_strings_summary "$filepath")

    if [[ "$strings_results" != "[]" ]]; then
        echo -e "${YELLOW}[!]${NC} Notable strings found:"
        echo "$strings_results" | jq -r '.[]' 2>/dev/null | head -10 | while read -r str; do
            echo -e "    → $str"
        done
    fi

    # Log analysis results
    local analysis_result
    analysis_result=$(cat <<EOF
{
    "timestamp": "$(date -Iseconds)",
    "sha256": "$sha256",
    "file_path": "$filepath",
    "file_type": "$file_type",
    "file_size": $file_size,
    "yara_matches": $yara_results,
    "virustotal": ${vt_results:-null},
    "interesting_strings_count": $(echo "$strings_results" | jq 'length')
}
EOF
)

    echo "$analysis_result" >> "$ANALYSIS_LOG"

    echo ""
    echo -e "${GREEN}[+]${NC} Analysis complete"
}

batch_analyze() {
    echo -e "${BLUE}[*]${NC} Batch analyzing unanalyzed samples..."

    local analyzed_hashes
    analyzed_hashes=$(jq -r '.sha256' "$ANALYSIS_LOG" 2>/dev/null | sort -u || echo "")

    find "$QUARANTINE_BASE" -type f ! -name "*.name" ! -name "*.json" ! -name "catalog.json" | while read -r filepath; do
        local sha256
        sha256=$(basename "$filepath")

        # Skip if already analyzed
        if echo "$analyzed_hashes" | grep -q "^$sha256$"; then
            continue
        fi

        analyze_sample "$filepath"
        echo "---"

        # Rate limit for VT API
        sleep 15
    done
}

watch_mode() {
    echo -e "${BLUE}[*]${NC} Watching for new samples..."

    if ! command -v inotifywait &>/dev/null; then
        echo -e "${RED}[ERROR]${NC} inotifywait not installed. Install inotify-tools."
        exit 1
    fi

    inotifywait -m -r -e create --format '%w%f' "$QUARANTINE_BASE" | while read -r filepath; do
        # Skip non-sample files
        [[ "$filepath" == *.name ]] && continue
        [[ "$filepath" == *.json ]] && continue
        [[ -d "$filepath" ]] && continue

        echo ""
        echo -e "${YELLOW}[!]${NC} New sample detected!"
        sleep 2  # Wait for file to be fully written
        analyze_sample "$filepath"
    done
}

#===============================================================================
# Main
#===============================================================================

usage() {
    echo "Usage: $0 <sample_path_or_sha256>"
    echo "       $0 --batch    Analyze all unanalyzed samples"
    echo "       $0 --watch    Watch for new samples and analyze"
    echo ""
    echo "Environment variables:"
    echo "  VT_API_KEY        VirusTotal API key for lookups"
    echo "  YARA_RULES_DIR    Directory containing YARA rules (default: /opt/yara-rules)"
    echo "  QUARANTINE_BASE   Base quarantine directory (default: /opt/honeypot-quarantine)"
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    mkdir -p "$(dirname "$ANALYSIS_LOG")"

    case "$1" in
        --batch)
            batch_analyze
            ;;
        --watch)
            watch_mode
            ;;
        --help|-h)
            usage
            ;;
        *)
            analyze_sample "$1"
            ;;
    esac
}

main "$@"
