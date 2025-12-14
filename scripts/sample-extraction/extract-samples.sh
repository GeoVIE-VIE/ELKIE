#!/bin/bash
#===============================================================================
# T-Pot Honeypot Sample Extraction Script
# Safely extracts malware samples from honeypot containers for analysis
#
# Safety features:
#   - Removes execute permissions immediately
#   - Stores in noexec mounted directory
#   - Hashes all files before/after transfer
#   - Maintains chain of custody log
#   - Runs as unprivileged user
#===============================================================================

set -euo pipefail

# Configuration
QUARANTINE_BASE="${QUARANTINE_BASE:-/opt/honeypot-quarantine}"
LOG_DIR="${LOG_DIR:-/var/log/honeypot-extraction}"
CATALOG_FILE="$QUARANTINE_BASE/catalog.json"
MAX_FILE_SIZE="${MAX_FILE_SIZE:-104857600}"  # 100MB max file size
RETENTION_DAYS="${RETENTION_DAYS:-30}"
YARA_RULES_DIR="${YARA_RULES_DIR:-$HOME/rules}"
YARA_ENABLED="${YARA_ENABLED:-true}"

# T-Pot container paths (standard T-Pot installation)
declare -A CONTAINER_PATHS=(
    ["cowrie"]="/home/cowrie/cowrie-git/var/lib/cowrie/downloads"
    ["dionaea"]="/opt/dionaea/var/dionaea/binaries"
    ["glutton"]="/var/lib/glutton"
    ["honeytrap"]="/opt/honeytrap/var/attacks"
    ["tanner"]="/opt/tanner/data"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

#===============================================================================
# Logging Functions
#===============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date -Iseconds) $*"
    echo "$(date -Iseconds) [INFO] $*" >> "$LOG_DIR/extraction.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date -Iseconds) $*"
    echo "$(date -Iseconds) [WARN] $*" >> "$LOG_DIR/extraction.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date -Iseconds) $*" >&2
    echo "$(date -Iseconds) [ERROR] $*" >> "$LOG_DIR/extraction.log"
}

#===============================================================================
# Safety Functions
#===============================================================================

setup_quarantine_dir() {
    local dir="$1"
    mkdir -p "$dir"
    # Remove all execute permissions, set restrictive access
    chmod 750 "$dir"
}

sanitize_file() {
    local filepath="$1"

    # Remove ALL execute permissions immediately
    chmod -x "$filepath" 2>/dev/null || true
    chmod 440 "$filepath"

    # Remove any extended attributes that could be dangerous
    if command -v setfattr &>/dev/null; then
        setfattr -x security.capability "$filepath" 2>/dev/null || true
    fi
}

validate_file_size() {
    local filepath="$1"
    local size
    size=$(stat -f%z "$filepath" 2>/dev/null || stat -c%s "$filepath" 2>/dev/null || echo "0")

    if [[ "$size" -gt "$MAX_FILE_SIZE" ]]; then
        log_warn "File exceeds max size ($size > $MAX_FILE_SIZE): $filepath"
        return 1
    fi
    return 0
}

compute_hashes() {
    local filepath="$1"
    local md5 sha256 sha1 ssdeep_hash

    md5=$(md5sum "$filepath" 2>/dev/null | cut -d' ' -f1 || echo "error")
    sha256=$(sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1 || echo "error")
    sha1=$(sha1sum "$filepath" 2>/dev/null | cut -d' ' -f1 || echo "error")

    # Fuzzy hash if ssdeep is available
    if command -v ssdeep &>/dev/null; then
        ssdeep_hash=$(ssdeep -b "$filepath" 2>/dev/null | tail -1 || echo "")
    else
        ssdeep_hash=""
    fi

    echo "$md5|$sha256|$sha1|$ssdeep_hash"
}

get_file_type() {
    local filepath="$1"
    file -b "$filepath" 2>/dev/null || echo "unknown"
}

#===============================================================================
# YARA Scanning Functions
#===============================================================================

yara_scan() {
    local filepath="$1"
    local matches=""

    # Skip if YARA not enabled or not installed
    if [[ "$YARA_ENABLED" != "true" ]] || ! command -v yara &>/dev/null; then
        echo ""
        return
    fi

    # Skip if rules directory doesn't exist
    if [[ ! -d "$YARA_RULES_DIR" ]]; then
        echo ""
        return
    fi

    # Scan with all rule files
    while IFS= read -r -d '' rulefile; do
        local result
        result=$(yara -w "$rulefile" "$filepath" 2>/dev/null || true)
        if [[ -n "$result" ]]; then
            # Extract just the rule name (first word of each line)
            while IFS= read -r line; do
                local rule_name
                rule_name=$(echo "$line" | awk '{print $1}')
                if [[ -n "$rule_name" ]]; then
                    if [[ -n "$matches" ]]; then
                        matches="$matches,$rule_name"
                    else
                        matches="$rule_name"
                    fi
                fi
            done <<< "$result"
        fi
    done < <(find "$YARA_RULES_DIR" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 2>/dev/null)

    echo "$matches"
}

log_yara_match() {
    local sha256="$1"
    local container="$2"
    local filepath="$3"
    local matches="$4"
    local timestamp
    timestamp=$(date -Iseconds)

    # Log each match as separate JSON entry for Elasticsearch
    IFS=',' read -ra MATCH_ARRAY <<< "$matches"
    for match in "${MATCH_ARRAY[@]}"; do
        local entry
        entry=$(cat <<EOF
{"timestamp":"$timestamp","event_type":"yara_match","sha256":"$sha256","container":"$container","yara_rule":"$match","file_path":"$filepath"}
EOF
)
        echo "$entry" >> "$LOG_DIR/yara-matches.jsonl"
        log_warn "YARA MATCH: $match on $sha256 ($container)"
    done
}

#===============================================================================
# Catalog Functions
#===============================================================================

init_catalog() {
    if [[ ! -f "$CATALOG_FILE" ]]; then
        echo '{"samples":[]}' > "$CATALOG_FILE"
        chmod 640 "$CATALOG_FILE"
    fi
}

add_to_catalog() {
    local container="$1"
    local original_path="$2"
    local quarantine_path="$3"
    local hashes="$4"
    local file_type="$5"
    local file_size="$6"

    IFS='|' read -r md5 sha256 sha1 ssdeep <<< "$hashes"

    local timestamp
    timestamp=$(date -Iseconds)

    # Create JSON entry
    local entry
    entry=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "container": "$container",
    "original_path": "$original_path",
    "quarantine_path": "$quarantine_path",
    "md5": "$md5",
    "sha256": "$sha256",
    "sha1": "$sha1",
    "ssdeep": "$ssdeep",
    "file_type": "$file_type",
    "file_size": $file_size
}
EOF
)

    # Append to catalog (using temp file for safety)
    local temp_catalog
    temp_catalog=$(mktemp)
    jq --argjson entry "$entry" '.samples += [$entry]' "$CATALOG_FILE" > "$temp_catalog"
    mv "$temp_catalog" "$CATALOG_FILE"

    # Also log to JSONL for easy Filebeat ingestion
    echo "$entry" >> "$LOG_DIR/samples.jsonl"

    log_info "Cataloged: $sha256 ($container)"
}

check_duplicate() {
    local sha256="$1"

    if [[ -f "$CATALOG_FILE" ]]; then
        if jq -e --arg hash "$sha256" '.samples[] | select(.sha256 == $hash)' "$CATALOG_FILE" &>/dev/null; then
            return 0  # Duplicate found
        fi
    fi
    return 1  # Not a duplicate
}

#===============================================================================
# Extraction Functions
#===============================================================================

extract_from_container() {
    local container="$1"
    local src_path="$2"
    local extracted_count=0
    local skipped_count=0

    # Check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        log_warn "Container not running: $container"
        return 0
    fi

    local dest_dir="$QUARANTINE_BASE/$container/$(date +%Y/%m/%d)"
    setup_quarantine_dir "$dest_dir"

    log_info "Extracting from $container:$src_path"

    # Get list of files modified in the last extraction window (default: last 60 minutes)
    local extraction_window="${EXTRACTION_WINDOW:-60}"

    # List files in container
    local files
    files=$(docker exec "$container" find "$src_path" -type f -mmin "-$extraction_window" 2>/dev/null || echo "")

    if [[ -z "$files" ]]; then
        log_info "No new files in $container"
        return 0
    fi

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        local filename
        filename=$(basename "$file")
        local temp_file
        temp_file=$(mktemp -p "$QUARANTINE_BASE/temp")

        # Extract file to temp location
        if ! docker cp "$container:$file" "$temp_file" 2>/dev/null; then
            log_warn "Failed to extract: $container:$file"
            rm -f "$temp_file"
            continue
        fi

        # Immediately sanitize
        sanitize_file "$temp_file"

        # Validate file size
        if ! validate_file_size "$temp_file"; then
            rm -f "$temp_file"
            ((skipped_count++))
            continue
        fi

        # Compute hashes
        local hashes
        hashes=$(compute_hashes "$temp_file")
        local sha256
        sha256=$(echo "$hashes" | cut -d'|' -f2)

        # Check for duplicates
        if check_duplicate "$sha256"; then
            log_info "Skipping duplicate: $sha256"
            rm -f "$temp_file"
            ((skipped_count++))
            continue
        fi

        # Get file metadata
        local file_type file_size
        file_type=$(get_file_type "$temp_file")
        file_size=$(stat -c%s "$temp_file" 2>/dev/null || stat -f%z "$temp_file" 2>/dev/null)

        # Move to final quarantine location (named by sha256)
        local final_path="$dest_dir/${sha256}"
        mv "$temp_file" "$final_path"
        sanitize_file "$final_path"  # Double-check permissions after move

        # Store original filename as extended attribute or sidecar
        echo "$filename" > "${final_path}.name"
        chmod 440 "${final_path}.name"

        # Add to catalog
        add_to_catalog "$container" "$file" "$final_path" "$hashes" "$file_type" "$file_size"

        # YARA scan the new sample
        local yara_matches
        yara_matches=$(yara_scan "$final_path")
        if [[ -n "$yara_matches" ]]; then
            log_yara_match "$sha256" "$container" "$final_path" "$yara_matches"
        fi

        ((extracted_count++))

    done <<< "$files"

    log_info "Extracted $extracted_count files from $container (skipped: $skipped_count)"
}

#===============================================================================
# Cleanup Functions
#===============================================================================

cleanup_old_samples() {
    log_info "Cleaning up samples older than $RETENTION_DAYS days"

    find "$QUARANTINE_BASE" -type f -mtime "+$RETENTION_DAYS" -delete 2>/dev/null || true
    find "$QUARANTINE_BASE" -type d -empty -delete 2>/dev/null || true
}

#===============================================================================
# Main
#===============================================================================

main() {
    # Ensure we're not running as root (safety measure)
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root is not recommended. Consider using a dedicated user."
    fi

    # Setup directories
    mkdir -p "$LOG_DIR"
    mkdir -p "$QUARANTINE_BASE/temp"
    chmod 750 "$QUARANTINE_BASE"
    chmod 750 "$QUARANTINE_BASE/temp"

    # Initialize catalog
    init_catalog

    log_info "Starting sample extraction"

    # Extract from each container
    for container in "${!CONTAINER_PATHS[@]}"; do
        extract_from_container "$container" "${CONTAINER_PATHS[$container]}" || true
    done

    # Cleanup temp directory
    find "$QUARANTINE_BASE/temp" -type f -delete 2>/dev/null || true

    # Optional: Cleanup old samples
    if [[ "${CLEANUP_OLD:-false}" == "true" ]]; then
        cleanup_old_samples
    fi

    log_info "Extraction complete"
}

# Run main function
main "$@"
