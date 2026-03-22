#!/usr/bin/env bash
# analyze_sample.sh — Static malware analysis pipeline for REMnux
# Takes a sample path as argument, outputs JSON to /home/nalyzer/results/<sha256>.json
#
# Usage: bash analyze_sample.sh /home/nalyzer/inbox/<filename>

set -euo pipefail

RESULTS_DIR="/home/nalyzer/results"
YARA_RULES_CUSTOM="/home/nalyzer/yara-rules"
YARA_RULES_RAT="/opt/ratdecoders/lib/python3.8/site-packages/malwareconfig/yaraRules"
MAX_SIZE=52428800  # 50MB
ANALYSIS_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() { echo "ERROR: $1" >&2; exit 1; }

json_escape() {
    python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))"
}

json_array_from_lines() {
    python3 -c "
import json, sys
lines = [l.strip() for l in sys.stdin if l.strip()]
print(json.dumps(lines))
"
}

# ---------------------------------------------------------------------------
# Validate input
# ---------------------------------------------------------------------------

SAMPLE="${1:-}"
[ -z "$SAMPLE" ] && die "Usage: analyze_sample.sh <sample_path>"
[ -f "$SAMPLE" ] || die "Sample not found: $SAMPLE"

FILE_SIZE=$(stat -c%s "$SAMPLE" 2>/dev/null || stat -f%z "$SAMPLE" 2>/dev/null)
[ "$FILE_SIZE" -gt "$MAX_SIZE" ] && die "Sample too large: ${FILE_SIZE} bytes (max ${MAX_SIZE})"

mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

SHA256=$(sha256sum "$SAMPLE" | awk '{print $1}')
MD5=$(md5sum "$SAMPLE" | awk '{print $1}')

# Fuzzy hash for similarity matching
SSDEEP_HASH=""
if command -v ssdeep &>/dev/null; then
    SSDEEP_HASH=$(timeout 10 ssdeep -b "$SAMPLE" 2>/dev/null | tail -1 | cut -d, -f1)
fi

# Idempotent: skip if already analyzed
RESULT_FILE="${RESULTS_DIR}/${SHA256}.json"
if [ -f "$RESULT_FILE" ]; then
    echo "Already analyzed: $SHA256"
    exit 0
fi

echo "Analyzing: $SHA256 (${FILE_SIZE} bytes)"

# ---------------------------------------------------------------------------
# Unpack (UPX, etc.) before analysis to reveal hidden strings/code
# ---------------------------------------------------------------------------

UNPACKED=false
# Try multiple UPX versions (newest first) to handle all packer versions
for UPX_BIN in upx5 upx; do
    if command -v "$UPX_BIN" &>/dev/null; then
        cp "$SAMPLE" "${SAMPLE}.packed"
        UPX_OUTPUT=$("$UPX_BIN" -d "$SAMPLE" 2>&1)
        if [ $? -eq 0 ]; then
            NEW_SIZE=$(stat -c%s "$SAMPLE" 2>/dev/null)
            echo "Unpacked with $UPX_BIN: ${FILE_SIZE} → ${NEW_SIZE} bytes"
            UNPACKED=true
            rm -f "${SAMPLE}.packed"
            break
        else
            echo "UPX unpack failed with $UPX_BIN: $UPX_OUTPUT"
            mv "${SAMPLE}.packed" "$SAMPLE"
        fi
        rm -f "${SAMPLE}.packed"
    fi
done

# ---------------------------------------------------------------------------
# File type
# ---------------------------------------------------------------------------

FILE_TYPE=$(timeout 10 file -b "$SAMPLE" 2>/dev/null || echo "unknown")
MIME_TYPE=$(timeout 10 file -b --mime-type "$SAMPLE" 2>/dev/null || echo "unknown")

IS_PE=false
IS_ELF=false
echo "$FILE_TYPE" | grep -qi "PE32" && IS_PE=true
echo "$FILE_TYPE" | grep -qi "ELF" && IS_ELF=true

# ---------------------------------------------------------------------------
# Interesting strings
# ---------------------------------------------------------------------------

INTERESTING_STRINGS="[]"
if command -v strings &>/dev/null; then
    INTERESTING_STRINGS=$(timeout 60 strings -n 6 "$SAMPLE" 2>/dev/null | \
        grep -iE '(https?://|ftp://|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\.onion|\.top|\.xyz|\.ru|\.cn|\.com|\.net|\.org|/tmp/|/dev/shm|/var/tmp|/bin/sh|/bin/bash|cmd\.exe|powershell|wget|curl|chmod|crontab|authorized_keys|shadow|passwd|stratum|pool\.|xmrig|monero|bitcoin|wallet|c2|beacon|bot|scan|exploit|payload|shell|bind|reverse|connect|socket|download|upload|encrypt|decrypt|ransom|lock|crypto|base64|eval|exec|nicehash|donate|mining|miner|redtail|mirai|gafgyt|tsunami)' | \
        head -200 | sort -u | json_array_from_lines) || INTERESTING_STRINGS="[]"
fi

# ---------------------------------------------------------------------------
# YARA scan
# ---------------------------------------------------------------------------

YARA_MATCHES="[]"
if command -v yara &>/dev/null; then
    YARA_OUTPUT=""
    # Scan custom rules
    if [ -d "$YARA_RULES_CUSTOM" ] && ls "$YARA_RULES_CUSTOM"/*.yar "$YARA_RULES_CUSTOM"/*.yara 2>/dev/null | head -1 >/dev/null; then
        for rule in "$YARA_RULES_CUSTOM"/*.yar "$YARA_RULES_CUSTOM"/*.yara; do
            [ -f "$rule" ] || continue
            YARA_OUTPUT+=$(timeout 30 yara -w "$rule" "$SAMPLE" 2>/dev/null | awk '{print $1}')$'\n'
        done
    fi
    # Scan ratdecoders rules
    if [ -d "$YARA_RULES_RAT" ] && ls "$YARA_RULES_RAT"/*.yar "$YARA_RULES_RAT"/*.yara 2>/dev/null | head -1 >/dev/null; then
        for rule in "$YARA_RULES_RAT"/*.yar "$YARA_RULES_RAT"/*.yara; do
            [ -f "$rule" ] || continue
            YARA_OUTPUT+=$(timeout 30 yara -w "$rule" "$SAMPLE" 2>/dev/null | awk '{print $1}')$'\n'
        done
    fi
    if [ -n "$YARA_OUTPUT" ]; then
        YARA_MATCHES=$(echo "$YARA_OUTPUT" | grep -v '^$' | sort -u | json_array_from_lines)
    fi
fi

# ---------------------------------------------------------------------------
# capa — capability analysis
# ---------------------------------------------------------------------------

CAPA_CAPABILITIES="[]"
if command -v capa &>/dev/null; then
    CAPA_JSON=$(timeout 120 capa -j "$SAMPLE" 2>/dev/null || echo "{}")
    if [ -n "$CAPA_JSON" ] && [ "$CAPA_JSON" != "{}" ]; then
        CAPA_CAPABILITIES=$(echo "$CAPA_JSON" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    rules = data.get('rules', {})
    caps = []
    for name, info in rules.items():
        meta = info.get('meta', {})
        ns = meta.get('namespace', '')
        caps.append({'name': name, 'namespace': ns})
    print(json.dumps(caps))
except:
    print('[]')
" 2>/dev/null) || CAPA_CAPABILITIES="[]"
    fi
fi

# ---------------------------------------------------------------------------
# FLOSS — deobfuscated strings
# ---------------------------------------------------------------------------

FLOSS_STRINGS="[]"
if command -v floss &>/dev/null; then
    FLOSS_OUTPUT=$(timeout 120 floss --no static "$SAMPLE" 2>/dev/null || echo "")
    if [ -n "$FLOSS_OUTPUT" ]; then
        FLOSS_STRINGS=$(echo "$FLOSS_OUTPUT" | grep -v '^\s*$' | head -50 | json_array_from_lines) || FLOSS_STRINGS="[]"
    fi
fi

# ---------------------------------------------------------------------------
# peframe — PE analysis (PE files only)
# ---------------------------------------------------------------------------

PEFRAME_JSON="null"
if [ "$IS_PE" = "true" ] && command -v peframe &>/dev/null; then
    PEFRAME_OUTPUT=$(timeout 60 peframe --json "$SAMPLE" 2>/dev/null || echo "")
    if [ -n "$PEFRAME_OUTPUT" ]; then
        # Validate it's actual JSON
        PEFRAME_JSON=$(echo "$PEFRAME_OUTPUT" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(json.dumps(data))
except:
    print('null')
" 2>/dev/null) || PEFRAME_JSON="null"
    fi
fi

# ---------------------------------------------------------------------------
# Ghidra headless decompilation (PE and ELF binaries only)
# ---------------------------------------------------------------------------

GHIDRA_JSON="null"
GHIDRA_SCRIPT="/home/nalyzer/ghidra_extract.py"
GHIDRA_BIN="/opt/ghidra/support/analyzeHeadless"
GHIDRA_PROJECT="/tmp/ghidra_projects"

if ( [ "$IS_PE" = "true" ] || [ "$IS_ELF" = "true" ] ) && [ -x "$GHIDRA_BIN" ] && [ -f "$GHIDRA_SCRIPT" ]; then
    echo "Running Ghidra headless analysis..."
    mkdir -p "$GHIDRA_PROJECT"

    # Clean any previous project for this sample
    rm -rf "${GHIDRA_PROJECT}/sample_${SHA256:0:16}" "${GHIDRA_PROJECT}/sample_${SHA256:0:16}.rep" 2>/dev/null

    # Run Ghidra headless with extraction postscript
    SA_SHA256="$SHA256" timeout 180 "$GHIDRA_BIN" \
        "$GHIDRA_PROJECT" "sample_${SHA256:0:16}" \
        -import "$SAMPLE" \
        -postscript "$GHIDRA_SCRIPT" \
        -deleteProject \
        -analysisTimeoutPerFile 120 \
        2>/dev/null

    # Read the output
    GHIDRA_RESULT="/home/nalyzer/results/${SHA256}_ghidra.json"
    if [ -f "$GHIDRA_RESULT" ]; then
        GHIDRA_JSON=$(cat "$GHIDRA_RESULT")
        echo "Ghidra analysis complete"
    else
        echo "Ghidra analysis produced no output"
    fi

    # Cleanup
    rm -rf "${GHIDRA_PROJECT}/sample_${SHA256:0:16}" "${GHIDRA_PROJECT}/sample_${SHA256:0:16}.rep" 2>/dev/null
fi

# ---------------------------------------------------------------------------
# LLM analysis moved to ELK (Claude API) — REMnux only does static tools
# ---------------------------------------------------------------------------

LLM_SUMMARY=""
GENERATED_YARA=""
ANALYZED_AT=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

# ---------------------------------------------------------------------------
# Assemble final JSON
# ---------------------------------------------------------------------------

export SA_SHA256="$SHA256"
export SA_MD5="$MD5"
export SA_SSDEEP="${SSDEEP_HASH:-}"
export SA_FILE_TYPE="$FILE_TYPE"
export SA_MIME_TYPE="$MIME_TYPE"
export SA_FILE_SIZE="$FILE_SIZE"
export SA_IS_PE="$IS_PE"
export SA_IS_ELF="$IS_ELF"
export SA_ANALYZED_AT="$ANALYZED_AT"
export SA_RESULT_FILE="$RESULT_FILE"
export SA_LLM_SUMMARY="$LLM_SUMMARY"
export SA_GENERATED_YARA="${GENERATED_YARA:-}"
export SA_YARA="$YARA_MATCHES"
export SA_STRINGS="$INTERESTING_STRINGS"
export SA_FLOSS="$FLOSS_STRINGS"
export SA_CAPA="$CAPA_CAPABILITIES"
export SA_PEFRAME="$PEFRAME_JSON"
export SA_GHIDRA="$GHIDRA_JSON"

python3 << 'PYEOF'
import json, os

# Read environment via files/stdin to avoid shell escaping issues
def read_json_or_default(val, default):
    try:
        return json.loads(val)
    except:
        return default

sha256 = os.environ["SA_SHA256"]
md5 = os.environ["SA_MD5"]
ssdeep_hash = os.environ.get("SA_SSDEEP", "") or None
file_type = os.environ["SA_FILE_TYPE"]
mime_type = os.environ["SA_MIME_TYPE"]
file_size = int(os.environ["SA_FILE_SIZE"])
is_pe = os.environ.get("SA_IS_PE", "false") == "true"
is_elf = os.environ.get("SA_IS_ELF", "false") == "true"
analyzed_at = os.environ["SA_ANALYZED_AT"]
result_file = os.environ["SA_RESULT_FILE"]
llm_summary = os.environ.get("SA_LLM_SUMMARY", "") or None
generated_yara = os.environ.get("SA_GENERATED_YARA", "") or None

yara_matches = read_json_or_default(os.environ.get("SA_YARA", "[]"), [])
interesting_strings = read_json_or_default(os.environ.get("SA_STRINGS", "[]"), [])
floss_strings = read_json_or_default(os.environ.get("SA_FLOSS", "[]"), [])
capa_capabilities = read_json_or_default(os.environ.get("SA_CAPA", "[]"), [])
peframe = read_json_or_default(os.environ.get("SA_PEFRAME", "null"), None)
ghidra = read_json_or_default(os.environ.get("SA_GHIDRA", "null"), None)

result = {
    "sha256": sha256,
    "md5": md5,
    "ssdeep": ssdeep_hash,
    "file_type": file_type,
    "mime_type": mime_type,
    "file_size": file_size,
    "is_pe": is_pe,
    "is_elf": is_elf,
    "analyzed_at": analyzed_at,
    "yara_matches": yara_matches,
    "interesting_strings": interesting_strings,
    "floss_strings": floss_strings,
    "capa_capabilities": capa_capabilities,
    "peframe": peframe,
    "llm_summary": llm_summary,
    "ghidra": ghidra,
    "generated_yara_rule": generated_yara,
    "analysis_version": "1.2.0"
}

with open(result_file, "w") as f:
    json.dump(result, f, indent=2)

print(f"Analysis complete: {result_file}")
PYEOF
