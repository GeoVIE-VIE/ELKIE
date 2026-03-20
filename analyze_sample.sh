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

# Idempotent: skip if already analyzed
RESULT_FILE="${RESULTS_DIR}/${SHA256}.json"
if [ -f "$RESULT_FILE" ]; then
    echo "Already analyzed: $SHA256"
    exit 0
fi

echo "Analyzing: $SHA256 (${FILE_SIZE} bytes)"

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
    INTERESTING_STRINGS=$(timeout 30 strings -n 6 "$SAMPLE" 2>/dev/null | \
        grep -iE '(https?://|ftp://|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\.onion|\.top|\.xyz|\.ru|\.cn|/tmp/|/dev/shm|/var/tmp|/bin/sh|/bin/bash|cmd\.exe|powershell|wget|curl|chmod|crontab|authorized_keys|shadow|passwd|stratum|pool\.|xmrig|monero|bitcoin|wallet|c2|beacon|bot|scan|exploit|payload|shell|bind|reverse|connect|socket|download|upload|encrypt|decrypt|ransom|lock|crypto|base64|eval|exec)' | \
        head -100 | sort -u | json_array_from_lines) || INTERESTING_STRINGS="[]"
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
# Ollama LLM summary
# ---------------------------------------------------------------------------

LLM_SUMMARY=""
ANALYZED_AT=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    # Build prompt — write to temp file to avoid shell escaping issues
    PROMPT_FILE=$(mktemp /tmp/llm_prompt.XXXXXX)
    cat > "$PROMPT_FILE" << 'PROMPT_HEADER'
You are a malware analyst. Analyze the following static analysis results and provide:
1. Classification (botnet, trojan, miner, ransomware, backdoor, worm, dropper, RAT, unknown)
2. Severity (critical, high, medium, low)
3. Key IOCs (IPs, domains, URLs)
4. MITRE ATT&CK TTPs observed
5. Brief threat assessment (2-3 paragraphs)

Be concise and factual. If evidence is insufficient, say so.

--- ANALYSIS RESULTS ---
PROMPT_HEADER

    cat >> "$PROMPT_FILE" << EOF
File Type: ${FILE_TYPE}
MIME: ${MIME_TYPE}
Size: ${FILE_SIZE} bytes
SHA256: ${SHA256}
MD5: ${MD5}
Is PE: ${IS_PE}
Is ELF: ${IS_ELF}

YARA Matches: ${YARA_MATCHES}

Interesting Strings (sample):
$(echo "$INTERESTING_STRINGS" | python3 -c "import json,sys; [print(s) for s in json.load(sys.stdin)[:30]]" 2>/dev/null)

FLOSS Decoded Strings:
$(echo "$FLOSS_STRINGS" | python3 -c "import json,sys; [print(s) for s in json.load(sys.stdin)[:20]]" 2>/dev/null)

capa Capabilities:
$(echo "$CAPA_CAPABILITIES" | python3 -c "import json,sys; [print(f'{c[\"namespace\"]}: {c[\"name\"]}') for c in json.load(sys.stdin)[:20]]" 2>/dev/null)

peframe: $([ "$PEFRAME_JSON" = "null" ] && echo "N/A (not a PE file or peframe unavailable)" || echo "$PEFRAME_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps({k:v for k,v in d.items() if k in ('imports','sections','packer','strings_analysis')}, indent=2)[:1000])" 2>/dev/null)
EOF

    PROMPT_CONTENT=$(cat "$PROMPT_FILE")
    rm -f "$PROMPT_FILE"

    # Call Ollama API
    LLM_RESPONSE=$(echo "$PROMPT_CONTENT" | python3 -c "
import json, sys, urllib.request

prompt = sys.stdin.read()
payload = json.dumps({
    'model': 'qwen2.5:14b',
    'prompt': prompt,
    'stream': False,
    'options': {'temperature': 0.3, 'num_predict': 1024}
}).encode()

req = urllib.request.Request(
    'http://localhost:11434/api/generate',
    data=payload,
    headers={'Content-Type': 'application/json'}
)
try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read())
        print(data.get('response', ''))
except Exception as e:
    print('', file=sys.stderr)
" 2>/dev/null || echo "")

    if [ -n "$LLM_RESPONSE" ]; then
        LLM_SUMMARY="$LLM_RESPONSE"
    fi

    # --- Auto-generate YARA rule via LLM ---
    YARA_PROMPT_FILE=$(mktemp /tmp/yara_prompt.XXXXXX)
    cat > "$YARA_PROMPT_FILE" << 'YARA_HEADER'
You are a YARA rule author. Based on the following malware analysis results, write a single YARA rule that would detect this sample and similar variants.

Requirements:
- Rule name should be descriptive (e.g., Linux_Mirai_Downloader, Win_CryptoMiner_XMRig)
- Include meta: author="ELKIE SOC", date, description, sha256, severity
- Use a combination of string matches ($s1, $s2, etc.) and conditions
- Focus on unique/identifying strings: C2 URLs, distinctive commands, hardcoded IPs, unique byte patterns
- Use hex patterns for binary-specific matches where appropriate
- The condition should require multiple strings to match (not just one) to reduce false positives
- Output ONLY the YARA rule, no explanation or markdown. Start with "rule" and end with "}"

--- ANALYSIS DATA ---
YARA_HEADER

    cat >> "$YARA_PROMPT_FILE" << EOF
File Type: ${FILE_TYPE}
SHA256: ${SHA256}
MD5: ${MD5}

Interesting Strings:
$(echo "$INTERESTING_STRINGS" | python3 -c "import json,sys; [print(s) for s in json.load(sys.stdin)[:30]]" 2>/dev/null)

FLOSS Decoded Strings:
$(echo "$FLOSS_STRINGS" | python3 -c "import json,sys; [print(s) for s in json.load(sys.stdin)[:15]]" 2>/dev/null)

Existing YARA Matches: ${YARA_MATCHES}

capa Capabilities:
$(echo "$CAPA_CAPABILITIES" | python3 -c "import json,sys; [print(f'{c[\"namespace\"]}: {c[\"name\"]}') for c in json.load(sys.stdin)[:10]]" 2>/dev/null)

LLM Classification Summary:
$(echo "$LLM_SUMMARY" | head -20)
EOF

    YARA_PROMPT_CONTENT=$(cat "$YARA_PROMPT_FILE")
    rm -f "$YARA_PROMPT_FILE"

    YARA_RULE=$(echo "$YARA_PROMPT_CONTENT" | python3 -c "
import json, sys, urllib.request

prompt = sys.stdin.read()
payload = json.dumps({
    'model': 'qwen2.5:14b',
    'prompt': prompt,
    'stream': False,
    'options': {'temperature': 0.2, 'num_predict': 1024}
}).encode()

req = urllib.request.Request(
    'http://localhost:11434/api/generate',
    data=payload,
    headers={'Content-Type': 'application/json'}
)
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
        rule = data.get('response', '')
        # Clean up — extract just the YARA rule
        lines = rule.strip().splitlines()
        in_rule = False
        clean = []
        for line in lines:
            if line.strip().startswith('rule '):
                in_rule = True
            if in_rule:
                clean.append(line)
            if in_rule and line.strip() == '}':
                break
        print('\n'.join(clean) if clean else '')
except Exception:
    print('')
" 2>/dev/null || echo "")

    # Validate and save the YARA rule
    GENERATED_YARA=""
    if [ -n "$YARA_RULE" ] && echo "$YARA_RULE" | grep -q "^rule "; then
        RULE_FILE="${YARA_RULES_CUSTOM}/auto_${SHA256:0:16}.yar"
        echo "$YARA_RULE" > "$RULE_FILE"

        # Validate the rule compiles
        if yara "$RULE_FILE" /dev/null 2>/dev/null; then
            GENERATED_YARA="$YARA_RULE"
            echo "Generated YARA rule: $RULE_FILE"
        else
            echo "Generated YARA rule failed validation, discarding"
            rm -f "$RULE_FILE"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Assemble final JSON
# ---------------------------------------------------------------------------

export SA_SHA256="$SHA256"
export SA_MD5="$MD5"
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

result = {
    "sha256": sha256,
    "md5": md5,
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
    "generated_yara_rule": generated_yara,
    "analysis_version": "1.1.0"
}

with open(result_file, "w") as f:
    json.dump(result, f, indent=2)

print(f"Analysis complete: {result_file}")
PYEOF
