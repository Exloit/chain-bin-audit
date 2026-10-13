#!/usr/bin/env bash
set -euo pipefail

# Usage: bash vt_scan.sh <file_path>
# Requires: VT_API_KEY environment variable
# Outputs: JSON to stdout with scan results

FILE_PATH="${1:-}"
API_KEY="${VT_API_KEY:-}"

json_output() {
    python3 -c "
import json, sys
d = {}
for arg in sys.argv[1:]:
    k, v = arg.split('=', 1)
    try:
        d[k] = json.loads(v)
    except (json.JSONDecodeError, ValueError):
        d[k] = v
print(json.dumps(d, ensure_ascii=False))
" "$@"
}

if [ -z "$FILE_PATH" ]; then
    json_output status=error error_msg="Usage: bash vt_scan.sh <file_path>"
    exit 1
fi

if [ ! -f "$FILE_PATH" ]; then
    json_output status=error error_msg="File not found: $FILE_PATH"
    exit 1
fi

if [ -z "$API_KEY" ]; then
    json_output status=skipped error_msg="VT_API_KEY not set"
    exit 0
fi

FILE_SIZE=$(stat -c%s "$FILE_PATH" 2>/dev/null || stat -f%z "$FILE_PATH" 2>/dev/null)
if [ "$FILE_SIZE" -gt 33554432 ]; then
    json_output status=skipped error_msg="File exceeds 32MB VT free tier limit (${FILE_SIZE} bytes)"
    exit 0
fi

SHA256=$(sha256sum "$FILE_PATH" | cut -d' ' -f1)

# Step 1: Check existing report by hash
sleep 15
LOOKUP=$(curl -s -w "\n%{http_code}" \
    -H "x-apikey: $API_KEY" \
    "https://www.virustotal.com/api/v3/files/$SHA256")
LOOKUP_CODE=$(echo "$LOOKUP" | tail -1)
LOOKUP_BODY=$(echo "$LOOKUP" | sed '$d')

if [ "$LOOKUP_CODE" = "429" ]; then
    sleep 60
    LOOKUP=$(curl -s -w "\n%{http_code}" \
        -H "x-apikey: $API_KEY" \
        "https://www.virustotal.com/api/v3/files/$SHA256")
    LOOKUP_CODE=$(echo "$LOOKUP" | tail -1)
    LOOKUP_BODY=$(echo "$LOOKUP" | sed '$d')
fi

if [ "$LOOKUP_CODE" = "200" ]; then
    LAST_ANALYSIS_EPOCH=$(echo "$LOOKUP_BODY" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data.get('data',{}).get('attributes',{}).get('last_analysis_date', 0))
" 2>/dev/null || echo "0")
    NOW_EPOCH=$(date +%s)
    SEVEN_DAYS=604800
    if [ $((NOW_EPOCH - LAST_ANALYSIS_EPOCH)) -lt $SEVEN_DAYS ]; then
        echo "$LOOKUP_BODY" | python3 -c "
import json, sys
data = json.load(sys.stdin)
attrs = data.get('data',{}).get('attributes',{})
stats = attrs.get('last_analysis_stats',{})
malicious = stats.get('malicious', 0)
total = sum(stats.values())
engines = []
for name, result in attrs.get('last_analysis_results',{}).items():
    if result.get('category') == 'malicious':
        engines.append({'name': name, 'result': result.get('result','')})
sha = attrs.get('sha256','')
vt_link = f'https://www.virustotal.com/gui/file/{sha}'
status = 'detected' if malicious > 0 else 'clean'
print(json.dumps({
    'status': status,
    'detection_rate': f'{malicious}/{total}',
    'malicious_count': malicious,
    'total_engines': total,
    'engines': engines,
    'vt_link': vt_link,
    'sha256': sha
}, ensure_ascii=False))
"
        exit 0
    fi
fi

if [ "$LOOKUP_CODE" = "401" ]; then
    json_output status=error error_msg="VT API key invalid (HTTP 401)" sha256="$SHA256"
    exit 1
fi

# Step 2: Upload file
sleep 15
UPLOAD=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "x-apikey: $API_KEY" \
    --form "file=@$FILE_PATH" \
    "https://www.virustotal.com/api/v3/files")
UPLOAD_CODE=$(echo "$UPLOAD" | tail -1)
UPLOAD_BODY=$(echo "$UPLOAD" | sed '$d')

if [ "$UPLOAD_CODE" = "429" ]; then
    sleep 60
    UPLOAD=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "x-apikey: $API_KEY" \
        --form "file=@$FILE_PATH" \
        "https://www.virustotal.com/api/v3/files")
    UPLOAD_CODE=$(echo "$UPLOAD" | tail -1)
    UPLOAD_BODY=$(echo "$UPLOAD" | sed '$d')
fi

if [ "$UPLOAD_CODE" != "200" ]; then
    json_output status=error error_msg="VT upload failed (HTTP $UPLOAD_CODE)" sha256="$SHA256"
    exit 1
fi

ANALYSIS_ID=$(echo "$UPLOAD_BODY" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data.get('data',{}).get('id',''))
" 2>/dev/null)

if [ -z "$ANALYSIS_ID" ]; then
    json_output status=error error_msg="Failed to parse analysis ID from upload response" sha256="$SHA256"
    exit 1
fi

# Step 3: Poll for results (max 10 min = 40 polls * 15s)
POLL_COUNT=0
MAX_POLLS=40
while [ $POLL_COUNT -lt $MAX_POLLS ]; do
    sleep 15
    POLL=$(curl -s -w "\n%{http_code}" \
        -H "x-apikey: $API_KEY" \
        "https://www.virustotal.com/api/v3/analyses/$ANALYSIS_ID")
    POLL_CODE=$(echo "$POLL" | tail -1)
    POLL_BODY=$(echo "$POLL" | sed '$d')

    if [ "$POLL_CODE" = "429" ]; then
        sleep 60
        POLL_COUNT=$((POLL_COUNT + 1))
        continue
    fi

    POLL_STATUS=$(echo "$POLL_BODY" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data.get('data',{}).get('attributes',{}).get('status',''))
" 2>/dev/null || echo "")

    if [ "$POLL_STATUS" = "completed" ]; then
        echo "$POLL_BODY" | python3 -c "
import json, sys
data = json.load(sys.stdin)
attrs = data.get('data',{}).get('attributes',{})
stats = attrs.get('stats',{})
malicious = stats.get('malicious', 0)
total = sum(stats.values())
engines = []
for name, result in attrs.get('results',{}).items():
    if result.get('category') == 'malicious':
        engines.append({'name': name, 'result': result.get('result','')})
sha = sys.argv[1]
vt_link = f'https://www.virustotal.com/gui/file/{sha}'
status = 'detected' if malicious > 0 else 'clean'
print(json.dumps({
    'status': status,
    'detection_rate': f'{malicious}/{total}',
    'malicious_count': malicious,
    'total_engines': total,
    'engines': engines,
    'vt_link': vt_link,
    'sha256': sha
}, ensure_ascii=False))
" "$SHA256"
        exit 0
    fi

    POLL_COUNT=$((POLL_COUNT + 1))
done

# Timeout
VT_LINK="https://www.virustotal.com/gui/file/$SHA256"
json_output status=timeout vt_link="$VT_LINK" sha256="$SHA256" error_msg="Scan did not complete within 10 minutes"
exit 0
