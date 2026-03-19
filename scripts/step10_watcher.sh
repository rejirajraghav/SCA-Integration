#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 10 — Enrich policy refresh watcher"
echo "═══════════════════════════════════════════"

# Extract host and port from ES_HOST
ES_HOST_ONLY=$(echo "${ES_HOST}" | sed 's|https://||' | cut -d: -f1)
ES_PORT=$(echo "${ES_HOST}" | sed 's|.*:||')

info "Creating watcher: osv-enrich-policy-refresh"
RES=$(curl -sf -u "elastic:${ES_PASSWORD}" \
  -X PUT "${ES_HOST}/_watcher/watch/osv-enrich-policy-refresh" \
  -H "Content-Type: application/json" \
  -d "{
    \"trigger\": {
      \"schedule\": { \"interval\": \"6h\" }
    },
    \"actions\": {
      \"refresh_enrich_policy\": {
        \"webhook\": {
          \"method\": \"POST\",
          \"host\": \"${ES_HOST_ONLY}\",
          \"port\": ${ES_PORT},
          \"scheme\": \"https\",
          \"path\": \"/_enrich/policy/osv-purl-enrich-policy/_execute\",
          \"auth\": {
            \"basic\": {
              \"username\": \"elastic\",
              \"password\": \"${ES_PASSWORD}\"
            }
          }
        }
      }
    }
  }")
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.created // false') == "false" ]] && \
  [[ $(echo "$RES" | jq -r '._id // empty') == "" ]] && \
  fail "Watcher creation failed"
ok "Watcher osv-enrich-policy-refresh created (fires every 6h)"

echo ""
ok "Step 10 complete"
