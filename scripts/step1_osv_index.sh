#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 1 — security-osv-vulns index"
echo "═══════════════════════════════════════════"

# ILM policy
info "Creating ILM policy: security-reference-data-policy"
RES=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/_ilm/policy/security-reference-data-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "actions": {
            "set_priority": { "priority": 100 }
          }
        }
      }
    }
  }')
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.acknowledged') != "true" ]] && fail "ILM policy creation failed"
ok "ILM policy created"

# Index template
info "Creating index template: security-osv-vulns-template"
RES=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/_index_template/security-osv-vulns-template" \
  -H "Content-Type: application/json" \
  -d @"$(dirname "$0")/../mappings/security-osv-vulns.json")
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.acknowledged') != "true" ]] && fail "Index template creation failed"
ok "Index template created"

# Create index
info "Creating index: security-osv-vulns"
RES=$(curl -s -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/security-osv-vulns" \
  -H "Content-Type: application/json" \
  -d '{"aliases": {"security-osv-vulns-latest": {"is_write_index": true}}}')
echo "$RES" | jq .
# index may already exist — that is fine
ACK=$(echo "$RES" | jq -r '.acknowledged // .error.type')
[[ "$ACK" == "resource_already_exists_exception" ]] && ok "Index already exists — skipping" && exit 0
[[ "$ACK" != "true" ]] && fail "Index creation failed: $ACK"
ok "Index security-osv-vulns created"

echo ""
ok "Step 1 complete"
