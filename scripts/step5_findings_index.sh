#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 5 — security-sca-findings index"
echo "═══════════════════════════════════════════"

info "Creating index template: security-sca-findings-template"
RES=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/_index_template/security-sca-findings-template" \
  -H "Content-Type: application/json" \
  -d @"$(dirname "$0")/../mappings/security-sca-findings.json")
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.acknowledged') != "true" ]] && fail "Index template creation failed"
ok "Index template security-sca-findings-template created"

echo ""
ok "Step 5 complete"
