#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 7 — sca-findings-enrich pipeline"
echo "═══════════════════════════════════════════"

info "Creating ingest pipeline: sca-findings-enrich"
RES=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/_ingest/pipeline/sca-findings-enrich" \
  -H "Content-Type: application/json" \
  -d @"$(dirname "$0")/../pipelines/sca-findings-enrich.json")
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.acknowledged') != "true" ]] && fail "Pipeline creation failed"
ok "Pipeline sca-findings-enrich created"

echo ""
ok "Step 7 complete"
