#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 2 — osv-vuln-ingest pipeline"
echo "═══════════════════════════════════════════"

info "Creating ingest pipeline: osv-vuln-ingest"
RES=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/_ingest/pipeline/osv-vuln-ingest" \
  -H "Content-Type: application/json" \
  -d @"$(dirname "$0")/../pipelines/osv-vuln-ingest.json")
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.acknowledged') != "true" ]] && fail "Pipeline creation failed"
ok "Pipeline osv-vuln-ingest created"

# Verify — simulate with real OSV data
info "Simulating pipeline with real log4j-core vuln from OSV..."
curl -sf -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"version":"2.14.1","package":{"name":"org.apache.logging.log4j:log4j-core","ecosystem":"Maven"}}' \
  > /tmp/osv_response.json

FIRST_VULN=$(jq -c '.vulns[0]' /tmp/osv_response.json)

SIM=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X POST "${ES_HOST}/_ingest/pipeline/osv-vuln-ingest/_simulate" \
  -H "Content-Type: application/json" \
  -d "{\"docs\": [{\"_source\": ${FIRST_VULN}}]}")

echo "$SIM" | jq '.docs[0].doc._source | {
  vuln_id:        ."vulnerability.id",
  cve_id:         ."vulnerability.cve_id",
  severity:       ."vulnerability.severity",
  cvss_vector:    ."vulnerability.cvss_vector",
  purl_bases:     ."vulnerability.purl_bases",
  versions_count: (."vulnerability.vulnerable_versions" | length),
  fix_version:    ."vulnerability.fix_version",
  ecosystem:      ."vulnerability.ecosystem"
}'

# Check for pipeline error
ERROR=$(echo "$SIM" | jq -r '.docs[0].error // empty')
[ -n "${ERROR:-}" ] && fail "Pipeline simulation failed: $ERROR"

VULN_ID=$(echo "$SIM" | jq -r '.docs[0].doc._source."vulnerability.id"')
[ "$VULN_ID" = "null" ] || [ -z "$VULN_ID" ] && fail "vulnerability.id is missing from simulation output"
ok "Pipeline simulation passed — vuln_id: ${VULN_ID}"

echo ""
ok "Step 2 complete"
