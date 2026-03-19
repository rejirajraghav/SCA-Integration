#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 6 — osv-purl-enrich-policy"
echo "═══════════════════════════════════════════"

info "Creating enrich policy: osv-purl-enrich-policy"
RES=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/_enrich/policy/osv-purl-enrich-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "match": {
      "indices": "security-osv-vulns",
      "match_field": "vulnerability.purl_bases",
      "enrich_fields": [
        "vulnerability.id",
        "vulnerability.cve_id",
        "vulnerability.severity",
        "vulnerability.cvss_vector",
        "vulnerability.cvss_type",
        "vulnerability.cwe_ids",
        "vulnerability.vulnerable_versions",
        "vulnerability.fix_version",
        "vulnerability.published_at"
      ]
    }
  }')
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.acknowledged') != "true" ]] && fail "Enrich policy creation failed"
ok "Enrich policy created"

info "Executing enrich policy (building internal index)..."
curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X POST "${ES_HOST}/_enrich/policy/osv-purl-enrich-policy/_execute" | jq .

info "Polling for COMPLETE status..."
for i in 1 2 3 4 5 6 7 8 9 10; do
  STATUS=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
    "${ES_HOST}/_enrich/policy/osv-purl-enrich-policy" \
    | jq -r '.policies[0].config.match.status // "pending"')
  echo "  Attempt ${i}: ${STATUS}"
  [ "$STATUS" = "COMPLETE" ] && ok "Enrich policy is COMPLETE" && exit 0
  sleep 5
done

fail "Enrich policy did not reach COMPLETE status after 50s"
