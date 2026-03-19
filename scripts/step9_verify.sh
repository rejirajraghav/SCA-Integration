#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 9 — Verify findings"
echo "═══════════════════════════════════════════"

info "security-osv-vulns count:"
curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/security-osv-vulns/_count" | jq .count

info "security-sca-findings count:"
FINDINGS=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/security-sca-findings/_count" | jq .count)
echo "$FINDINGS"
[ "$FINDINGS" = "0" ] || [ "$FINDINGS" = "null" ] && fail "security-sca-findings is empty — check transform and enrich pipeline"

info "Findings by severity:"
curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/security-sca-findings/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":0,"aggs":{"by_severity":{"terms":{"field":"vulnerability.severity"}}}}' \
  | jq '[.aggregations.by_severity.buckets[] | {severity: .key, count: .doc_count}]'

info "Findings by service:"
curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/security-sca-findings/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":0,"aggs":{"by_service":{"terms":{"field":"service.name","size":20}}}}' \
  | jq '[.aggregations.by_service.buckets[] | {service: .key, findings: .doc_count}]'

info "All CVEs for log4j-core (if present):"
curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/security-sca-findings/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"term": {"library.name": "log4j-core"}},
    "sort": [{"vulnerability.severity": "asc"}],
    "_source": ["vulnerability.cve_id","vulnerability.severity","vulnerability.fix_version","service.name","finding.status"]
  }' | jq '[.hits.hits[]._source]'

info "One full CRITICAL finding:"
curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/security-sca-findings/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":1,"query":{"term":{"vulnerability.severity":"CRITICAL"}}}' \
  | jq '.hits.hits[0]._source'

echo ""
ok "Step 9 complete — ${FINDINGS} findings in security-sca-findings"
