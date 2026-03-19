#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 3 — Seed security-osv-vulns"
echo "  (top 5 libraries from agent index)"
echo "═══════════════════════════════════════════"

# Pull top 5 libraries from agent index
info "Fetching top libraries from ${LIBRARY_INDEX}..."
LIBS=$(curl -sf -u "elastic:${ES_PASSWORD}" "${ES_HOST}/${LIBRARY_INDEX}/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": { "term": { "event.action": "library-loaded" } },
    "aggs": {
      "libs": {
        "composite": {
          "size": 5,
          "sources": [
            { "group_id": { "terms": { "field": "library.group_id" } } },
            { "name":     { "terms": { "field": "library.name"     } } },
            { "version":  { "terms": { "field": "library.version"  } } }
          ]
        }
      }
    }
  }')

echo "$LIBS" | jq '.aggregations.libs.buckets[] | {
  osv_name: (.key.group_id + ":" + .key.name),
  version:  .key.version
}'

TOTAL_SEEDED=0

while IFS= read -r lib; do
  GROUP_ID=$(echo "$lib" | jq -r '.key.group_id')
  NAME=$(echo "$lib" | jq -r '.key.name')
  VERSION=$(echo "$lib" | jq -r '.key.version')
  OSV_NAME="${GROUP_ID}:${NAME}"

  info "Querying OSV for ${OSV_NAME}@${VERSION}..."

  VULNS=$(curl -sf -X POST "https://api.osv.dev/v1/query" \
    -H "Content-Type: application/json" \
    -d "{
      \"version\": \"${VERSION}\",
      \"package\": {
        \"name\": \"${OSV_NAME}\",
        \"ecosystem\": \"Maven\"
      }
    }" | jq -r '.vulns // [] | length')

  echo "  Found ${VULNS} vulns"

  if [ "$VULNS" -gt 0 ]; then
    curl -sf -X POST "https://api.osv.dev/v1/query" \
      -H "Content-Type: application/json" \
      -d "{
        \"version\": \"${VERSION}\",
        \"package\": {
          \"name\": \"${OSV_NAME}\",
          \"ecosystem\": \"Maven\"
        }
      }" | jq -c '.vulns[]' | while IFS= read -r vuln; do
        VULN_ID=$(echo "$vuln" | jq -r '.id')
        RESULT=$(curl -sf -u "elastic:${ES_PASSWORD}" \
          -X POST "${ES_HOST}/security-osv-vulns/_doc?pipeline=osv-vuln-ingest" \
          -H "Content-Type: application/json" \
          -d "${vuln}")
        RESULT_VAL=$(echo "$RESULT" | jq -r '._result // .error.reason')
        echo "    ${VULN_ID}: ${RESULT_VAL}"
        TOTAL_SEEDED=$((TOTAL_SEEDED + 1))
      done
  else
    echo "  No vulns found for ${OSV_NAME}@${VERSION} — skipping"
  fi

done < <(echo "$LIBS" | jq -c '.aggregations.libs.buckets[]')

echo ""
info "Verifying index..."
COUNT=$(curl -sf -u "elastic:${ES_PASSWORD}" \
  "${ES_HOST}/security-osv-vulns/_count" | jq .count)
echo "Total docs in security-osv-vulns: ${COUNT}"

if [ "$COUNT" = "0" ] || [ "$COUNT" = "null" ]; then
  echo ""
  echo "No CVEs found for the top 5 libraries."
  echo "This is normal if the libraries are not vulnerable."
  echo "Seeding log4j-core 2.14.1 (known vulnerable) as a guaranteed seed..."

  curl -sf -X POST "https://api.osv.dev/v1/query" \
    -H "Content-Type: application/json" \
    -d '{"version":"2.14.1","package":{"name":"org.apache.logging.log4j:log4j-core","ecosystem":"Maven"}}' \
    | jq -c '.vulns[]' | while IFS= read -r vuln; do
      VULN_ID=$(echo "$vuln" | jq -r '.id')
      RESULT=$(curl -sf -u "elastic:${ES_PASSWORD}" \
        -X POST "${ES_HOST}/security-osv-vulns/_doc?pipeline=osv-vuln-ingest" \
        -H "Content-Type: application/json" \
        -d "${vuln}")
      echo "  ${VULN_ID}: $(echo "$RESULT" | jq -r '._result')"
    done

  COUNT=$(curl -sf -u "elastic:${ES_PASSWORD}" \
    "${ES_HOST}/security-osv-vulns/_count" | jq .count)
  echo "Total docs after fallback seed: ${COUNT}"
fi

[ "$COUNT" = "0" ] && fail "security-osv-vulns is empty after seeding"

info "Sample documents:"
curl -sf -u "elastic:${ES_PASSWORD}" "${ES_HOST}/security-osv-vulns/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 5,
    "_source": [
      "vulnerability.id","vulnerability.cve_id","vulnerability.severity",
      "vulnerability.ecosystem","vulnerability.purl_bases","vulnerability.fix_version"
    ]
  }' | jq '.hits.hits[]._source'

echo ""
ok "Step 3 complete — ${COUNT} docs in security-osv-vulns"
