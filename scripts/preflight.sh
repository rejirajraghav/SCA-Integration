#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  PRE-FLIGHT CHECKS"
echo "═══════════════════════════════════════════"

# P1 — Elasticsearch connectivity
info "P1 — Elasticsearch connectivity"
HEALTH=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/_cluster/health" \
  | jq '{status: .status, nodes: .number_of_nodes, cluster: .cluster_name}')
echo "$HEALTH"
STATUS=$(echo "$HEALTH" | jq -r '.status')
[ "$STATUS" = "red" ] && fail "Cluster status is RED — fix before continuing"
ok "Cluster is ${STATUS}"

# P2 — Confirm agent index and field names
# Note: Elastic Cloud uses synthetic _source — use fields API, not _source
info "P2 — Confirming agent index and real field names"
DOC=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/${LIBRARY_INDEX}/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1,
    "query": {
      "bool": {
        "must": [{ "term": { "event.action": "library-loaded" } }],
        "must_not": [
          { "term": { "library.group_id": "" } },
          { "term": { "library.version": "" } }
        ]
      }
    },
    "fields": [
      "library.purl","library.name","library.group_id","library.version",
      "library.sha1","library.language","service.name","service.version",
      "deployment.environment.name","@timestamp"
    ],
    "_source": false
  }' | jq '.hits.hits[0].fields | with_entries(.value = .value[0])')

COUNT=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/${LIBRARY_INDEX}/_count" \
  -H "Content-Type: application/json" \
  -d '{"query": {"term": {"event.action": "library-loaded"}}}' | jq .count)

GOOD_COUNT=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/${LIBRARY_INDEX}/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"bool":{"must":[{"term":{"event.action":"library-loaded"}}],"must_not":[{"term":{"library.group_id":""}},{"term":{"library.version":""}}]}}}' | jq .count)

echo "Sample doc: $DOC"
echo "Total library-loaded docs: $COUNT (${GOOD_COUNT} with valid group_id+version for OSV lookup)"
[ "$COUNT" = "0" ] || [ "$COUNT" = "null" ] && fail "No library.loaded documents found — start the EDOT agent first"
ok "Found ${COUNT} library-loaded events (${GOOD_COUNT} usable for CVE correlation)"

# P3 — OSV API reachable
info "P3 — OSV API connectivity"
OSV=$(curl -sf -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"version":"2.14.1","package":{"name":"org.apache.logging.log4j:log4j-core","ecosystem":"Maven"}}' \
  | jq '{total: (.vulns | length), first_id: .vulns[0].id}')
echo "$OSV"
TOTAL=$(echo "$OSV" | jq -r '.total')
[ "$TOTAL" = "0" ] || [ "$TOTAL" = "null" ] && fail "OSV API returned no results"
ok "OSV API reachable — ${TOTAL} vulns for log4j-core test query"

# P4 — Show 5 real libraries (filter out malformed entries with empty group_id/version)
info "P4 — 5 real libraries from agent index (usable for OSV lookup)"
curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" "${ES_HOST}/${LIBRARY_INDEX}/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {
      "bool": {
        "must": [{ "term": { "event.action": "library-loaded" } }],
        "must_not": [
          { "term": { "library.group_id": "" } },
          { "term": { "library.version":  "" } }
        ]
      }
    },
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
  }' | jq '.aggregations.libs.buckets[] | {
    osv_name: (.key.group_id + ":" + .key.name),
    version:  .key.version
  }'

echo ""
ok "Pre-flight complete — safe to proceed to Step 1"
