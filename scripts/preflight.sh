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
HEALTH=$(curl -sf -u "elastic:${ES_PASSWORD}" "${ES_HOST}/_cluster/health" \
  | jq '{status: .status, nodes: .number_of_nodes, cluster: .cluster_name}')
echo "$HEALTH"
STATUS=$(echo "$HEALTH" | jq -r '.status')
[ "$STATUS" = "red" ] && fail "Cluster status is RED — fix before continuing"
ok "Cluster is ${STATUS}"

# P2 — Confirm agent index and field names
info "P2 — Confirming agent index and real field names"
DOC=$(curl -sf -u "elastic:${ES_PASSWORD}" "${ES_HOST}/${LIBRARY_INDEX}/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1,
    "query": { "term": { "event.action": "library-loaded" } },
    "_source": [
      "library.purl","library.name","library.group_id","library.version",
      "library.sha1","library.language","service.name","service.version",
      "deployment.environment.name","@timestamp"
    ]
  }' | jq '.hits.hits[0]._source')

COUNT=$(curl -sf -u "elastic:${ES_PASSWORD}" "${ES_HOST}/${LIBRARY_INDEX}/_count" \
  -H "Content-Type: application/json" \
  -d '{"query": {"term": {"event.action": "library-loaded"}}}' | jq .count)

echo "Sample doc: $DOC"
echo "Total library-loaded docs: $COUNT"
[ "$COUNT" = "0" ] || [ "$COUNT" = "null" ] && fail "No library.loaded documents found — start the EDOT agent first"
ok "Found ${COUNT} library-loaded events"

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

# P4 — Show 5 real libraries
info "P4 — 5 real libraries from agent index"
curl -sf -u "elastic:${ES_PASSWORD}" "${ES_HOST}/${LIBRARY_INDEX}/_search" \
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
  }' | jq '.aggregations.libs.buckets[] | {
    osv_name: (.key.group_id + ":" + .key.name),
    version:  .key.version
  }'

echo ""
ok "Pre-flight complete — safe to proceed to Step 1"
