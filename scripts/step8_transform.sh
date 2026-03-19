#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $*${NC}"; }

echo "═══════════════════════════════════════════"
echo "  STEP 8 — sca-correlation-transform"
echo "═══════════════════════════════════════════"

info "Creating transform: sca-correlation-transform"
RES=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X PUT "${ES_HOST}/_transform/sca-correlation-transform" \
  -H "Content-Type: application/json" \
  -d "{
    \"description\": \"Joins library.loaded events with osv-vulns to produce sca-findings. One finding per CVE per service.\",
    \"source\": {
      \"index\": [\"${LIBRARY_INDEX}\"],
      \"query\": {
        \"term\": { \"event.action\": \"library-loaded\" }
      },
      \"runtime_mappings\": {
        \"library.purl_base\": {
          \"type\": \"keyword\",
          \"script\": {
            \"source\": \"def p = doc['library.purl'].value; if (p != null) { int at = p.indexOf('@'); emit(at > 0 ? p.substring(0, at) : p); }\"
          }
        }
      }
    },
    \"pivot\": {
      \"group_by\": {
        \"library.purl_base\": { \"terms\": { \"field\": \"library.purl_base\" } },
        \"library.version\":   { \"terms\": { \"field\": \"library.version\"   } },
        \"service.name\":      { \"terms\": { \"field\": \"service.name\"      } }
      },
      \"aggregations\": {
        \"library.purl\":        { \"terms\": { \"field\": \"library.purl\"             } },
        \"library.name\":        { \"terms\": { \"field\": \"library.name\"             } },
        \"library.group_id\":    { \"terms\": { \"field\": \"library.group_id\"         } },
        \"library.sha1\":        { \"terms\": { \"field\": \"library.sha1\"             } },
        \"library.language\":    { \"terms\": { \"field\": \"library.language\"         } },
        \"service.version\":     { \"terms\": { \"field\": \"service.version\"          } },
        \"deployment.environment\": { \"terms\": { \"field\": \"deployment.environment.name\" } },
        \"host.name\":           { \"terms\": { \"field\": \"host.name\"                } },
        \"finding.first_seen\":  { \"min\":   { \"field\": \"@timestamp\"               } },
        \"finding.last_seen\":   { \"max\":   { \"field\": \"@timestamp\"               } }
      }
    },
    \"dest\": {
      \"index\": \"security-sca-findings\",
      \"pipeline\": \"sca-findings-enrich\"
    },
    \"sync\": {
      \"time\": {
        \"field\": \"@timestamp\",
        \"delay\": \"60s\"
      }
    },
    \"frequency\": \"5m\",
    \"settings\": {
      \"max_page_search_size\": 500,
      \"docs_per_second\": 500
    }
  }")
echo "$RES" | jq .
[[ $(echo "$RES" | jq -r '.acknowledged') != "true" ]] && fail "Transform creation failed"
ok "Transform created"

info "Starting transform..."
START=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
  -X POST "${ES_HOST}/_transform/sca-correlation-transform/_start")
echo "$START" | jq .
ok "Transform started"

info "Monitoring for 3 minutes (6 x 30s checks)..."
for i in 1 2 3 4 5 6; do
  echo "=== Check ${i} ($(date)) ==="
  STATS=$(curl -sf -H "Authorization: ApiKey ${ES_API_KEY}" \
    "${ES_HOST}/_transform/sca-correlation-transform/_stats")
  echo "$STATS" | jq '.transforms[0] | {
    state:           .state,
    docs_processed:  .stats.documents_processed,
    docs_indexed:    .stats.documents_indexed,
    trigger_count:   .stats.trigger_count,
    last_checkpoint: .checkpointing.last.checkpoint
  }'
  STATE=$(echo "$STATS" | jq -r '.transforms[0].state')
  [ "$STATE" = "failed" ] && echo "$STATS" | jq . && fail "Transform state is FAILED"
  sleep 30
done

echo ""
ok "Step 8 complete — transform is running"
