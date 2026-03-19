# Step 4 — Fleet Custom API Integration (Manual UI Setup)

This step is performed in the Kibana Fleet UI. No scripts.

## 4.0 — Create a scoped API key

Run this before opening Fleet:

```bash
source ../.env
curl -s -u elastic:${ES_PASSWORD} \
  -X POST "${ES_HOST}/_security/api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fleet-osv-sync-key",
    "expiration": "365d",
    "role_descriptors": {
      "osv-sync-role": {
        "cluster": [],
        "indices": [
          {
            "names": ["security-osv-vulns*"],
            "privileges": ["index", "create", "create_index"]
          }
        ]
      }
    }
  }' | jq '{id: .id, api_key: .api_key, encoded: .encoded}'
```

Save the `encoded` value — you will need it in the integration config.

## 4.1 — Install Elastic Agent on sync host

1. Fleet → Agents → **Add Agent**
2. Create new policy: `osv-sync-policy`
3. Uncheck "Collect system logs and metrics"
4. Run the enrollment command on your sync host
5. Confirm agent status is **Healthy** before continuing

## 4.2 — Add Custom API integration

Fleet → Agent Policies → `osv-sync-policy` → **Add Integration**

Search: **Custom API** → Add Custom API

## 4.3 — Integration Settings

| Field | Value |
|---|---|
| Integration name | `osv-maven-vuln-sync` |
| Description | `Polls OSV API for Maven vulnerability data every 6 hours. Writes to security-osv-vulns via osv-vuln-ingest pipeline.` |
| Namespace | `security` |
| Output | _(your Elasticsearch output)_ |

## 4.4 — REST API Configuration

| Field | Value |
|---|---|
| Dataset name | `osv.maven` |
| **Ingest Pipeline** | `osv-vuln-ingest` ← critical, must match exactly |
| Request URL | `https://api.osv.dev/v1/query` |
| Request Interval | `6h` |
| Request HTTP Method | `POST` |
| Basic Auth Username | _(leave blank)_ |
| Basic Auth Password | _(leave blank)_ |
| Request Timeout | `30s` |
| Request Retry Max Attempts | `5` |
| Request Retry Wait Min | `1s` |
| Request Retry Wait Max | `60s` |
| Enable request tracing | ✅ ON (turn off after first successful run) |

**Request Body** (static seed for first validation):
```json
{
  "version": "2.14.1",
  "package": {
    "name": "org.apache.logging.log4j:log4j-core",
    "ecosystem": "Maven"
  }
}
```

**Response Split:**
```yaml
target: body.vulns
type: array
keep_parent: false
```

**Tags:** `osv`, `osv-maven`, `sca-sync`

Everything else: leave blank.

## 4.5 — Deploy

Select: **Existing hosts** → `osv-sync-policy` → **Save and deploy changes**

## 4.6 — Verify (wait 2 minutes after deploy)

```bash
source ../.env
curl -s -u elastic:${ES_PASSWORD} "${ES_HOST}/security-osv-vulns/_count" | jq .
```

Expected: count > 0. If 0, check agent logs.

## 4.7 — Check agent trace logs

```bash
# On the agent host:
find /var/log/elastic-agent -name "*.ndjson" | head -5
tail -f /var/log/elastic-agent/httpjson-trace-*.ndjson | jq .
```
