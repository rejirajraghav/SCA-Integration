# SCA-Integration

SCA Vulnerability Correlation system for EDOT Java agent.

Joins runtime JAR inventory (`logs-generic.otel-*`) with OSV vulnerability data
to produce actionable security findings in `security-sca-findings`.

## Architecture

```
EDOT Agent → logs-generic.otel-*
                    ↓ (read by transform)
OSV API → Fleet Custom API → security-osv-vulns
                    ↓ (enrich lookup)
          ES Transform → security-sca-findings
                    ↓
              Security Dashboard
```

## Setup

```bash
cp .env.example .env
# edit .env with your Elasticsearch credentials
source .env
bash scripts/preflight.sh
bash scripts/step1_osv_index.sh
bash scripts/step2_osv_pipeline.sh
bash scripts/step3_seed.sh
# Step 4: Fleet UI — follow docs/step4_fleet_ui.md
bash scripts/step5_findings_index.sh
bash scripts/step6_enrich_policy.sh
bash scripts/step7_findings_pipeline.sh
bash scripts/step8_transform.sh
bash scripts/step9_verify.sh
bash scripts/step10_watcher.sh
```

## Indices

| Index | Owner | Purpose |
|---|---|---|
| `logs-generic.otel-*` | EDOT Java agent | Raw JAR events (READ ONLY) |
| `security-osv-vulns` | Fleet Custom API | CVE reference data |
| `security-sca-findings` | ES Transform | One finding per CVE × service |
