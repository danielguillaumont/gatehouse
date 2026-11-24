# Sending gatehouse events to Microsoft Sentinel

gatehouse writes events to a local JSONL file by default. To send them to Sentinel too,
deploy the resources in `infra/` once, then start gatehouse with two extra settings. This
repo builds and tests all of it, but doesn't deploy it: the commands below run in your
own subscription.

What gets created (`infra/main.bicep`, resource-group scope):

| Resource | Purpose |
|---|---|
| Log Analytics workspace (optional) | Where events land. Set `createWorkspace=false` to use an existing one. |
| `GatehouseEvents_CL` table | Columns generated from `detections/schema/GatehouseEvents_CL.json`. |
| Data collection endpoint (`gatehouse-dce`) | The HTTPS endpoint gatehouse uploads to. |
| Data collection rule (`gatehouse-dcr`) | Stream `Custom-GatehouseEvents_CL` → the table, `transformKql: source`. |
| Role assignment (optional) | Monitoring Metrics Publisher on the DCR, for the identity gatehouse runs as. |
| Sentinel onboarding (optional) | Enables Sentinel on the workspace. |
| Analytics rules GH001–GH006 | Generated from `detections/rules/*.yaml`, the same files tested in the Kusto emulator. |

## 1. Deploy

Prerequisites: Azure CLI 2.60 or later, and Owner (or Contributor plus User Access
Administrator) on the resource group if you want the role assignment created for you.

```sh
az login
az group create -n rg-gatehouse -l westeurope
# the object id of the identity gatehouse will authenticate as; here, yourself
az ad signed-in-user show --query id -o tsv
```

Edit `infra/main.bicepparam` (`workspaceName`, `publisherPrincipalId`, and
`publisherPrincipalType` = `User` for yourself, `ServicePrincipal` for an app or managed
identity), then:

```sh
az deployment group create -g rg-gatehouse -f infra/main.bicep -p infra/main.bicepparam
az deployment group show -g rg-gatehouse -n main \
  --query "properties.outputs.{endpoint: ingestionEndpoint.value, dcr: dcrImmutableId.value}"
```

Notes:

- **Existing Sentinel workspace:** set `createWorkspace=false` and `enableSentinel=false`.
- **Rules without Sentinel:** `deployAnalyticsRules=false` deploys just the ingestion path.
- **Role propagation** can take a few minutes. Uploads fail with 403 until it has.
- **Redeploying is safe.** Rule resource names are the GUIDs in the YAML files, so rules
  are updated in place, not duplicated.

## 2. Run gatehouse with the Sentinel sink

```sh
pip install "gatehouse[sentinel]"     # or: uv sync --extra sentinel
```

Either pass flags:

```sh
gatehouse run --name github --policy policy.yaml \
  --sentinel-endpoint https://gatehouse-dce-xxxx.westeurope-1.ingest.monitor.azure.com \
  --sentinel-dcr-id dcr-0123456789abcdef0123456789abcdef \
  -- npx -y @modelcontextprotocol/server-github
```

or set `GATEHOUSE_SENTINEL_ENDPOINT` and `GATEHOUSE_SENTINEL_DCR_ID` in the MCP client's
`env` block, which is easier when one config file wraps several servers.
`GATEHOUSE_SENTINEL_STREAM` overrides the stream name (default
`Custom-GatehouseEvents_CL`).

**Authentication** is `DefaultAzureCredential`: managed identity on Azure hosts, your
`az login` session on a workstation, or `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` /
`AZURE_CLIENT_SECRET` for a service principal. gatehouse never reads or stores a secret
for this itself.

**Behaviour:**

- Events are batched (up to 500, or every 5 seconds) and uploaded from a background
  thread. The proxy never waits on the network.
- The local JSONL log is still written. Keep it: it's the record of what happened if
  Sentinel ingestion fails.
- If uploads keep failing after retries, or the queue fills up, gatehouse emits
  `gatehouse.fail_open` to the local log and stderr, and traffic continues (ADR-0001).
- A half configuration (endpoint without a DCR id, or the other way round) refuses to
  start, rather than running without the feed you asked for.
- If the `sentinel` extra is missing, gatehouse starts and reports `gatehouse.fail_open`
  ("install gatehouse[sentinel]").

## 3. Check it works

Ingestion latency is usually a few minutes. In the workspace:

```kql
GatehouseEvents_CL
| where TimeGenerated > ago(1h)
| summarize Events = count() by ServerName, EventType
```

To see the analytics rules fire without a live attack, replay the sample data:

```sh
uv run python - <<'PY'
import json, pathlib
from datetime import UTC, datetime
from gatehouse.events.sentinel import SentinelConfig, azure_uploader
cfg = SentinelConfig.from_env()   # GATEHOUSE_SENTINEL_ENDPOINT / _DCR_ID must be set
assert cfg is not None
rows = [json.loads(l) for l in pathlib.Path("detections/sample_data/events.jsonl").read_text().splitlines()]
now = datetime.now(UTC).isoformat()
for r in rows:  # make them recent so the rules' lookback windows include them
    r["TimeGenerated"] = now
azure_uploader(cfg)(rows)
PY
```

Rewriting every timestamp to "now" collapses the per-story spacing. That's fine for GH001
to GH005. GH006 needs its injection before its egress, so expect it to fire only from
real sessions, or after a replay that keeps the offsets.

## What's tested and what isn't

| Tested in this repo | How |
|---|---|
| Rule KQL runs and returns the expected rows | Kusto emulator in CI (`detections` job, D-027) |
| Table schema matches the event model | `gatehouse table-schema` generates the schema; tests compare |
| Bicep inputs match the rules and schema | `tests/detections/test_infra.py` |
| Bicep compiles, with known resource types and API versions | `infra` CI job (`az bicep build`) |
| Sink batching, retries, fail-open reporting | `tests/events/test_sentinel.py` (fake uploader) |

Not tested here, because it needs a subscription: the actual deployment, role
propagation, a real upload, and Sentinel-only KQL behaviour that the emulator can't run.
The rules avoid Sentinel-only operators for that reason.
