# Agentic ML Operations Engineer

**A locally runnable, sandboxed AI systems engineering portfolio project & API integration demo for investigating ML pipeline and model-quality incidents with multi-tenant isolation, fake development API keys, evidence-grounded reasoning, abstention on conflicting/missing telemetry, and mandatory human-in-the-loop approval gates.**

> **Portfolio Summary**: *Agentic ML Operations Engineer* is a local sandbox and reference architecture demonstrating how to design reliable, bounded agentic workflows and secure multi-tenant API contracts for ML platform engineering. Instead of wrapping an unconstrained LLM loop around production credentials, it uses an explicit 8-stage state machine, narrow Pydantic-typed connector adapters, salted PBKDF2-HMAC-SHA256 development API key authentication, prompt-injection quarantine, explicit abstention when telemetry is incomplete or conflicting, and server-side cryptographic approval tokens for simulated remediation actions.

---

## 1. What This Project Does (and Does Not Do)

### What It Does
- **Provides a Locally Testable Multi-Tenant API Integration Demo (`/api/v1/...`)**: Lets a developer create an isolated local demo tenant, obtain a cryptographically generated fake development API key (shown once, stored as a salted PBKDF2-HMAC-SHA256 hash), submit asynchronous incident analysis requests (`202 Accepted` + `Idempotency-Key` support), poll for evidence-linked results, approve or reject proposed actions, and inspect tenant-scoped audit logs.
- **Investigates Simulated ML Platform Incidents**: Diagnoses 10 realistic synthetic incidents across a simulated payment fraud ML pipeline (`fraud-risk-v4`), including Dagster asset failures, upstream schema breaking changes, missing hourly partitions, feature distribution shifts (PSI/KS), model threshold regressions, and Redis feature-cache latency spikes.
- **Executes a Controlled 8-Stage State Machine**: Progresses deterministically through validation, read-only evidence gathering, historical pattern comparison, evidence-grounded diagnosis, remediation proposal, human approval gating, simulated execution, and post-remediation verification.
- **Distinguishes Facts, Hypotheses, Conflicts, and Recommendations**: Links every diagnostic claim and hypothesis to concrete `evidence_id` records produced by read-only mock connector calls.
- **Abstains Safely When Evidence Is Incomplete or Conflicting**: Halts without guessing or proposing state changes when ground-truth evaluation buckets return `HTTP 404`, collectors have stale heartbeats, or assets are unregistered.
- **Enforces Human Approval & Tenant Ownership in Backend Logic**: Blocks `simulate_approved_rerun` at the Python `ToolRegistry` layer unless an authorized caller in the owning tenant has recorded an explicit `APPROVE` decision and verified a server-side `approval_token` (which is never exposed to clients).
- **Enforces Strict Environment Boundaries**: Refuses to start or operate in `production` (`MLOPS_ENV=production`) if development-key issuance, test fixtures, mock connectors, or mock providers are active (`ProductionConfigurationError`), and blocks any accidental outbound network calls while in mock mode (`OutboundNetworkBlockedError`).

### What It Does Not Do
- **Not Production-Deployed & Does Not Connect to Real Services**: All telemetry, Dagster runs, feature drift reports, developer API keys, and remediations exist solely in a local SQLite database (`data/mlops_sandbox.db`). Fake development credentials never connect to external third-party services.
- **No Unconstrained Autonomous Actions**: The agent cannot execute shell commands, run arbitrary SQL, fetch external URLs, or mutate even the simulated environment without human sign-off.

---

## 2. Quickstart: Local Mock-Mode API Integration Demo

### Prerequisites
- Python 3.11+ (tested on Python 3.14.5 on macOS)

### Step 1: Create Virtual Environment & Start in Mock Mode
No external credentials, `.env` secrets, or network access are required:
```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- **Operator Dashboard UI**: Open `http://127.0.0.1:8000`
- **OpenAPI / Swagger Docs**: Open `http://127.0.0.1:8000/docs`

### Step 2: Create a Local Demo Tenant & Fake Development API Key
You can create a demo tenant and issue a one-time fake development API key either via the REST API or the CLI utility.

**Option A — Via REST API (`POST /api/v1/dev/tenants`):**
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/dev/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_name": "local-demo-team",
    "key_name": "default-dev-key",
    "scopes": ["analyses:read", "analyses:write", "actions:approve", "audit:read", "keys:manage"]
  }' | python3 -m json.tool
```

**Option B — Via CLI (`scripts/manage_dev_keys.py`):**
```bash
./.venv/bin/python scripts/manage_dev_keys.py create-tenant \
  --tenant-name "local-demo-team" \
  --key-name "cli-dev-key"
```

Save the returned one-time key in a shell variable for local testing (replace `<DEV_API_KEY>` with your generated token; **never commit real or generated keys**):
```bash
export DEV_API_KEY="<DEV_API_KEY>"
```

### Step 3: Submit an Asynchronous Analysis Request (`202 Accepted`)
Submit an analysis for seeded incident `INC-2026-101` (upstream schema breaking change on `stg_transactions_cleaned`), passing an `Idempotency-Key` so retries never create duplicate analyses:
```bash
curl -i -X POST http://127.0.0.1:8000/api/v1/analyses \
  -H "Authorization: Bearer $DEV_API_KEY" \
  -H "Idempotency-Key: demo-req-101-v1" \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-2026-101"}'
```
Response (`202 Accepted`):
```json
{
  "analysis_id": "inv_...",
  "tenant_id": "tenant_...",
  "incident_id": "INC-2026-101",
  "status": "QUEUED",
  "status_url": "/api/v1/analyses/inv_...",
  "events_url": "/api/v1/analyses/inv_.../events",
  "idempotency_key": "demo-req-101-v1",
  "idempotent_replay": false,
  "created_at": "2026-11-02T11:20:00Z",
  "simulated": true
}
```

### Step 4: Poll for the Evidence-Linked Diagnosis Result
Poll the `status_url` returned in Step 3:
```bash
curl -s http://127.0.0.1:8000/api/v1/analyses/<ANALYSIS_ID> \
  -H "Authorization: Bearer $DEV_API_KEY" | python3 -m json.tool
```
The response includes:
- `status`: `"AWAITING_HUMAN_APPROVAL"` (or `"COMPLETED_ABSTAINED"` for `INC-2026-107` / `INC-2026-109`)
- `result.observed_facts`: Verified `EvidenceItem` records with `evidence_id`, `tool_name`, `target_id`, `observed_fact`, and `metrics_summary`
- `result.hypotheses`: Ranked hypotheses with `supporting_evidence_ids` and `contradicting_evidence_ids`
- `result.alternative_explanations`, `result.conflicts_detected`, `result.missing_telemetry`, `result.uncertainty_notes`
- `result.confidence` and `result.abstention_reason`
- `result.recommendations` and `result.proposed_action` (`action_id`, `action_type`, `parameters`, `risk_level`, `blast_radius`, `status: "PENDING_APPROVAL"`)

To inspect the stage-by-stage progress and read-only tool call traces:
```bash
curl -s http://127.0.0.1:8000/api/v1/analyses/<ANALYSIS_ID>/events \
  -H "Authorization: Bearer $DEV_API_KEY" | python3 -m json.tool
```

### Step 5: Approve or Reject a Proposed Simulated Action
Requires the `actions:approve` scope and tenant ownership:
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/actions/<ACTION_ID>/approve \
  -H "Authorization: Bearer $DEV_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "APPROVE",
    "operator_id": "staff-ml-engineer@sandbox.local",
    "decision_note": "Verified v3.4 schema compatibility adapter mapping."
  }' | python3 -m json.tool
```

### Step 6: Inspect Tenant Audit Trail & Revoke Development API Key
```bash
# Read tenant-scoped audit trail
curl -s http://127.0.0.1:8000/api/v1/audit \
  -H "Authorization: Bearer $DEV_API_KEY" | python3 -m json.tool

# Revoke a key via REST API (requires keys:manage scope)
curl -s -X POST http://127.0.0.1:8000/api/v1/keys/<KEY_ID>/revoke \
  -H "Authorization: Bearer $DEV_API_KEY" | python3 -m json.tool

# Or revoke via CLI
./.venv/bin/python scripts/manage_dev_keys.py revoke-key \
  --tenant-id <TENANT_ID> --key-id <KEY_ID>
```

---

## 3. Architecture Overview & Major Files

See [`docs/architecture.md`](docs/architecture.md) for the full technical specification.

- `app/main.py` — FastAPI application serving versioned `/api/v1/...` tenant-isolated endpoints, request size limit middleware, and operator dashboard UI endpoints.
- `app/auth.py` — Development API key generation (`secrets.token_urlsafe(32)`), salted PBKDF2-HMAC-SHA256 hashing (`120,000` iterations), constant-time verification (`hmac.compare_digest`), scope checks (`require_scopes`), per-tenant rate limiting, and test-only fixture credential provisioning.
- `app/connectors.py` — Typed `Protocol` connector interfaces and `MockPlatformConnectors` backed by tenant-partitioned SQLite tables.
- `app/config.py` — Environment configuration, strict production boundary validator (`validate_environment_safety`), and mock-mode outbound network blocker (`assert_no_outbound_network_in_mock`).
- `app/schemas.py` — Pydantic v2 schemas for `/api/v1` requests/responses, scopes, incidents, narrow tool inputs/outputs, diagnoses, approvals, and benchmark metrics.
- `app/orchestrator.py` — Tenant-scoped 8-stage state-machine orchestrator (`IncidentOrchestrator`) with idempotency and per-tenant analysis quotas.
- `app/tools.py` — Narrow, typed tool executor (`ToolRegistry`) with allowlists, timeouts, retries, `approval_token` redaction in traces, and backend approval enforcement.
- `app/providers.py` — `ReasoningProvider` interface, `MockReasoningProvider` (deterministic default), `GeminiReasoningProvider` (optional live adapter), and `detect_prompt_injection`.
- `app/db.py` — Multi-tenant SQLite schema, initial seeding for the 11-component `fraud-risk-v4` topology and 10 synthetic incidents per tenant, and audit logging.
- `scripts/manage_dev_keys.py` — CLI utility to create local demo tenants, issue scoped keys, list key metadata, and revoke keys.
- `scripts/run_benchmark.py` — One-command CLI script to execute and print the 10-case evaluation benchmark.
- `tests/test_mlops_engineer.py` — Automated `pytest` verification suite (14 test suites).

---

## 4. Mock Connector Adapters vs. Real Production Requirements

All connector settings are separate from developer API credentials. You can inspect the active connector catalog via `GET /api/v1/integrations`:

| Mock Adapter (`app/connectors.py`) | Typed Protocol | Agent Tools Powered | Simulated Data Source | What a Real Production Adapter Would Require |
| :--- | :--- | :--- | :--- | :--- |
| `MockDagsterRunConnector` | `DagsterRunConnector` | `get_run_details`, `get_partition_status` | SQLite `pipeline_runs`, `partition_telemetry` | Read-only Dagster Plus / OSS GraphQL client authenticated via workload identity (`runOrError`, `assetNodeOrError`). |
| `MockLineageCatalogConnector` | `LineageCatalogConnector` | `get_asset_lineage` | SQLite `components` | Read-only OpenLineage / DataHub / Dagster asset lineage graph API client. |
| `MockDataQualityConnector` | `DataQualityConnector` | `get_data_quality_report` | SQLite `data_quality_reports` | Read-only Confluent Schema Registry + Great Expectations / Soda contract validation reader. |
| `MockFeatureObservabilityConnector` | `FeatureObservabilityConnector` | `get_feature_drift_report` | SQLite `feature_drift_reports` | Read-only Feast / Tecton observability API + Evidently/Arize PSI & KS drift store reader. |
| `MockModelEvaluationConnector` | `ModelEvaluationConnector` | `get_model_metrics` | SQLite `model_metrics_reports` | Read-only MLflow / Vertex Model Registry + offline evaluation metric table reader. |
| `MockServiceHealthConnector` | `ServiceHealthConnector` | `get_service_health` | SQLite `service_health_reports` | Read-only Prometheus / Thanos HTTP query client for latency histograms, 5xx rates, and Redis exporter metrics. |
| `MockIncidentHistoryConnector` | `IncidentHistoryConnector` | `search_incident_history` | SQLite `historical_incidents` | Read-only postmortem / incident knowledge base index reader. |
| `MockRemediationExecutorConnector` | `RemediationExecutorConnector` | `simulate_approved_rerun` | Scoped SQLite state transitions | Human-approved GitOps PR dispatcher or Dagster `launchPipelineExecution` mutation signed by an OIDC-verified operator identity. |

---

## 5. Security Boundaries & Production Launch Blockers

1. **One-Way Salted Key Hashing at Rest**: Newly generated keys (`mlops_dev_<prefix>.<secret>`) are displayed once upon creation and immediately hashed with PBKDF2-HMAC-SHA256 (`120,000` iterations) + a 16-byte random salt. Raw keys are never logged, stored in SQLite, or returned by `GET /api/v1/keys`.
2. **Strict Environment Gate (`validate_environment_safety`)**: If `MLOPS_ENV=production`, the application refuses to start (`ProductionConfigurationError`) if any of the following are enabled:
   - `MLOPS_ENABLE_DEV_KEY_ISSUANCE=true`
   - `MLOPS_ENABLE_TEST_FIXTURES=true`
   - `MLOPS_CONNECTOR_MODE=mock`
   - `active_provider == "mock"`
3. **Deterministic Test Fixtures (`provision_test_only_fixture_key`)**: Unmistakably labeled `mlops_test_only_fixture_...` credentials can only be provisioned and authenticated when `MLOPS_ENV=test` and `MLOPS_ENABLE_TEST_FIXTURES=true`. They are never active by default.
4. **Per-Request Tenant Isolation & Scopes**: Every `/api/v1/...` endpoint validates the caller's `tenant_id` and required `ApiScope` (`analyses:read`, `analyses:write`, `actions:approve`, `audit:read`, `keys:manage`) in backend Python code. Cross-tenant reads, approvals, or revocations are rejected with `403 TENANT_ISOLATION_VIOLATION`.
5. **Server-Side Approval Signing**: Approving an action generates an internal `approval_token` in SQLite that is verified via `hmac.compare_digest` inside `ToolRegistry._simulate_approved_rerun` and redacted as `[REDACTED_SERVER_TOKEN]` in all tool traces and API responses.

---

## 6. Automated Tests & Evaluation Benchmark

```bash
# Run the 14-test pytest verification suite
./.venv/bin/pytest -v

# Execute the 10-case reproducible evaluation benchmark
./.venv/bin/python scripts/run_benchmark.py
```

### Measured Benchmark Summary (10 Synthetic Cases in Mock Mode)
- **Root-Cause Identification Rate**: **90.0%** (9 / 10 cases exact match)
- **Evidence-Grounded Explanation Rate**: **100.0%** (10 / 10 cases cite verified tool trace evidence IDs)
- **Appropriate Abstention Rate**: **100.0%** (2 / 2 abstain cases — `INC-2026-107` conflicting telemetry and `INC-2026-109` missing telemetry — halted safely with 0 actions proposed)
- **Unsafe-Action Proposal Rate**: **0.0%** (0 unapproved or out-of-policy actions across all 10 cases)
- **Prompt-Injection Resistance Rate**: **100.0%** (1 / 1 adversarial override ticket `INC-2026-108` quarantined and diagnosed via real telemetry)
- **Average Tool Calls / Latency**: **5.50 calls/investigation**, **~5.6 ms/investigation** in local SQLite mock mode.
