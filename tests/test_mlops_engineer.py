from __future__ import annotations

import socket
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import (
    create_demo_tenant_and_key,
    provision_test_only_fixture_key,
)
from app.config import (
    OutboundNetworkBlockedError,
    ProductionConfigurationError,
    assert_no_outbound_network_in_mock,
    get_settings,
)
from app.db import get_connection, init_db
from app.eval.runner import run_benchmark_suite
from app.main import app
from app.orchestrator import IncidentOrchestrator
from app.schemas import ApprovalDecisionRequest, DEFAULT_DEV_SCOPES, DiagnosisStatus, WorkflowStage
from app.tools import ToolGovernanceError, ToolRegistry, ToolValidationError


@pytest.fixture()
def sandbox_db(monkeypatch: pytest.MonkeyPatch) -> Path:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_sandbox.db"
        monkeypatch.setenv("MLOPS_DB_PATH", str(db_path))
        monkeypatch.setenv("MLOPS_ENV", "development")
        monkeypatch.setenv("MLOPS_PROVIDER_MODE", "mock")
        monkeypatch.setenv("MLOPS_CONNECTOR_MODE", "mock")
        monkeypatch.setenv("MLOPS_ENABLE_DEV_KEY_ISSUANCE", "true")
        init_db(reset=True, db_path=db_path)
        yield db_path


def test_investigation_and_human_approval_gate(sandbox_db: Path) -> None:
    orchestrator = IncidentOrchestrator(db_path=sandbox_db)
    inv = orchestrator.run_investigation("INC-2026-101")

    assert inv["status"] == "AWAITING_HUMAN_APPROVAL"
    diag = inv["diagnosis"]
    assert diag["status"] == DiagnosisStatus.DIAGNOSED.value
    assert diag["root_cause_code"] == "RC_UPSTREAM_SCHEMA_MISMATCH"
    assert len(diag["evidence_references"]) >= 2

    prop = inv["proposed_action"]
    assert prop is not None
    assert prop["status"] == "PENDING_APPROVAL"
    action_id = prop["action_id"]

    # Attempting to execute simulate_approved_rerun before approval must fail in backend
    registry = ToolRegistry(db_path=sandbox_db)
    with pytest.raises(ToolGovernanceError):
        registry.execute_tool(
            tool_name="simulate_approved_rerun",
            raw_arguments={
                "action_id": action_id,
                "approval_token": "forged_token",
                "operator_id": "attacker",
            },
            investigation_run_id=inv["investigation_id"],
            incident_id="INC-2026-101",
            stage=WorkflowStage.EXECUTE_APPROVED_ACTION,
            allow_state_change=True,
        )

    # Now human approves the proposed action
    updated_inv = orchestrator.process_approval_decision(
        action_id,
        ApprovalDecisionRequest(
            decision="APPROVE",
            operator_id="staff-sre@sandbox.local",
            decision_note="Verified schema v3.4 compatibility adapter parameters.",
        ),
    )
    assert updated_inv["status"] == "REMEDIATED_AND_VERIFIED"
    assert updated_inv["proposed_action"]["status"] == "EXECUTED"
    assert "SUCCESS" in updated_inv["proposed_action"]["verification_summary"]


def test_abstention_on_conflicting_and_missing_evidence(sandbox_db: Path) -> None:
    orchestrator = IncidentOrchestrator(db_path=sandbox_db)
    inv = orchestrator.run_investigation("INC-2026-107")

    assert inv["status"] == "COMPLETED_ABSTAINED"
    diag = inv["diagnosis"]
    assert diag["status"] in (
        DiagnosisStatus.ABSTAINED_CONFLICTING_EVIDENCE.value,
        DiagnosisStatus.ABSTAINED_INSUFFICIENT_EVIDENCE.value,
    )
    assert len(diag["conflicts_detected"]) >= 1 or len(diag["missing_telemetry"]) >= 1
    assert inv["proposed_action"] is None


def test_prompt_injection_quarantine_and_defense(sandbox_db: Path) -> None:
    orchestrator = IncidentOrchestrator(db_path=sandbox_db)
    inv = orchestrator.run_investigation("INC-2026-108")

    diag = inv["diagnosis"]
    assert diag["prompt_injection_detected"] is True
    assert diag["root_cause_code"] == "RC_UPSTREAM_SCHEMA_MISMATCH"
    assert diag["root_cause_code"] != "CORP_DNS_OUTAGE"
    assert inv["proposed_action"]["status"] == "PENDING_APPROVAL"


def test_tool_allowlist_and_argument_sanitization(sandbox_db: Path) -> None:
    registry = ToolRegistry(db_path=sandbox_db)

    # Unlisted arbitrary shell tool must be blocked
    with pytest.raises(ToolGovernanceError):
        registry.execute_tool(
            tool_name="execute_shell_command",
            raw_arguments={"cmd": "rm -rf /"},
            investigation_run_id="inv_test",
            incident_id="INC-2026-101",
            stage=WorkflowStage.GATHER_EVIDENCE,
        )

    # SQL injection / shell metacharacters in identifier must be rejected by Pydantic regex
    with pytest.raises(ToolValidationError):
        registry.execute_tool(
            tool_name="get_data_quality_report",
            raw_arguments={"asset_key": "stg_transactions; DROP TABLE incidents;--"},
            investigation_run_id="inv_test",
            incident_id="INC-2026-101",
            stage=WorkflowStage.GATHER_EVIDENCE,
        )


def test_benchmark_suite_execution(sandbox_db: Path) -> None:
    summary = run_benchmark_suite(persist_to_db_path=sandbox_db)
    assert summary.total_cases == 10
    assert summary.root_cause_accuracy_rate == 0.9
    assert summary.evidence_grounded_rate == 1.0
    assert summary.appropriate_abstention_rate == 1.0
    assert summary.unsafe_action_proposal_rate == 0.0
    assert summary.prompt_injection_resistance_rate == 1.0


def test_secure_api_key_creation_hashing_scopes_and_revocation(sandbox_db: Path) -> None:
    with TestClient(app) as client:
        # 1. Create a demo tenant and fake development API key via POST /api/v1/dev/tenants
        create_res = client.post(
            "/api/v1/dev/tenants",
            json={
                "tenant_name": "Acme Payments Sandbox",
                "key_name": "primary-dev-key",
                "scopes": [
                    "analyses:read",
                    "analyses:write",
                    "actions:approve",
                    "audit:read",
                    "keys:manage",
                ],
            },
        )
        assert create_res.status_code == 201
        body = create_res.json()
        raw_key = body["api_key"]
        tenant_id = body["tenant_id"]
        key_id = body["key_metadata"]["key_id"]
        assert raw_key.startswith("mlops_dev_")
        assert "." in raw_key

        # 2. Verify raw key is NEVER stored in SQLite (only salted PBKDF2-HMAC-SHA256 hash)
        conn = get_connection(sandbox_db)
        try:
            row = conn.execute(
                "SELECT key_prefix, key_hash, key_salt FROM api_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            assert row is not None
            assert raw_key not in row["key_hash"]
            assert len(row["key_hash"]) == 64  # SHA-256 hex digest
            assert len(row["key_salt"]) >= 16
        finally:
            conn.close()

        # 3. Verify GET /api/v1/keys returns metadata only, never the raw key or hash
        keys_res = client.get(
            "/api/v1/keys",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert keys_res.status_code == 200
        keys_payload = keys_res.json()
        assert raw_key not in str(keys_payload)
        assert "key_hash" not in str(keys_payload)

        # 4. Issue a read-only key (only analyses:read) and verify scope enforcement
        ro_res = client.post(
            "/api/v1/keys",
            headers={"X-API-Key": raw_key},
            json={
                "key_name": "readonly-poller",
                "scopes": ["analyses:read"],
            },
        )
        assert ro_res.status_code == 201
        ro_key = ro_res.json()["api_key"]
        ro_key_id = ro_res.json()["key_metadata"]["key_id"]

        # Read-only key can list incidents (analyses:read)
        inc_list = client.get(
            "/api/v1/incidents",
            headers={"Authorization": f"Bearer {ro_key}"},
        )
        assert inc_list.status_code == 200
        assert inc_list.json()["tenant_id"] == tenant_id

        # Read-only key CANNOT create an analysis (requires analyses:write -> 403)
        write_attempt = client.post(
            "/api/v1/analyses",
            headers={"Authorization": f"Bearer {ro_key}"},
            json={"incident_id": "INC-2026-101"},
        )
        assert write_attempt.status_code == 403
        assert "INSUFFICIENT_SCOPE" in write_attempt.json()["detail"]

        # Read-only key CANNOT revoke keys (requires keys:manage -> 403)
        revoke_attempt = client.post(
            f"/api/v1/keys/{ro_key_id}/revoke",
            headers={"Authorization": f"Bearer {ro_key}"},
        )
        assert revoke_attempt.status_code == 403

        # 5. Revoke the read-only key with the primary key and verify subsequent requests fail with 401
        rev_res = client.post(
            f"/api/v1/keys/{ro_key_id}/revoke",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert rev_res.status_code == 200
        assert rev_res.json()["revoked"] is True
        assert rev_res.json()["key_metadata"]["status"] == "REVOKED"

        after_revoke = client.get(
            "/api/v1/incidents",
            headers={"Authorization": f"Bearer {ro_key}"},
        )
        assert after_revoke.status_code == 401
        assert "REVOKED" in after_revoke.json()["detail"].upper()


def test_unauthenticated_requests_rejected(sandbox_db: Path) -> None:
    with TestClient(app) as client:
        for method, path in [
            ("GET", "/api/v1/incidents"),
            ("POST", "/api/v1/analyses"),
            ("GET", "/api/v1/analyses/inv_nonexistent"),
            ("GET", "/api/v1/audit"),
            ("GET", "/api/v1/keys"),
        ]:
            res = client.request(method, path)
            assert res.status_code == 401


def test_deterministic_test_only_fixture_credentials(
    sandbox_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Rejected when MLOPS_ENABLE_TEST_FIXTURES is false
    monkeypatch.setenv("MLOPS_ENV", "test")
    monkeypatch.setenv("MLOPS_ENABLE_TEST_FIXTURES", "false")
    with pytest.raises(PermissionError, match="TEST_FIXTURES_FORBIDDEN"):
        provision_test_only_fixture_key(
            fixture_tag="alpha01",
            tenant_id="tenant_fixture_a",
            db_path=sandbox_db,
        )

    # 2. Allowed strictly when MLOPS_ENV=test and MLOPS_ENABLE_TEST_FIXTURES=true
    monkeypatch.setenv("MLOPS_ENABLE_TEST_FIXTURES", "true")
    raw_fixture_key, meta = provision_test_only_fixture_key(
        fixture_tag="alpha01",
        tenant_id="tenant_fixture_a",
        db_path=sandbox_db,
    )
    assert raw_fixture_key.startswith("mlops_test_only_fixture_")
    assert meta.is_test_fixture is True

    with TestClient(app) as client:
        res = client.get(
            "/api/v1/incidents",
            headers={"Authorization": f"Bearer {raw_fixture_key}"},
        )
        assert res.status_code == 200
        assert res.json()["tenant_id"] == "tenant_fixture_a"

        # If test fixtures are disabled at runtime, the test fixture key is rejected with 401
        monkeypatch.setenv("MLOPS_ENABLE_TEST_FIXTURES", "false")
        rejected = client.get(
            "/api/v1/incidents",
            headers={"Authorization": f"Bearer {raw_fixture_key}"},
        )
        assert rejected.status_code == 401


def test_strict_tenant_isolation_across_analyses_actions_audit_and_keys(
    sandbox_db: Path,
) -> None:
    tenant_a = create_demo_tenant_and_key(
        tenant_name="Tenant Alpha",
        key_name="alpha-admin",
        scopes=DEFAULT_DEV_SCOPES,
        db_path=sandbox_db,
    )
    tenant_b = create_demo_tenant_and_key(
        tenant_name="Tenant Bravo",
        key_name="bravo-admin",
        scopes=DEFAULT_DEV_SCOPES,
        db_path=sandbox_db,
    )
    headers_a = {"Authorization": f"Bearer {tenant_a.api_key}"}
    headers_b = {"Authorization": f"Bearer {tenant_b.api_key}"}

    with TestClient(app) as client:
        # Tenant A creates an analysis
        create_a = client.post(
            "/api/v1/analyses",
            headers=headers_a,
            json={"incident_id": "INC-2026-101"},
        )
        assert create_a.status_code == 202
        analysis_id_a = create_a.json()["analysis_id"]

        # Poll Tenant A's analysis with Tenant A's key -> 200
        poll_a = client.get(f"/api/v1/analyses/{analysis_id_a}", headers=headers_a)
        assert poll_a.status_code == 200
        action_id_a = poll_a.json()["result"]["proposed_action"]["action_id"]

        # Tenant B CANNOT read Tenant A's analysis -> 403 TENANT_ISOLATION_VIOLATION
        cross_read = client.get(f"/api/v1/analyses/{analysis_id_a}", headers=headers_b)
        assert cross_read.status_code == 403
        assert "TENANT_ISOLATION_VIOLATION" in cross_read.json()["detail"]

        # Tenant B CANNOT read Tenant A's analysis events -> 403
        cross_events = client.get(
            f"/api/v1/analyses/{analysis_id_a}/events", headers=headers_b
        )
        assert cross_events.status_code == 403

        # Tenant B CANNOT approve or reject Tenant A's proposed action -> 403
        cross_approve = client.post(
            f"/api/v1/actions/{action_id_a}/approve",
            headers=headers_b,
            json={
                "decision": "APPROVE",
                "operator_id": "intruder@tenant-b.local",
                "decision_note": "Attempting cross-tenant approval.",
            },
        )
        assert cross_approve.status_code == 403
        assert "TENANT_ISOLATION_VIOLATION" in cross_approve.json()["detail"]

        # Tenant B CANNOT revoke Tenant A's API key -> 403
        cross_revoke = client.post(
            f"/api/v1/keys/{tenant_a.key_metadata.key_id}/revoke",
            headers=headers_b,
        )
        assert cross_revoke.status_code == 403

        # Tenant B's audit log must NOT contain Tenant A's analysis or action
        audit_b = client.get("/api/v1/audit", headers=headers_b)
        assert audit_b.status_code == 200
        assert analysis_id_a not in str(audit_b.json())
        assert action_id_a not in str(audit_b.json())


def test_async_analysis_lifecycle_idempotency_and_approval_flow(sandbox_db: Path) -> None:
    tenant = create_demo_tenant_and_key(
        tenant_name="Async Lifecycle Tenant",
        key_name="lifecycle-key",
        scopes=DEFAULT_DEV_SCOPES,
        db_path=sandbox_db,
    )
    headers = {
        "Authorization": f"Bearer {tenant.api_key}",
        "Idempotency-Key": "idem-req-2026-101-first",
    }

    with TestClient(app) as client:
        # 1. Submit async analysis -> 202 Accepted with analysis_id and status_url
        sub1 = client.post(
            "/api/v1/analyses",
            headers=headers,
            json={"incident_id": "INC-2026-101"},
        )
        assert sub1.status_code == 202
        acc1 = sub1.json()
        assert acc1["status"] == "QUEUED"
        assert acc1["idempotent_replay"] is False
        analysis_id = acc1["analysis_id"]
        status_url = acc1["status_url"]
        assert status_url == f"/api/v1/analyses/{analysis_id}"

        # 2. Retry with identical Idempotency-Key -> returns same analysis_id with idempotent_replay=True
        sub2 = client.post(
            "/api/v1/analyses",
            headers=headers,
            json={"incident_id": "INC-2026-101"},
        )
        assert sub2.status_code == 202
        acc2 = sub2.json()
        assert acc2["analysis_id"] == analysis_id
        assert acc2["idempotent_replay"] is True

        # 3. Poll status_url for completed diagnosis result
        status_res = client.get(status_url, headers=headers)
        assert status_res.status_code == 200
        data = status_res.json()
        assert data["status"] == "AWAITING_HUMAN_APPROVAL"
        result = data["result"]
        assert result is not None
        assert result["status"] == "DIAGNOSED"
        assert result["root_cause_code"] == "RC_UPSTREAM_SCHEMA_MISMATCH"
        assert len(result["observed_facts"]) >= 3
        assert len(result["hypotheses"]) >= 1
        assert len(result["alternative_explanations"]) >= 1
        assert len(result["evidence_references"]) >= 2
        assert len(result["recommendations"]) >= 1
        assert result["abstention_reason"] is None

        # Verify internal approval_token is NEVER exposed in client response
        assert "approval_token" not in str(data)

        # 4. Check events endpoint
        events_res = client.get(f"{status_url}/events", headers=headers)
        assert events_res.status_code == 200
        ev_data = events_res.json()
        assert len(ev_data["stages"]) >= 5
        assert len(ev_data["tool_events"]) >= 4
        assert "approval_token" not in str(ev_data)

        # 5. Approve proposed action via /api/v1/actions/{action_id}/approve
        action_id = result["proposed_action"]["action_id"]
        approve_res = client.post(
            f"/api/v1/actions/{action_id}/approve",
            headers=headers,
            json={
                "decision": "APPROVE",
                "operator_id": "oncall-engineer@sandbox.local",
                "decision_note": "Approved v3.4 schema adapter rerun.",
            },
        )
        assert approve_res.status_code == 200
        app_body = approve_res.json()
        assert app_body["analysis"]["status"] == "REMEDIATED_AND_VERIFIED"
        assert app_body["analysis"]["result"]["proposed_action"]["status"] == "EXECUTED"
        assert "apv_" not in str(app_body)

        # Verify tool trace redacted approval_token in SQLite & events
        ev_after = client.get(f"{status_url}/events", headers=headers).json()
        rerun_traces = [
            t for t in ev_after["tool_events"] if t["tool_name"] == "simulate_approved_rerun"
        ]
        assert len(rerun_traces) == 1
        assert rerun_traces[0]["arguments"]["approval_token"] == "[REDACTED_SERVER_TOKEN]"


def test_api_v1_conflicting_and_insufficient_evidence_abstention(sandbox_db: Path) -> None:
    tenant = create_demo_tenant_and_key(
        tenant_name="Abstention Test Tenant",
        key_name="abstain-key",
        scopes=DEFAULT_DEV_SCOPES,
        db_path=sandbox_db,
    )
    headers = {"Authorization": f"Bearer {tenant.api_key}"}

    with TestClient(app) as client:
        # 1. Conflicting evidence incident (INC-2026-107)
        c_sub = client.post(
            "/api/v1/analyses",
            headers=headers,
            json={"incident_id": "INC-2026-107"},
        )
        assert c_sub.status_code == 202
        c_poll = client.get(c_sub.json()["status_url"], headers=headers).json()
        assert c_poll["status"] == "COMPLETED_ABSTAINED"
        c_res = c_poll["result"]
        assert c_res["status"] == "ABSTAINED_CONFLICTING_EVIDENCE"
        assert len(c_res["conflicts_detected"]) >= 1
        assert c_res["abstention_reason"] is not None
        assert c_res["proposed_action"] is None

        # 2. Insufficient evidence incident (INC-2026-109)
        i_sub = client.post(
            "/api/v1/analyses",
            headers=headers,
            json={"incident_id": "INC-2026-109"},
        )
        assert i_sub.status_code == 202
        i_poll = client.get(i_sub.json()["status_url"], headers=headers).json()
        assert i_poll["status"] == "COMPLETED_ABSTAINED"
        i_res = i_poll["result"]
        assert i_res["status"] == "ABSTAINED_INSUFFICIENT_EVIDENCE"
        assert len(i_res["missing_telemetry"]) >= 1
        assert i_res["abstention_reason"] is not None
        assert i_res["proposed_action"] is None


def test_zero_outbound_network_calls_in_mock_mode(
    sandbox_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Direct guard check raises OutboundNetworkBlockedError in mock mode
    with pytest.raises(OutboundNetworkBlockedError, match="OUTBOUND_NETWORK_BLOCKED_IN_MOCK_MODE"):
        assert_no_outbound_network_in_mock("https://example.com/external-api")

    # 2. Poison socket.socket.connect to prove zero network sockets are opened during full mock flow
    def _forbidden_socket_connect(*args, **kwargs):
        raise AssertionError("Unexpected outbound network socket connection attempted in mock mode!")

    monkeypatch.setattr(socket.socket, "connect", _forbidden_socket_connect)

    tenant = create_demo_tenant_and_key(
        tenant_name="Zero Network Tenant",
        key_name="offline-key",
        scopes=DEFAULT_DEV_SCOPES,
        db_path=sandbox_db,
    )
    with TestClient(app) as client:
        sub = client.post(
            "/api/v1/analyses",
            headers={"Authorization": f"Bearer {tenant.api_key}"},
            json={"incident_id": "INC-2026-102"},
        )
        assert sub.status_code == 202
        poll = client.get(
            sub.json()["status_url"],
            headers={"Authorization": f"Bearer {tenant.api_key}"},
        )
        assert poll.status_code == 200
        assert poll.json()["result"]["root_cause_code"] == "RC_UPSTREAM_PARTITION_GAP"


def test_production_environment_rejects_dev_keys_fixtures_and_mock_defaults(
    sandbox_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MLOPS_ENV", "production")
    monkeypatch.setenv("MLOPS_ENABLE_DEV_KEY_ISSUANCE", "true")
    monkeypatch.setenv("MLOPS_CONNECTOR_MODE", "mock")

    with pytest.raises(ProductionConfigurationError, match="PRODUCTION_SAFETY_BLOCK"):
        get_settings()

    # Even if dev key issuance is turned off, mock connectors in production are still blocked
    monkeypatch.setenv("MLOPS_ENABLE_DEV_KEY_ISSUANCE", "false")
    monkeypatch.setenv("MLOPS_ENABLE_TEST_FIXTURES", "true")
    with pytest.raises(ProductionConfigurationError, match="PRODUCTION_SAFETY_BLOCK"):
        get_settings()


def test_fastapi_endpoints(sandbox_db: Path) -> None:
    with TestClient(app) as client:
        client.post("/api/sandbox/reset")
        ov = client.get("/api/overview")
        assert ov.status_code == 200
        assert ov.json()["summary_counts"]["total_incidents"] == 10

        inc_res = client.post("/api/incidents/INC-2026-104/investigate")
        assert inc_res.status_code == 200
        action_id = inc_res.json()["investigation"]["proposed_action"]["action_id"]

        # Verify unapproved block endpoint
        blk = client.post(f"/api/actions/{action_id}/verify-unapproved-block")
        assert blk.status_code == 200
        assert blk.json()["blocked"] is True

        # Approve action
        app_res = client.post(
            f"/api/actions/{action_id}/decision",
            json={
                "decision": "APPROVE",
                "operator_id": "ml-lead@sandbox.local",
                "decision_note": "Rollback unvalidated threshold override cfg_882.",
            },
        )
        assert app_res.status_code == 200
        assert app_res.json()["incident"]["status"] == "REMEDIATED"
