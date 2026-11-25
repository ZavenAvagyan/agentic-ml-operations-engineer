from __future__ import annotations

import concurrent.futures
import hmac
import json
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from pydantic import ValidationError

from app.config import get_settings
from app.connectors import MockPlatformConnectors
from app.db import DEFAULT_TENANT_ID, get_connection, record_audit_event, utc_now_iso
from app.schemas import (
    ActionStatus,
    EvidenceItem,
    GetAssetLineageInput,
    GetDataQualityReportInput,
    GetFeatureDriftReportInput,
    GetModelMetricsInput,
    GetPartitionStatusInput,
    GetRunDetailsInput,
    GetServiceHealthInput,
    ProposeRemediationInput,
    SearchIncidentHistoryInput,
    SimulateApprovedActionInput,
    ToolCallTrace,
    WorkflowStage,
)

READ_ONLY_TOOLS = frozenset(
    {
        "get_run_details",
        "get_asset_lineage",
        "get_partition_status",
        "get_data_quality_report",
        "get_feature_drift_report",
        "get_model_metrics",
        "get_service_health",
        "search_incident_history",
    }
)

PROPOSAL_TOOLS = frozenset({"propose_rerun"})
STATE_CHANGING_TOOLS = frozenset({"simulate_approved_rerun"})
ALL_ALLOWED_TOOLS = READ_ONLY_TOOLS | PROPOSAL_TOOLS | STATE_CHANGING_TOOLS


class ToolGovernanceError(PermissionError):
    """Raised when a tool call violates read-only, tenant isolation, or human-approval boundaries."""


class ToolValidationError(ValueError):
    """Raised when tool arguments fail allowlist or Pydantic validation."""


class ToolRegistry:
    """Bounded, typed tool executor with stage-based access control, tenant isolation, timeouts, retries, and trace persistence."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> None:
        self.settings = get_settings()
        self.db_path = db_path or self.settings.db_path
        self.tenant_id = tenant_id
        self.connectors = MockPlatformConnectors(db_path=self.db_path)
        self._handlers: Dict[str, Tuple[Any, Callable[[Any], Dict[str, Any]]]] = {
            "get_run_details": (
                GetRunDetailsInput,
                lambda inp: self.connectors.get_run_details(self.tenant_id, inp),
            ),
            "get_asset_lineage": (
                GetAssetLineageInput,
                lambda inp: self.connectors.get_asset_lineage(self.tenant_id, inp),
            ),
            "get_partition_status": (
                GetPartitionStatusInput,
                lambda inp: self.connectors.get_partition_status(self.tenant_id, inp),
            ),
            "get_data_quality_report": (
                GetDataQualityReportInput,
                lambda inp: self.connectors.get_data_quality_report(self.tenant_id, inp),
            ),
            "get_feature_drift_report": (
                GetFeatureDriftReportInput,
                lambda inp: self.connectors.get_feature_drift_report(self.tenant_id, inp),
            ),
            "get_model_metrics": (
                GetModelMetricsInput,
                lambda inp: self.connectors.get_model_metrics(self.tenant_id, inp),
            ),
            "get_service_health": (
                GetServiceHealthInput,
                lambda inp: self.connectors.get_service_health(self.tenant_id, inp),
            ),
            "search_incident_history": (
                SearchIncidentHistoryInput,
                lambda inp: self.connectors.search_incident_history(self.tenant_id, inp),
            ),
            "propose_rerun": (ProposeRemediationInput, self._propose_rerun),
            "simulate_approved_rerun": (
                SimulateApprovedActionInput,
                self._simulate_approved_rerun,
            ),
        }

    def execute_tool(
        self,
        *,
        tool_name: str,
        raw_arguments: Dict[str, Any],
        investigation_run_id: str,
        incident_id: str,
        stage: WorkflowStage,
        allow_state_change: bool = False,
    ) -> Tuple[ToolCallTrace, Optional[EvidenceItem]]:
        start_ts = time.perf_counter()
        call_id = f"call_{uuid.uuid4().hex[:10]}"
        now_iso = utc_now_iso()

        # Redact any internal approval_token before storing trace arguments
        safe_trace_args = {
            k: ("[REDACTED_SERVER_TOKEN]" if k == "approval_token" else v)
            for k, v in (raw_arguments or {}).items()
        }

        # 1. Allowlist enforcement
        if tool_name not in ALL_ALLOWED_TOOLS:
            trace = self._save_trace(
                call_id=call_id,
                investigation_run_id=investigation_run_id,
                incident_id=incident_id,
                stage=stage,
                tool_name=tool_name,
                arguments=safe_trace_args,
                status="BLOCKED_POLICY",
                duration_ms=(time.perf_counter() - start_ts) * 1000.0,
                retries_used=0,
                evidence_id=None,
                output_summary=f"Blocked unlisted tool '{tool_name}'. Only allowlisted narrow tools are permitted.",
                raw_output={"error": "TOOL_NOT_IN_ALLOWLIST", "tool_name": tool_name},
                timestamp=now_iso,
            )
            raise ToolGovernanceError(trace.output_summary)

        # 2. Stage & approval boundary enforcement
        if tool_name in STATE_CHANGING_TOOLS:
            if stage != WorkflowStage.EXECUTE_APPROVED_ACTION or not allow_state_change:
                msg = (
                    f"Blocked '{tool_name}' during stage {stage.value}: state-changing tools are disabled "
                    "until explicit human approval is recorded."
                )
                self._save_trace(
                    call_id=call_id,
                    investigation_run_id=investigation_run_id,
                    incident_id=incident_id,
                    stage=stage,
                    tool_name=tool_name,
                    arguments=safe_trace_args,
                    status="BLOCKED_UNAPPROVED",
                    duration_ms=(time.perf_counter() - start_ts) * 1000.0,
                    retries_used=0,
                    evidence_id=None,
                    output_summary=msg,
                    raw_output={"error": "STATE_CHANGE_BLOCKED_UNAPPROVED", "stage": stage.value},
                    timestamp=now_iso,
                )
                record_audit_event(
                    event_type="UNAUTHORIZED_TOOL_BLOCKED",
                    actor="agent-orchestrator",
                    tenant_id=self.tenant_id,
                    incident_id=incident_id,
                    investigation_id=investigation_run_id,
                    summary=msg,
                    details={"tool_name": tool_name, "stage": stage.value},
                    db_path=self.db_path,
                )
                raise ToolGovernanceError(msg)

        if tool_name in PROPOSAL_TOOLS and stage != WorkflowStage.PROPOSE_REMEDIATION:
            msg = f"Tool '{tool_name}' is only permitted in stage {WorkflowStage.PROPOSE_REMEDIATION.value}."
            self._save_trace(
                call_id=call_id,
                investigation_run_id=investigation_run_id,
                incident_id=incident_id,
                stage=stage,
                tool_name=tool_name,
                arguments=safe_trace_args,
                status="BLOCKED_POLICY",
                duration_ms=(time.perf_counter() - start_ts) * 1000.0,
                retries_used=0,
                evidence_id=None,
                output_summary=msg,
                raw_output={"error": "INVALID_STAGE_FOR_PROPOSAL"},
                timestamp=now_iso,
            )
            raise ToolGovernanceError(msg)

        # 3. Input schema validation
        schema_cls, handler = self._handlers[tool_name]
        try:
            validated_input = schema_cls(**raw_arguments)
        except ValidationError as exc:
            msg = f"Input validation failed for '{tool_name}': {exc.errors()[0].get('msg', 'invalid input')}"
            self._save_trace(
                call_id=call_id,
                investigation_run_id=investigation_run_id,
                incident_id=incident_id,
                stage=stage,
                tool_name=tool_name,
                arguments=safe_trace_args,
                status="ERROR",
                duration_ms=(time.perf_counter() - start_ts) * 1000.0,
                retries_used=0,
                evidence_id=None,
                output_summary=msg,
                raw_output={"error": "VALIDATION_ERROR", "details": exc.errors()},
                timestamp=now_iso,
            )
            raise ToolValidationError(msg) from exc

        validated_dump = {
            k: ("[REDACTED_SERVER_TOKEN]" if k == "approval_token" else v)
            for k, v in validated_input.model_dump().items()
        }

        # 4. Bounded retries + timeout execution
        max_retries = self.settings.max_retries if tool_name in READ_ONLY_TOOLS else 0
        timeout_sec = self.settings.tool_timeout_seconds
        retries_used = 0

        for attempt in range(max_retries + 1):
            retries_used = attempt
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(handler, validated_input)
                    result = future.result(timeout=timeout_sec)
                break
            except ToolGovernanceError as gov_err:
                self._save_trace(
                    call_id=call_id,
                    investigation_run_id=investigation_run_id,
                    incident_id=incident_id,
                    stage=stage,
                    tool_name=tool_name,
                    arguments=validated_dump,
                    status="BLOCKED_UNAPPROVED",
                    duration_ms=(time.perf_counter() - start_ts) * 1000.0,
                    retries_used=retries_used,
                    evidence_id=None,
                    output_summary=str(gov_err),
                    raw_output={"error": "BLOCKED_UNAPPROVED", "message": str(gov_err)},
                    timestamp=now_iso,
                )
                record_audit_event(
                    event_type="UNAUTHORIZED_TOOL_BLOCKED",
                    actor="agent-orchestrator",
                    tenant_id=self.tenant_id,
                    incident_id=incident_id,
                    investigation_id=investigation_run_id,
                    summary=str(gov_err),
                    details={"tool_name": tool_name, "stage": stage.value},
                    db_path=self.db_path,
                )
                raise
            except Exception as exc:
                if attempt >= max_retries:
                    msg = f"Tool '{tool_name}' failed after {retries_used + 1} attempt(s): {exc}"
                    trace = self._save_trace(
                        call_id=call_id,
                        investigation_run_id=investigation_run_id,
                        incident_id=incident_id,
                        stage=stage,
                        tool_name=tool_name,
                        arguments=validated_dump,
                        status="ERROR",
                        duration_ms=(time.perf_counter() - start_ts) * 1000.0,
                        retries_used=retries_used,
                        evidence_id=None,
                        output_summary=msg,
                        raw_output={"error": str(exc)},
                        timestamp=now_iso,
                    )
                    return trace, None

        duration_ms = round((time.perf_counter() - start_ts) * 1000.0, 2)
        evidence_item: Optional[EvidenceItem] = None
        evidence_id: Optional[str] = None

        if tool_name in READ_ONLY_TOOLS:
            evidence_id = f"ev_{uuid.uuid4().hex[:8]}"
            evidence_item = EvidenceItem(
                evidence_id=evidence_id,
                tool_name=tool_name,
                target_id=result.get("target_id", "unknown"),
                observed_fact=result.get("summary", ""),
                metrics_summary=result.get("metrics", {}),
                timestamp=now_iso,
                status_indicator=result.get("status_indicator", "NORMAL"),
            )

        trace = self._save_trace(
            call_id=call_id,
            investigation_run_id=investigation_run_id,
            incident_id=incident_id,
            stage=stage,
            tool_name=tool_name,
            arguments=validated_dump,
            status="SUCCESS",
            duration_ms=duration_ms,
            retries_used=retries_used,
            evidence_id=evidence_id,
            output_summary=result.get("summary", "Tool completed."),
            raw_output=result,
            timestamp=now_iso,
        )
        return trace, evidence_item

    def _save_trace(
        self,
        *,
        call_id: str,
        investigation_run_id: str,
        incident_id: str,
        stage: WorkflowStage,
        tool_name: str,
        arguments: Dict[str, Any],
        status: str,
        duration_ms: float,
        retries_used: int,
        evidence_id: Optional[str],
        output_summary: str,
        raw_output: Dict[str, Any],
        timestamp: str,
    ) -> ToolCallTrace:
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """INSERT INTO tool_traces VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    call_id,
                    self.tenant_id,
                    investigation_run_id,
                    incident_id,
                    stage.value,
                    tool_name,
                    json.dumps(arguments),
                    status,
                    round(duration_ms, 2),
                    retries_used,
                    evidence_id,
                    output_summary,
                    json.dumps(raw_output),
                    timestamp,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        return ToolCallTrace(
            call_id=call_id,
            investigation_run_id=investigation_run_id,
            incident_id=incident_id,
            stage=stage,
            tool_name=tool_name,
            arguments=arguments,
            status=status,  # type: ignore[arg-type]
            duration_ms=round(duration_ms, 2),
            retries_used=retries_used,
            evidence_id=evidence_id,
            output_summary=output_summary,
            raw_output=raw_output,
            timestamp=timestamp,
        )

    def _propose_rerun(self, inp: ProposeRemediationInput) -> Dict[str, Any]:
        action_id = f"act_{uuid.uuid4().hex[:10]}"
        now = utc_now_iso()
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """INSERT INTO proposed_actions
                   (action_id, tenant_id, incident_id, investigation_run_id, action_type, target_component,
                    parameters_json, title, rationale, expected_impact, risk_level, blast_radius,
                    reversible, status, approval_token, created_at, approved_by, decision_note,
                    decided_at, executed_at, verification_summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL, NULL, NULL, NULL)""",
                (
                    action_id,
                    self.tenant_id,
                    inp.incident_id,
                    inp.investigation_run_id,
                    inp.action_type.value,
                    inp.target_component,
                    json.dumps(inp.parameters),
                    inp.title,
                    inp.rationale,
                    inp.expected_impact,
                    inp.risk_level,
                    inp.blast_radius,
                    1 if inp.reversible else 0,
                    ActionStatus.PENDING_APPROVAL.value,
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        record_audit_event(
            event_type="ACTION_PROPOSED_AWAITING_APPROVAL",
            actor="agent-orchestrator",
            tenant_id=self.tenant_id,
            incident_id=inp.incident_id,
            investigation_id=inp.investigation_run_id,
            action_id=action_id,
            summary=f"Proposed simulated action `{inp.action_type.value}` on `{inp.target_component}` (Status: PENDING_APPROVAL).",
            details={
                "action_type": inp.action_type.value,
                "target_component": inp.target_component,
                "risk_level": inp.risk_level,
                "parameters": inp.parameters,
            },
            db_path=self.db_path,
        )
        return {
            "action_id": action_id,
            "status": ActionStatus.PENDING_APPROVAL.value,
            "target_id": inp.target_component,
            "summary": (
                f"Registered proposed action `{action_id}` ({inp.action_type.value}) for `{inp.target_component}`. "
                "Execution is locked until explicit human approval."
            ),
        }

    def _simulate_approved_rerun(self, inp: SimulateApprovedActionInput) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM proposed_actions WHERE action_id = ?", (inp.action_id,)
            ).fetchone()
            if not row:
                raise ToolGovernanceError(f"Action `{inp.action_id}` does not exist.")
            if row["tenant_id"] != self.tenant_id:
                raise ToolGovernanceError(
                    f"TENANT_ISOLATION_VIOLATION: Action `{inp.action_id}` does not belong to tenant `{self.tenant_id}`."
                )
            if row["status"] != ActionStatus.APPROVED.value:
                raise ToolGovernanceError(
                    f"Action `{inp.action_id}` has status `{row['status']}` — explicit human APPROVAL is required before execution."
                )
            stored_token = row["approval_token"] or ""
            if not stored_token or not hmac.compare_digest(
                stored_token.encode("utf-8"), inp.approval_token.encode("utf-8")
            ):
                raise ToolGovernanceError(
                    f"Invalid or missing server-side approval_token for action `{inp.action_id}`."
                )

            action_type = row["action_type"]
            target = row["target_component"]
            incident_id = row["incident_id"]
            now = utc_now_iso()

            verification_msg = self.connectors.apply_approved_remediation(
                conn,
                tenant_id=self.tenant_id,
                action_type=action_type,
                target_component=target,
                now=now,
            )

            conn.execute(
                """UPDATE proposed_actions
                   SET status = ?, executed_at = ?, verification_summary = ?
                   WHERE action_id = ? AND tenant_id = ?""",
                (
                    ActionStatus.EXECUTED.value,
                    now,
                    verification_msg,
                    inp.action_id,
                    self.tenant_id,
                ),
            )
            conn.execute(
                """UPDATE incidents
                   SET status = 'REMEDIATED', updated_at = ?
                   WHERE tenant_id = ? AND incident_id = ?""",
                (now, self.tenant_id, incident_id),
            )
            conn.commit()
        finally:
            conn.close()

        record_audit_event(
            event_type="SIMULATED_ACTION_EXECUTED",
            actor=inp.operator_id,
            tenant_id=self.tenant_id,
            incident_id=incident_id,
            investigation_id=row["investigation_run_id"],
            action_id=inp.action_id,
            summary=f"Executed human-approved simulated action `{action_type}` on `{target}`.",
            details={
                "action_id": inp.action_id,
                "action_type": action_type,
                "target_component": target,
                "verification_summary": verification_msg,
                "simulated_only": True,
            },
            db_path=self.db_path,
        )

        return {
            "action_id": inp.action_id,
            "status": ActionStatus.EXECUTED.value,
            "target_id": target,
            "verification_summary": verification_msg,
            "summary": f"Simulated execution of `{action_type}` on `{target}` succeeded: {verification_msg}",
        }
