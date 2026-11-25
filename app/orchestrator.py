from __future__ import annotations

import json
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import get_settings
from app.db import DEFAULT_TENANT_ID, get_connection, record_audit_event, utc_now_iso
from app.providers import detect_prompt_injection, get_reasoning_provider
from app.schemas import (
    ActionStatus,
    ApprovalDecisionRequest,
    DiagnosisStatus,
    EvidenceItem,
    IncidentStatus,
    WorkflowStage,
    WorkflowStageRecord,
)
from app.tools import ToolRegistry


class TenantAccessDeniedError(PermissionError):
    """Raised when a caller attempts to access an analysis, incident, or action owned by another tenant."""


class TenantQuotaExceededError(RuntimeError):
    """Raised when a tenant exceeds its configured maximum analyses limit."""


class IncidentOrchestrator:
    """
    Explicit 8-stage state-machine orchestrator for ML incident investigation and human-gated remediation.
    Enforces tenant isolation, read-only defaults during investigation, idempotency, and server-side approval tokens.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        tenant_id: str = DEFAULT_TENANT_ID,
    ) -> None:
        self.settings = get_settings()
        self.db_path = db_path or self.settings.db_path
        self.tenant_id = tenant_id
        self.tools = ToolRegistry(db_path=self.db_path, tenant_id=self.tenant_id)
        self.provider = get_reasoning_provider()

    def create_or_get_analysis(
        self,
        incident_id: str,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[str, bool, str]:
        """
        Creates a new QUEUED analysis or returns an existing analysis when idempotency_key matches.
        Returns (analysis_id, is_idempotent_replay, created_at).
        """
        now = utc_now_iso()
        conn = get_connection(self.db_path)
        try:
            # 1. Check idempotency key for this tenant first
            if idempotency_key:
                existing = conn.execute(
                    """SELECT investigation_id, started_at
                       FROM investigations
                       WHERE tenant_id = ? AND idempotency_key = ?""",
                    (self.tenant_id, idempotency_key),
                ).fetchone()
                if existing:
                    return existing["investigation_id"], True, existing["started_at"]

            # 2. Verify incident exists and belongs to this tenant
            inc_row = conn.execute(
                "SELECT incident_id FROM incidents WHERE tenant_id = ? AND incident_id = ?",
                (self.tenant_id, incident_id),
            ).fetchone()
            if not inc_row:
                # Check if incident exists in another tenant to raise clear isolation error if appropriate
                other = conn.execute(
                    "SELECT tenant_id FROM incidents WHERE incident_id = ? AND tenant_id != ?",
                    (incident_id, self.tenant_id),
                ).fetchone()
                if other:
                    raise TenantAccessDeniedError(
                        f"TENANT_ISOLATION_VIOLATION: Incident `{incident_id}` does not belong to tenant `{self.tenant_id}`."
                    )
                raise ValueError(f"Incident `{incident_id}` not found in tenant `{self.tenant_id}`.")

            # 3. Check per-tenant analysis quota
            cnt_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM investigations WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchone()
            if cnt_row and cnt_row["cnt"] >= self.settings.max_analyses_per_tenant:
                raise TenantQuotaExceededError(
                    f"TENANT_QUOTA_EXCEEDED: Tenant `{self.tenant_id}` reached limit of {self.settings.max_analyses_per_tenant} analyses."
                )

            investigation_id = f"inv_{uuid.uuid4().hex[:10]}"
            conn.execute(
                """INSERT INTO investigations
                   (investigation_id, tenant_id, incident_id, idempotency_key, status,
                    provider_used, started_at, completed_at, total_duration_ms,
                    stages_json, diagnosis_json, proposed_action_id)
                   VALUES (?, ?, ?, ?, 'QUEUED', ?, ?, NULL, 0.0, '[]', NULL, NULL)""",
                (
                    investigation_id,
                    self.tenant_id,
                    incident_id,
                    idempotency_key,
                    self.settings.active_provider,
                    now,
                ),
            )
            conn.commit()
            return investigation_id, False, now
        finally:
            conn.close()

    def run_investigation(
        self,
        incident_id: str,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        investigation_id, is_replay, _ = self.create_or_get_analysis(
            incident_id=incident_id, idempotency_key=idempotency_key
        )
        if is_replay:
            inv = self.get_investigation_detail(investigation_id)
            if inv["status"] != "QUEUED":
                return inv
        return self.execute_queued_analysis(investigation_id)

    def execute_queued_analysis(self, investigation_id: str) -> Dict[str, Any]:
        overall_start = time.perf_counter()
        started_at = utc_now_iso()

        conn = get_connection(self.db_path)
        try:
            inv_row = conn.execute(
                "SELECT * FROM investigations WHERE investigation_id = ? AND tenant_id = ?",
                (investigation_id, self.tenant_id),
            ).fetchone()
            if not inv_row:
                raise ValueError(f"Investigation `{investigation_id}` not found.")
            incident_id = inv_row["incident_id"]

            inc_row = conn.execute(
                "SELECT * FROM incidents WHERE tenant_id = ? AND incident_id = ?",
                (self.tenant_id, incident_id),
            ).fetchone()
            if not inc_row:
                raise ValueError(f"Incident `{incident_id}` not found.")
            incident = dict(inc_row)

            conn.execute(
                "UPDATE investigations SET status = 'RUNNING' WHERE investigation_id = ? AND tenant_id = ?",
                (investigation_id, self.tenant_id),
            )
            conn.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE tenant_id = ? AND incident_id = ?",
                (IncidentStatus.INVESTIGATING.value, started_at, self.tenant_id, incident_id),
            )
            conn.commit()
        finally:
            conn.close()

        record_audit_event(
            event_type="INVESTIGATION_STARTED",
            actor="agent-orchestrator",
            tenant_id=self.tenant_id,
            incident_id=incident_id,
            investigation_id=investigation_id,
            summary=f"Started controlled 8-stage investigation `{investigation_id}` for `{incident_id}`.",
            details={
                "category": incident["category"],
                "affected_component": incident["affected_component"],
                "tenant_id": self.tenant_id,
            },
            db_path=self.db_path,
        )

        stages: List[WorkflowStageRecord] = []
        evidence_items: List[EvidenceItem] = []
        raw_tool_outputs: Dict[str, Dict[str, Any]] = {}
        tool_call_count = 0

        # --- STAGE 1: VALIDATE_AND_CLASSIFY ---
        s1_start = time.perf_counter()
        untrusted_text = (
            f"{incident.get('symptom_summary', '')}\n{incident.get('untrusted_incident_payload', '')}"
        )[: self.settings.max_input_chars]
        injection_detected, injection_findings = detect_prompt_injection(untrusted_text)

        if injection_detected:
            record_audit_event(
                event_type="PROMPT_INJECTION_QUARANTINED",
                actor="agent-orchestrator",
                tenant_id=self.tenant_id,
                incident_id=incident_id,
                investigation_id=investigation_id,
                summary="Detected and quarantined adversarial instruction-override text in incident payload.",
                details={"findings": injection_findings},
                db_path=self.db_path,
            )

        s1_summary = (
            f"Validated incident `{incident_id}` (Category: {incident['category']}, Component: `{incident['affected_component']}`). "
            + (
                f"SECURITY ALERT: Quarantined {len(injection_findings)} adversarial prompt-injection pattern(s) in untrusted text."
                if injection_detected
                else "Untrusted text sanitized; no prompt-injection patterns detected."
            )
        )
        stages.append(
            WorkflowStageRecord(
                stage=WorkflowStage.VALIDATE_AND_CLASSIFY,
                label="1. Validate & Classify Incident",
                status="COMPLETED",
                duration_ms=round((time.perf_counter() - s1_start) * 1000.0, 2),
                summary=s1_summary,
                tool_calls=[],
                timestamp=utc_now_iso(),
            )
        )

        # --- STAGE 2: GATHER_EVIDENCE (Read-Only Tools Only) ---
        s2_start = time.perf_counter()
        s2_calls: List[str] = []
        planned_tools = self._plan_evidence_tools(incident)

        for tool_name, args in planned_tools:
            if tool_call_count >= self.settings.max_tool_calls_per_investigation:
                break
            trace, ev_item = self.tools.execute_tool(
                tool_name=tool_name,
                raw_arguments=args,
                investigation_run_id=investigation_id,
                incident_id=incident_id,
                stage=WorkflowStage.GATHER_EVIDENCE,
                allow_state_change=False,
            )
            tool_call_count += 1
            s2_calls.append(trace.call_id)
            raw_tool_outputs[tool_name] = trace.raw_output
            if ev_item:
                evidence_items.append(ev_item)

        stages.append(
            WorkflowStageRecord(
                stage=WorkflowStage.GATHER_EVIDENCE,
                label="2. Gather Read-Only Evidence",
                status="COMPLETED",
                duration_ms=round((time.perf_counter() - s2_start) * 1000.0, 2),
                summary=f"Executed {len(s2_calls)} bounded read-only tool call(s) and collected {len(evidence_items)} structured evidence item(s).",
                tool_calls=s2_calls,
                timestamp=utc_now_iso(),
            )
        )

        # --- STAGE 3: COMPARE_PATTERNS ---
        s3_start = time.perf_counter()
        s3_calls: List[str] = []
        historical_matches: List[Dict[str, Any]] = []
        if tool_call_count < self.settings.max_tool_calls_per_investigation:
            hist_trace, hist_ev = self.tools.execute_tool(
                tool_name="search_incident_history",
                raw_arguments={
                    "category": incident["category"],
                    "component_id": incident["affected_component"],
                },
                investigation_run_id=investigation_id,
                incident_id=incident_id,
                stage=WorkflowStage.COMPARE_PATTERNS,
                allow_state_change=False,
            )
            tool_call_count += 1
            s3_calls.append(hist_trace.call_id)
            raw_tool_outputs["search_incident_history"] = hist_trace.raw_output
            historical_matches = hist_trace.raw_output.get("matches", [])
            if hist_ev:
                evidence_items.append(hist_ev)

        stages.append(
            WorkflowStageRecord(
                stage=WorkflowStage.COMPARE_PATTERNS,
                label="3. Compare Known Incident Patterns",
                status="COMPLETED",
                duration_ms=round((time.perf_counter() - s3_start) * 1000.0, 2),
                summary=f"Matched {len(historical_matches)} historical incident signature(s) for `{incident['affected_component']}`.",
                tool_calls=s3_calls,
                timestamp=utc_now_iso(),
            )
        )

        # --- STAGE 4: FORM_DIAGNOSIS ---
        s4_start = time.perf_counter()
        diagnosis, proposal_spec = self.provider.synthesize(
            incident=incident,
            evidence_items=evidence_items,
            raw_tool_outputs=raw_tool_outputs,
            historical_matches=historical_matches,
            injection_detected=injection_detected,
            injection_findings=injection_findings,
        )
        is_abstained = diagnosis.status != DiagnosisStatus.DIAGNOSED
        stages.append(
            WorkflowStageRecord(
                stage=WorkflowStage.FORM_DIAGNOSIS,
                label="4. Form Evidence-Grounded Diagnosis",
                status="ABSTAINED" if is_abstained else "COMPLETED",
                duration_ms=round((time.perf_counter() - s4_start) * 1000.0, 2),
                summary=(
                    f"Abstained ({diagnosis.status.value}): {diagnosis.root_cause_summary}"
                    if is_abstained
                    else f"Diagnosed `{diagnosis.root_cause_code}` (confidence={diagnosis.confidence:.0%}) grounded in {len(diagnosis.evidence_references)} evidence item(s)."
                ),
                tool_calls=[],
                timestamp=utc_now_iso(),
            )
        )

        # --- STAGE 5 & 6: PROPOSE_REMEDIATION & AWAIT_APPROVAL ---
        proposed_action_id: Optional[str] = None
        if is_abstained or not proposal_spec:
            stages.append(
                WorkflowStageRecord(
                    stage=WorkflowStage.PROPOSE_REMEDIATION,
                    label="5. Generate Bounded Remediation Proposal",
                    status="SKIPPED",
                    duration_ms=0.1,
                    summary="Skipped remediation proposal because agent abstained due to conflicting or insufficient evidence.",
                    tool_calls=[],
                    timestamp=utc_now_iso(),
                )
            )
            stages.append(
                WorkflowStageRecord(
                    stage=WorkflowStage.AWAIT_APPROVAL,
                    label="6. Human Approval Gate",
                    status="SKIPPED",
                    duration_ms=0.1,
                    summary="No state-changing action proposed; human escalation requested for missing telemetry.",
                    tool_calls=[],
                    timestamp=utc_now_iso(),
                )
            )
            final_inc_status = IncidentStatus.ABSTAINED.value
            inv_status = "COMPLETED_ABSTAINED"
        else:
            s5_start = time.perf_counter()
            prop_trace, _ = self.tools.execute_tool(
                tool_name="propose_rerun",
                raw_arguments={
                    "incident_id": incident_id,
                    "investigation_run_id": investigation_id,
                    "action_type": proposal_spec["action_type"],
                    "target_component": proposal_spec["target_component"],
                    "parameters": proposal_spec["parameters"],
                    "title": proposal_spec["title"],
                    "rationale": proposal_spec["rationale"],
                    "expected_impact": proposal_spec["expected_impact"],
                    "risk_level": proposal_spec["risk_level"],
                    "blast_radius": proposal_spec["blast_radius"],
                    "reversible": proposal_spec["reversible"],
                },
                investigation_run_id=investigation_id,
                incident_id=incident_id,
                stage=WorkflowStage.PROPOSE_REMEDIATION,
                allow_state_change=False,
            )
            proposed_action_id = prop_trace.raw_output.get("action_id")
            stages.append(
                WorkflowStageRecord(
                    stage=WorkflowStage.PROPOSE_REMEDIATION,
                    label="5. Generate Bounded Remediation Proposal",
                    status="COMPLETED",
                    duration_ms=round((time.perf_counter() - s5_start) * 1000.0, 2),
                    summary=f"Created proposal `{proposed_action_id}` ({proposal_spec['action_type'].value}) with risk={proposal_spec['risk_level']}.",
                    tool_calls=[prop_trace.call_id],
                    timestamp=utc_now_iso(),
                )
            )
            stages.append(
                WorkflowStageRecord(
                    stage=WorkflowStage.AWAIT_APPROVAL,
                    label="6. Human Approval Gate",
                    status="BLOCKED_WAITING_APPROVAL",
                    duration_ms=0.1,
                    summary=f"Workflow paused at human approval gate for action `{proposed_action_id}`. State-changing tools remain locked.",
                    tool_calls=[],
                    timestamp=utc_now_iso(),
                )
            )
            final_inc_status = IncidentStatus.AWAITING_APPROVAL.value
            inv_status = "AWAITING_HUMAN_APPROVAL"

        total_duration_ms = round((time.perf_counter() - overall_start) * 1000.0, 2)
        completed_at = utc_now_iso()

        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """UPDATE investigations
                   SET status = ?, provider_used = ?, completed_at = ?,
                       total_duration_ms = ?, stages_json = ?, diagnosis_json = ?,
                       proposed_action_id = ?
                   WHERE investigation_id = ? AND tenant_id = ?""",
                (
                    inv_status,
                    diagnosis.provider_used,
                    completed_at,
                    total_duration_ms,
                    json.dumps([s.model_dump() for s in stages]),
                    json.dumps(diagnosis.model_dump()),
                    proposed_action_id,
                    investigation_id,
                    self.tenant_id,
                ),
            )
            conn.execute(
                """UPDATE incidents
                   SET status = ?, updated_at = ?, latest_investigation_id = ?
                   WHERE tenant_id = ? AND incident_id = ?""",
                (final_inc_status, completed_at, investigation_id, self.tenant_id, incident_id),
            )
            conn.commit()
        finally:
            conn.close()

        record_audit_event(
            event_type="INVESTIGATION_FINISHED",
            actor="agent-orchestrator",
            tenant_id=self.tenant_id,
            incident_id=incident_id,
            investigation_id=investigation_id,
            action_id=proposed_action_id,
            summary=(
                f"Investigation `{investigation_id}` finished with status `{inv_status}` "
                f"(diagnosis={diagnosis.root_cause_code}, confidence={diagnosis.confidence:.0%})."
            ),
            details={
                "status": inv_status,
                "root_cause_code": diagnosis.root_cause_code,
                "confidence": diagnosis.confidence,
                "proposed_action_id": proposed_action_id,
                "duration_ms": total_duration_ms,
            },
            db_path=self.db_path,
        )

        return self.get_investigation_detail(investigation_id)

    def process_approval_decision(
        self, action_id: str, req: ApprovalDecisionRequest
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        conn = get_connection(self.db_path)
        try:
            act_row = conn.execute(
                "SELECT * FROM proposed_actions WHERE action_id = ?", (action_id,)
            ).fetchone()
            if not act_row:
                raise LookupError(f"Proposed action `{action_id}` not found.")
            if act_row["tenant_id"] != self.tenant_id:
                raise TenantAccessDeniedError(
                    f"TENANT_ISOLATION_VIOLATION: Action `{action_id}` does not belong to tenant `{self.tenant_id}`."
                )
            if act_row["status"] != ActionStatus.PENDING_APPROVAL.value:
                raise ValueError(
                    f"Proposed action `{action_id}` is already in state `{act_row['status']}`."
                )

            incident_id = act_row["incident_id"]
            investigation_id = act_row["investigation_run_id"]
            target_component = act_row["target_component"]

            inv_row = conn.execute(
                "SELECT * FROM investigations WHERE investigation_id = ? AND tenant_id = ?",
                (investigation_id, self.tenant_id),
            ).fetchone()
            stages_data = json.loads(inv_row["stages_json"]) if inv_row else []

            if req.decision == "REJECT":
                conn.execute(
                    """UPDATE proposed_actions
                       SET status = ?, approved_by = ?, decision_note = ?, decided_at = ?
                       WHERE action_id = ? AND tenant_id = ?""",
                    (
                        ActionStatus.REJECTED.value,
                        req.operator_id,
                        req.decision_note,
                        now,
                        action_id,
                        self.tenant_id,
                    ),
                )
                conn.execute(
                    "UPDATE incidents SET status = ?, updated_at = ? WHERE tenant_id = ? AND incident_id = ?",
                    (IncidentStatus.OPEN.value, now, self.tenant_id, incident_id),
                )
                for s in stages_data:
                    if s["stage"] == WorkflowStage.AWAIT_APPROVAL.value:
                        s["status"] = "COMPLETED"
                        s["summary"] = (
                            f"Rejected by `{req.operator_id}`: {req.decision_note}. "
                            "No simulated state changes were executed."
                        )
                stages_data.append(
                    WorkflowStageRecord(
                        stage=WorkflowStage.EXECUTE_APPROVED_ACTION,
                        label="7. Execute Approved Simulated Action",
                        status="SKIPPED",
                        duration_ms=0.0,
                        summary="Skipped because operator rejected the proposed remediation.",
                        tool_calls=[],
                        timestamp=now,
                    ).model_dump()
                )
                conn.execute(
                    "UPDATE investigations SET status = 'REJECTED_BY_HUMAN', stages_json = ? WHERE investigation_id = ? AND tenant_id = ?",
                    (json.dumps(stages_data), investigation_id, self.tenant_id),
                )
                conn.commit()

                record_audit_event(
                    event_type="ACTION_REJECTED_BY_OPERATOR",
                    actor=req.operator_id,
                    tenant_id=self.tenant_id,
                    incident_id=incident_id,
                    investigation_id=investigation_id,
                    action_id=action_id,
                    summary=f"Operator `{req.operator_id}` REJECTED action `{action_id}`: {req.decision_note}",
                    details={"decision": "REJECT", "note": req.decision_note},
                    db_path=self.db_path,
                )
                return self.get_investigation_detail(investigation_id)

            # APPROVE flow: issue cryptographic approval token server-side in DB only
            approval_token = f"tok_{secrets.token_hex(24)}"
            conn.execute(
                """UPDATE proposed_actions
                   SET status = ?, approval_token = ?, approved_by = ?, decision_note = ?, decided_at = ?
                   WHERE action_id = ? AND tenant_id = ?""",
                (
                    ActionStatus.APPROVED.value,
                    approval_token,
                    req.operator_id,
                    req.decision_note,
                    now,
                    action_id,
                    self.tenant_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        record_audit_event(
            event_type="ACTION_APPROVED_BY_OPERATOR",
            actor=req.operator_id,
            tenant_id=self.tenant_id,
            incident_id=incident_id,
            investigation_id=investigation_id,
            action_id=action_id,
            summary=f"Operator `{req.operator_id}` APPROVED simulated action `{action_id}`: {req.decision_note}",
            details={"decision": "APPROVE", "note": req.decision_note},
            db_path=self.db_path,
        )

        # --- STAGE 7: EXECUTE_APPROVED_ACTION ---
        s7_start = time.perf_counter()
        exec_trace, _ = self.tools.execute_tool(
            tool_name="simulate_approved_rerun",
            raw_arguments={
                "action_id": action_id,
                "approval_token": approval_token,
                "operator_id": req.operator_id,
            },
            investigation_run_id=investigation_id,
            incident_id=incident_id,
            stage=WorkflowStage.EXECUTE_APPROVED_ACTION,
            allow_state_change=True,
        )
        s7_dur = round((time.perf_counter() - s7_start) * 1000.0, 2)

        # --- STAGE 8: VERIFY_AND_RECORD ---
        s8_start = time.perf_counter()
        verify_trace, _ = self.tools.execute_tool(
            tool_name="get_asset_lineage",
            raw_arguments={"asset_key": target_component},
            investigation_run_id=investigation_id,
            incident_id=incident_id,
            stage=WorkflowStage.VERIFY_AND_RECORD,
            allow_state_change=False,
        )
        s8_dur = round((time.perf_counter() - s8_start) * 1000.0, 2)

        conn = get_connection(self.db_path)
        try:
            for s in stages_data:
                if s["stage"] == WorkflowStage.AWAIT_APPROVAL.value:
                    s["status"] = "COMPLETED"
                    s["summary"] = f"Approved by `{req.operator_id}` ({req.decision_note})."

            stages_data.append(
                WorkflowStageRecord(
                    stage=WorkflowStage.EXECUTE_APPROVED_ACTION,
                    label="7. Execute Approved Simulated Action",
                    status="COMPLETED",
                    duration_ms=s7_dur,
                    summary=exec_trace.output_summary,
                    tool_calls=[exec_trace.call_id],
                    timestamp=utc_now_iso(),
                ).model_dump()
            )
            stages_data.append(
                WorkflowStageRecord(
                    stage=WorkflowStage.VERIFY_AND_RECORD,
                    label="8. Verify Simulated Outcome & Record Trace",
                    status="COMPLETED",
                    duration_ms=s8_dur,
                    summary=f"Post-remediation verification confirmed `{target_component}` status is now `{verify_trace.raw_output.get('status', 'HEALTHY')}`.",
                    tool_calls=[verify_trace.call_id],
                    timestamp=utc_now_iso(),
                ).model_dump()
            )
            conn.execute(
                """UPDATE investigations
                   SET status = 'REMEDIATED_AND_VERIFIED', stages_json = ?, completed_at = ?
                   WHERE investigation_id = ? AND tenant_id = ?""",
                (json.dumps(stages_data), utc_now_iso(), investigation_id, self.tenant_id),
            )
            conn.commit()
        finally:
            conn.close()

        return self.get_investigation_detail(investigation_id)

    def _plan_evidence_tools(self, incident: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        comp = incident["affected_component"]
        cat = incident["category"]
        run_id = incident.get("triggered_run_id")

        planned: List[Tuple[str, Dict[str, Any]]] = [
            ("get_asset_lineage", {"asset_key": comp}),
        ]
        if run_id:
            planned.append(("get_run_details", {"run_id": run_id}))

        if cat in ("UPSTREAM_SCHEMA_CHANGE", "DAGSTER_RUN_FAILURE"):
            planned.append(("get_data_quality_report", {"asset_key": comp}))
            planned.append(("get_partition_status", {"asset_key": comp, "window_hours": 48}))
        elif cat == "STALE_DATA_MISSING_PARTITION":
            planned.append(("get_partition_status", {"asset_key": comp, "window_hours": 48}))
            planned.append(("get_data_quality_report", {"asset_key": comp}))
        elif cat == "FEATURE_DISTRIBUTION_SHIFT":
            planned.append(("get_feature_drift_report", {"feature_group": comp}))
            planned.append(("get_data_quality_report", {"asset_key": comp}))
            planned.append(("get_partition_status", {"asset_key": comp, "window_hours": 48}))
        elif cat == "MODEL_METRIC_DEGRADATION":
            planned.append(("get_model_metrics", {"model_id": comp}))
            planned.append(("get_feature_drift_report", {"feature_group": "feat_merchant_risk_score"}))
        elif cat == "SERVICE_LATENCY_OR_ERRORS":
            planned.append(("get_service_health", {"service_id": comp}))
            planned.append(("get_model_metrics", {"model_id": "mdl_xgboost_fraud_v4"}))
        else:
            planned.append(("get_model_metrics", {"model_id": comp}))
            planned.append(("get_feature_drift_report", {"feature_group": "feat_experimental_graph_v1"}))

        return planned

    def get_investigation_detail(self, investigation_id: str) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            inv_row = conn.execute(
                "SELECT * FROM investigations WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()
            if not inv_row:
                raise LookupError(f"Investigation `{investigation_id}` not found.")
            if inv_row["tenant_id"] != self.tenant_id:
                raise TenantAccessDeniedError(
                    f"TENANT_ISOLATION_VIOLATION: Analysis `{investigation_id}` does not belong to tenant `{self.tenant_id}`."
                )

            traces = conn.execute(
                "SELECT * FROM tool_traces WHERE investigation_run_id = ? AND tenant_id = ? ORDER BY rowid ASC",
                (investigation_id, self.tenant_id),
            ).fetchall()

            action_row = None
            if inv_row["proposed_action_id"]:
                # Explicitly omit approval_token from query so it never leaves server storage
                action_row = conn.execute(
                    """SELECT action_id, incident_id, investigation_run_id, action_type,
                              target_component, parameters_json, title, rationale,
                              expected_impact, risk_level, blast_radius, reversible,
                              status, created_at, approved_by, decision_note,
                              decided_at, executed_at, verification_summary
                       FROM proposed_actions
                       WHERE action_id = ? AND tenant_id = ?""",
                    (inv_row["proposed_action_id"], self.tenant_id),
                ).fetchone()

            action_dict = None
            if action_row:
                action_dict = dict(action_row)
                action_dict["parameters"] = json.loads(action_dict.pop("parameters_json"))
                action_dict["reversible"] = bool(action_dict["reversible"])

            diag_dict = (
                json.loads(inv_row["diagnosis_json"])
                if inv_row["diagnosis_json"]
                else None
            )

            # Build structured result block for API v1 consumers
            structured_result = None
            if diag_dict:
                is_abstained = diag_dict["status"] != DiagnosisStatus.DIAGNOSED.value
                abstention_reason = None
                recommendations: List[str] = []
                if is_abstained:
                    reasons = (diag_dict.get("conflicts_detected") or []) + (
                        diag_dict.get("missing_telemetry") or []
                    )
                    abstention_reason = (
                        "; ".join(reasons)
                        if reasons
                        else diag_dict.get("root_cause_summary")
                    )
                    recommendations.append(
                        "Restore missing or conflicting telemetry collectors before proposing any state-changing remediation."
                    )
                elif action_dict:
                    recommendations.append(
                        f"Review proposed action `{action_dict['action_id']}` ({action_dict['action_type']} on `{action_dict['target_component']}`) "
                        f"and submit explicit human approval if blast radius is acceptable."
                    )

                structured_result = {
                    "status": diag_dict["status"],
                    "root_cause_code": diag_dict["root_cause_code"],
                    "root_cause_summary": diag_dict["root_cause_summary"],
                    "confidence": diag_dict["confidence"],
                    "abstention_reason": abstention_reason,
                    "observed_facts": diag_dict.get("observed_facts", []),
                    "hypotheses": diag_dict.get("hypotheses", []),
                    "alternative_explanations": diag_dict.get(
                        "alternative_explanations", []
                    ),
                    "conflicts_detected": diag_dict.get("conflicts_detected", []),
                    "missing_telemetry": diag_dict.get("missing_telemetry", []),
                    "uncertainty_notes": diag_dict.get("uncertainty_notes", []),
                    "evidence_references": diag_dict.get("evidence_references", []),
                    "recommendations": recommendations,
                    "proposed_action": action_dict,
                    "prompt_injection_detected": diag_dict.get(
                        "prompt_injection_detected", False
                    ),
                    "security_notes": diag_dict.get("security_notes", []),
                }

            return {
                "investigation_id": inv_row["investigation_id"],
                "analysis_id": inv_row["investigation_id"],
                "tenant_id": inv_row["tenant_id"],
                "incident_id": inv_row["incident_id"],
                "idempotency_key": inv_row["idempotency_key"],
                "status": inv_row["status"],
                "provider_used": inv_row["provider_used"],
                "started_at": inv_row["started_at"],
                "completed_at": inv_row["completed_at"],
                "total_duration_ms": inv_row["total_duration_ms"],
                "stages": json.loads(inv_row["stages_json"]),
                "diagnosis": diag_dict,
                "result": structured_result,
                "proposed_action": action_dict,
                "tool_traces": [
                    {
                        "call_id": t["call_id"],
                        "investigation_run_id": t["investigation_run_id"],
                        "incident_id": t["incident_id"],
                        "stage": t["stage"],
                        "tool_name": t["tool_name"],
                        "arguments": json.loads(t["arguments_json"]),
                        "status": t["status"],
                        "duration_ms": t["duration_ms"],
                        "retries_used": t["retries_used"],
                        "evidence_id": t["evidence_id"],
                        "output_summary": t["output_summary"],
                        "raw_output": json.loads(t["raw_output_json"]),
                        "timestamp": t["timestamp"],
                    }
                    for t in traces
                ],
                "simulated": True,
            }
        finally:
            conn.close()
