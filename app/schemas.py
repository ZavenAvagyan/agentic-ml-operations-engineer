from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    ABSTAINED = "ABSTAINED"
    REMEDIATED = "REMEDIATED"
    RESOLVED = "RESOLVED"


class IncidentCategory(str, Enum):
    DAGSTER_RUN_FAILURE = "DAGSTER_RUN_FAILURE"
    UPSTREAM_SCHEMA_CHANGE = "UPSTREAM_SCHEMA_CHANGE"
    STALE_DATA_MISSING_PARTITION = "STALE_DATA_MISSING_PARTITION"
    FEATURE_DISTRIBUTION_SHIFT = "FEATURE_DISTRIBUTION_SHIFT"
    MODEL_METRIC_DEGRADATION = "MODEL_METRIC_DEGRADATION"
    SERVICE_LATENCY_OR_ERRORS = "SERVICE_LATENCY_OR_ERRORS"
    AMBIGUOUS_OR_UNKNOWN = "AMBIGUOUS_OR_UNKNOWN"


class WorkflowStage(str, Enum):
    VALIDATE_AND_CLASSIFY = "1_VALIDATE_AND_CLASSIFY"
    GATHER_EVIDENCE = "2_GATHER_EVIDENCE"
    COMPARE_PATTERNS = "3_COMPARE_PATTERNS"
    FORM_DIAGNOSIS = "4_FORM_DIAGNOSIS"
    PROPOSE_REMEDIATION = "5_PROPOSE_REMEDIATION"
    AWAIT_APPROVAL = "6_AWAIT_APPROVAL"
    EXECUTE_APPROVED_ACTION = "7_EXECUTE_APPROVED_ACTION"
    VERIFY_AND_RECORD = "8_VERIFY_AND_RECORD"


class DiagnosisStatus(str, Enum):
    DIAGNOSED = "DIAGNOSED"
    ABSTAINED_INSUFFICIENT_EVIDENCE = "ABSTAINED_INSUFFICIENT_EVIDENCE"
    ABSTAINED_CONFLICTING_EVIDENCE = "ABSTAINED_CONFLICTING_EVIDENCE"


class ActionStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"


class SafeActionType(str, Enum):
    RERUN_DAGSTER_ASSET_WITH_SCHEMA_ADAPTER = "RERUN_DAGSTER_ASSET_WITH_SCHEMA_ADAPTER"
    BACKFILL_MISSING_PARTITION = "BACKFILL_MISSING_PARTITION"
    RERUN_FAILED_DAGSTER_JOB = "RERUN_FAILED_DAGSTER_JOB"
    PIN_FEATURE_BASELINE_AND_SHADOW_RECALIBRATE = "PIN_FEATURE_BASELINE_AND_SHADOW_RECALIBRATE"
    ROLLBACK_MODEL_THRESHOLD_CONFIG = "ROLLBACK_MODEL_THRESHOLD_CONFIG"
    SCALE_INFERENCE_REPLICAS_AND_FLUSH_CACHE = "SCALE_INFERENCE_REPLICAS_AND_FLUSH_CACHE"


# --- Narrow Tool Input Schemas ---

SafeIdentifier = Field(
    ...,
    min_length=2,
    max_length=80,
    pattern=r"^[a-zA-Z0-9_\-\.:]+$",
    description="Strict alphanumeric identifier allowlisted for sandboxed lookup.",
)


class GetRunDetailsInput(BaseModel):
    run_id: str = SafeIdentifier


class GetAssetLineageInput(BaseModel):
    asset_key: str = SafeIdentifier


class GetPartitionStatusInput(BaseModel):
    asset_key: str = SafeIdentifier
    window_hours: int = Field(default=48, ge=1, le=168)


class GetDataQualityReportInput(BaseModel):
    asset_key: str = SafeIdentifier


class GetFeatureDriftReportInput(BaseModel):
    feature_group: str = SafeIdentifier


class GetModelMetricsInput(BaseModel):
    model_id: str = SafeIdentifier


class GetServiceHealthInput(BaseModel):
    service_id: str = SafeIdentifier


class SearchIncidentHistoryInput(BaseModel):
    category: str = Field(..., min_length=2, max_length=64, pattern=r"^[A-Z0-9_]+$")
    component_id: Optional[str] = Field(
        default=None, max_length=80, pattern=r"^[a-zA-Z0-9_\-\.:]+$"
    )


class ProposeRemediationInput(BaseModel):
    incident_id: str = SafeIdentifier
    investigation_run_id: str = SafeIdentifier
    action_type: SafeActionType
    target_component: str = SafeIdentifier
    parameters: Dict[str, Any] = Field(default_factory=dict)
    title: str = Field(..., min_length=5, max_length=160)
    rationale: str = Field(..., min_length=10, max_length=800)
    expected_impact: str = Field(..., min_length=5, max_length=500)
    risk_level: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"
    blast_radius: str = Field(..., min_length=5, max_length=300)
    reversible: bool = True


class SimulateApprovedActionInput(BaseModel):
    action_id: str = SafeIdentifier
    approval_token: str = SafeIdentifier
    operator_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_\-\.@]+$")


# --- Evidence & Diagnosis Schemas ---


class EvidenceItem(BaseModel):
    evidence_id: str
    tool_name: str
    target_id: str
    observed_fact: str
    metrics_summary: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    status_indicator: Literal["NORMAL", "WARNING", "CRITICAL", "MISSING", "CONFLICT"] = "NORMAL"


class HypothesisItem(BaseModel):
    hypothesis_id: str
    statement: str
    likelihood: Literal["HIGH", "MEDIUM", "LOW", "RULED_OUT"]
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)


class DiagnosisResult(BaseModel):
    status: DiagnosisStatus
    root_cause_code: str
    root_cause_summary: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    observed_facts: List[EvidenceItem] = Field(default_factory=list)
    hypotheses: List[HypothesisItem] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    uncertainty_notes: List[str] = Field(default_factory=list)
    conflicts_detected: List[str] = Field(default_factory=list)
    missing_telemetry: List[str] = Field(default_factory=list)
    prompt_injection_detected: bool = False
    security_notes: List[str] = Field(default_factory=list)
    provider_used: str = "mock"
    estimated_tokens: int = 0
    estimated_cost_usd: float = 0.0


class ToolCallTrace(BaseModel):
    call_id: str
    investigation_run_id: str
    incident_id: str
    stage: WorkflowStage
    tool_name: str
    arguments: Dict[str, Any]
    status: Literal["SUCCESS", "ERROR", "BLOCKED_UNAPPROVED", "BLOCKED_POLICY"]
    duration_ms: float
    retries_used: int = 0
    evidence_id: Optional[str] = None
    output_summary: str
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str


class WorkflowStageRecord(BaseModel):
    stage: WorkflowStage
    label: str
    status: Literal["COMPLETED", "SKIPPED", "BLOCKED_WAITING_APPROVAL", "ABSTAINED", "FAILED"]
    duration_ms: float
    summary: str
    tool_calls: List[str] = Field(default_factory=list)
    timestamp: str


class ProposedActionRecord(BaseModel):
    action_id: str
    incident_id: str
    investigation_run_id: str
    action_type: SafeActionType
    target_component: str
    parameters: Dict[str, Any]
    title: str
    rationale: str
    expected_impact: str
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    blast_radius: str
    reversible: bool
    status: ActionStatus
    created_at: str
    approved_by: Optional[str] = None
    decision_note: Optional[str] = None
    decided_at: Optional[str] = None
    executed_at: Optional[str] = None
    verification_summary: Optional[str] = None


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    operator_id: str = Field(
        default="staff-ml-engineer@sandbox.local",
        min_length=3,
        max_length=80,
        pattern=r"^[a-zA-Z0-9_\-\.@]+$",
    )
    decision_note: str = Field(
        ...,
        min_length=4,
        max_length=500,
        description="Reason for approving or rejecting the proposed simulated action.",
    )

    @field_validator("decision_note")
    @classmethod
    def sanitize_note(cls, v: str) -> str:
        return v.strip()


class TriggerScenarioRequest(BaseModel):
    scenario_key: str = Field(..., min_length=2, max_length=80, pattern=r"^[a-zA-Z0-9_\-]+$")
    reset_existing: bool = True


class SystemComponentNode(BaseModel):
    component_id: str
    name: str
    layer: Literal["SOURCE", "DAGSTER_ASSET", "FEATURE_STORE", "MODEL", "SERVICE", "MONITOR"]
    status: Literal["HEALTHY", "DEGRADED", "FAILED", "STALE"]
    freshness_sla_minutes: int
    current_lag_minutes: int
    owner_team: str
    description: str
    metrics: Dict[str, Any] = Field(default_factory=dict)
    upstreams: List[str] = Field(default_factory=list)
    downstreams: List[str] = Field(default_factory=list)


class BenchmarkCaseResult(BaseModel):
    case_id: str
    title: str
    incident_id: str
    scenario_type: str
    expected_outcome_type: Literal["DIAGNOSE", "ABSTAIN"]
    expected_root_cause_code: str
    actual_status: DiagnosisStatus
    actual_root_cause_code: str
    root_cause_correct: bool
    evidence_grounded: bool
    abstained_appropriately: bool
    unsafe_action_proposed: bool
    prompt_injection_resisted: bool
    confidence: float
    tool_calls_count: int
    duration_ms: float
    estimated_tokens: int
    estimated_cost_usd: float
    explanation: str
    proposed_action_type: Optional[str] = None


class BenchmarkRunSummary(BaseModel):
    benchmark_run_id: str
    executed_at: str
    provider_used: str
    total_cases: int
    diagnose_cases_count: int
    abstain_cases_count: int
    root_cause_accuracy_rate: float
    evidence_grounded_rate: float
    unsafe_action_proposal_rate: float
    appropriate_abstention_rate: float
    prompt_injection_resistance_rate: float
    avg_tool_calls: float
    avg_duration_ms: float
    total_duration_ms: float
    total_estimated_tokens: int
    total_estimated_cost_usd: float
    cases: List[BenchmarkCaseResult]


# --- Versioned API v1 Schemas: Tenants, Scoped API Keys, Async Analyses ---


class ApiScope(str, Enum):
    ANALYSES_READ = "analyses:read"
    ANALYSES_WRITE = "analyses:write"
    ACTIONS_APPROVE = "actions:approve"
    AUDIT_READ = "audit:read"
    KEYS_MANAGE = "keys:manage"


DEFAULT_DEV_SCOPES: List[ApiScope] = [
    ApiScope.ANALYSES_READ,
    ApiScope.ANALYSES_WRITE,
    ApiScope.ACTIONS_APPROVE,
    ApiScope.AUDIT_READ,
    ApiScope.KEYS_MANAGE,
]


class CreateDevTenantRequest(BaseModel):
    tenant_name: str = Field(
        default="local-demo-team",
        min_length=2,
        max_length=80,
        pattern=r"^[a-zA-Z0-9_\-\. ]+$",
    )
    key_name: str = Field(
        default="default-dev-key",
        min_length=2,
        max_length=80,
        pattern=r"^[a-zA-Z0-9_\-\. ]+$",
    )
    scopes: List[ApiScope] = Field(default_factory=lambda: list(DEFAULT_DEV_SCOPES))


class ApiKeyMetadata(BaseModel):
    key_id: str
    tenant_id: str
    key_name: str
    key_prefix: str
    scopes: List[str]
    status: Literal["ACTIVE", "REVOKED"]
    is_test_fixture: bool = False
    created_at: str
    revoked_at: Optional[str] = None
    last_used_at: Optional[str] = None


class CreateDevTenantResponse(BaseModel):
    tenant_id: str
    tenant_name: str
    environment: str
    api_key: str = Field(
        ...,
        description="One-time display of the newly generated fake development API key. Stored only as PBKDF2-HMAC-SHA256 hash.",
    )
    key_metadata: ApiKeyMetadata
    seeded_incidents: List[str]
    notice: str = (
        "DEVELOPMENT SANDBOX KEY: Shown only once. Store securely for local API calls; "
        "this key does not connect to any external or production service."
    )


class IssueApiKeyRequest(BaseModel):
    key_name: str = Field(
        default="secondary-dev-key",
        min_length=2,
        max_length=80,
        pattern=r"^[a-zA-Z0-9_\-\. ]+$",
    )
    scopes: List[ApiScope] = Field(default_factory=lambda: list(DEFAULT_DEV_SCOPES))


class CreateAnalysisRequest(BaseModel):
    incident_id: str = SafeIdentifier
    idempotency_key: Optional[str] = Field(
        default=None,
        min_length=4,
        max_length=120,
        pattern=r"^[a-zA-Z0-9_\-\.:]+$",
    )
    notes: Optional[str] = Field(default=None, max_length=500)


class AnalysisAcceptedResponse(BaseModel):
    analysis_id: str
    tenant_id: str
    incident_id: str
    status: str
    status_url: str
    events_url: str
    idempotency_key: Optional[str] = None
    idempotent_replay: bool = False
    created_at: str
    simulated: bool = True


class AnalysisStructuredResult(BaseModel):
    status: DiagnosisStatus
    root_cause_code: str
    root_cause_summary: str
    confidence: float
    abstention_reason: Optional[str] = None
    observed_facts: List[EvidenceItem] = Field(default_factory=list)
    hypotheses: List[HypothesisItem] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    conflicts_detected: List[str] = Field(default_factory=list)
    missing_telemetry: List[str] = Field(default_factory=list)
    uncertainty_notes: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    proposed_action: Optional[ProposedActionRecord] = None
    prompt_injection_detected: bool = False
    security_notes: List[str] = Field(default_factory=list)


class AnalysisStatusResponse(BaseModel):
    analysis_id: str
    tenant_id: str
    incident_id: str
    status: str
    provider_used: str
    started_at: str
    completed_at: Optional[str] = None
    total_duration_ms: float
    stages: List[WorkflowStageRecord] = Field(default_factory=list)
    result: Optional[AnalysisStructuredResult] = None
    tool_traces: List[ToolCallTrace] = Field(default_factory=list)
    simulated: bool = True


