from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

from app.config import assert_no_outbound_network_in_mock, get_settings
from app.db import DEFAULT_TENANT_ID, get_connection, utc_now_iso
from app.schemas import (
    GetAssetLineageInput,
    GetDataQualityReportInput,
    GetFeatureDriftReportInput,
    GetModelMetricsInput,
    GetPartitionStatusInput,
    GetRunDetailsInput,
    GetServiceHealthInput,
    SearchIncidentHistoryInput,
)


class DagsterRunConnector(Protocol):
    def get_run_details(self, tenant_id: str, inp: GetRunDetailsInput) -> Dict[str, Any]: ...
    def get_partition_status(self, tenant_id: str, inp: GetPartitionStatusInput) -> Dict[str, Any]: ...


class LineageCatalogConnector(Protocol):
    def get_asset_lineage(self, tenant_id: str, inp: GetAssetLineageInput) -> Dict[str, Any]: ...


class DataQualityConnector(Protocol):
    def get_data_quality_report(self, tenant_id: str, inp: GetDataQualityReportInput) -> Dict[str, Any]: ...


class FeatureObservabilityConnector(Protocol):
    def get_feature_drift_report(self, tenant_id: str, inp: GetFeatureDriftReportInput) -> Dict[str, Any]: ...


class ModelEvaluationConnector(Protocol):
    def get_model_metrics(self, tenant_id: str, inp: GetModelMetricsInput) -> Dict[str, Any]: ...


class ServiceHealthConnector(Protocol):
    def get_service_health(self, tenant_id: str, inp: GetServiceHealthInput) -> Dict[str, Any]: ...


class IncidentHistoryConnector(Protocol):
    def search_incident_history(self, tenant_id: str, inp: SearchIncidentHistoryInput) -> Dict[str, Any]: ...


class RemediationExecutorConnector(Protocol):
    def apply_approved_remediation(
        self,
        *,
        tenant_id: str,
        action_type: str,
        target_component: str,
    ) -> str: ...


class MockPlatformConnectors:
    """
    Deterministic, local SQLite-backed mock connectors implementing the typed connector interfaces.
    Enforces tenant isolation and zero outbound network calls.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.settings = get_settings()
        self.db_path = db_path or self.settings.db_path

    def get_run_details(
        self, tenant_id: str, inp: GetRunDetailsInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM pipeline_runs WHERE tenant_id = ? AND run_id = ?",
                (tenant_id, inp.run_id),
            ).fetchone()
            if not row:
                return {
                    "target_id": inp.run_id,
                    "found": False,
                    "simulated": True,
                    "connector": "MockDagsterRunConnector",
                    "status_indicator": "MISSING",
                    "summary": f"No pipeline run record found for run_id='{inp.run_id}'.",
                    "metrics": {},
                }
            metrics = json.loads(row["metrics_json"])
            status = row["status"]
            indicator = "CRITICAL" if "FAIL" in status or "SKIP" in status else "NORMAL"
            summary = (
                f"Dagster run `{row['run_id']}` on asset `{row['asset_key']}` exited with status `{status}` "
                f"(error_code={row['error_code'] or 'NONE'}): {row['error_message'] or 'Completed normally.'}"
            )
            return {
                "target_id": row["run_id"],
                "found": True,
                "simulated": True,
                "connector": "MockDagsterRunConnector",
                "asset_key": row["asset_key"],
                "job_name": row["job_name"],
                "status": status,
                "partition_key": row["partition_key"],
                "duration_seconds": row["duration_seconds"],
                "error_code": row["error_code"],
                "error_message": row["error_message"],
                "logs_excerpt": row["logs_excerpt"],
                "metrics": metrics,
                "status_indicator": indicator,
                "summary": summary,
            }
        finally:
            conn.close()

    def get_asset_lineage(
        self, tenant_id: str, inp: GetAssetLineageInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM components WHERE tenant_id = ? AND component_id = ?",
                (tenant_id, inp.asset_key),
            ).fetchone()
            if not row:
                return {
                    "target_id": inp.asset_key,
                    "found": False,
                    "simulated": True,
                    "connector": "MockLineageCatalogConnector",
                    "status_indicator": "MISSING",
                    "summary": f"Component `{inp.asset_key}` not registered in lineage catalog.",
                    "metrics": {},
                }
            upstreams = json.loads(row["upstreams_json"])
            downstreams = json.loads(row["downstreams_json"])
            metrics = json.loads(row["metrics_json"])
            indicator = "NORMAL" if row["status"] == "HEALTHY" else "WARNING"
            summary = (
                f"Component `{inp.asset_key}` ({row['layer']}, status={row['status']}) depends on "
                f"upstreams {upstreams or ['none']} and feeds downstreams {downstreams or ['none']}."
            )
            return {
                "target_id": inp.asset_key,
                "found": True,
                "simulated": True,
                "connector": "MockLineageCatalogConnector",
                "layer": row["layer"],
                "status": row["status"],
                "owner_team": row["owner_team"],
                "upstreams": upstreams,
                "downstreams": downstreams,
                "metrics": {
                    "upstreams_count": len(upstreams),
                    "downstreams_count": len(downstreams),
                    **metrics,
                },
                "status_indicator": indicator,
                "summary": summary,
            }
        finally:
            conn.close()

    def get_partition_status(
        self, tenant_id: str, inp: GetPartitionStatusInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM partition_telemetry WHERE tenant_id = ? AND asset_key = ?",
                (tenant_id, inp.asset_key),
            ).fetchone()
            if not row:
                return {
                    "target_id": inp.asset_key,
                    "found": False,
                    "simulated": True,
                    "connector": "MockDagsterRunConnector",
                    "status_indicator": "MISSING",
                    "summary": f"No partition telemetry available for `{inp.asset_key}`.",
                    "metrics": {},
                }
            missing = json.loads(row["missing_partitions_json"])
            lag = row["stale_lag_minutes"]
            sla = row["sla_minutes"]
            indicator = "CRITICAL" if missing or lag > sla else "NORMAL"
            summary = (
                f"Partition check for `{inp.asset_key}`: {row['materialized_partitions_48h']}/{row['total_partitions_48h']} "
                f"partitions materialized in 48h window; missing={missing}; freshness lag={lag}m (SLA={sla}m)."
            )
            return {
                "target_id": inp.asset_key,
                "found": True,
                "simulated": True,
                "connector": "MockDagsterRunConnector",
                "status": row["status"],
                "missing_partitions": missing,
                "stale_lag_minutes": lag,
                "sla_minutes": sla,
                "last_materialized_at": row["last_materialized_at"],
                "metrics": {
                    "missing_count": len(missing),
                    "stale_lag_minutes": lag,
                    "sla_minutes": sla,
                },
                "status_indicator": indicator,
                "summary": summary,
            }
        finally:
            conn.close()

    def get_data_quality_report(
        self, tenant_id: str, inp: GetDataQualityReportInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM data_quality_reports WHERE tenant_id = ? AND asset_key = ?",
                (tenant_id, inp.asset_key),
            ).fetchone()
            if not row:
                return {
                    "target_id": inp.asset_key,
                    "found": False,
                    "simulated": True,
                    "connector": "MockDataQualityConnector",
                    "status_indicator": "MISSING",
                    "summary": f"No data quality contract report found for `{inp.asset_key}`.",
                    "metrics": {},
                }
            breaking = json.loads(row["breaking_changes_json"])
            schema_valid = bool(row["schema_valid"])
            indicator = "CRITICAL" if not schema_valid or row["null_rate_max"] > 0.05 else "NORMAL"
            summary = (
                f"Data quality report for `{inp.asset_key}`: status={row['status']}, "
                f"schema_valid={schema_valid} (observed={row['schema_version']} vs expected={row['expected_schema_version']}), "
                f"breaking_changes={len(breaking)}, max_null_rate={row['null_rate_max']:.3f}."
            )
            return {
                "target_id": inp.asset_key,
                "found": True,
                "simulated": True,
                "connector": "MockDataQualityConnector",
                "status": row["status"],
                "schema_version": row["schema_version"],
                "expected_schema_version": row["expected_schema_version"],
                "schema_valid": schema_valid,
                "breaking_changes": breaking,
                "metrics": {
                    "schema_valid": schema_valid,
                    "null_rate_max": row["null_rate_max"],
                    "row_count_delta_pct": row["row_count_delta_pct"],
                    "breaking_changes_count": len(breaking),
                },
                "status_indicator": indicator,
                "summary": summary,
            }
        finally:
            conn.close()

    def get_feature_drift_report(
        self, tenant_id: str, inp: GetFeatureDriftReportInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM feature_drift_reports WHERE tenant_id = ? AND feature_group = ?",
                (tenant_id, inp.feature_group),
            ).fetchone()
            if not row:
                return {
                    "target_id": inp.feature_group,
                    "found": False,
                    "simulated": True,
                    "connector": "MockFeatureObservabilityConnector",
                    "status_indicator": "MISSING",
                    "summary": f"No feature drift telemetry found for `{inp.feature_group}`.",
                    "metrics": {},
                }
            drifted = json.loads(row["drifted_features_json"])
            heartbeat_ok = bool(row["collector_heartbeat_ok"])
            psi = row["psi_score"]
            threshold = row["psi_threshold"]
            if not heartbeat_ok:
                indicator = "CONFLICT"
            elif psi > threshold:
                indicator = "CRITICAL"
            else:
                indicator = "NORMAL"

            summary = (
                f"Feature drift report for `{inp.feature_group}`: PSI={psi:.2f} (threshold={threshold:.2f}), "
                f"KS={row['ks_statistic']:.2f}, collector_heartbeat_ok={heartbeat_ok}, "
                f"drifted_features={len(drifted)}."
            )
            return {
                "target_id": inp.feature_group,
                "found": True,
                "simulated": True,
                "connector": "MockFeatureObservabilityConnector",
                "status": row["status"],
                "psi_score": psi,
                "psi_threshold": threshold,
                "ks_statistic": row["ks_statistic"],
                "drifted_features": drifted,
                "collector_heartbeat_ok": heartbeat_ok,
                "metrics": {
                    "psi_score": psi,
                    "psi_threshold": threshold,
                    "ks_statistic": row["ks_statistic"],
                    "collector_heartbeat_ok": heartbeat_ok,
                },
                "status_indicator": indicator,
                "summary": summary,
            }
        finally:
            conn.close()

    def get_model_metrics(
        self, tenant_id: str, inp: GetModelMetricsInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM model_metrics_reports WHERE tenant_id = ? AND model_id = ?",
                (tenant_id, inp.model_id),
            ).fetchone()
            if not row:
                return {
                    "target_id": inp.model_id,
                    "found": False,
                    "simulated": True,
                    "connector": "MockModelEvaluationConnector",
                    "status_indicator": "MISSING",
                    "summary": f"No model evaluation report found for `{inp.model_id}`.",
                    "metrics": {},
                }
            complete = bool(row["telemetry_complete"])
            if not complete:
                return {
                    "target_id": inp.model_id,
                    "found": True,
                    "simulated": True,
                    "connector": "MockModelEvaluationConnector",
                    "telemetry_complete": False,
                    "status": row["status"],
                    "missing_reason": row["missing_reason"],
                    "metrics": {"telemetry_complete": False},
                    "status_indicator": "MISSING",
                    "summary": (
                        f"Model evaluation telemetry for `{inp.model_id}` is INCOMPLETE: "
                        f"{row['missing_reason']}"
                    ),
                }

            prec = row["precision_at_top5pct"]
            base_prec = row["baseline_precision_at_top5pct"]
            fpr = row["false_positive_rate"]
            base_fpr = row["baseline_fpr"]
            indicator = "CRITICAL" if prec < (base_prec - 0.10) else "NORMAL"
            summary = (
                f"Model `{inp.model_id}` ({row['model_version']}): precision@top5%={prec:.2f} "
                f"(baseline={base_prec:.2f}), FPR={fpr:.3f} (baseline={base_fpr:.3f}), "
                f"active_threshold={row['decision_threshold']} (baseline={row['baseline_threshold']}), "
                f"last_config_change={row['last_config_change_id']}."
            )
            return {
                "target_id": inp.model_id,
                "found": True,
                "simulated": True,
                "connector": "MockModelEvaluationConnector",
                "telemetry_complete": True,
                "status": row["status"],
                "precision_at_top5pct": prec,
                "baseline_precision_at_top5pct": base_prec,
                "false_positive_rate": fpr,
                "baseline_fpr": base_fpr,
                "decision_threshold": row["decision_threshold"],
                "baseline_threshold": row["baseline_threshold"],
                "last_config_change_id": row["last_config_change_id"],
                "metrics": {
                    "precision_at_top5pct": prec,
                    "baseline_precision": base_prec,
                    "false_positive_rate": fpr,
                    "decision_threshold": row["decision_threshold"],
                    "baseline_threshold": row["baseline_threshold"],
                },
                "status_indicator": indicator,
                "summary": summary,
            }
        finally:
            conn.close()

    def get_service_health(
        self, tenant_id: str, inp: GetServiceHealthInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM service_health_reports WHERE tenant_id = ? AND service_id = ?",
                (tenant_id, inp.service_id),
            ).fetchone()
            if not row:
                return {
                    "target_id": inp.service_id,
                    "found": False,
                    "simulated": True,
                    "connector": "MockServiceHealthConnector",
                    "status_indicator": "MISSING",
                    "summary": f"No service health telemetry found for `{inp.service_id}`.",
                    "metrics": {},
                }
            p99 = row["p99_latency_ms"]
            slo = row["slo_p99_latency_ms"]
            err = row["error_rate_5xx_pct"]
            sat = row["redis_pool_saturation"]
            indicator = "CRITICAL" if p99 > slo or err > 1.0 else "NORMAL"
            summary = (
                f"Service `{inp.service_id}` status={row['status']}: p99={p99:.1f}ms (SLO={slo:.1f}ms), "
                f"5xx_error_rate={err:.1f}%, replicas={row['active_replicas']}/{row['max_replicas']}, "
                f"redis_pool_saturation={sat*100:.0f}% ({row['cache_evictions_per_min']} evictions/min)."
            )
            return {
                "target_id": inp.service_id,
                "found": True,
                "simulated": True,
                "connector": "MockServiceHealthConnector",
                "status": row["status"],
                "p99_latency_ms": p99,
                "slo_p99_latency_ms": slo,
                "error_rate_5xx_pct": err,
                "active_replicas": row["active_replicas"],
                "max_replicas": row["max_replicas"],
                "redis_pool_saturation": sat,
                "cache_evictions_per_min": row["cache_evictions_per_min"],
                "metrics": {
                    "p99_latency_ms": p99,
                    "slo_p99_latency_ms": slo,
                    "error_rate_5xx_pct": err,
                    "redis_pool_saturation": sat,
                    "active_replicas": row["active_replicas"],
                },
                "status_indicator": indicator,
                "summary": summary,
            }
        finally:
            conn.close()

    def search_incident_history(
        self, tenant_id: str, inp: SearchIncidentHistoryInput
    ) -> Dict[str, Any]:
        conn = get_connection(self.db_path)
        try:
            if inp.component_id:
                rows = conn.execute(
                    "SELECT * FROM historical_incidents WHERE category = ? OR component_id = ? ORDER BY occurred_at DESC LIMIT 5",
                    (inp.category, inp.component_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM historical_incidents WHERE category = ? ORDER BY occurred_at DESC LIMIT 5",
                    (inp.category,),
                ).fetchall()

            matches = [
                {
                    "history_id": r["history_id"],
                    "category": r["category"],
                    "component_id": r["component_id"],
                    "root_cause_code": r["root_cause_code"],
                    "title": r["title"],
                    "resolution_summary": r["resolution_summary"],
                    "occurred_at": r["occurred_at"],
                }
                for r in rows
            ]
            target = inp.component_id or inp.category
            summary = (
                f"Historical pattern lookup for category=`{inp.category}`, component=`{inp.component_id}` "
                f"returned {len(matches)} prior incident(s): "
                + (
                    ", ".join(f"{m['history_id']} ({m['root_cause_code']})" for m in matches)
                    if matches
                    else "none"
                )
            )
            return {
                "target_id": target,
                "simulated": True,
                "connector": "MockIncidentHistoryConnector",
                "matches": matches,
                "metrics": {"matched_incidents": len(matches)},
                "status_indicator": "NORMAL",
                "summary": summary,
            }
        finally:
            conn.close()

    def apply_approved_remediation(
        self,
        conn: Any,
        *,
        tenant_id: str = DEFAULT_TENANT_ID,
        action_type: str,
        target_component: str,
        now: Optional[str] = None,
    ) -> str:
        now_ts = now or utc_now_iso()

        if action_type == "RERUN_DAGSTER_ASSET_WITH_SCHEMA_ADAPTER":
            conn.execute(
                """UPDATE data_quality_reports
                   SET schema_valid = 1, breaking_changes_json = '[]', row_count_delta_pct = 1.2,
                       status = 'HEALTHY_WITH_COMPAT_ADAPTER', checked_at = ?
                   WHERE tenant_id = ? AND asset_key = ?""",
                (now_ts, tenant_id, target_component),
            )
            conn.execute(
                """UPDATE pipeline_runs
                   SET status = 'SUCCESS', error_code = NULL,
                       error_message = 'Remediated via schema v3.4 compatibility adapter.'
                   WHERE tenant_id = ? AND asset_key = ?""",
                (tenant_id, target_component),
            )
            conn.execute(
                """UPDATE components
                   SET status = 'HEALTHY', current_lag_minutes = 4, updated_at = ?
                   WHERE tenant_id = ? AND component_id IN (?, 'src_transactions_stream')""",
                (now_ts, tenant_id, target_component),
            )
            return (
                "Applied schema v3.4 alias mapping (`merchant_category_code -> merchant_mcc_code`), "
                "reran Dagster asset `stg_transactions_cleaned` (status=SUCCESS), and verified 0 contract violations."
            )

        if action_type == "BACKFILL_MISSING_PARTITION":
            conn.execute(
                """UPDATE partition_telemetry
                   SET materialized_partitions_48h = 48, missing_partitions_json = '[]',
                       stale_lag_minutes = 8, status = 'HEALTHY', last_materialized_at = ?
                   WHERE tenant_id = ? AND asset_key = ?""",
                (now_ts, tenant_id, target_component),
            )
            conn.execute(
                """UPDATE components
                   SET status = 'HEALTHY', current_lag_minutes = 8, updated_at = ?
                   WHERE tenant_id = ? AND component_id = ?""",
                (now_ts, tenant_id, target_component),
            )
            return (
                "Backfilled missing hourly partitions `2026-11-01-13:00..15:00` on `feat_user_velocity_24h`; "
                "48/48 partitions materialized and freshness lag reduced from 215m to 8m (within 30m SLA)."
            )

        if action_type == "PIN_FEATURE_BASELINE_AND_SHADOW_RECALIBRATE":
            conn.execute(
                """UPDATE feature_drift_reports
                   SET psi_score = 0.11, ks_statistic = 0.09, drifted_features_json = '[]',
                       status = 'RECALIBRATED_WITHIN_THRESHOLD', computed_at = ?
                   WHERE tenant_id = ? AND feature_group = ?""",
                (now_ts, tenant_id, target_component),
            )
            conn.execute(
                """UPDATE components
                   SET status = 'HEALTHY', current_lag_minutes = 10, updated_at = ?
                   WHERE tenant_id = ? AND component_id = ?""",
                (now_ts, tenant_id, target_component),
            )
            return (
                "Pinned segmented regional merchant prior for newly onboarded cross-border cohort and triggered "
                "shadow recalibration; post-remediation PSI dropped from 0.44 to 0.11 (< 0.20 threshold)."
            )

        if action_type == "ROLLBACK_MODEL_THRESHOLD_CONFIG":
            conn.execute(
                """UPDATE model_metrics_reports
                   SET decision_threshold = baseline_threshold, precision_at_top5pct = 0.91,
                       false_positive_rate = 0.027, status = 'HEALTHY_RESTORED', evaluated_at = ?
                   WHERE tenant_id = ? AND model_id = ?""",
                (now_ts, tenant_id, target_component),
            )
            conn.execute(
                """UPDATE components
                   SET status = 'HEALTHY', updated_at = ?
                   WHERE tenant_id = ? AND component_id = ?""",
                (now_ts, tenant_id, target_component),
            )
            return (
                "Rolled back `cfg_882_threshold_override` on `mdl_xgboost_fraud_v4` (threshold 0.42 -> 0.78); "
                "simulated evaluation shows precision@top5% restored to 0.91 and FPR reduced to 2.7%."
            )

        if action_type == "SCALE_INFERENCE_REPLICAS_AND_FLUSH_CACHE":
            conn.execute(
                """UPDATE service_health_reports
                   SET status = 'HEALTHY_WITHIN_SLO', p99_latency_ms = 54.0, error_rate_5xx_pct = 0.05,
                       active_replicas = 8, redis_pool_saturation = 0.42, cache_evictions_per_min = 0,
                       checked_at = ?
                   WHERE tenant_id = ? AND service_id = ?""",
                (now_ts, tenant_id, target_component),
            )
            conn.execute(
                """UPDATE components
                   SET status = 'HEALTHY', updated_at = ?
                   WHERE tenant_id = ? AND component_id = ?""",
                (now_ts, tenant_id, target_component),
            )
            return (
                "Scaled `svc_realtime_fraud_scorer` replicas from 4 to 8 and expanded Redis connection pool; "
                "simulated p99 latency dropped from 485ms to 54ms (SLO <= 120ms) and 5xx rate fell to 0.05%."
            )

        if action_type == "RERUN_FAILED_DAGSTER_JOB":
            conn.execute(
                """UPDATE pipeline_runs
                   SET status = 'SUCCESS', error_code = NULL,
                       error_message = 'Completed 90-day backfill using 7-day chunked sort-merge join (peak memory 14.2 GiB).'
                   WHERE tenant_id = ? AND asset_key = ?""",
                (tenant_id, target_component),
            )
            conn.execute(
                """UPDATE partition_telemetry
                   SET materialized_partitions_48h = total_partitions_48h, missing_partitions_json = '[]',
                       stale_lag_minutes = 25, status = 'HEALTHY', last_materialized_at = ?
                   WHERE tenant_id = ? AND asset_key = ?""",
                (now_ts, tenant_id, target_component),
            )
            conn.execute(
                """UPDATE components
                   SET status = 'HEALTHY', current_lag_minutes = 25, updated_at = ?
                   WHERE tenant_id = ? AND component_id = ?""",
                (now_ts, tenant_id, target_component),
            )
            return (
                "Reran `ds_training_cohort` backfill with 7-day partition chunking enabled; "
                "peak worker memory stayed at 14.2 GiB / 32.0 GiB and all partitions materialized cleanly."
            )

        return f"Simulated action `{action_type}` applied to `{target_component}`."


def get_connector_catalog() -> List[Dict[str, Any]]:
    """Documents the simulated adapters and what real production adapters would require."""
    return [
        {
            "adapter_name": "MockDagsterRunConnector",
            "protocol": "DagsterRunConnector",
            "tools": ["get_run_details", "get_partition_status"],
            "simulated": True,
            "data_source": "SQLite tables `pipeline_runs`, `partition_telemetry` (tenant-partitioned)",
            "real_adapter_requirements": "Read-only Dagster Plus / OSS GraphQL client authenticated via workload identity; queries `runOrError` and `assetNodeOrError.partitionStats`.",
        },
        {
            "adapter_name": "MockLineageCatalogConnector",
            "protocol": "LineageCatalogConnector",
            "tools": ["get_asset_lineage"],
            "simulated": True,
            "data_source": "SQLite table `components` (tenant-partitioned)",
            "real_adapter_requirements": "Read-only OpenLineage / DataHub / Dagster asset graph client.",
        },
        {
            "adapter_name": "MockDataQualityConnector",
            "protocol": "DataQualityConnector",
            "tools": ["get_data_quality_report"],
            "simulated": True,
            "data_source": "SQLite table `data_quality_reports` (tenant-partitioned)",
            "real_adapter_requirements": "Read-only Confluent Schema Registry + Great Expectations / Soda check results reader.",
        },
        {
            "adapter_name": "MockFeatureObservabilityConnector",
            "protocol": "FeatureObservabilityConnector",
            "tools": ["get_feature_drift_report"],
            "simulated": True,
            "data_source": "SQLite table `feature_drift_reports` (tenant-partitioned)",
            "real_adapter_requirements": "Read-only Feast / Tecton observability API + Arize/Evidently drift metrics reader.",
        },
        {
            "adapter_name": "MockModelEvaluationConnector",
            "protocol": "ModelEvaluationConnector",
            "tools": ["get_model_metrics"],
            "simulated": True,
            "data_source": "SQLite table `model_metrics_reports` (tenant-partitioned)",
            "real_adapter_requirements": "Read-only MLflow / Vertex Model Registry + offline evaluation parquet reader.",
        },
        {
            "adapter_name": "MockServiceHealthConnector",
            "protocol": "ServiceHealthConnector",
            "tools": ["get_service_health"],
            "simulated": True,
            "data_source": "SQLite table `service_health_reports` (tenant-partitioned)",
            "real_adapter_requirements": "Read-only Prometheus / Thanos HTTP query client for latency histograms, 5xx rates, and Redis exporter metrics.",
        },
        {
            "adapter_name": "MockRemediationExecutorConnector",
            "protocol": "RemediationExecutorConnector",
            "tools": ["simulate_approved_rerun"],
            "simulated": True,
            "data_source": "Scoped SQLite state transitions gated on server-side `approval_token`",
            "real_adapter_requirements": "Human-approved GitOps PR dispatcher or Dagster `launchPipelineExecution` mutation signed by an OIDC-verified operator token.",
        },
    ]
