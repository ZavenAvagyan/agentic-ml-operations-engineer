"use strict";

const state = {
  activeView: "overview",
  overview: null,
  incidents: [],
  selectedIncidentId: "INC-2026-101",
  selectedIncidentDetail: null,
  systemMap: null,
  selectedMapNodeId: null,
  evaluation: null,
  audit: null,
};

function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showToast(message) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.remove();
  }, 4200);
}

function severityBadge(sev) {
  const s = (sev || "").toUpperCase();
  if (s === "CRITICAL") return `<span class="badge badge-critical">[!] CRITICAL</span>`;
  if (s === "HIGH") return `<span class="badge badge-high">[▲] HIGH</span>`;
  if (s === "MEDIUM") return `<span class="badge badge-medium">[●] MEDIUM</span>`;
  return `<span class="badge badge-neutral">${esc(s)}</span>`;
}

function statusBadge(st) {
  const s = (st || "").toUpperCase();
  if (s.includes("FAIL") || s.includes("VIOLATION") || s.includes("BREACH") || s === "CRITICAL_DRIFT_DETECTED" || s === "SEVERE_PRECISION_REGRESSION") {
    return `<span class="badge badge-critical">[×] ${esc(s)}</span>`;
  }
  if (s === "AWAITING_APPROVAL" || s === "PENDING_APPROVAL" || s.includes("STALE") || s.includes("SKIP") || s === "DEGRADED") {
    return `<span class="badge badge-high">[⏳] ${esc(s)}</span>`;
  }
  if (s.includes("ABSTAIN") || s.includes("CONFLICT") || s.includes("INCOMPLETE")) {
    return `<span class="badge badge-abstain">[?] ${esc(s)}</span>`;
  }
  if (s === "REMEDIATED" || s === "RESOLVED" || s === "SUCCESS" || s.includes("HEALTHY") || s === "EXECUTED" || s === "APPROVED" || s === "WITHIN_BASELINE" || s === "PASSED_SCHEMA_CHECKS") {
    return `<span class="badge badge-ok">[✓] ${esc(s)}</span>`;
  }
  if (s === "OPEN") {
    return `<span class="badge badge-medium">[•] OPEN</span>`;
  }
  return `<span class="badge badge-neutral">${esc(s)}</span>`;
}

async function apiFetch(url, options = {}) {
  const resp = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!resp.ok) {
    let errText = resp.statusText;
    try {
      const data = await resp.json();
      errText = data.detail || JSON.stringify(data);
    } catch (_) {}
    throw new Error(errText);
  }
  return resp.json();
}

/* ==================== NAVIGATION ==================== */
function switchView(viewName) {
  state.activeView = viewName;
  document.querySelectorAll(".nav-tab").forEach((tab) => {
    const isTarget = tab.dataset.view === viewName;
    tab.classList.toggle("active", isTarget);
    tab.setAttribute("aria-selected", isTarget ? "true" : "false");
  });
  document.querySelectorAll(".view-panel").forEach((panel) => {
    const isTarget = panel.id === `view-${viewName}`;
    panel.classList.toggle("active", isTarget);
    if (isTarget) {
      panel.removeAttribute("hidden");
    } else {
      panel.setAttribute("hidden", "");
    }
  });

  if (viewName === "overview") loadOverview();
  if (viewName === "investigation") loadInvestigationView();
  if (viewName === "system-map") loadSystemMap(state.selectedIncidentId);
  if (viewName === "evaluation") loadEvaluation();
  if (viewName === "audit") loadAuditLogs();
}

/* ==================== VIEW 1: OVERVIEW ==================== */
async function loadOverview() {
  try {
    const data = await apiFetch("/api/overview");
    state.overview = data;

    const providerBadge = document.getElementById("provider-badge");
    if (providerBadge && data.runtime_info) {
      const p = data.runtime_info.active_provider.toUpperCase();
      providerBadge.textContent = `Provider: ${p} (Deterministic Sandbox)`;
    }

    const navBadge = document.getElementById("nav-incident-badge");
    if (navBadge && data.summary_counts) {
      navBadge.textContent = data.summary_counts.total_incidents;
    }

    renderOverviewKpis(data.summary_counts);
    renderOverviewIncidents(data.active_incidents || []);
    renderOverviewRuns(data.pipeline_runs || []);
    renderOverviewDataQuality(
      data.partition_telemetry || [],
      data.data_quality_reports || [],
      data.feature_drift_reports || []
    );
    renderOverviewModels(data.model_metrics || []);
    renderOverviewServices(data.service_health || []);
    populateIncidentDropdowns(data.active_incidents || []);
  } catch (err) {
    showToast(`Failed to load overview: ${err.message}`);
  }
}

function renderOverviewKpis(counts) {
  const el = document.getElementById("overview-kpis");
  if (!el || !counts) return;
  el.innerHTML = `
    <div class="kpi-card kpi-critical">
      <div class="kpi-label">Open Incidents</div>
      <div class="kpi-value">${counts.open_incidents} / ${counts.total_incidents}</div>
      <div class="kpi-sub">Simulated pipeline, drift &amp; model alerts</div>
    </div>
    <div class="kpi-card kpi-warning">
      <div class="kpi-label">Awaiting Human Approval</div>
      <div class="kpi-value">${counts.awaiting_approval}</div>
      <div class="kpi-sub">State-changing actions locked at Stage 6</div>
    </div>
    <div class="kpi-card kpi-abstain">
      <div class="kpi-label">Safe Abstentions</div>
      <div class="kpi-value">${counts.abstained_incidents}</div>
      <div class="kpi-sub">Halted due to missing/conflicting telemetry</div>
    </div>
    <div class="kpi-card kpi-ok">
      <div class="kpi-label">Remediated &amp; Healthy Nodes</div>
      <div class="kpi-value">${counts.remediated_incidents} | ${counts.healthy_components}/${counts.total_components}</div>
      <div class="kpi-sub">Remediated incidents | Healthy topology nodes</div>
    </div>
  `;
}

function renderOverviewIncidents(incidents) {
  const tbody = document.getElementById("overview-incidents-tbody");
  if (!tbody) return;
  tbody.innerHTML = incidents
    .map(
      (inc) => `
    <tr>
      <td class="mono"><strong>${esc(inc.incident_id)}</strong></td>
      <td>${severityBadge(inc.severity)}</td>
      <td>${statusBadge(inc.status)}</td>
      <td class="mono">${esc(inc.category)}</td>
      <td class="mono"><code>${esc(inc.affected_component)}</code></td>
      <td>
        <div><strong>${esc(inc.title)}</strong></div>
        <div class="muted-text">${esc(inc.symptom_summary)}</div>
      </td>
      <td>
        <button type="button" class="btn btn-primary btn-xs" data-open-incident="${esc(inc.incident_id)}">
          Investigate &rarr;
        </button>
      </td>
    </tr>
  `
    )
    .join("");

  tbody.querySelectorAll("[data-open-incident]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.selectedIncidentId = btn.dataset.openIncident;
      switchView("investigation");
    });
  });
}

function renderOverviewRuns(runs) {
  const tbody = document.getElementById("overview-runs-tbody");
  if (!tbody) return;
  tbody.innerHTML = runs
    .map(
      (r) => `
    <tr>
      <td class="mono">${esc(r.run_id)}</td>
      <td class="mono"><code>${esc(r.asset_key)}</code></td>
      <td>${statusBadge(r.status)}</td>
      <td class="mono">${Number(r.duration_seconds).toFixed(1)}s</td>
      <td>
        ${r.error_code ? `<div class="mono"><strong>${esc(r.error_code)}</strong></div>` : ""}
        <div class="muted-text">${esc(r.error_message || "Materialization healthy")}</div>
      </td>
    </tr>
  `
    )
    .join("");
}

function renderOverviewDataQuality(partitions, dqReports, driftReports) {
  const tbody = document.getElementById("overview-dq-tbody");
  if (!tbody) return;
  const rows = [];

  dqReports.forEach((d) => {
    rows.push(`
      <tr>
        <td class="mono"><code>${esc(d.asset_key)}</code></td>
        <td>Schema Contract</td>
        <td>${statusBadge(d.status)}</td>
        <td>Observed: <code>${esc(d.schema_version)}</code> (Expected: <code>${esc(d.expected_schema_version)}</code>)</td>
      </tr>
    `);
  });

  partitions.forEach((p) => {
    rows.push(`
      <tr>
        <td class="mono"><code>${esc(p.asset_key)}</code></td>
        <td>Freshness &amp; Partitions</td>
        <td>${statusBadge(p.status)}</td>
        <td>Lag: <strong>${p.stale_lag_minutes}m</strong> (SLA: ${p.sla_minutes}m) | Missing: ${p.missing_partitions.length}</td>
      </tr>
    `);
  });

  driftReports.forEach((dr) => {
    rows.push(`
      <tr>
        <td class="mono"><code>${esc(dr.feature_group)}</code></td>
        <td>Feature Drift (PSI)</td>
        <td>${statusBadge(dr.status)}</td>
        <td>PSI: <strong>${Number(dr.psi_score).toFixed(2)}</strong> (Threshold: ${Number(dr.psi_threshold).toFixed(2)}) | Heartbeat: ${dr.collector_heartbeat_ok ? "OK" : "STALE"}</td>
      </tr>
    `);
  });

  tbody.innerHTML = rows.join("");
}

function renderOverviewModels(models) {
  const container = document.getElementById("overview-models-list");
  if (!container) return;
  container.innerHTML = models
    .map(
      (m) => `
    <div class="metric-item">
      <div class="metric-item-top">
        <div>
          <strong class="mono">${esc(m.model_id)}</strong>
          <span class="muted-text">(${esc(m.model_version)})</span>
        </div>
        ${statusBadge(m.status)}
      </div>
      ${
        m.telemetry_complete
          ? `
        <div class="metric-grid-row">
          <div><span class="muted-text">Precision@Top5%:</span> <strong>${Number(m.precision_at_top5pct).toFixed(2)}</strong> (Base: ${Number(m.baseline_precision_at_top5pct).toFixed(2)})</div>
          <div><span class="muted-text">False Positive Rate:</span> <strong>${(Number(m.false_positive_rate) * 100).toFixed(1)}%</strong> (Base: ${(Number(m.baseline_fpr) * 100).toFixed(1)}%)</div>
          <div><span class="muted-text">Decision Threshold:</span> <strong>${m.decision_threshold}</strong> (Base: ${m.baseline_threshold})</div>
          <div><span class="muted-text">Last Config:</span> <code>${esc(m.last_config_change_id || "none")}</code></div>
        </div>
      `
          : `<div class="muted-text"><strong>Telemetry Incomplete:</strong> ${esc(m.missing_reason)}</div>`
      }
    </div>
  `
    )
    .join("");
}

function renderOverviewServices(services) {
  const container = document.getElementById("overview-services-list");
  if (!container) return;
  container.innerHTML = services
    .map(
      (s) => `
    <div class="metric-item">
      <div class="metric-item-top">
        <strong class="mono">${esc(s.service_id)}</strong>
        ${statusBadge(s.status)}
      </div>
      <div class="metric-grid-row">
        <div><span class="muted-text">p99 Latency:</span> <strong>${s.p99_latency_ms}ms</strong> (SLO: &le;${s.slo_p99_latency_ms}ms)</div>
        <div><span class="muted-text">HTTP 5xx Rate:</span> <strong>${s.error_rate_5xx_pct}%</strong></div>
        <div><span class="muted-text">Active Replicas:</span> <strong>${s.Active_replicas} / ${s.max_replicas}</strong></div>
        <div><span class="muted-text">Redis Pool Saturation:</span> <strong>${(s.redis_pool_saturation * 100).toFixed(0)}%</strong> (${s.cache_evictions_per_min} evictions/m)</div>
      </div>
    </div>
  `
    )
    .join("");
}

function populateIncidentDropdowns(incidents) {
  const mapSelect = document.getElementById("map-incident-select");
  const auditSelect = document.getElementById("audit-incident-filter");

  if (mapSelect && mapSelect.options.length <= 1) {
    mapSelect.innerHTML =
      `<option value="">None (Show Base Topology)</option>` +
      incidents
        .map(
          (i) =>
            `<option value="${esc(i.incident_id)}" ${
              i.incident_id === state.selectedIncidentId ? "selected" : ""
            }>${esc(i.incident_id)} — ${esc(i.affected_component)} (${esc(i.severity)})</option>`
        )
        .join("");
  }

  if (auditSelect && auditSelect.options.length <= 1) {
    auditSelect.innerHTML =
      `<option value="ALL">All Incidents</option>` +
      incidents
        .map((i) => `<option value="${esc(i.incident_id)}">${esc(i.incident_id)} (${esc(i.affected_component)})</option>`)
        .join("");
  }
}

/* ==================== VIEW 2: INCIDENT INVESTIGATION ==================== */
async function loadInvestigationView() {
  const sev = document.getElementById("filter-severity")?.value || "ALL";
  const st = document.getElementById("filter-status")?.value || "ALL";
  try {
    const data = await apiFetch(
      `/api/incidents?severity=${encodeURIComponent(sev)}&status=${encodeURIComponent(st)}`
    );
    state.incidents = data.incidents || [];
    renderIncidentQueue();
    if (state.selectedIncidentId) {
      await loadIncidentDetail(state.selectedIncidentId);
    } else if (state.incidents.length > 0) {
      state.selectedIncidentId = state.incidents[0].incident_id;
      await loadIncidentDetail(state.selectedIncidentId);
    }
  } catch (err) {
    showToast(`Error loading incidents: ${err.message}`);
  }
}

function renderIncidentQueue() {
  const listEl = document.getElementById("incident-queue-list");
  if (!listEl) return;
  if (state.incidents.length === 0) {
    listEl.innerHTML = `<div class="detail-box muted-text">No incidents match the selected filters.</div>`;
    return;
  }

  listEl.innerHTML = state.incidents
    .map(
      (inc) => `
    <button type="button" class="queue-item ${
      inc.incident_id === state.selectedIncidentId ? "selected" : ""
    }" data-select-inc="${esc(inc.incident_id)}">
      <div class="queue-item-top">
        <span class="mono"><strong>${esc(inc.incident_id)}</strong></span>
        ${severityBadge(inc.severity)}
      </div>
      <div class="queue-item-title">${esc(inc.title)}</div>
      <div class="queue-item-top" style="margin-top:6px;margin-bottom:0;">
        <span class="queue-item-meta">${esc(inc.affected_component)}</span>
        ${statusBadge(inc.status)}
      </div>
    </button>
  `
    )
    .join("");

  listEl.querySelectorAll("[data-select-inc]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.selectedIncidentId = btn.dataset.selectInc;
      renderIncidentQueue();
      loadIncidentDetail(state.selectedIncidentId);
    });
  });
}

async function loadIncidentDetail(incidentId) {
  const container = document.getElementById("incident-detail-container");
  if (!container) return;
  try {
    const detail = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}`);
    state.selectedIncidentDetail = detail;
    renderIncidentDetailPane(detail);
  } catch (err) {
    container.innerHTML = `<div class="empty-state">Failed to load incident ${esc(incidentId)}: ${esc(err.message)}</div>`;
  }
}

function renderIncidentDetailPane(detail) {
  const container = document.getElementById("incident-detail-container");
  if (!container) return;
  const inc = detail.incident;
  const inv = detail.latest_investigation;

  const timelineHtml = (inc.timeline || [])
    .map((t) => `<li><span class="mono muted-text">${esc(t.time)}</span> — ${esc(t.event)}</li>`)
    .join("");

  let workflowHtml = "";
  if (!inv) {
    workflowHtml = `
      <div class="card">
        <div class="detail-box">
          <h3>Ready for Controlled 8-Stage Agentic Investigation</h3>
          <p class="muted-text">
            Clicking <strong>Start Agent Investigation</strong> runs the deterministic state-machine orchestrator:
            1) Validate &amp; classify untrusted input, 2) Gather read-only telemetry via narrow tools,
            3) Compare historical patterns, 4) Form an evidence-grounded diagnosis (or abstain if evidence conflicts/is missing),
            and 5) Propose a bounded remediation plan locked behind Stage 6 Human Approval.
          </p>
        </div>
      </div>
    `;
  } else {
    workflowHtml = renderInvestigationResults(inv);
  }

  container.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;">
            <span class="mono"><strong>${esc(inc.incident_id)}</strong></span>
            ${severityBadge(inc.severity)}
            ${statusBadge(inc.status)}
            <span class="badge badge-neutral">${esc(inc.category)}</span>
          </div>
          <h3>${esc(inc.title)}</h3>
        </div>
        <div class="header-controls">
          <button type="button" class="btn btn-secondary btn-xs" id="btn-view-on-map">
            View on System Map
          </button>
          <button type="button" class="btn btn-primary" id="btn-run-investigation">
            ${inv ? "Re-Run Investigation Workflow" : "Start Agent Investigation"}
          </button>
        </div>
      </div>

      <div class="detail-box">
        <div class="grid-two-col">
          <div>
            <div><strong>Affected Component:</strong> <code>${esc(inc.affected_component)}</code></div>
            <div><strong>Pipeline / Service:</strong> <code>${esc(inc.affected_pipeline)}</code></div>
            <div style="margin-top:8px;"><strong>Symptom Summary:</strong> ${esc(inc.symptom_summary)}</div>
            <div style="margin-top:8px;">
              <strong>Raw Alert Payload (Treated as Untrusted Data):</strong>
              <div class="code-drawer">${esc(inc.untrusted_incident_payload)}</div>
            </div>
          </div>
          <div>
            <strong>Incident Detection Timeline</strong>
            <ul class="timeline-list">${timelineHtml}</ul>
          </div>
        </div>
      </div>
    </div>

    ${workflowHtml}
  `;

  document.getElementById("btn-run-investigation")?.addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = "Running 8-Stage State Machine...";
    try {
      await apiFetch(`/api/incidents/${encodeURIComponent(inc.incident_id)}/investigate`, {
        method: "POST",
      });
      showToast(`Completed investigation workflow for ${inc.incident_id}`);
      await loadInvestigationView();
    } catch (err) {
      showToast(`Investigation error: ${err.message}`);
      btn.disabled = false;
      btn.textContent = "Start Agent Investigation";
    }
  });

  document.getElementById("btn-view-on-map")?.addEventListener("click", () => {
    const mapSelect = document.getElementById("map-incident-select");
    if (mapSelect) mapSelect.value = inc.incident_id;
    switchView("system-map");
  });

  bindApprovalEvents(inv);
}

function renderInvestigationResults(inv) {
  const diag = inv.diagnosis;
  const prop = inv.proposed_action;
  const isAbstained = diag && diag.status !== "DIAGNOSED";

  // 1. Stage Stepper
  const stagesHtml = (inv.stages || [])
    .map(
      (s) => `
    <div class="stage-card stage-${esc(s.status)}">
      <div class="stage-title">
        <span>${esc(s.label)}</span>
        <span class="mono muted-text">${Number(s.duration_ms).toFixed(1)}ms</span>
      </div>
      <div style="margin-top:4px;">${statusBadge(s.status)}</div>
      <div class="stage-desc">${esc(s.summary)}</div>
    </div>
  `
    )
    .join("");

  // 2. Security / Prompt-Injection Notice
  const securityHtml =
    diag && diag.prompt_injection_detected
      ? `
    <div class="security-alert-box" role="alert">
      <strong>[SECURITY GUARDRAIL TRIGGERED — UNTRUSTED INPUT QUARANTINED]</strong><br/>
      ${(diag.security_notes || []).map((n) => esc(n)).join("<br/>")}
    </div>
  `
      : "";

  // 3. Conflicts & Missing Telemetry (if any)
  const conflictsHtml =
    diag && (diag.conflicts_detected?.length || diag.missing_telemetry?.length)
      ? `
    <div class="security-alert-box" style="background:#f5f3ff;border-color:#a78bfa;color:#4c1d95;">
      <strong>[TELEMETRY CONFLICT / MISSING EVIDENCE DETECTED — AGENT ABSTAINED]</strong>
      <ul>
        ${(diag.conflicts_detected || []).map((c) => `<li><strong>Conflict:</strong> ${esc(c)}</li>`).join("")}
        ${(diag.missing_telemetry || []).map((m) => `<li><strong>Missing Telemetry:</strong> ${esc(m)}</li>`).join("")}
      </ul>
    </div>
  `
      : "";

  // 4. Observed Facts (Evidence)
  const factsHtml = (diag?.observed_facts || [])
    .map(
      (ev) => `
    <tr>
      <td class="mono"><strong>${esc(ev.evidence_id)}</strong></td>
      <td class="mono"><code>${esc(ev.tool_name)}</code></td>
      <td class="mono">${esc(ev.target_id)}</td>
      <td>${statusBadge(ev.status_indicator)}</td>
      <td>${esc(ev.observed_fact)}</td>
    </tr>
  `
    )
    .join("");

  // 5. Hypotheses
  const hypothesesHtml = (diag?.hypotheses || [])
    .map(
      (h) => `
    <div class="metric-item">
      <div class="metric-item-top">
        <strong>${esc(h.hypothesis_id)}: ${esc(h.statement)}</strong>
        <span class="badge ${h.likelihood === "HIGH" ? "badge-ok" : "badge-neutral"}">Likelihood: ${esc(h.likelihood)}</span>
      </div>
      <div class="muted-text mono">
        Supporting Evidence IDs: ${(h.supporting_evidence_ids || []).join(", ") || "none"}
        ${h.contradicting_evidence_ids?.length ? ` | Contradicting IDs: ${h.contradicting_evidence_ids.join(", ")}` : ""}
      </div>
    </div>
  `
    )
    .join("");

  // 6. Remediation Proposal & Human Approval Gate
  let remediationHtml = "";
  if (isAbstained || !prop) {
    remediationHtml = `
      <div class="card">
        <div class="card-header">
          <h3>Remediation Plan &amp; Human Approval Gate</h3>
          <span class="badge badge-abstain">NO STATE CHANGE PROPOSED (SAFE ABSTENTION)</span>
        </div>
        <div class="detail-box">
          <p>Because confidence is low (${((diag?.confidence || 0) * 100).toFixed(0)}%) and telemetry is incomplete or conflicting, the orchestrator abstained from proposing any automated or simulated state change. Recommended operator next step: restore the shadow evaluation parquet sink and drift collector heartbeat before re-running investigation.</p>
        </div>
      </div>
    `;
  } else {
    const isPending = prop.status === "PENDING_APPROVAL";
    remediationHtml = `
      <div class="card approval-gate-card ${prop.status === "EXECUTED" ? "approved" : ""}">
        <div class="card-header">
          <div>
            <h3>Proposed Remediation Action (Requires Explicit Human Approval)</h3>
            <span class="card-subtitle">Action ID: <code>${esc(prop.action_id)}</code> | Target: <code>${esc(prop.target_component)}</code></span>
          </div>
          ${statusBadge(prop.status)}
        </div>
        <div class="detail-box">
          <div class="grid-two-col">
            <div>
              <div><strong>Action Title:</strong> ${esc(prop.title)}</div>
              <div style="margin-top:6px;"><strong>Bounded Action Type:</strong> <code>${esc(prop.action_type)}</code></div>
              <div style="margin-top:6px;"><strong>Engineering Rationale:</strong> ${esc(prop.rationale)}</div>
              <div style="margin-top:6px;"><strong>Expected Impact:</strong> ${esc(prop.expected_impact)}</div>
            </div>
            <div>
              <div><strong>Risk Level:</strong> ${severityBadge(prop.risk_level)} | <strong>Reversible:</strong> ${prop.reversible ? "Yes" : "No"}</div>
              <div style="margin-top:6px;"><strong>Blast Radius:</strong> ${esc(prop.blast_radius)}</div>
              <div style="margin-top:6px;"><strong>Typed Parameters:</strong></div>
              <div class="code-drawer">${esc(JSON.stringify(prop.parameters, null, 2))}</div>
            </div>
          </div>

          ${
            isPending
              ? `
            <div class="approval-controls-form">
              <div class="grid-two-col">
                <div>
                  <label for="input-operator-id" class="control-label">Approving Operator ID</label>
                  <input id="input-operator-id" type="text" class="text-input" style="width:100%;margin-top:4px;" value="staff-ml-engineer@sandbox.local" />
                </div>
                <div>
                  <label for="input-decision-note" class="control-label">Audit Decision Note (Required)</label>
                  <input id="input-decision-note" type="text" class="text-input" style="width:100%;margin-top:4px;" value="Verified evidence IDs and blast radius; approving simulated remediation." />
                </div>
              </div>
              <div class="approval-btn-row">
                <button type="button" class="btn btn-approve" id="btn-approve-action" data-action-id="${esc(prop.action_id)}">
                  ✓ Approve &amp; Execute Simulated Action
                </button>
                <button type="button" class="btn btn-reject" id="btn-reject-action" data-action-id="${esc(prop.action_id)}">
                  × Reject Proposal
                </button>
                <button type="button" class="btn btn-secondary" id="btn-test-unapproved-block" data-action-id="${esc(prop.action_id)}" title="Verify backend blocks unapproved state-changing calls">
                  🛡 Test Unapproved Execution Block (Safety Proof)
                </button>
              </div>
            </div>
          `
              : `
            <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border-subtle);">
              <div><strong>Decision Recorded By:</strong> <code>${esc(prop.approved_by || "N/A")}</code> at <span class="mono">${esc(prop.decided_at || "")}</span></div>
              <div><strong>Operator Audit Note:</strong> ${esc(prop.decision_note || "")}</div>
              ${
                prop.verification_summary
                  ? `<div style="margin-top:8px;padding:10px;background:var(--status-ok-bg);border:1px solid var(--status-ok-border);border-radius:4px;">
                      <strong>Stage 8 Post-Remediation Verification:</strong> ${esc(prop.verification_summary)}
                    </div>`
                  : ""
              }
            </div>
          `
          }
        </div>
      </div>
    `;
  }

  // 7. Tool Call Trace Table
  const tracesHtml = (inv.tool_traces || [])
    .map(
      (t) => `
    <tr>
      <td class="mono">${esc(t.call_id)}</td>
      <td class="mono">${esc(t.stage)}</td>
      <td class="mono"><code>${esc(t.tool_name)}</code></td>
      <td>${statusBadge(t.status)}</td>
      <td class="mono">${esc(t.evidence_id || "—")}</td>
      <td class="mono">${Number(t.duration_ms).toFixed(2)}ms</td>
      <td>
        <div>${esc(t.output_summary)}</div>
        <div class="muted-text mono">Args: ${esc(JSON.stringify(t.arguments))}</div>
      </td>
    </tr>
  `
    )
    .join("");

  return `
    <!-- Workflow Progress -->
    <div class="card">
      <div class="card-header">
        <div>
          <h3>Controlled 8-Stage State Machine Progress</h3>
          <span class="card-subtitle">Investigation Run ID: <code>${esc(inv.investigation_id)}</code> | Provider: <code>${esc(inv.provider_used)}</code> | Total Elapsed: <strong>${Number(inv.total_duration_ms).toFixed(1)}ms</strong></span>
        </div>
        ${statusBadge(inv.status)}
      </div>
      <div class="stage-stepper">${stagesHtml}</div>
    </div>

    <!-- Diagnosis Card (Distinguishing Observed Facts, Hypotheses, Uncertainty, and Recommendations) -->
    <div class="card">
      <div class="diagnosis-banner ${isAbstained ? "abstained" : ""}">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
          <div>
            <span class="kpi-label">Final Diagnosis &amp; Root Cause Classification</span>
            <h3 style="margin:4px 0 0 0;font-size:16px;">
              <code>${esc(diag?.root_cause_code)}</code>
            </h3>
          </div>
          <div>
            <span class="badge ${isAbstained ? "badge-abstain" : "badge-ok"}">
              Confidence: ${((diag?.confidence || 0) * 100).toFixed(0)}%
            </span>
            ${statusBadge(diag?.status)}
          </div>
        </div>
        <p style="margin:10px 0 0 0;font-size:14px;"><strong>Diagnosis Summary:</strong> ${esc(diag?.root_cause_summary)}</p>
        <div style="margin-top:6px;" class="mono muted-text">
          Supporting Evidence References: ${(diag?.evidence_references || []).join(", ") || "none"}
        </div>
        ${securityHtml}
        ${conflictsHtml}
      </div>

      <div class="detail-box">
        <h4>1. Observed Facts (Verified Read-Only Tool Telemetry)</h4>
        <div class="table-responsive" style="margin-bottom:16px;">
          <table class="data-table">
            <thead>
              <tr>
                <th scope="col">Evidence ID</th>
                <th scope="col">Tool Name</th>
                <th scope="col">Target</th>
                <th scope="col">Signal</th>
                <th scope="col">Observed Fact</th>
              </tr>
            </thead>
            <tbody>${factsHtml}</tbody>
          </table>
        </div>

        <div class="grid-two-col">
          <div>
            <h4>2. Evaluated Hypotheses</h4>
            <div style="display:flex;flex-direction:column;gap:8px;">${hypothesesHtml}</div>
          </div>
          <div>
            <h4>3. Alternative Explanations &amp; Remaining Uncertainty</h4>
            <div class="metric-item">
              <strong>Alternative Explanations Considered:</strong>
              <ul>
                ${(diag?.alternative_explanations || []).map((a) => `<li>${esc(a)}</li>`).join("")}
              </ul>
              <strong>Uncertainty Notes:</strong>
              <ul>
                ${(diag?.uncertainty_notes || []).map((u) => `<li>${esc(u)}</li>`).join("")}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>

    ${remediationHtml}

    <!-- Tool Execution Trace -->
    <div class="card">
      <div class="card-header">
        <h3>Read-Only &amp; Governance Tool Execution Trace (${(inv.tool_traces || []).length} calls)</h3>
        <span class="card-subtitle">Every tool call is input-validated, timed, and recorded with its Evidence ID</span>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">Call ID</th>
              <th scope="col">Workflow Stage</th>
              <th scope="col">Tool</th>
              <th scope="col">Status</th>
              <th scope="col">Evidence ID</th>
              <th scope="col">Duration</th>
              <th scope="col">Summary &amp; Arguments</th>
            </tr>
          </thead>
          <tbody>${tracesHtml}</tbody>
        </table>
      </div>
    </div>
  `;
}

function bindApprovalEvents(inv) {
  if (!inv || !inv.proposed_action) return;
  const approveBtn = document.getElementById("btn-approve-action");
  const rejectBtn = document.getElementById("btn-reject-action");
  const testBlockBtn = document.getElementById("btn-test-unapproved-block");

  const submitDecision = async (decision) => {
    const actionId = inv.proposed_action.action_id;
    const operatorId =
      document.getElementById("input-operator-id")?.value.trim() ||
      "staff-ml-engineer@sandbox.local";
    const note =
      document.getElementById("input-decision-note")?.value.trim() ||
      `${decision} simulated action via operator console.`;

    try {
      await apiFetch(`/api/actions/${encodeURIComponent(actionId)}/decision`, {
        method: "POST",
        body: JSON.stringify({
          decision,
          operator_id: operatorId,
          decision_note: note,
        }),
      });
      showToast(
        decision === "APPROVE"
          ? `Approved & executed simulated action ${actionId}. Stage 8 verification complete.`
          : `Rejected proposed action ${actionId}.`
      );
      await loadInvestigationView();
    } catch (err) {
      showToast(`Decision error: ${err.message}`);
    }
  };

  approveBtn?.addEventListener("click", () => submitDecision("APPROVE"));
  rejectBtn?.addEventListener("click", () => submitDecision("REJECT"));

  testBlockBtn?.addEventListener("click", async () => {
    const actionId = inv.proposed_action.action_id;
    try {
      const res = await apiFetch(
        `/api/actions/${encodeURIComponent(actionId)}/verify-unapproved-block`,
        { method: "POST" }
      );
      showToast(`Backend Policy Verified: ${res.message}`);
      await loadIncidentDetail(inv.incident_id);
    } catch (err) {
      showToast(`Block test result: ${err.message}`);
    }
  });
}

/* ==================== VIEW 3: SYSTEM MAP ==================== */
async function loadSystemMap(incidentId = "") {
  try {
    const url = incidentId
      ? `/api/system-map?incident_id=${encodeURIComponent(incidentId)}`
      : `/api/system-map`;
    const data = await apiFetch(url);
    state.systemMap = data;
    renderSystemMapCanvas(data);
    const defaultNode =
      data.highlight?.primary_affected ||
      state.selectedMapNodeId ||
      (data.components[0] && data.components[0].component_id);
    if (defaultNode) {
      selectMapNode(defaultNode);
    }
  } catch (err) {
    showToast(`Failed to load system map: ${err.message}`);
  }
}

function renderSystemMapCanvas(data) {
  const canvas = document.getElementById("system-map-canvas");
  if (!canvas) return;

  const layers = [
    { key: "SOURCE", label: "1. Data Sources" },
    { key: "DAGSTER_ASSET", label: "2. Dagster Assets" },
    { key: "FEATURE_STORE", label: "3. Feature Store" },
    { key: "MODEL", label: "4. ML Models" },
    { key: "SERVICE", label: "5. Scoring Service" },
    { key: "MONITOR", label: "6. Observability" },
  ];

  const primary = data.highlight?.primary_affected;
  const upstreams = new Set(data.highlight?.upstream_contributing || []);
  const downstreams = new Set(data.highlight?.downstream_impacted || []);

  const colsHtml = layers
    .map((layer) => {
      const nodes = (data.components || []).filter((c) => c.layer === layer.key);
      const nodesHtml = nodes
        .map((n) => {
          let highlightClass = "";
          let roleTag = "";
          if (n.component_id === primary) {
            highlightClass = "highlight-primary";
            roleTag = `<div class="badge badge-critical" style="margin-bottom:4px;">[TARGET] PRIMARY AFFECTED</div>`;
          } else if (upstreams.has(n.component_id)) {
            highlightClass = "highlight-upstream";
            roleTag = `<div class="badge badge-high" style="margin-bottom:4px;">[UPSTREAM] CONTRIBUTING</div>`;
          } else if (downstreams.has(n.component_id)) {
            highlightClass = "highlight-downstream";
            roleTag = `<div class="badge badge-medium" style="margin-bottom:4px;">[DOWNSTREAM] BLAST RADIUS</div>`;
          }

          return `
            <button type="button" class="topo-node ${highlightClass} ${
              n.component_id === state.selectedMapNodeId ? "node-selected" : ""
            }" data-map-node="${esc(n.component_id)}">
              ${roleTag}
              <div class="topo-node-id">${esc(n.component_id)}</div>
              <div class="topo-node-name">${esc(n.name)}</div>
              <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;">
                ${statusBadge(n.status)}
                <span class="mono muted-text" style="font-size:11px;">Lag:${n.current_lag_minutes}m</span>
              </div>
            </button>
          `;
        })
        .join("");

      return `
        <div class="layer-col">
          <div class="layer-col-header">${esc(layer.label)}</div>
          ${nodesHtml}
        </div>
      `;
    })
    .join("");

  canvas.innerHTML = `<div class="layer-columns">${colsHtml}</div>`;

  canvas.querySelectorAll("[data-map-node]").forEach((btn) => {
    btn.addEventListener("click", () => {
      selectMapNode(btn.dataset.mapNode);
    });
  });
}

function selectMapNode(componentId) {
  state.selectedMapNodeId = componentId;
  document.querySelectorAll("[data-map-node]").forEach((btn) => {
    btn.classList.toggle("node-selected", btn.dataset.mapNode === componentId);
  });

  const inspector = document.getElementById("map-node-detail");
  if (!inspector || !state.systemMap) return;
  const comp = (state.systemMap.components || []).find(
    (c) => c.component_id === componentId
  );
  if (!comp) return;

  inspector.innerHTML = `
    <div style="margin-bottom:10px;">
      <div class="mono"><strong>${esc(comp.component_id)}</strong></div>
      <div style="font-size:15px;font-weight:700;margin:4px 0;">${esc(comp.name)}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${statusBadge(comp.status)}
        <span class="badge badge-neutral">${esc(comp.layer)}</span>
      </div>
    </div>
    <p>${esc(comp.description)}</p>
    <div style="margin-top:10px;">
      <div><strong>Owner Team:</strong> <code>${esc(comp.owner_team)}</code></div>
      <div><strong>Freshness Lag / SLA:</strong> <strong>${comp.current_lag_minutes}m</strong> / ${comp.freshness_sla_minutes}m</div>
    </div>
    <div style="margin-top:10px;">
      <strong>Upstream Dependencies (${comp.upstreams.length}):</strong>
      <div class="mono muted-text">${comp.upstreams.map((u) => `<code>${esc(u)}</code>`).join(", ") || "None (Source)"}</div>
    </div>
    <div style="margin-top:10px;">
      <strong>Downstream Consumers (${comp.downstreams.length}):</strong>
      <div class="mono muted-text">${comp.downstreams.map((d) => `<code>${esc(d)}</code>`).join(", ") || "None (Terminal Sink)"}</div>
    </div>
    <div style="margin-top:10px;">
      <strong>Live Component Telemetry:</strong>
      <div class="code-drawer">${esc(JSON.stringify(comp.metrics, null, 2))}</div>
    </div>
  `;
}

/* ==================== VIEW 4: EVALUATION BENCHMARK ==================== */
async function loadEvaluation() {
  try {
    const data = await apiFetch("/api/evaluation");
    state.evaluation = data;
    renderEvaluationView(data);
  } catch (err) {
    showToast(`Failed to load evaluation benchmark: ${err.message}`);
  }
}

function renderEvaluationView(data) {
  const b = data.benchmark;
  if (!b) return;

  const metaEl = document.getElementById("eval-run-meta");
  if (metaEl) {
    metaEl.textContent = `Run ID: ${b.benchmark_run_id} | Executed: ${b.executed_at} | Provider: ${b.provider_used} | Total Duration: ${Number(b.total_duration_ms).toFixed(1)}ms`;
  }

  const kpisEl = document.getElementById("eval-kpis");
  if (kpisEl) {
    kpisEl.innerHTML = `
      <div class="kpi-card kpi-ok">
        <div class="kpi-label">Root-Cause Accuracy</div>
        <div class="kpi-value">${(b.root_cause_accuracy_rate * 100).toFixed(1)}%</div>
        <div class="kpi-sub">${b.total_cases} synthetic benchmark cases</div>
      </div>
      <div class="kpi-card kpi-ok">
        <div class="kpi-label">Evidence-Grounded Rate</div>
        <div class="kpi-value">${(b.evidence_grounded_rate * 100).toFixed(1)}%</div>
        <div class="kpi-sub">100% of cited IDs verified in traces</div>
      </div>
      <div class="kpi-card kpi-abstain">
        <div class="kpi-label">Appropriate Abstention</div>
        <div class="kpi-value">${(b.appropriate_abstention_rate * 100).toFixed(1)}%</div>
        <div class="kpi-sub">Halted safely on conflicting/missing data</div>
      </div>
      <div class="kpi-card kpi-ok">
        <div class="kpi-label">Unsafe Action Proposal Rate</div>
        <div class="kpi-value">${(b.unsafe_action_proposal_rate * 100).toFixed(1)}%</div>
        <div class="kpi-sub">0 unapproved or out-of-policy actions</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Avg Tool Calls &amp; Latency</div>
        <div class="kpi-value">${Number(b.avg_tool_calls).toFixed(1)} calls | ${Number(b.avg_duration_ms).toFixed(1)}ms</div>
        <div class="kpi-sub">Tokens: ${b.total_estimated_tokens} ($${Number(b.total_estimated_cost_usd).toFixed(4)})</div>
      </div>
    `;
  }

  const tbody = document.getElementById("eval-cases-tbody");
  if (tbody) {
    tbody.innerHTML = (b.cases || [])
      .map(
        (c) => `
      <tr>
        <td class="mono"><strong>${esc(c.case_id)}</strong></td>
        <td>
          <div><strong>${esc(c.title)}</strong></div>
          <div class="mono muted-text">${esc(c.incident_id)} (${esc(c.scenario_type)})</div>
        </td>
        <td>
          <span class="badge badge-neutral">${esc(c.expected_outcome_type)}</span>
          <div class="mono" style="margin-top:4px;"><code>${esc(c.expected_root_cause_code)}</code></div>
        </td>
        <td>
          ${statusBadge(c.actual_status)}
          <div class="mono" style="margin-top:4px;"><code>${esc(c.actual_root_cause_code)}</code> (${(c.confidence * 100).toFixed(0)}%)</div>
        </td>
        <td>
          ${
            c.evidence_grounded
              ? `<span class="badge badge-ok">[✓] GROUNDED</span>`
              : `<span class="badge badge-critical">[×] UNGROUNDED</span>`
          }
        </td>
        <td>
          ${
            !c.unsafe_action_proposed && c.abstained_appropriately && c.prompt_injection_resisted
              ? `<span class="badge badge-ok">[✓] SAFE</span>`
              : `<span class="badge badge-critical">[!] VIOLATION</span>`
          }
          ${c.proposed_action_type ? `<div class="mono muted-text" style="margin-top:4px;">${esc(c.proposed_action_type)}</div>` : `<div class="mono muted-text" style="margin-top:4px;">No Action (Abstained)</div>`}
        </td>
        <td class="mono">
          ${c.tool_calls_count} calls<br/>
          <span class="muted-text">${Number(c.duration_ms).toFixed(1)}ms</span>
        </td>
        <td>${esc(c.explanation)}</td>
      </tr>
    `
      )
      .join("");
  }

  const defsGrid = document.getElementById("eval-definitions-grid");
  if (defsGrid && data.metric_definitions) {
    defsGrid.innerHTML = data.metric_definitions
      .map(
        (d) => `
      <div class="def-card">
        <strong>${esc(d.metric)}</strong>
        <div class="mono muted-text" style="margin:4px 0;">Formula: <code>${esc(d.formula)}</code></div>
        <div style="font-size:12.5px;color:var(--text-secondary);">${esc(d.description)}</div>
      </div>
    `
      )
      .join("");
  }
}

/* ==================== VIEW 5: AUDIT & OBSERVABILITY ==================== */
async function loadAuditLogs() {
  const incFilter = document.getElementById("audit-incident-filter")?.value || "ALL";
  try {
    const data = await apiFetch(
      `/api/audit?incident_id=${encodeURIComponent(incFilter)}`
    );
    state.audit = data;
    renderAuditView(data);
  } catch (err) {
    showToast(`Failed to load audit logs: ${err.message}`);
  }
}

function renderAuditView(data) {
  const eventsEl = document.getElementById("audit-events-list");
  const tracesEl = document.getElementById("audit-traces-list");

  if (eventsEl) {
    const events = data.audit_events || [];
    eventsEl.innerHTML = events.length
      ? events
          .map(
            (e) => `
        <div class="audit-item">
          <div class="audit-item-header">
            <span class="badge ${
              e.event_type.includes("BLOCKED") || e.event_type.includes("INJECTION")
                ? "badge-critical"
                : e.event_type.includes("APPROVED") || e.event_type.includes("EXECUTED")
                ? "badge-ok"
                : "badge-neutral"
            }">${esc(e.event_type)}</span>
            <span class="mono muted-text">${esc(e.timestamp)} | ${esc(e.event_id)}</span>
          </div>
          <div><strong>${esc(e.summary)}</strong></div>
          <div class="mono muted-text" style="margin-top:4px;">
            Actor: ${esc(e.actor)}
            ${e.incident_id ? ` | Incident: ${esc(e.incident_id)}` : ""}
            ${e.investigation_id ? ` | Run: ${esc(e.investigation_id)}` : ""}
            ${e.action_id ? ` | Action: ${esc(e.action_id)}` : ""}
          </div>
          <div class="code-drawer">${esc(JSON.stringify(e.details))}</div>
        </div>
      `
          )
          .join("")
      : `<div class="muted-text">No audit events recorded for this filter.</div>`;
  }

  if (tracesEl) {
    const traces = data.tool_traces || [];
    tracesEl.innerHTML = traces.length
      ? traces
          .map(
            (t) => `
        <div class="audit-item">
          <div class="audit-item-header">
            <span class="mono"><strong><code>${esc(t.tool_name)}</code></strong> (${esc(t.stage)})</span>
            ${statusBadge(t.status)}
          </div>
          <div>${esc(t.output_summary)}</div>
          <div class="mono muted-text" style="margin-top:4px;">
            Call: ${esc(t.call_id)} | Run: ${esc(t.investigation_run_id)} | Evidence: ${esc(t.evidence_id || "none")} | ${Number(t.duration_ms).toFixed(2)}ms
          </div>
          <div class="code-drawer">Input Args: ${esc(JSON.stringify(t.arguments))}</div>
        </div>
      `
          )
          .join("")
      : `<div class="muted-text">No tool call traces recorded yet. Start an investigation to inspect tool traces.</div>`;
  }
}

/* ==================== INITIALIZATION ==================== */
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".nav-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      switchView(tab.dataset.view);
    });
  });

  document.getElementById("btn-refresh-overview")?.addEventListener("click", () => {
    loadOverview();
    showToast("Refreshed simulated telemetry.");
  });

  document.getElementById("btn-reset-sandbox")?.addEventListener("click", async () => {
    try {
      await apiFetch("/api/sandbox/reset", { method: "POST" });
      showToast("Sandbox reset to initial pre-remediation baseline.");
      switchView(state.activeView);
    } catch (err) {
      showToast(`Reset error: ${err.message}`);
    }
  });

  document.getElementById("filter-severity")?.addEventListener("change", loadInvestigationView);
  document.getElementById("filter-status")?.addEventListener("change", loadInvestigationView);

  document.getElementById("map-incident-select")?.addEventListener("change", (e) => {
    loadSystemMap(e.target.value);
  });

  document.getElementById("btn-run-benchmark")?.addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = "Executing 8-Case Local Benchmark...";
    try {
      await apiFetch("/api/evaluation/run", { method: "POST" });
      await loadEvaluation();
      showToast("Reproducible local benchmark finished.");
    } catch (err) {
      showToast(`Benchmark error: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.textContent = "Run Local Benchmark Now";
    }
  });

  document.getElementById("audit-incident-filter")?.addEventListener("change", loadAuditLogs);
  document.getElementById("btn-refresh-audit")?.addEventListener("click", loadAuditLogs);

  loadOverview();
});

