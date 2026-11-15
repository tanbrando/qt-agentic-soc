import { escapeHtml, renderMarkdown } from "/static/markdown.js";

const TOKEN_STORAGE_KEY = "asp_op_token";

const state = {
  token: localStorage.getItem(TOKEN_STORAGE_KEY) || "",
  activeTab: "cases",
  cases: [],
  selectedCaseId: null,
  selectedCase: null,
  alerts: [],
  events: [],
  autoRefreshTimer: null,
  isInvestigating: false,
  lastSyncAt: null,
};

const els = {
  healthPill: document.getElementById("health-pill"),
  healthText: document.getElementById("health-text"),
  autoRefreshToggle: document.getElementById("auto-refresh-toggle"),
  refreshBtn: document.getElementById("refresh-btn"),
  tokenBtn: document.getElementById("token-btn"),
  tokenBtnLabel: document.getElementById("token-btn-label"),
  alertBanner: document.getElementById("alert-banner"),
  alertBannerMsg: document.getElementById("alert-banner-msg"),
  alertBannerClose: document.getElementById("alert-banner-close"),
  authEmptyState: document.getElementById("auth-empty-state"),
  authEmptyOpenBtn: document.getElementById("auth-empty-open-btn"),
  navTabs: document.querySelectorAll(".nav-tab"),
  tabPanels: {
    cases: document.getElementById("tab-cases"),
    alerts: document.getElementById("tab-alerts"),
    events: document.getElementById("tab-events"),
  },
  // KPI & Breakdown
  kpiTotalCases: document.getElementById("kpi-total-cases"),
  kpiOpenCases: document.getElementById("kpi-open-cases"),
  kpiHighCases: document.getElementById("kpi-high-cases"),
  kpiCriticalCount: document.getElementById("kpi-critical-count"),
  kpiAiCases: document.getElementById("kpi-ai-cases"),
  kpiTpCount: document.getElementById("kpi-tp-count"),
  kpiTotalAlerts: document.getElementById("kpi-total-alerts"),
  kpiLastSync: document.getElementById("kpi-last-sync"),
  severityBars: document.getElementById("severity-bars"),
  verdictBars: document.getElementById("verdict-bars"),
  // Cases
  casesFilterForm: document.getElementById("cases-filter-form"),
  casesFilterReset: document.getElementById("cases-filter-reset"),
  filterCaseStatus: document.getElementById("filter-case-status"),
  filterCaseLevel: document.getElementById("filter-case-level"),
  filterCaseIp: document.getElementById("filter-case-ip"),
  filterCaseSearch: document.getElementById("filter-case-search"),
  casesCountLabel: document.getElementById("cases-count-label"),
  caseQueueList: document.getElementById("case-queue-list"),
  caseDetailEmpty: document.getElementById("case-detail-empty"),
  caseDetailContent: document.getElementById("case-detail-content"),
  // Alerts
  alertsFilterForm: document.getElementById("alerts-filter-form"),
  alertsFilterReset: document.getElementById("alerts-filter-reset"),
  filterAlertRule: document.getElementById("filter-alert-rule"),
  filterAlertLevel: document.getElementById("filter-alert-level"),
  filterAlertStatus: document.getElementById("filter-alert-status"),
  filterAlertCase: document.getElementById("filter-alert-case"),
  alertsCountLabel: document.getElementById("alerts-count-label"),
  alertsTableBody: document.getElementById("alerts-table-body"),
  // Events
  eventsFilterForm: document.getElementById("events-filter-form"),
  eventsFilterReset: document.getElementById("events-filter-reset"),
  filterEventIp: document.getElementById("filter-event-ip"),
  filterEventUser: document.getElementById("filter-event-user"),
  filterEventAction: document.getElementById("filter-event-action"),
  filterEventDataset: document.getElementById("filter-event-dataset"),
  filterEventParse: document.getElementById("filter-event-parse"),
  eventsCountLabel: document.getElementById("events-count-label"),
  eventsTableBody: document.getElementById("events-table-body"),
  // Modals
  tokenModal: document.getElementById("token-modal"),
  tokenForm: document.getElementById("token-form"),
  tokenInput: document.getElementById("token-input"),
  tokenClearBtn: document.getElementById("token-clear-btn"),
  eventModal: document.getElementById("event-modal"),
  eventModalRaw: document.getElementById("event-modal-raw"),
  eventModalJson: document.getElementById("event-modal-json"),
};

// ==================== HELPERS ====================

function showBanner(message, type = "error") {
  els.alertBannerMsg.textContent = message;
  els.alertBanner.classList.remove("hidden", "banner-info");
  if (type === "info") {
    els.alertBanner.classList.add("banner-info");
  }
}

function hideBanner() {
  els.alertBanner.classList.add("hidden");
}

function formatDate(iso) {
  if (!iso) return "--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString("vi-VN", { hour12: false });
}

function severityBadge(level) {
  const norm = String(level || "low").toLowerCase();
  return `<span class="badge badge-${escapeHtml(norm)}">${escapeHtml(norm)}</span>`;
}

function statusBadge(statusValue) {
  const norm = String(statusValue || "open").toLowerCase();
  const cls = norm === "closed" ? "badge-closed" : "badge-open";
  return `<span class="badge ${cls}">${escapeHtml(norm)}</span>`;
}

function verdictBadge(verdict) {
  if (!verdict) return `<span class="badge badge-pending">Pending AI</span>`;
  const lower = verdict.toLowerCase();
  let cls = "badge-suspicious";
  if (lower.includes("true")) cls = "badge-tp";
  else if (lower.includes("false")) cls = "badge-fp";
  return `<span class="badge ${cls}">${escapeHtml(verdict)}</span>`;
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const resp = await fetch(path, { ...options, headers });
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const payload = await resp.json();
      if (payload?.detail) detail = payload.detail;
    } catch {
      // ignore non-JSON errors
    }
    const err = new Error(detail);
    err.status = resp.status;
    throw err;
  }
  return resp.json();
}

function handleApiError(err) {
  if (err.status === 401 || err.status === 403) {
    showBanner(`Lỗi xác thực (${err.status}): ${err.message}. Vui lòng kiểm tra Operator Token.`, "error");
    updateAuthUi();
    return;
  }
  showBanner(`Lỗi API: ${err.message}`, "error");
}

function updateAuthUi() {
  const hasToken = Boolean(state.token.trim());
  els.tokenBtnLabel.textContent = hasToken ? "Token: Connected" : "Set Operator Token";
  els.authEmptyState.classList.toggle("hidden", hasToken);
}

// ==================== HEALTH & TOKEN ====================

async function checkHealth() {
  try {
    const data = await fetch("/api/v1/health").then((r) => r.json());
    const ok = data?.status === "ok";
    els.healthPill.className = `status-pill ${ok ? "status-ok" : "status-err"}`;
    els.healthText.textContent = ok ? "Server Online" : "Degraded";
  } catch {
    els.healthPill.className = "status-pill status-err";
    els.healthText.textContent = "Server Offline";
  }
}

function openModal(modalEl) {
  modalEl.classList.remove("hidden");
}

function closeModal(modalEl) {
  modalEl.classList.add("hidden");
}

// ==================== OVERVIEW & BREAKDOWNS ====================

function renderBarList(container, items, total) {
  if (!items.length) {
    container.innerHTML = '<div class="empty-placeholder">Chưa có dữ liệu.</div>';
    return;
  }
  const safeTotal = Math.max(total, 1);
  container.innerHTML = items
    .map(({ label, count, color }) => {
      const pct = Math.round((count / safeTotal) * 100);
      return `
        <div class="bar-row">
          <span class="bar-label">${escapeHtml(label)}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:${pct}%; background:${color};"></div>
          </div>
          <span class="bar-count">${count}</span>
        </div>
      `;
    })
    .join("");
}

function renderOverviewMetrics(allCases, allAlerts) {
  const total = allCases.length;
  const openCount = allCases.filter((c) => c.status === "open").length;
  const closedCount = total - openCount;
  const criticalCount = allCases.filter((c) => c.level === "critical").length;
  const highCount = allCases.filter((c) => c.level === "high").length;
  const mediumCount = allCases.filter((c) => c.level === "medium").length;
  const lowCount = allCases.filter((c) => c.level === "low").length;

  const investigated = allCases.filter((c) => Boolean(c.agent_verdict));
  const tpCount = investigated.filter((c) => String(c.agent_verdict).toLowerCase().includes("true")).length;
  const fpCount = investigated.filter((c) => String(c.agent_verdict).toLowerCase().includes("false")).length;
  const suspCount = investigated.length - tpCount - fpCount;
  const pendingCount = total - investigated.length;

  els.kpiTotalCases.textContent = String(total);
  els.kpiOpenCases.textContent = `${openCount} open / ${closedCount} closed`;
  els.kpiHighCases.textContent = String(criticalCount + highCount);
  els.kpiCriticalCount.textContent = `${criticalCount} critical, ${highCount} high`;
  els.kpiAiCases.textContent = String(investigated.length);
  els.kpiTpCount.textContent = `${tpCount} True Positive`;
  els.kpiTotalAlerts.textContent = String(allAlerts.length);
  els.kpiLastSync.textContent = `Last sync: ${state.lastSyncAt ? formatDate(state.lastSyncAt) : "--"}`;

  renderBarList(
    els.severityBars,
    [
      { label: "Critical", count: criticalCount, color: "var(--critical)" },
      { label: "High", count: highCount, color: "var(--high)" },
      { label: "Medium", count: mediumCount, color: "var(--medium)" },
      { label: "Low", count: lowCount, color: "var(--low)" },
    ],
    total
  );

  renderBarList(
    els.verdictBars,
    [
      { label: "True Positive", count: tpCount, color: "var(--critical)" },
      { label: "Suspicious", count: suspCount, color: "var(--medium)" },
      { label: "False Positive", count: fpCount, color: "var(--success)" },
      { label: "Pending AI", count: pendingCount, color: "var(--text-dim)" },
    ],
    total
  );
}

// ==================== CASES TAB ====================

function renderCaseQueue(cases) {
  els.casesCountLabel.textContent = String(cases.length);
  if (!cases.length) {
    els.caseQueueList.innerHTML = '<div class="empty-placeholder">Không có Case nào khớp bộ lọc.</div>';
    return;
  }

  els.caseQueueList.innerHTML = cases
    .map((c) => {
      const active = c.id === state.selectedCaseId ? "active" : "";
      const conf = c.agent_confidence != null ? `${Math.round(c.agent_confidence * 100)}%` : "--";
      return `
        <button type="button" class="case-item ${active}" data-case-id="${c.id}">
          <div class="case-item-top">
            <span class="case-item-id">Case #${c.id} · ${escapeHtml(c.source_ip || c.case_key)}</span>
            ${severityBadge(c.level)}
          </div>
          <div class="case-item-title">${escapeHtml(c.title || c.case_key)}</div>
          <div class="case-item-meta">
            <span>${verdictBadge(c.agent_verdict)} ${statusBadge(c.status)}</span>
            <span>Conf: ${conf}</span>
          </div>
        </button>
      `;
    })
    .join("");

  els.caseQueueList.querySelectorAll(".case-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = Number(btn.dataset.caseId);
      selectCase(id);
    });
  });
}

function renderArtifactCard(art) {
  const meta = art.metadata || {};
  const scoreText = art.reputation_score != null ? `${art.reputation_score}/100` : "Observed";
  const reports = Array.isArray(meta.reports) ? meta.reports : [];

  const metaItems = [];
  if (meta.usageType) metaItems.push(`<div>Usage: <strong>${escapeHtml(meta.usageType)}</strong></div>`);
  if (meta.countryName || meta.countryCode) {
    metaItems.push(`<div>Country: <strong>${escapeHtml(meta.countryName || meta.countryCode)}</strong></div>`);
  }
  if (meta.isp) metaItems.push(`<div>ISP: <strong>${escapeHtml(meta.isp)}</strong></div>`);
  if (typeof meta.isTor === "boolean") metaItems.push(`<div>Tor: <strong>${meta.isTor ? "Yes" : "No"}</strong></div>`);
  if (typeof meta.isWhitelisted === "boolean") {
    metaItems.push(`<div>Whitelisted: <strong>${meta.isWhitelisted ? "Yes" : "No"}</strong></div>`);
  }
  if (meta.totalReports != null) metaItems.push(`<div>Total Reports: <strong>${meta.totalReports}</strong></div>`);
  if (meta.numDistinctUsers != null) {
    metaItems.push(`<div>Distinct Reporters: <strong>${meta.numDistinctUsers}</strong></div>`);
  }
  if (meta.source) metaItems.push(`<div>Source: <strong>${escapeHtml(meta.source)}</strong></div>`);

  let reportsHtml = "";
  if (reports.length) {
    const rows = reports
      .slice(0, 15)
      .map(
        (r) => `
          <tr>
            <td class="mono">${escapeHtml(formatDate(r.reportedAt))}</td>
            <td>${escapeHtml(r.reporterCountryCode || "--")}</td>
            <td>${escapeHtml((r.categories || []).join(", ") || "--")}</td>
            <td>${escapeHtml(r.comment || "(no comment)")}</td>
          </tr>
        `
      )
      .join("");
    reportsHtml = `
      <details class="reports-details">
        <summary>Xem ${reports.length} AbuseIPDB Community Reports</summary>
        <div class="table-scroll" style="margin-top:8px;">
          <table class="data-table">
            <thead>
              <tr>
                <th>Reported At</th>
                <th>Country</th>
                <th>Categories</th>
                <th>Comment</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </details>
    `;
  }

  return `
    <div class="artifact-card">
      <div class="artifact-head">
        <div>
          <span class="badge badge-open">${escapeHtml(art.artifact_type)}</span>
          <strong class="mono" style="margin-left:6px;">${escapeHtml(art.value)}</strong>
        </div>
        <div style="font-size:12px; color:var(--text-muted);">
          Vendor: <strong>${escapeHtml(art.reputation_vendor || "N/A")}</strong> ·
          Score: <strong>${escapeHtml(scoreText)}</strong>
        </div>
      </div>
      ${metaItems.length ? `<div class="artifact-meta-grid">${metaItems.join("")}</div>` : ""}
      ${reportsHtml}
    </div>
  `;
}

function renderCaseDetail(c) {
  if (!c) {
    els.caseDetailEmpty.classList.remove("hidden");
    els.caseDetailContent.classList.add("hidden");
    return;
  }

  els.caseDetailEmpty.classList.add("hidden");
  els.caseDetailContent.classList.remove("hidden");

  const confPct = c.agent_confidence != null ? Math.round(c.agent_confidence * 100) : 0;
  const confLabel = c.agent_confidence != null ? `${confPct}%` : "N/A";
  const nextStatus = c.status === "open" ? "closed" : "open";
  const statusBtnLabel = c.status === "open" ? "✓ Close Case" : "↺ Reopen Case";

  const artifacts = c.artifacts?.length
    ? c.artifacts
    : c.ai_report?.extracted_artifacts || [];
  const alerts = c.alerts || [];

  const artifactsHtml = artifacts.length
    ? `<div class="artifact-grid">${artifacts.map(renderArtifactCard).join("")}</div>`
    : '<p class="empty-placeholder">Chưa có artifact làm giàu nào. Bấm "Run AI Investigation" để truy vấn Threat Intel.</p>';

  const alertsHtml = alerts.length
    ? alerts
        .map((a) => {
          const uids = (a.event_uids || [])
            .map((uid) => `<span class="uid-pill" title="Event UID">${escapeHtml(uid.slice(0, 14))}…</span>`)
            .join("");
          return `
            <div class="artifact-card">
              <div class="artifact-head">
                <div>
                  ${severityBadge(a.level)}
                  <strong style="margin-left:6px;">${escapeHtml(a.title || a.rule_id)}</strong>
                  <span class="mono" style="color:var(--text-muted); margin-left:6px;">(${escapeHtml(a.rule_id)})</span>
                </div>
                <div style="font-size:12px; color:var(--text-muted);">
                  Events: <strong>${a.event_count}</strong> · End: ${escapeHtml(formatDate(a.window_end))}
                </div>
              </div>
              <div class="mono" style="font-size:11px; color:var(--text-dim);">
                alert_key: ${escapeHtml(a.alert_key)} | group_key: ${escapeHtml(JSON.stringify(a.group_key || {}))}
              </div>
              ${uids ? `<div class="uid-pills">${uids}</div>` : ""}
            </div>
          `;
        })
        .join("")
    : '<p class="empty-placeholder">Không có alert liên kết.</p>';

  els.caseDetailContent.innerHTML = `
    <div class="detail-header">
      <div>
        <h2 class="detail-title">Case #${c.id}: ${escapeHtml(c.title || c.case_key)}</h2>
        <div class="detail-sub">
          ${severityBadge(c.level)}
          ${statusBadge(c.status)}
          <span class="mono">key: ${escapeHtml(c.case_key)}</span>
          ${
            c.source_ip
              ? `<button id="jump-ip-events-btn" type="button" class="link-btn mono">🔍 Xem log của ${escapeHtml(c.source_ip)}</button>`
              : ""
          }
        </div>
      </div>

      <div class="detail-actions">
        <button id="run-investigate-btn" type="button" class="btn btn-primary btn-sm" ${state.isInvestigating ? "disabled" : ""}>
          ${state.isInvestigating ? "⏳ Đang điều tra AI..." : "🤖 Run AI Investigation"}
        </button>
        <button id="toggle-status-btn" type="button" class="btn btn-secondary btn-sm">
          ${statusBtnLabel}
        </button>
      </div>
    </div>

    <div class="detail-metrics">
      <div class="metric-box">
        <div class="metric-label">AI Verdict</div>
        <div class="metric-value">${verdictBadge(c.agent_verdict)}</div>
      </div>
      <div class="metric-box">
        <div class="metric-label">Confidence</div>
        <div class="metric-value">${confLabel}</div>
        <div class="confidence-track">
          <div class="confidence-fill" style="width:${confPct}%;"></div>
        </div>
      </div>
      <div class="metric-box">
        <div class="metric-label">Activity Window</div>
        <div class="metric-value" style="font-size:12px;">
          ${escapeHtml(formatDate(c.first_activity_at))} → ${escapeHtml(formatDate(c.last_activity_at))}
        </div>
      </div>
      <div class="metric-box">
        <div class="metric-label">AI Investigated At</div>
        <div class="metric-value" style="font-size:12px;">
          ${escapeHtml(formatDate(c.ai_investigated_at))}
        </div>
      </div>
    </div>

    <div class="detail-section">
      <h3 class="detail-section-title">AI Forensic Investigation Report</h3>
      <div class="markdown-body">${renderMarkdown(c.agent_report_markdown)}</div>
    </div>

    <div class="detail-section">
      <h3 class="detail-section-title">Threat Intelligence &amp; Enriched Artifacts (${artifacts.length})</h3>
      ${artifactsHtml}
    </div>

    <div class="detail-section">
      <h3 class="detail-section-title">Correlated Alerts (${alerts.length})</h3>
      <div class="artifact-grid">${alertsHtml}</div>
    </div>
  `;

  document.getElementById("run-investigate-btn")?.addEventListener("click", () => triggerInvestigation(c.id));
  document.getElementById("toggle-status-btn")?.addEventListener("click", () => toggleCaseStatus(c.id, nextStatus));
  document.getElementById("jump-ip-events-btn")?.addEventListener("click", () => {
    switchTab("events");
    els.filterEventIp.value = c.source_ip || "";
    loadEvents();
  });
}

async function loadCases() {
  if (!state.token) return;
  const params = new URLSearchParams({ limit: "200" });
  if (els.filterCaseStatus.value) params.set("status", els.filterCaseStatus.value);
  if (els.filterCaseLevel.value) params.set("level", els.filterCaseLevel.value);
  if (els.filterCaseIp.value.trim()) params.set("source_ip", els.filterCaseIp.value.trim());

  const [filteredCases, allCases, allAlerts] = await Promise.all([
    apiFetch(`/api/v1/cases?${params.toString()}`),
    apiFetch("/api/v1/cases?limit=500"),
    apiFetch("/api/v1/alerts?limit=500"),
  ]);

  const query = els.filterCaseSearch.value.trim().toLowerCase();
  const visibleCases = query
    ? filteredCases.filter(
        (c) =>
          String(c.title || "").toLowerCase().includes(query) ||
          String(c.case_key || "").toLowerCase().includes(query) ||
          String(c.source_ip || "").toLowerCase().includes(query)
      )
    : filteredCases;

  state.cases = visibleCases;
  state.lastSyncAt = new Date().toISOString();
  renderOverviewMetrics(allCases, allAlerts);
  renderCaseQueue(visibleCases);

  if (state.selectedCaseId == null && visibleCases.length > 0) {
    await selectCase(visibleCases[0].id);
  } else if (state.selectedCaseId != null) {
    await selectCase(state.selectedCaseId, { silentNotFound: true });
  }
}

async function selectCase(caseId, { silentNotFound = false } = {}) {
  state.selectedCaseId = caseId;
  renderCaseQueue(state.cases);
  try {
    const fullCase = await apiFetch(`/api/v1/cases/${caseId}`);
    state.selectedCase = fullCase;
    renderCaseDetail(fullCase);
  } catch (err) {
    if (silentNotFound && err.status === 404) {
      state.selectedCase = null;
      renderCaseDetail(null);
      return;
    }
    handleApiError(err);
  }
}

async function triggerInvestigation(caseId) {
  if (state.isInvestigating) return;
  state.isInvestigating = true;
  renderCaseDetail(state.selectedCase);
  hideBanner();

  try {
    const updated = await apiFetch(`/api/v1/cases/${caseId}/investigate`, { method: "POST" });
    state.selectedCase = updated;
    await loadCases();
    showBanner(`Đã hoàn tất điều tra AI cho Case #${caseId}.`, "info");
  } catch (err) {
    handleApiError(err);
  } finally {
    state.isInvestigating = false;
    renderCaseDetail(state.selectedCase);
  }
}

async function toggleCaseStatus(caseId, nextStatus) {
  hideBanner();
  try {
    const updated = await apiFetch(`/api/v1/cases/${caseId}`, {
      method: "PATCH",
      body: JSON.stringify({ status: nextStatus }),
    });
    state.selectedCase = updated;
    await loadCases();
    showBanner(`Đã chuyển Case #${caseId} sang trạng thái "${nextStatus}".`, "info");
  } catch (err) {
    handleApiError(err);
  }
}

// ==================== ALERTS TAB ====================

async function loadAlerts() {
  if (!state.token) return;
  const params = new URLSearchParams({ limit: "200" });
  if (els.filterAlertRule.value) params.set("rule_id", els.filterAlertRule.value);
  if (els.filterAlertLevel.value) params.set("level", els.filterAlertLevel.value);
  if (els.filterAlertStatus.value) params.set("status", els.filterAlertStatus.value);
  if (els.filterAlertCase.value.trim()) params.set("case_id", els.filterAlertCase.value.trim());

  const alerts = await apiFetch(`/api/v1/alerts?${params.toString()}`);
  state.alerts = alerts;
  els.alertsCountLabel.textContent = String(alerts.length);

  if (!alerts.length) {
    els.alertsTableBody.innerHTML = '<tr><td colspan="9" class="empty-cell">Không tìm thấy alert nào.</td></tr>';
    return;
  }

  els.alertsTableBody.innerHTML = alerts
    .map(
      (a) => `
        <tr>
          <td class="mono">#${a.id}</td>
          <td>${severityBadge(a.level)}</td>
          <td class="mono">${escapeHtml(a.rule_id)}</td>
          <td>${escapeHtml(a.title || "--")}</td>
          <td class="mono" style="font-size:11px;">${escapeHtml(JSON.stringify(a.group_key || {}))}</td>
          <td><strong>${a.event_count}</strong></td>
          <td>${escapeHtml(formatDate(a.window_end))}</td>
          <td>${escapeHtml(a.status)}</td>
          <td>
            ${
              a.case_id
                ? `<button type="button" class="link-btn jump-case-btn" data-case-id="${a.case_id}">Case #${a.case_id} →</button>`
                : "--"
            }
          </td>
        </tr>
      `
    )
    .join("");

  els.alertsTableBody.querySelectorAll(".jump-case-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const caseId = Number(btn.dataset.caseId);
      switchTab("cases");
      await selectCase(caseId);
    });
  });
}

// ==================== ECS EVENTS TAB ====================

async function loadEvents() {
  if (!state.token) return;
  const params = new URLSearchParams({ limit: "200" });
  if (els.filterEventIp.value.trim()) params.set("source_ip", els.filterEventIp.value.trim());
  if (els.filterEventUser.value.trim()) params.set("user_name", els.filterEventUser.value.trim());
  if (els.filterEventAction.value.trim()) params.set("action", els.filterEventAction.value.trim());
  if (els.filterEventDataset.value) params.set("dataset", els.filterEventDataset.value);
  if (els.filterEventParse.value) params.set("parse_status", els.filterEventParse.value);

  const events = await apiFetch(`/api/v1/events?${params.toString()}`);
  state.events = events;
  els.eventsCountLabel.textContent = String(events.length);

  if (!events.length) {
    els.eventsTableBody.innerHTML = '<tr><td colspan="9" class="empty-cell">Không tìm thấy ECS event nào.</td></tr>';
    return;
  }

  els.eventsTableBody.innerHTML = events
    .map((ev, idx) => {
      const ts = ev["@timestamp"] || ev.event?.created;
      const host = ev.host?.name || "--";
      const ip = ev.source?.ip || "--";
      const user = ev.user?.name || "--";
      const action = ev.event?.action || "--";
      const outcome = ev.event?.outcome || "--";
      const dataset = ev.event?.dataset || "--";
      const parseStatus = ev.asp?.parse_status || "--";
      const rawLine = ev.message || ev.event?.original || "";
      const preview = rawLine.length > 90 ? `${rawLine.slice(0, 90)}…` : rawLine;

      return `
        <tr data-event-idx="${idx}">
          <td class="mono" style="white-space:nowrap;">${escapeHtml(formatDate(ts))}</td>
          <td>${escapeHtml(host)}</td>
          <td class="mono">${escapeHtml(ip)}</td>
          <td class="mono">${escapeHtml(user)}</td>
          <td class="mono">${escapeHtml(action)}</td>
          <td>${escapeHtml(outcome)}</td>
          <td>${escapeHtml(dataset)}</td>
          <td>${escapeHtml(parseStatus)}</td>
          <td class="mono" style="font-size:11.5px;">${escapeHtml(preview)}</td>
        </tr>
      `;
    })
    .join("");

  els.eventsTableBody.querySelectorAll("tr[data-event-idx]").forEach((row) => {
    row.addEventListener("click", () => {
      const ev = state.events[Number(row.dataset.eventIdx)];
      if (!ev) return;
      els.eventModalRaw.textContent = ev.event?.original || ev.message || "(empty)";
      els.eventModalJson.textContent = JSON.stringify(ev, null, 2);
      openModal(els.eventModal);
    });
  });
}

// ==================== NAVIGATION & REFRESH ====================

function switchTab(tabName) {
  state.activeTab = tabName;
  els.navTabs.forEach((btn) => {
    const isActive = btn.dataset.tab === tabName;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", String(isActive));
  });
  Object.entries(els.tabPanels).forEach(([key, panel]) => {
    panel.classList.toggle("hidden", key !== tabName);
    panel.classList.toggle("active", key === tabName);
  });
  refreshActiveTab();
}

async function refreshActiveTab() {
  await checkHealth();
  if (!state.token) return;
  try {
    if (state.activeTab === "cases") await loadCases();
    else if (state.activeTab === "alerts") await loadAlerts();
    else if (state.activeTab === "events") await loadEvents();
  } catch (err) {
    handleApiError(err);
  }
}

function setAutoRefresh(enabled) {
  if (state.autoRefreshTimer) {
    clearInterval(state.autoRefreshTimer);
    state.autoRefreshTimer = null;
  }
  if (enabled) {
    state.autoRefreshTimer = setInterval(() => {
      if (!state.isInvestigating) refreshActiveTab();
    }, 10_000);
  }
}

// ==================== EVENT LISTENERS ====================

function bindEvents() {
  els.navTabs.forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  els.refreshBtn.addEventListener("click", () => {
    hideBanner();
    refreshActiveTab();
  });

  els.autoRefreshToggle.addEventListener("change", (e) => {
    setAutoRefresh(e.target.checked);
  });

  els.alertBannerClose.addEventListener("click", hideBanner);

  const openTokenDialog = () => {
    els.tokenInput.value = state.token;
    openModal(els.tokenModal);
    els.tokenInput.focus();
  };
  els.tokenBtn.addEventListener("click", openTokenDialog);
  els.authEmptyOpenBtn.addEventListener("click", openTokenDialog);

  els.tokenForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    state.token = els.tokenInput.value.trim();
    if (state.token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, state.token);
    }
    closeModal(els.tokenModal);
    updateAuthUi();
    hideBanner();
    await refreshActiveTab();
  });

  els.tokenClearBtn.addEventListener("click", () => {
    state.token = "";
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    els.tokenInput.value = "";
    closeModal(els.tokenModal);
    updateAuthUi();
  });

  document.querySelectorAll("[data-close-modal]").forEach((el) => {
    el.addEventListener("click", () => {
      const target = document.getElementById(el.dataset.closeModal);
      if (target) closeModal(target);
    });
  });

  els.casesFilterForm.addEventListener("submit", (e) => {
    e.preventDefault();
    refreshActiveTab();
  });
  els.casesFilterReset.addEventListener("click", () => {
    els.casesFilterForm.reset();
    refreshActiveTab();
  });

  els.alertsFilterForm.addEventListener("submit", (e) => {
    e.preventDefault();
    refreshActiveTab();
  });
  els.alertsFilterReset.addEventListener("click", () => {
    els.alertsFilterForm.reset();
    refreshActiveTab();
  });

  els.eventsFilterForm.addEventListener("submit", (e) => {
    e.preventDefault();
    refreshActiveTab();
  });
  els.eventsFilterReset.addEventListener("click", () => {
    els.eventsFilterForm.reset();
    refreshActiveTab();
  });
}

// ==================== BOOTSTRAP ====================

bindEvents();
updateAuthUi();
refreshActiveTab();

