import { escapeHtml, renderMarkdown } from "/static/markdown.js";

const TOKEN_STORAGE_KEY = "asp_op_token";

const TAB_META = {
  overview: {
    title: "Tổng quan An ninh & Phân tích Trực quan",
    subtitle: "Giám sát toàn cảnh sự kiện, cảnh báo và hiệu suất điều tra AI",
  },
  cases: {
    title: "Điều tra Sự cố (Incident Cases)",
    subtitle: "Phân loại Case, xem báo cáo AI Forensic & Threat Intelligence",
  },
  "ai-flow": {
    title: "Giám sát Luồng Hoạt động AI (LangGraph Monitor)",
    subtitle: "Theo dõi từng bước suy luận, lệnh gọi Tool và chấm điểm bằng chứng của AI Agent",
  },
  telemetry: {
    title: "Tra cứu Cảnh báo & ECS Telemetry",
    subtitle: "Khám phá Detection Alerts và dữ liệu log chuẩn hóa ECS v1.1",
  },
};

const state = {
  token: localStorage.getItem(TOKEN_STORAGE_KEY) || "",
  activeTab: "overview",
  telemetrySubtab: "alerts",
  caseDetailSubtab: "report",
  allCases: [],
  cases: [],
  selectedCaseId: null,
  selectedCase: null,
  alerts: [],
  allAlerts: [],
  events: [],
  autoRefreshTimer: null,
  isInvestigating: false,
  replayTimer: null,
  lastSyncAt: null,
};

const els = {
  pageTitle: document.getElementById("page-title"),
  pageSubtitle: document.getElementById("page-subtitle"),
  healthPill: document.getElementById("health-pill"),
  healthText: document.getElementById("health-text"),
  sidebarLastSync: document.getElementById("sidebar-last-sync"),
  navBadgeCases: document.getElementById("nav-badge-cases"),
  navBadgeAi: document.getElementById("nav-badge-ai"),
  autoRefreshToggle: document.getElementById("auto-refresh-toggle"),
  refreshBtn: document.getElementById("refresh-btn"),
  tokenBtn: document.getElementById("token-btn"),
  tokenBtnLabel: document.getElementById("token-btn-label"),
  alertBanner: document.getElementById("alert-banner"),
  alertBannerMsg: document.getElementById("alert-banner-msg"),
  alertBannerClose: document.getElementById("alert-banner-close"),
  authEmptyState: document.getElementById("auth-empty-state"),
  authEmptyOpenBtn: document.getElementById("auth-empty-open-btn"),
  navItems: document.querySelectorAll(".nav-item"),
  tabPanels: {
    overview: document.getElementById("tab-overview"),
    cases: document.getElementById("tab-cases"),
    "ai-flow": document.getElementById("tab-ai-flow"),
    telemetry: document.getElementById("tab-telemetry"),
  },
  // Overview KPI & Charts
  kpiTotalCases: document.getElementById("kpi-total-cases"),
  kpiOpenCases: document.getElementById("kpi-open-cases"),
  kpiHighCases: document.getElementById("kpi-high-cases"),
  kpiCriticalCount: document.getElementById("kpi-critical-count"),
  kpiAiCases: document.getElementById("kpi-ai-cases"),
  kpiTpCount: document.getElementById("kpi-tp-count"),
  kpiTotalAlerts: document.getElementById("kpi-total-alerts"),
  kpiTotalEventsSub: document.getElementById("kpi-total-events-sub"),
  chartSeverityDonut: document.getElementById("chart-severity-donut"),
  chartVerdictDonut: document.getElementById("chart-verdict-donut"),
  chartAlertsTimeline: document.getElementById("chart-alerts-timeline"),
  chartTopRules: document.getElementById("chart-top-rules"),
  chartTopIps: document.getElementById("chart-top-ips"),
  overviewPriorityBody: document.getElementById("overview-priority-body"),
  overviewGotoCases: document.getElementById("overview-goto-cases"),
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
  // AI Flow Monitor
  aiFlowCaseSelect: document.getElementById("ai-flow-case-select"),
  aiFlowReplayBtn: document.getElementById("ai-flow-replay-btn"),
  aiFlowRunBtn: document.getElementById("ai-flow-run-btn"),
  aiPipelineSubtitle: document.getElementById("ai-pipeline-subtitle"),
  aiPipelineStats: document.getElementById("ai-pipeline-stats"),
  langgraphDiagram: document.getElementById("langgraph-diagram"),
  lgMetaLoad: document.getElementById("lg-meta-load"),
  lgMetaReason: document.getElementById("lg-meta-reason"),
  lgMetaTool: document.getElementById("lg-meta-tool"),
  lgMetaSynth: document.getElementById("lg-meta-synth"),
  aiTraceCount: document.getElementById("ai-trace-count"),
  aiTraceTimeline: document.getElementById("ai-trace-timeline"),
  aiForensicBreakdown: document.getElementById("ai-forensic-breakdown"),
  aiLlmNotes: document.getElementById("ai-llm-notes"),
  // Telemetry
  subtabBtns: document.querySelectorAll(".subtab-btn"),
  subpanelAlerts: document.getElementById("subpanel-alerts"),
  subpanelEvents: document.getElementById("subpanel-events"),
  telemetryMiniSummary: document.getElementById("telemetry-mini-summary"),
  alertsFilterForm: document.getElementById("alerts-filter-form"),
  alertsFilterReset: document.getElementById("alerts-filter-reset"),
  filterAlertRule: document.getElementById("filter-alert-rule"),
  filterAlertLevel: document.getElementById("filter-alert-level"),
  filterAlertStatus: document.getElementById("filter-alert-status"),
  filterAlertCase: document.getElementById("filter-alert-case"),
  alertsCountLabel: document.getElementById("alerts-count-label"),
  alertsTableBody: document.getElementById("alerts-table-body"),
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

function formatShortTime(iso) {
  if (!iso) return "--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "--";
  return d.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", hour12: false });
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

// ==================== HEALTH & MODALS ====================

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

// ==================== SVG CHARTS ====================

function renderDonutChart(container, segments, centerLabel) {
  const total = segments.reduce((acc, s) => acc + s.count, 0);
  if (total === 0) {
    container.innerHTML = '<div class="empty-placeholder" style="width:100%;">Chưa có dữ liệu.</div>';
    return;
  }

  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  let cumulativePct = 0;

  const circles = segments
    .filter((s) => s.count > 0)
    .map((s) => {
      const pct = s.count / total;
      const dash = pct * circumference;
      const offset = -cumulativePct * circumference;
      cumulativePct += pct;
      return `
        <circle
          cx="66" cy="66" r="${radius}"
          fill="transparent"
          stroke="${s.color}"
          stroke-width="16"
          stroke-dasharray="${dash} ${circumference - dash}"
          stroke-dashoffset="${offset}"
          transform="rotate(-90 66 66)"
        />
      `;
    })
    .join("");

  const legend = segments
    .map(
      (s) => `
      <div class="legend-row">
        <div class="legend-left">
          <span class="legend-dot" style="background:${s.color};"></span>
          <span>${escapeHtml(s.label)}</span>
        </div>
        <span class="legend-val">${s.count}</span>
      </div>
    `
    )
    .join("");

  container.innerHTML = `
    <div class="donut-svg-wrap">
      <svg viewBox="0 0 132 132" width="132" height="132" aria-hidden="true">
        <circle cx="66" cy="66" r="${radius}" fill="transparent" stroke="rgba(148,163,184,0.12)" stroke-width="16" />
        ${circles}
      </svg>
      <div class="donut-center">
        <span class="donut-center-val">${total}</span>
        <span class="donut-center-lbl">${escapeHtml(centerLabel)}</span>
      </div>
    </div>
    <div class="donut-legend">${legend}</div>
  `;
}

function renderTimelineChart(container, alerts) {
  if (!alerts.length) {
    container.innerHTML = '<div class="empty-placeholder">Chưa có cảnh báo để vẽ biểu đồ thời gian.</div>';
    return;
  }

  const buckets = new Map();
  alerts.forEach((a) => {
    const ts = a.window_end || a.created_at;
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return;
    const key = `${String(d.getHours()).padStart(2, "0")}:${String(Math.floor(d.getMinutes() / 10) * 10).padStart(2, "0")}`;
    const prev = buckets.get(key) || { label: key, alerts: 0, events: 0 };
    prev.alerts += 1;
    prev.events += Number(a.event_count || 0);
    buckets.set(key, prev);
  });

  const series = Array.from(buckets.values()).slice(-10);
  if (!series.length) {
    container.innerHTML = '<div class="empty-placeholder">Không có mốc thời gian hợp lệ.</div>';
    return;
  }

  const maxVal = Math.max(...series.map((s) => s.alerts), 1);
  const w = 360;
  const h = 138;
  const padX = 18;
  const padY = 18;
  const chartW = w - padX * 2;
  const chartH = h - padY * 2;
  const step = chartW / series.length;
  const barW = Math.min(24, step * 0.55);

  const bars = series
    .map((s, idx) => {
      const barH = Math.max(4, (s.alerts / maxVal) * chartH);
      const x = padX + idx * step + (step - barW) / 2;
      const y = h - padY - barH;
      return `
        <g>
          <title>${escapeHtml(s.label)}: ${s.alerts} alerts (${s.events} events)</title>
          <rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${barH.toFixed(1)}" rx="4" fill="#38bdf8" opacity="0.88" />
          <text x="${(x + barW / 2).toFixed(1)}" y="${(y - 4).toFixed(1)}" text-anchor="middle" fill="#cbd5e1" font-size="9">${s.alerts}</text>
          <text x="${(x + barW / 2).toFixed(1)}" y="${h - 4}" text-anchor="middle" fill="#64748b" font-size="9">${escapeHtml(s.label)}</text>
        </g>
      `;
    })
    .join("");

  container.innerHTML = `
    <svg class="timeline-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <line x1="${padX}" y1="${h - padY}" x2="${w - padX}" y2="${h - padY}" stroke="rgba(148,163,184,0.22)" stroke-width="1" />
      ${bars}
    </svg>
  `;
}

function renderHorizontalBars(container, items, colorFn) {
  if (!items.length) {
    container.innerHTML = '<div class="empty-placeholder">Chưa có dữ liệu.</div>';
    return;
  }
  const maxCount = Math.max(...items.map((i) => i.count), 1);
  container.innerHTML = items
    .map((item, idx) => {
      const pct = Math.round((item.count / maxCount) * 100);
      const color = colorFn ? colorFn(item, idx) : "var(--accent)";
      return `
        <div class="hbar-row">
          <span class="hbar-label mono" title="${escapeHtml(item.label)}">${escapeHtml(item.label)}</span>
          <div class="hbar-track">
            <div class="hbar-fill" style="width:${pct}%; background:${color};"></div>
          </div>
          <span class="hbar-count">${item.count}</span>
        </div>
      `;
    })
    .join("");
}

// ==================== OVERVIEW RENDERING ====================

function renderOverview(allCases, allAlerts, recentEventsCount) {
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

  els.navBadgeCases.textContent = String(openCount);
  els.kpiTotalCases.textContent = String(total);
  els.kpiOpenCases.textContent = `${openCount} open / ${closedCount} closed`;
  els.kpiHighCases.textContent = String(criticalCount + highCount);
  els.kpiCriticalCount.textContent = `${criticalCount} critical, ${highCount} high`;
  els.kpiAiCases.textContent = String(investigated.length);
  els.kpiTpCount.textContent = `${tpCount} True Positive`;
  els.kpiTotalAlerts.textContent = String(allAlerts.length);
  els.kpiTotalEventsSub.textContent = `${recentEventsCount} ECS events gần nhất`;
  els.sidebarLastSync.textContent = `Sync: ${state.lastSyncAt ? formatShortTime(state.lastSyncAt) : "--"}`;

  renderDonutChart(
    els.chartSeverityDonut,
    [
      { label: "Critical", count: criticalCount, color: "var(--critical)" },
      { label: "High", count: highCount, color: "var(--high)" },
      { label: "Medium", count: mediumCount, color: "var(--medium)" },
      { label: "Low", count: lowCount, color: "var(--low)" },
    ],
    "Cases"
  );

  renderDonutChart(
    els.chartVerdictDonut,
    [
      { label: "True Positive", count: tpCount, color: "var(--critical)" },
      { label: "Suspicious", count: suspCount, color: "var(--medium)" },
      { label: "False Positive", count: fpCount, color: "var(--success)" },
      { label: "Pending AI", count: pendingCount, color: "#64748b" },
    ],
    "Verdict"
  );

  renderTimelineChart(els.chartAlertsTimeline, allAlerts);

  // Top Rules
  const ruleCounts = new Map();
  allAlerts.forEach((a) => {
    ruleCounts.set(a.rule_id, (ruleCounts.get(a.rule_id) || 0) + 1);
  });
  const topRules = Array.from(ruleCounts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
  renderHorizontalBars(els.chartTopRules, topRules, (_, idx) =>
    idx === 0 ? "var(--high)" : idx === 1 ? "var(--medium)" : "var(--accent)"
  );

  // Top Source IPs
  const ipCounts = new Map();
  allCases.forEach((c) => {
    if (c.source_ip) {
      const alertWeight = (c.alerts || []).length || 1;
      ipCounts.set(c.source_ip, (ipCounts.get(c.source_ip) || 0) + alertWeight);
    }
  });
  const topIps = Array.from(ipCounts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
  renderHorizontalBars(els.chartTopIps, topIps, () => "var(--purple)");

  // Priority Cases Table
  const priority = [...allCases]
    .sort((a, b) => {
      const rank = { critical: 4, high: 3, medium: 2, low: 1 };
      return (rank[b.level] || 0) - (rank[a.level] || 0) || b.id - a.id;
    })
    .slice(0, 8);

  if (!priority.length) {
    els.overviewPriorityBody.innerHTML = '<tr><td colspan="7" class="empty-cell">Chưa có dữ liệu Case.</td></tr>';
    return;
  }

  els.overviewPriorityBody.innerHTML = priority
    .map(
      (c) => `
      <tr>
        <td class="mono">#${c.id}</td>
        <td>${severityBadge(c.level)}</td>
        <td class="mono">${escapeHtml(c.source_ip || "--")}</td>
        <td>${escapeHtml(c.title || c.case_key)}</td>
        <td>${verdictBadge(c.agent_verdict)}</td>
        <td>${statusBadge(c.status)}</td>
        <td>
          <button type="button" class="link-btn ov-open-case" data-case-id="${c.id}">Điều tra</button>
          <button type="button" class="link-btn ov-open-ai" data-case-id="${c.id}">Luồng AI</button>
        </td>
      </tr>
    `
    )
    .join("");

  els.overviewPriorityBody.querySelectorAll(".ov-open-case").forEach((btn) => {
    btn.addEventListener("click", async () => {
      switchTab("cases");
      await selectCase(Number(btn.dataset.caseId));
    });
  });

  els.overviewPriorityBody.querySelectorAll(".ov-open-ai").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await selectCase(Number(btn.dataset.caseId));
      switchTab("ai-flow");
    });
  });
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
      selectCase(Number(btn.dataset.caseId));
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
  if (meta.totalReports != null) metaItems.push(`<div>Total Reports: <strong>${meta.totalReports}</strong></div>`);
  if (meta.source) metaItems.push(`<div>Source: <strong>${escapeHtml(meta.source)}</strong></div>`);

  let reportsHtml = "";
  if (reports.length) {
    const rows = reports
      .slice(0, 10)
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
      <details style="margin-top:8px;">
        <summary style="cursor:pointer; font-size:12px; color:var(--accent);">Xem ${reports.length} AbuseIPDB Community Reports</summary>
        <div class="table-scroll" style="margin-top:8px;">
          <table class="data-table">
            <thead>
              <tr><th>Reported At</th><th>Country</th><th>Categories</th><th>Comment</th></tr>
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

  const activeSub = state.caseDetailSubtab;

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
        <button id="open-ai-flow-btn" type="button" class="btn btn-ghost btn-sm">
          🕸️ Xem Luồng AI
        </button>
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
        <div class="confidence-track"><div class="confidence-fill" style="width:${confPct}%;"></div></div>
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

    <div class="subtab-bar">
      <div class="subtab-group">
        <button type="button" class="subtab-btn case-subtab ${activeSub === "report" ? "active" : ""}" data-case-sub="report">
          📋 Báo cáo AI Forensic
        </button>
        <button type="button" class="subtab-btn case-subtab ${activeSub === "artifacts" ? "active" : ""}" data-case-sub="artifacts">
          🌐 Threat Intel &amp; IoCs (${artifacts.length})
        </button>
        <button type="button" class="subtab-btn case-subtab ${activeSub === "alerts" ? "active" : ""}" data-case-sub="alerts">
          ⚡ Cảnh báo liên kết (${alerts.length})
        </button>
      </div>
    </div>

    <div class="${activeSub === "report" ? "" : "hidden"}">
      <div class="markdown-body">${renderMarkdown(c.agent_report_markdown)}</div>
    </div>
    <div class="${activeSub === "artifacts" ? "" : "hidden"}">
      ${artifactsHtml}
    </div>
    <div class="${activeSub === "alerts" ? "" : "hidden"}">
      <div class="artifact-grid">${alertsHtml}</div>
    </div>
  `;

  els.caseDetailContent.querySelectorAll(".case-subtab").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.caseDetailSubtab = btn.dataset.caseSub;
      renderCaseDetail(state.selectedCase);
    });
  });

  document.getElementById("run-investigate-btn")?.addEventListener("click", () => triggerInvestigation(c.id));
  document.getElementById("toggle-status-btn")?.addEventListener("click", () => toggleCaseStatus(c.id, nextStatus));
  document.getElementById("open-ai-flow-btn")?.addEventListener("click", () => switchTab("ai-flow"));
  document.getElementById("jump-ip-events-btn")?.addEventListener("click", () => {
    state.telemetrySubtab = "events";
    switchTab("telemetry");
    els.filterEventIp.value = c.source_ip || "";
    loadEvents();
  });
}

// ==================== AI WORKFLOW MONITOR ====================

function syncAiCaseSelector(allCases) {
  if (!allCases.length) {
    els.aiFlowCaseSelect.innerHTML = '<option value="">-- Chưa có Case --</option>';
    return;
  }
  els.aiFlowCaseSelect.innerHTML = allCases
    .map((c) => {
      const sel = c.id === state.selectedCaseId ? "selected" : "";
      const tag = c.agent_verdict ? `✓ ${c.agent_verdict}` : "Pending AI";
      return `<option value="${c.id}" ${sel}>Case #${c.id} · ${escapeHtml(c.source_ip || c.case_key)} (${escapeHtml(tag)})</option>`;
    })
    .join("");
}

function resetDiagramNodes() {
  els.langgraphDiagram.querySelectorAll(".lg-node").forEach((nodeEl) => {
    nodeEl.classList.remove("lg-active", "lg-done", "lg-error");
  });
}

function updateDiagramFromSteps(steps, highlightStepIdx = null) {
  resetDiagramNodes();
  const stats = {
    load_case_context: { count: 0, ms: 0, error: false },
    agent_reasoning: { count: 0, ms: 0, error: false },
    tool_execution: { count: 0, ms: 0, error: false },
    synthesize_verdict: { count: 0, ms: 0, error: false },
  };

  steps.forEach((s, idx) => {
    if (!stats[s.node]) return;
    stats[s.node].count += 1;
    stats[s.node].ms += Number(s.duration_ms || 0);
    if (s.status === "error") stats[s.node].error = true;

    if (highlightStepIdx === idx) {
      const activeNode = els.langgraphDiagram.querySelector(`[data-node="${s.node}"]`);
      if (activeNode) activeNode.classList.add("lg-active");
    }
  });

  Object.entries(stats).forEach(([nodeName, st]) => {
    const nodeEl = els.langgraphDiagram.querySelector(`[data-node="${nodeName}"]`);
    if (!nodeEl) return;
    if (highlightStepIdx === null && st.count > 0) {
      nodeEl.classList.add(st.error ? "lg-error" : "lg-done");
    } else if (highlightStepIdx !== null && st.count > 0 && !nodeEl.classList.contains("lg-active")) {
      nodeEl.classList.add("lg-done");
    }
  });

  els.lgMetaLoad.textContent = stats.load_case_context.count
    ? `${stats.load_case_context.ms.toFixed(1)} ms`
    : "Chưa chạy";
  els.lgMetaReason.textContent = stats.agent_reasoning.count
    ? `${stats.agent_reasoning.count} vòng · ${stats.agent_reasoning.ms.toFixed(1)} ms`
    : "Chưa chạy";
  els.lgMetaTool.textContent = stats.tool_execution.count
    ? `${stats.tool_execution.count} lượt · ${stats.tool_execution.ms.toFixed(1)} ms`
    : "Chưa chạy";
  els.lgMetaSynth.textContent = stats.synthesize_verdict.count
    ? `${stats.synthesize_verdict.ms.toFixed(1)} ms`
    : "Chưa chạy";
}

function renderAiWorkflowMonitor(c, highlightIdx = null) {
  syncAiCaseSelector(state.allCases);

  if (!c) {
    resetDiagramNodes();
    els.aiPipelineSubtitle.textContent = "Chưa chọn Case nào.";
    els.aiPipelineStats.innerHTML = "";
    els.aiTraceCount.textContent = "0 bước";
    els.aiTraceTimeline.innerHTML = '<div class="empty-placeholder">Hãy chọn một Case để xem luồng hoạt động của AI.</div>';
    els.aiForensicBreakdown.innerHTML = '<div class="empty-placeholder">Chưa có dữ liệu phân tích.</div>';
    els.aiLlmNotes.innerHTML = '<div class="empty-placeholder">Chưa có ghi chú suy luận.</div>';
    return;
  }

  const aiReport = c.ai_report || {};
  const steps = Array.isArray(aiReport.trace_steps) ? aiReport.trace_steps : [];
  const breakdown = aiReport.forensic_breakdown || {};
  const llmAnalysis = aiReport.llm_analysis || "";
  const totalMs = steps.reduce((sum, s) => sum + Number(s.duration_ms || 0), 0);

  els.aiPipelineSubtitle.textContent = `Case #${c.id}: ${c.title || c.case_key} (${c.source_ip || "N/A"})`;
  els.aiPipelineStats.innerHTML = `
    <span class="chip">LLM: ${escapeHtml(aiReport.llm_class || "RuleGuidedSOCAnalystLLM")}</span>
    <span class="chip">Iterations: ${aiReport.iteration_count ?? "--"}</span>
    <span class="chip">Total: ${totalMs.toFixed(1)} ms</span>
    ${verdictBadge(c.agent_verdict)}
  `;

  const visibleSteps = highlightIdx !== null ? steps.slice(0, highlightIdx + 1) : steps;
  updateDiagramFromSteps(visibleSteps, highlightIdx);

  els.aiTraceCount.textContent = `${steps.length} bước`;
  if (!steps.length) {
    els.aiTraceTimeline.innerHTML =
      '<div class="empty-placeholder">Case này chưa có nhật ký Execution Trace. Bấm "▶ Chạy &amp; Giám sát AI" để thực thi và ghi vết.</div>';
  } else {
    els.aiTraceTimeline.innerHTML = steps
      .map((s, idx) => {
        const hl = highlightIdx === idx ? "step-highlight" : "";
        const errCls = s.status === "error" ? "step-error" : "";
        const details = s.details || {};

        let toolsHtml = "";
        if (Array.isArray(details.tools) && details.tools.length) {
          toolsHtml = `
            <div class="trace-tools-list">
              ${details.tools
                .map(
                  (t) => `
                  <div class="trace-tool-item">
                    <div class="trace-tool-top">
                      <strong class="mono" style="color:var(--accent);">🔧 ${escapeHtml(t.tool)}</strong>
                      <span class="mono" style="color:var(--text-muted);">${Number(t.duration_ms || 0).toFixed(1)} ms</span>
                    </div>
                    <div class="mono" style="font-size:11px; color:var(--text-dim);">args: ${escapeHtml(JSON.stringify(t.args || {}))}</div>
                    <div style="margin-top:3px; color:var(--text);">↳ ${escapeHtml(t.output_summary || "")}</div>
                  </div>
                `
                )
                .join("")}
            </div>
          `;
        }

        return `
          <div class="trace-step-card ${hl} ${errCls}">
            <div class="trace-step-head">
              <span class="trace-step-title">#${s.step} · ${escapeHtml(s.title)}</span>
              <span class="trace-step-time">${Number(s.duration_ms || 0).toFixed(1)} ms</span>
            </div>
            <div class="trace-step-summary">${escapeHtml(s.summary || "")}</div>
            ${toolsHtml}
            <details class="trace-details-toggle">
              <summary>Xem chi tiết JSON State</summary>
              <pre class="code-block" style="margin-top:6px;">${escapeHtml(JSON.stringify(details, null, 2))}</pre>
            </details>
          </div>
        `;
      })
      .join("");
  }

  // Forensic Breakdown Card
  if (Object.keys(breakdown).length) {
    const confStr = breakdown.confidence != null ? `${(breakdown.confidence * 100).toFixed(1)}%` : "--";
    const ipScope =
      breakdown.is_private_source_ip === true
        ? "Internal / Private"
        : breakdown.is_private_source_ip === false
        ? "External / Public"
        : "N/A";
    els.aiForensicBreakdown.innerHTML = `
      <div class="forensic-kv-grid">
        <div class="forensic-kv">
          <div class="forensic-kv-label">Verdict</div>
          <div class="forensic-kv-val">${verdictBadge(breakdown.verdict)}</div>
        </div>
        <div class="forensic-kv">
          <div class="forensic-kv-label">Confidence Score</div>
          <div class="forensic-kv-val">${escapeHtml(confStr)}</div>
        </div>
        <div class="forensic-kv">
          <div class="forensic-kv-label">Max Threat Intel</div>
          <div class="forensic-kv-val">${escapeHtml(String(breakdown.max_reputation_score ?? 0))}/100</div>
        </div>
        <div class="forensic-kv">
          <div class="forensic-kv-label">Source IP Scope</div>
          <div class="forensic-kv-val">${escapeHtml(ipScope)}</div>
        </div>
        <div class="forensic-kv">
          <div class="forensic-kv-label">Evidence Logs</div>
          <div class="forensic-kv-val">${escapeHtml(String(breakdown.evidence_count ?? 0))} logs</div>
        </div>
        <div class="forensic-kv">
          <div class="forensic-kv-label">Extracted IoCs</div>
          <div class="forensic-kv-val">${escapeHtml(String(breakdown.artifact_count ?? 0))} artifacts</div>
        </div>
      </div>
      <div style="font-size:12.5px; color:var(--text-muted); margin-bottom:6px;">
        <strong>Matched Rules:</strong> <span class="mono">${escapeHtml((breakdown.matched_rules || []).join(", ") || "--")}</span>
      </div>
      <div style="font-size:12.5px; color:var(--text-muted);">
        <strong>Root Cause:</strong> ${escapeHtml(breakdown.root_cause || "--")}
      </div>
    `;
  } else {
    els.aiForensicBreakdown.innerHTML = '<div class="empty-placeholder">Chưa có bảng chấm điểm Forensic.</div>';
  }

  // LLM Notes
  if (llmAnalysis) {
    els.aiLlmNotes.innerHTML = `<div class="markdown-body">${renderMarkdown(llmAnalysis)}</div>`;
  } else {
    els.aiLlmNotes.innerHTML = '<div class="empty-placeholder">Chưa có ghi chú suy luận từ LLM.</div>';
  }
}

function replayAiFlow() {
  if (state.replayTimer) {
    clearInterval(state.replayTimer);
    state.replayTimer = null;
  }
  const c = state.selectedCase;
  const steps = c?.ai_report?.trace_steps || [];
  if (!steps.length) {
    showBanner("Case hiện tại chưa có Execution Trace để phát lại.", "info");
    return;
  }

  let idx = 0;
  renderAiWorkflowMonitor(c, idx);
  state.replayTimer = setInterval(() => {
    idx += 1;
    if (idx >= steps.length) {
      clearInterval(state.replayTimer);
      state.replayTimer = null;
      renderAiWorkflowMonitor(c, null);
      return;
    }
    renderAiWorkflowMonitor(c, idx);
  }, 850);
}

// ==================== DATA LOADING ====================

async function loadCases() {
  if (!state.token) return;
  const params = new URLSearchParams({ limit: "200" });
  if (els.filterCaseStatus.value) params.set("status", els.filterCaseStatus.value);
  if (els.filterCaseLevel.value) params.set("level", els.filterCaseLevel.value);
  if (els.filterCaseIp.value.trim()) params.set("source_ip", els.filterCaseIp.value.trim());

  const [filteredCases, allCases, allAlerts, recentEvents] = await Promise.all([
    apiFetch(`/api/v1/cases?${params.toString()}`),
    apiFetch("/api/v1/cases?limit=500"),
    apiFetch("/api/v1/alerts?limit=500"),
    apiFetch("/api/v1/events?limit=100"),
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

  state.allCases = allCases;
  state.allAlerts = allAlerts;
  state.cases = visibleCases;
  state.lastSyncAt = new Date().toISOString();

  renderOverview(allCases, allAlerts, recentEvents.length);
  renderCaseQueue(visibleCases);
  syncAiCaseSelector(allCases);

  if (state.selectedCaseId == null && allCases.length > 0) {
    await selectCase(allCases[0].id);
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
    renderAiWorkflowMonitor(fullCase);
  } catch (err) {
    if (silentNotFound && err.status === 404) {
      state.selectedCase = null;
      renderCaseDetail(null);
      renderAiWorkflowMonitor(null);
      return;
    }
    handleApiError(err);
  }
}

async function triggerInvestigation(caseId) {
  if (state.isInvestigating) return;
  state.isInvestigating = true;
  els.navBadgeAi.classList.remove("hidden");
  els.aiFlowRunBtn.disabled = true;
  els.aiFlowRunBtn.textContent = "⏳ Đang chạy AI Agent...";
  renderCaseDetail(state.selectedCase);

  // Highlight reasoning node while running
  resetDiagramNodes();
  els.langgraphDiagram.querySelector('[data-node="agent_reasoning"]')?.classList.add("lg-active");
  hideBanner();

  try {
    const updated = await apiFetch(`/api/v1/cases/${caseId}/investigate`, { method: "POST" });
    state.selectedCase = updated;
    await loadCases();
    renderAiWorkflowMonitor(updated);
    showBanner(`Đã hoàn tất điều tra AI cho Case #${caseId}.`, "info");
  } catch (err) {
    handleApiError(err);
  } finally {
    state.isInvestigating = false;
    els.navBadgeAi.classList.add("hidden");
    els.aiFlowRunBtn.disabled = false;
    els.aiFlowRunBtn.textContent = "▶ Chạy & Giám sát AI";
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

// ==================== TELEMETRY TAB (ALERTS & EVENTS) ====================

function switchTelemetrySubtab(subtab) {
  state.telemetrySubtab = subtab;
  els.subtabBtns.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.subtab === subtab);
  });
  els.subpanelAlerts.classList.toggle("hidden", subtab !== "alerts");
  els.subpanelEvents.classList.toggle("hidden", subtab !== "events");
  if (subtab === "alerts") loadAlerts();
  else loadEvents();
}

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
  els.telemetryMiniSummary.innerHTML = `<span class="chip">${alerts.length} Alerts</span>`;

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
      switchTab("cases");
      await selectCase(Number(btn.dataset.caseId));
    });
  });
}

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

  // Dataset mini chips
  const dsCounts = new Map();
  events.forEach((ev) => {
    const ds = ev.event?.dataset || "unknown";
    dsCounts.set(ds, (dsCounts.get(ds) || 0) + 1);
  });
  els.telemetryMiniSummary.innerHTML = Array.from(dsCounts.entries())
    .slice(0, 4)
    .map(([ds, cnt]) => `<span class="chip">${escapeHtml(ds)}: ${cnt}</span>`)
    .join("");

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
      const preview = rawLine.length > 85 ? `${rawLine.slice(0, 85)}…` : rawLine;

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
  const meta = TAB_META[tabName] || TAB_META.overview;
  els.pageTitle.textContent = meta.title;
  els.pageSubtitle.textContent = meta.subtitle;

  els.navItems.forEach((btn) => {
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
    if (state.activeTab === "overview" || state.activeTab === "cases" || state.activeTab === "ai-flow") {
      await loadCases();
    } else if (state.activeTab === "telemetry") {
      if (state.telemetrySubtab === "alerts") await loadAlerts();
      else await loadEvents();
    }
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
  els.navItems.forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  els.overviewGotoCases.addEventListener("click", () => switchTab("cases"));

  els.subtabBtns.forEach((btn) => {
    btn.addEventListener("click", () => switchTelemetrySubtab(btn.dataset.subtab));
  });

  els.aiFlowCaseSelect.addEventListener("change", (e) => {
    const id = Number(e.target.value);
    if (id) selectCase(id);
  });
  els.aiFlowReplayBtn.addEventListener("click", replayAiFlow);
  els.aiFlowRunBtn.addEventListener("click", () => {
    const id = Number(els.aiFlowCaseSelect.value) || state.selectedCaseId;
    if (id) triggerInvestigation(id);
    else showBanner("Vui lòng chọn một Case để chạy điều tra AI.", "info");
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
    loadAlerts();
  });
  els.alertsFilterReset.addEventListener("click", () => {
    els.alertsFilterForm.reset();
    loadAlerts();
  });

  els.eventsFilterForm.addEventListener("submit", (e) => {
    e.preventDefault();
    loadEvents();
  });
  els.eventsFilterReset.addEventListener("click", () => {
    els.eventsFilterForm.reset();
    loadEvents();
  });
}

// ==================== BOOTSTRAP ====================

bindEvents();
updateAuthUi();
refreshActiveTab();
