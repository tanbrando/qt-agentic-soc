import { escapeHtml, renderMarkdown } from "../../markdown.js";
import { els, state } from "../state.js";
import { formatDate, iconHtml, severityBadge, statusBadge, verdictBadge } from "../ui.js";

export function renderCaseQueue(cases, onSelectCase) {
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
    btn.addEventListener("click", () => onSelectCase(Number(btn.dataset.caseId)));
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
        <summary style="cursor:pointer; font-size:13px; color:var(--accent);">Xem ${reports.length} AbuseIPDB Community Reports</summary>
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
        <div style="font-size:13px; color:var(--text-muted);">
          Vendor: <strong>${escapeHtml(art.reputation_vendor || "N/A")}</strong> ·
          Score: <strong>${escapeHtml(scoreText)}</strong>
        </div>
      </div>
      ${metaItems.length ? `<div class="artifact-meta-grid">${metaItems.join("")}</div>` : ""}
      ${reportsHtml}
    </div>
  `;
}

export function renderCaseDetail(c, actions) {
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
  const statusBtnHtml =
    c.status === "open"
      ? `${iconHtml("check")}<span>Close Case</span>`
      : `${iconHtml("rotate-left")}<span>Reopen Case</span>`;

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
                <div style="font-size:13px; color:var(--text-muted);">
                  Events: <strong>${a.event_count}</strong> · End: ${escapeHtml(formatDate(a.window_end))}
                </div>
              </div>
              <div class="mono break-anywhere" style="font-size:12.5px; color:var(--text-dim);">
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
              ? `<button id="jump-ip-events-btn" type="button" class="link-btn mono">${iconHtml("magnifying-glass", "ui-icon-xs")}<span>Xem log của ${escapeHtml(c.source_ip)}</span></button>`
              : ""
          }
        </div>
      </div>

      <div class="detail-actions">
        <button id="open-ai-flow-btn" type="button" class="btn btn-ghost btn-sm">
          ${iconHtml("diagram-project")}<span>Xem Luồng AI</span>
        </button>
        <button id="run-investigate-btn" type="button" class="btn btn-primary btn-sm" ${state.isInvestigating ? "disabled" : ""}>
          ${
            state.isInvestigating
              ? `${iconHtml("spinner", "ui-icon-sm", "ui-icon-spin")}<span>Đang điều tra AI...</span>`
              : `${iconHtml("robot")}<span>Run AI Investigation</span>`
          }
        </button>
        <button id="toggle-status-btn" type="button" class="btn btn-secondary btn-sm">
          ${statusBtnHtml}
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
        <div class="metric-value" style="font-size:13px;">
          ${escapeHtml(formatDate(c.first_activity_at))} → ${escapeHtml(formatDate(c.last_activity_at))}
        </div>
      </div>
      <div class="metric-box">
        <div class="metric-label">AI Investigated At</div>
        <div class="metric-value" style="font-size:13px;">
          ${escapeHtml(formatDate(c.ai_investigated_at))}
        </div>
      </div>
    </div>

    <div class="subtab-bar">
      <div class="subtab-group">
        <button type="button" class="subtab-btn case-subtab ${activeSub === "report" ? "active" : ""}" data-case-sub="report">
          ${iconHtml("clipboard-check")}<span>Báo cáo AI Forensic</span>
        </button>
        <button type="button" class="subtab-btn case-subtab ${activeSub === "artifacts" ? "active" : ""}" data-case-sub="artifacts">
          ${iconHtml("globe")}<span>Threat Intel &amp; IoCs (${artifacts.length})</span>
        </button>
        <button type="button" class="subtab-btn case-subtab ${activeSub === "alerts" ? "active" : ""}" data-case-sub="alerts">
          ${iconHtml("bolt")}<span>Cảnh báo liên kết (${alerts.length})</span>
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
      renderCaseDetail(state.selectedCase, actions);
    });
  });

  document.getElementById("run-investigate-btn")?.addEventListener("click", () => actions.onInvestigate(c.id));
  document.getElementById("toggle-status-btn")?.addEventListener("click", () => actions.onToggleStatus(c.id, nextStatus));
  document.getElementById("open-ai-flow-btn")?.addEventListener("click", () => actions.onOpenAiFlow());
  document.getElementById("jump-ip-events-btn")?.addEventListener("click", () => actions.onJumpIpEvents(c.source_ip || ""));
}
