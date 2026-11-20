import { escapeHtml } from "../../markdown.js";
import { renderDonutChart, renderHorizontalBars, renderTimelineChart } from "../charts.js";
import { els, state } from "../state.js";
import { formatShortTime, severityBadge, statusBadge, verdictBadge } from "../ui.js";

export function renderOverview(allCases, allAlerts, recentEventsCount, { onOpenCase, onOpenAiFlow }) {
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
      { label: "Pending AI", count: pendingCount, color: "#94a3b8" },
    ],
    "Verdict"
  );

  renderTimelineChart(els.chartAlertsTimeline, allAlerts);

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
    btn.addEventListener("click", () => onOpenCase(Number(btn.dataset.caseId)));
  });

  els.overviewPriorityBody.querySelectorAll(".ov-open-ai").forEach((btn) => {
    btn.addEventListener("click", () => onOpenAiFlow(Number(btn.dataset.caseId)));
  });
}
