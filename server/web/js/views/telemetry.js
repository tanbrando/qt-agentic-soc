import { escapeHtml } from "../../markdown.js";
import { apiFetch } from "../api.js";
import { els, state } from "../state.js";
import { formatDate, openModal, severityBadge } from "../ui.js";

export async function loadAlerts(onJumpCase) {
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
          <td class="mono break-anywhere" style="font-size:12.5px;">${escapeHtml(JSON.stringify(a.group_key || {}))}</td>
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
    btn.addEventListener("click", () => onJumpCase(Number(btn.dataset.caseId)));
  });
}

export async function loadEvents() {
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
          <td class="mono" style="font-size:12.5px;">${escapeHtml(preview)}</td>
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

export function switchTelemetrySubtab(subtab, onJumpCase) {
  state.telemetrySubtab = subtab;
  els.subtabBtns.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.subtab === subtab);
  });
  els.subpanelAlerts.classList.toggle("hidden", subtab !== "alerts");
  els.subpanelEvents.classList.toggle("hidden", subtab !== "events");
  if (subtab === "alerts") loadAlerts(onJumpCase);
  else loadEvents();
}
