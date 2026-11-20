import { apiFetch, checkHealth, handleApiError, updateAuthUi } from "./js/api.js";
import { els, state, TAB_META, TOKEN_STORAGE_KEY } from "./js/state.js";
import { closeModal, hideBanner, iconHtml, openModal, showBanner } from "./js/ui.js";
import { renderAiWorkflowMonitor, replayAiFlow, resetDiagramNodes, syncAiCaseSelector } from "./js/views/aiFlow.js";
import { renderCaseDetail, renderCaseQueue } from "./js/views/cases.js";
import { renderOverview } from "./js/views/overview.js";
import { loadAlerts, loadEvents, switchTelemetrySubtab } from "./js/views/telemetry.js";

const caseDetailActions = {
  onInvestigate: (caseId) => triggerInvestigation(caseId),
  onToggleStatus: (caseId, nextStatus) => toggleCaseStatus(caseId, nextStatus),
  onOpenAiFlow: () => switchTab("ai-flow"),
  onJumpIpEvents: (ip) => {
    state.telemetrySubtab = "events";
    switchTab("telemetry");
    els.filterEventIp.value = ip;
    loadEvents();
  },
};

async function jumpToCase(caseId) {
  switchTab("cases");
  await selectCase(caseId);
}

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

  renderOverview(allCases, allAlerts, recentEvents.length, {
    onOpenCase: jumpToCase,
    onOpenAiFlow: async (caseId) => {
      await selectCase(caseId);
      switchTab("ai-flow");
    },
  });
  renderCaseQueue(visibleCases, selectCase);
  syncAiCaseSelector(allCases);

  if (state.selectedCaseId == null && allCases.length > 0) {
    await selectCase(allCases[0].id);
  } else if (state.selectedCaseId != null) {
    await selectCase(state.selectedCaseId, { silentNotFound: true });
  }
}

async function selectCase(caseId, { silentNotFound = false } = {}) {
  state.selectedCaseId = caseId;
  renderCaseQueue(state.cases, selectCase);
  try {
    const fullCase = await apiFetch(`/api/v1/cases/${caseId}`);
    state.selectedCase = fullCase;
    renderCaseDetail(fullCase, caseDetailActions);
    renderAiWorkflowMonitor(fullCase);
  } catch (err) {
    if (silentNotFound && err.status === 404) {
      state.selectedCase = null;
      renderCaseDetail(null, caseDetailActions);
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
  els.aiFlowRunBtn.innerHTML = `${iconHtml("spinner", "ui-icon-sm", "ui-icon-spin")}<span>Đang chạy AI Agent...</span>`;
  renderCaseDetail(state.selectedCase, caseDetailActions);

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
    els.aiFlowRunBtn.innerHTML = `${iconHtml("play")}<span>Chạy &amp; Giám sát AI</span>`;
    renderCaseDetail(state.selectedCase, caseDetailActions);
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
  document.querySelector(".main-content")?.scrollTo({ top: 0 });
  refreshActiveTab();
}

async function refreshActiveTab() {
  await checkHealth();
  if (!state.token) return;
  try {
    if (state.activeTab === "overview" || state.activeTab === "cases" || state.activeTab === "ai-flow") {
      await loadCases();
    } else if (state.activeTab === "telemetry") {
      if (state.telemetrySubtab === "alerts") await loadAlerts(jumpToCase);
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

function bindEvents() {
  els.navItems.forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  els.overviewGotoCases.addEventListener("click", () => switchTab("cases"));

  els.subtabBtns.forEach((btn) => {
    btn.addEventListener("click", () => switchTelemetrySubtab(btn.dataset.subtab, jumpToCase));
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
    loadAlerts(jumpToCase);
  });
  els.alertsFilterReset.addEventListener("click", () => {
    els.alertsFilterForm.reset();
    loadAlerts(jumpToCase);
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

bindEvents();
updateAuthUi();
refreshActiveTab();
