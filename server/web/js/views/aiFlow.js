import { escapeHtml, renderMarkdown } from "../../markdown.js";
import { els, state } from "../state.js";
import { iconHtml, showBanner, verdictBadge } from "../ui.js";

export function syncAiCaseSelector(allCases) {
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

export function resetDiagramNodes() {
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

export function renderAiWorkflowMonitor(c, highlightIdx = null) {
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
      '<div class="empty-placeholder">Case này chưa có nhật ký Execution Trace. Bấm "Chạy &amp; Giám sát AI" để thực thi và ghi vết.</div>';
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
                      <strong class="mono trace-tool-name">${iconHtml("screwdriver-wrench", "ui-icon-xs")}<span>${escapeHtml(t.tool)}</span></strong>
                      <span class="mono" style="color:var(--text-muted);">${Number(t.duration_ms || 0).toFixed(1)} ms</span>
                    </div>
                    <div class="mono break-anywhere" style="font-size:12.5px; color:var(--text-dim);">args: ${escapeHtml(JSON.stringify(t.args || {}))}</div>
                    <div class="break-anywhere" style="margin-top:4px; color:var(--text);">↳ ${escapeHtml(t.output_summary || "")}</div>
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
      <div style="font-size:13.5px; color:var(--text-muted); margin-bottom:6px;">
        <strong>Matched Rules:</strong> <span class="mono">${escapeHtml((breakdown.matched_rules || []).join(", ") || "--")}</span>
      </div>
      <div style="font-size:13.5px; color:var(--text-muted);">
        <strong>Root Cause:</strong> ${escapeHtml(breakdown.root_cause || "--")}
      </div>
    `;
  } else {
    els.aiForensicBreakdown.innerHTML = '<div class="empty-placeholder">Chưa có bảng chấm điểm Forensic.</div>';
  }

  if (llmAnalysis) {
    els.aiLlmNotes.innerHTML = `<div class="markdown-body">${renderMarkdown(llmAnalysis)}</div>`;
  } else {
    els.aiLlmNotes.innerHTML = '<div class="empty-placeholder">Chưa có ghi chú suy luận từ LLM.</div>';
  }
}

export function replayAiFlow() {
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
