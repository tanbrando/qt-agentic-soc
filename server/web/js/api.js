import { els, state } from "./state.js";
import { showBanner } from "./ui.js";

export async function apiFetch(path, options = {}) {
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

export function updateAuthUi() {
  const hasToken = Boolean(state.token.trim());
  els.tokenBtnLabel.textContent = hasToken ? "Token: Connected" : "Set Operator Token";
  els.authEmptyState.classList.toggle("hidden", hasToken);
}

export function handleApiError(err) {
  if (err.status === 401 || err.status === 403) {
    showBanner(`Lỗi xác thực (${err.status}): ${err.message}. Vui lòng kiểm tra Operator Token.`, "error");
    updateAuthUi();
    return;
  }
  showBanner(`Lỗi API: ${err.message}`, "error");
}

export async function checkHealth() {
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
