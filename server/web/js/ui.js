import { escapeHtml } from "../markdown.js";
import { els } from "./state.js";

export function iconHtml(name, sizeClass = "ui-icon-sm", extraClass = "") {
  const cls = ["ui-icon", sizeClass, extraClass].filter(Boolean).join(" ");
  return `<span class="${cls}" style="--icon-url: url('/static/icons/${escapeHtml(name)}.svg');" aria-hidden="true"></span>`;
}

export function showBanner(message, type = "error") {
  els.alertBannerMsg.textContent = message;
  els.alertBanner.classList.remove("hidden", "banner-info");
  if (type === "info") {
    els.alertBanner.classList.add("banner-info");
  }
}

export function hideBanner() {
  els.alertBanner.classList.add("hidden");
}

export function formatDate(iso) {
  if (!iso) return "--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString("vi-VN", { hour12: false });
}

export function formatShortTime(iso) {
  if (!iso) return "--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "--";
  return d.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", hour12: false });
}

export function severityBadge(level) {
  const norm = String(level || "low").toLowerCase();
  return `<span class="badge badge-${escapeHtml(norm)}">${escapeHtml(norm)}</span>`;
}

export function statusBadge(statusValue) {
  const norm = String(statusValue || "open").toLowerCase();
  const cls = norm === "closed" ? "badge-closed" : "badge-open";
  return `<span class="badge ${cls}">${escapeHtml(norm)}</span>`;
}

export function verdictBadge(verdict) {
  if (!verdict) return `<span class="badge badge-pending">Pending AI</span>`;
  const lower = verdict.toLowerCase();
  let cls = "badge-suspicious";
  if (lower.includes("true")) cls = "badge-tp";
  else if (lower.includes("false")) cls = "badge-fp";
  return `<span class="badge ${cls}">${escapeHtml(verdict)}</span>`;
}

export function openModal(modalEl) {
  modalEl.classList.remove("hidden");
}

export function closeModal(modalEl) {
  modalEl.classList.add("hidden");
}
