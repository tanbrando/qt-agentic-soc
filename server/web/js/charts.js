import { escapeHtml } from "../markdown.js";

export function renderDonutChart(container, segments, centerLabel) {
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
        <circle cx="66" cy="66" r="${radius}" fill="transparent" stroke="#e2e8f0" stroke-width="16" />
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

export function renderTimelineChart(container, alerts) {
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
          <rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${barH.toFixed(1)}" rx="4" fill="#0284c7" opacity="0.9" />
          <text x="${(x + barW / 2).toFixed(1)}" y="${(y - 4).toFixed(1)}" text-anchor="middle" fill="#0f172a" font-size="10" font-weight="600">${s.alerts}</text>
          <text x="${(x + barW / 2).toFixed(1)}" y="${h - 4}" text-anchor="middle" fill="#64748b" font-size="10">${escapeHtml(s.label)}</text>
        </g>
      `;
    })
    .join("");

  container.innerHTML = `
    <svg class="timeline-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <line x1="${padX}" y1="${h - padY}" x2="${w - padX}" y2="${h - padY}" stroke="#cbd5e1" stroke-width="1" />
      ${bars}
    </svg>
  `;
}

export function renderHorizontalBars(container, items, colorFn) {
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
