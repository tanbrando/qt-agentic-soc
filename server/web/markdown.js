/**
 * Zero-dependency, XSS-safe Markdown-to-HTML renderer for SOC AI Forensic Reports.
 * All input text is HTML-escaped before Markdown tags are applied.
 */

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatInline(escapedLine) {
  const codeTokens = [];
  let text = escapedLine.replace(/`([^`]+)`/g, (_m, code) => {
    const idx = codeTokens.length;
    codeTokens.push(`<code>${code}</code>`);
    return `\u0000CODE${idx}\u0000`;
  });

  text = text
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>");

  return text.replace(/\u0000CODE(\d+)\u0000/g, (_m, idx) => codeTokens[Number(idx)] || "");
}

export function renderMarkdown(markdownText) {
  if (!markdownText || !String(markdownText).trim()) {
    return '<p class="empty-placeholder">Chưa có báo cáo điều tra AI cho Case này.</p>';
  }

  const lines = escapeHtml(markdownText).replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let inCodeBlock = false;
  let codeLines = [];
  let listType = null; // "ul" | "ol"

  const closeList = () => {
    if (listType) {
      out.push(`</${listType}>`);
      listType = null;
    }
  };

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      closeList();
      if (!inCodeBlock) {
        inCodeBlock = true;
        codeLines = [];
      } else {
        out.push(`<pre><code>${codeLines.join("\n")}</code></pre>`);
        inCodeBlock = false;
        codeLines = [];
      }
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
      continue;
    }

    if (!trimmed) {
      closeList();
      continue;
    }

    if (/^---+$/.test(trimmed)) {
      closeList();
      out.push("<hr />");
      continue;
    }

    const headingMatch = trimmed.match(/^(#{1,4})\s+(.+)$/);
    if (headingMatch) {
      closeList();
      const level = headingMatch[1].length;
      out.push(`<h${level}>${formatInline(headingMatch[2])}</h${level}>`);
      continue;
    }

    if (trimmed.startsWith("&gt;")) {
      closeList();
      const quoteBody = trimmed.replace(/^&gt;\s?/, "");
      out.push(`<blockquote>${formatInline(quoteBody)}</blockquote>`);
      continue;
    }

    const ulMatch = trimmed.match(/^[-*]\s+(.+)$/);
    if (ulMatch) {
      if (listType !== "ul") {
        closeList();
        listType = "ul";
        out.push("<ul>");
      }
      out.push(`<li>${formatInline(ulMatch[1])}</li>`);
      continue;
    }

    const olMatch = trimmed.match(/^\d+\.\s+(.+)$/);
    if (olMatch) {
      if (listType !== "ol") {
        closeList();
        listType = "ol";
        out.push("<ol>");
      }
      out.push(`<li>${formatInline(olMatch[1])}</li>`);
      continue;
    }

    closeList();
    out.push(`<p>${formatInline(trimmed)}</p>`);
  }

  closeList();
  if (inCodeBlock) {
    out.push(`<pre><code>${codeLines.join("\n")}</code></pre>`);
  }

  return out.join("\n");
}

