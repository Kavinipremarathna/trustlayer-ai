const API_BASE = "http://127.0.0.1:8000";

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatErrorDetail(detail) {
  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    return detail
      .map((item) => item?.msg || item?.message || JSON.stringify(item))
      .join("; ");
  }

  if (detail && typeof detail === "object") {
    return detail.msg || detail.message || JSON.stringify(detail);
  }

  return "Request failed";
}

function renderResult(data) {
  let output = document.getElementById("output");
  let risk = data && data.risk ? data.risk : {};
  let analysis = data && data.analysis ? data.analysis : {};
  let label = (risk.label || "Unknown").toLowerCase();
  let chipClass = "chip";

  if (label === "safe") chipClass += " safe";
  else if (label === "suspicious") chipClass += " suspicious";
  else if (label === "dangerous") chipClass += " dangerous";

  let reasons = Array.isArray(risk.reasons) ? risk.reasons : [];
  let signals = Array.isArray(risk.signals) ? risk.signals : [];
  let recommendations = Array.isArray(risk.recommendations)
    ? risk.recommendations
    : [];
  let reasonsHtml = reasons.length
    ? `<ul class="reason-list">${reasons
        .map((reason) => `<li>${escapeHtml(reason)}</li>`)
        .join("")}</ul>`
    : '<p class="muted">No risk reasons reported.</p>';

  let signalsHtml = signals.length
    ? `<div class="signal-grid">${signals
        .map(
          (signal) => `
            <article class="signal-card">
              <div class="signal-card-head">
                <span class="signal-points">+${Number(signal.points) || 0}</span>
                <span class="signal-rule">${escapeHtml(signal.rule || "rule")}</span>
              </div>
              <p>${escapeHtml(signal.message || "Triggered rule")}</p>
              <small>${escapeHtml(signal.recommendation || "")}</small>
            </article>`,
        )
        .join("")}</div>`
    : "";

  let recommendationsHtml = recommendations.length
    ? `<ul class="recommend-list">${recommendations
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul>`
    : '<p class="muted">No recommendations generated.</p>';

  let target = analysis.filename || analysis.domain || "N/A";
  let detectedType =
    analysis.detected_type ||
    (analysis.uses_https === false ? "Non-HTTPS URL" : "N/A");

  output.innerHTML = `
    <div class="result-head">
      <h3>Latest Result</h3>
      <span class="${chipClass}">${escapeHtml(risk.label || "Unknown")}</span>
    </div>
    <div class="score-banner ${label}">
      <div>
        <p class="score-label">Risk Score</p>
        <p class="score-value">${Number.isFinite(risk.score) ? risk.score : 0}</p>
      </div>
      <div class="score-copy">
        <span>${escapeHtml(risk.confidence || "Medium")} confidence</span>
        <span>${escapeHtml(risk.scope || "balanced")} scope</span>
      </div>
    </div>
    <div class="meta-grid">
      <div class="meta-box">
        <p class="meta-title">Scope</p>
        <p class="meta-value">${escapeHtml(risk.scope || "balanced")}</p>
      </div>
      <div class="meta-box">
        <p class="meta-title">Confidence</p>
        <p class="meta-value">${escapeHtml(risk.confidence || "Medium")}</p>
      </div>
      <div class="meta-box">
        <p class="meta-title">Target</p>
        <p class="meta-value">${escapeHtml(target)}</p>
      </div>
    </div>
    <div class="summary">
      <div><strong>Detected Type:</strong> ${escapeHtml(detectedType)}</div>
    </div>
    ${signalsHtml}
    <h4>Reasons</h4>
    ${reasonsHtml}
    <h4>Recommendations</h4>
    ${recommendationsHtml}
    <pre class="raw">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
  `;
}

function renderError(message) {
  let output = document.getElementById("output");
  output.innerHTML = `
    <div class="result-head">
      <h3>Latest Result</h3>
      <span class="chip dangerous">Error</span>
    </div>
    <p class="muted">${escapeHtml(message)}</p>
  `;
}

async function uploadFile() {
  let file = document.getElementById("fileInput").files[0];
  let scope = document.getElementById("scopeInput").value;

  if (!file) {
    renderError("Please choose a file before scanning.");
    return;
  }

  let formData = new FormData();
  formData.append("file", file);

  try {
    let res = await fetch(
      `${API_BASE}/scan-file/?scope=${encodeURIComponent(scope)}`,
      {
        method: "POST",
        body: formData,
      },
    );

    let data = await res.json();
    if (!res.ok) {
      throw new Error(
        formatErrorDetail(data.detail || data.error || "File scan failed"),
      );
    }

    renderResult(data);
  } catch (err) {
    renderError(err.message || "File scan failed");
  }
}

async function scanURL() {
  let url = document.getElementById("urlInput").value;
  let scope = document.getElementById("scopeInput").value;

  if (!url.trim()) {
    renderError("Please enter a URL before scanning.");
    return;
  }

  try {
    let res = await fetch(`${API_BASE}/scan-url/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url, scope }),
    });

    let data = await res.json();
    if (!res.ok) {
      throw new Error(
        formatErrorDetail(data.detail || data.error || "URL scan failed"),
      );
    }

    renderResult(data);
  } catch (err) {
    renderError(err.message || "URL scan failed");
  }
}
