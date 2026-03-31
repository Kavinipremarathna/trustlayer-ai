function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
  let recommendations = Array.isArray(risk.recommendations)
    ? risk.recommendations
    : [];
  let reasonsHtml = reasons.length
    ? `<ul class="reason-list">${reasons
        .map((reason) => `<li>${escapeHtml(reason)}</li>`)
        .join("")}</ul>`
    : '<p class="muted">No risk reasons reported.</p>';

  let recommendationsHtml = recommendations.length
    ? `<ul class="recommend-list">${recommendations
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul>`
    : '<p class="muted">No recommendations generated.</p>';

  output.innerHTML = `
    <div class="result-head">
      <h3>Latest Result</h3>
      <span class="${chipClass}">${escapeHtml(risk.label || "Unknown")}</span>
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
        <p class="meta-title">Score</p>
        <p class="meta-value">${Number.isFinite(risk.score) ? risk.score : 0}</p>
      </div>
    </div>
    <div class="summary">
      <div><strong>Target:</strong> ${escapeHtml(analysis.filename || analysis.domain || "N/A")}</div>
      <div><strong>Detected Type:</strong> ${escapeHtml(analysis.detected_type || "N/A")}</div>
    </div>
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
      `http://127.0.0.1:8000/scan-file/?scope=${encodeURIComponent(scope)}`,
      {
        method: "POST",
        body: formData,
      },
    );

    let data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "File scan failed");
    }

    renderResult(data);
  } catch (err) {
    renderError(err.message);
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
    let res = await fetch(
      `http://127.0.0.1:8000/scan-url/?url=${encodeURIComponent(url)}&scope=${encodeURIComponent(scope)}`,
      {
        method: "POST",
      },
    );

    let data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "URL scan failed");
    }

    renderResult(data);
  } catch (err) {
    renderError(err.message);
  }
}
