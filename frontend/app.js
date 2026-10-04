/* ==========================================================================
   Network IDS — SOC Dashboard Logic
   Polls the REST API every 5 seconds and renders charts + alert table.
   Polling is used because it is the simplest reliable option for beginners.
   (SSE / WebSockets would reduce latency but add complexity.)
   ========================================================================== */

const API = "";
const POLL_MS = 5000;

const charts = {};
let currentAlertId = null;

/* ---------------- Helpers ---------------- */

async function getJSON(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return res.json();
}

async function sendJSON(path, method, body) {
  const res = await fetch(API + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

const SEV_COLORS = {
  CRITICAL: "#f2545b", HIGH: "#ff8c42", MEDIUM: "#f0b429",
  LOW: "#4fc3f7", INFO: "#8a94a6",
};

const PALETTE = ["#35c5f2", "#35d07f", "#f0b429", "#f2545b", "#ff8c42",
                 "#a78bfa", "#4fc3f7", "#fb7185", "#22d3ee", "#facc15"];

function destroyChart(id) {
  if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

function makeChart(id, type, data, options = {}) {
  destroyChart(id);
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, {
    type,
    data,
    options: Object.assign({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: "#7d8ea3", font: { size: 11 } } },
      },
      scales: type === "doughnut" || type === "pie" ? {} : {
        x: { ticks: { color: "#7d8ea3", font: { size: 10 } },
             grid: { color: "#1b2532" } },
        y: { ticks: { color: "#7d8ea3", font: { size: 10 } },
             grid: { color: "#1b2532" } },
      },
    }, options),
  });
}

/* ---------------- Cards ---------------- */

async function loadStats() {
  const s = await getJSON("/api/dashboard/stats");
  document.getElementById("c-total").textContent      = s.total_flows.toLocaleString();
  document.getElementById("c-normal").textContent     = s.normal_traffic.toLocaleString();
  document.getElementById("c-suspicious").textContent = s.suspicious_traffic.toLocaleString();
  document.getElementById("c-open").textContent       = s.open_alerts.toLocaleString();
  document.getElementById("c-critical").textContent   = s.critical_alerts.toLocaleString();
  document.getElementById("c-avgrisk").textContent    = s.average_risk_score;
}

/* ---------------- Charts ---------------- */

async function loadCharts() {
  const [traffic, alerts] = await Promise.all([
    getJSON("/api/dashboard/traffic"),
    getJSON("/api/dashboard/alerts"),
  ]);

  // 1. Traffic over time
  const series = traffic.series || [];
  makeChart("ch-timeline", "line", {
    labels: series.map(p => p.time.slice(11) || p.time),
    datasets: [
      { label: "Total Flows", data: series.map(p => p.total),
        borderColor: "#35c5f2", backgroundColor: "rgba(53,197,242,.12)",
        fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
      { label: "Suspicious", data: series.map(p => p.suspicious),
        borderColor: "#f2545b", backgroundColor: "rgba(242,84,91,.10)",
        fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
    ],
  });

  // 2. Alerts by severity
  const sev = alerts.by_severity || {};
  makeChart("ch-severity", "doughnut", {
    labels: Object.keys(sev),
    datasets: [{
      data: Object.values(sev),
      backgroundColor: Object.keys(sev).map(k => SEV_COLORS[k] || "#8a94a6"),
      borderColor: "#131a24", borderWidth: 2,
    }],
  }, { cutout: "62%" });

  // 3. Protocol distribution
  const proto = alerts.by_protocol || {};
  makeChart("ch-protocol", "pie", {
    labels: Object.keys(proto),
    datasets: [{ data: Object.values(proto),
                 backgroundColor: PALETTE, borderColor: "#131a24", borderWidth: 2 }],
  });

  // 4. Top alert types
  const types = alerts.by_type || {};
  makeChart("ch-types", "bar", {
    labels: Object.keys(types),
    datasets: [{ label: "Alerts", data: Object.values(types),
                 backgroundColor: "#35c5f2", borderRadius: 4 }],
  }, { indexAxis: "y",
       plugins: { legend: { display: false } },
       scales: { x: { ticks: { color: "#7d8ea3" }, grid: { color: "#1b2532" } },
                 y: { ticks: { color: "#7d8ea3", font: { size: 10 } },
                      grid: { display: false } } } });

  // 5. Top destination ports
  const ports = alerts.by_port || {};
  makeChart("ch-ports", "bar", {
    labels: Object.keys(ports),
    datasets: [{ label: "Alerts", data: Object.values(ports),
                 backgroundColor: "#f0b429", borderRadius: 4 }],
  }, { plugins: { legend: { display: false } } });

  // 6. Top source IPs
  const srcs = alerts.by_source_ip || {};
  makeChart("ch-sources", "bar", {
    labels: Object.keys(srcs),
    datasets: [{ label: "Alerts", data: Object.values(srcs),
                 backgroundColor: "#f2545b", borderRadius: 4 }],
  }, { indexAxis: "y",
       plugins: { legend: { display: false } },
       scales: { x: { ticks: { color: "#7d8ea3" }, grid: { color: "#1b2532" } },
                 y: { ticks: { color: "#7d8ea3", font: { size: 10 } },
                      grid: { display: false } } } });

  // 7. Risk histogram
  const hist = alerts.risk_histogram || {};
  makeChart("ch-risk", "bar", {
    labels: Object.keys(hist),
    datasets: [{ label: "Flows", data: Object.values(hist),
                 backgroundColor: ["#35d07f", "#4fc3f7", "#f0b429", "#ff8c42", "#f2545b"],
                 borderRadius: 4 }],
  }, { plugins: { legend: { display: false } } });

  // 8. Alert status
  const st = alerts.by_status || {};
  makeChart("ch-status", "doughnut", {
    labels: Object.keys(st),
    datasets: [{ data: Object.values(st), backgroundColor: PALETTE,
                 borderColor: "#131a24", borderWidth: 2 }],
  }, { cutout: "62%" });

  renderTable(alerts.recent_alerts || []);
}

/* ---------------- Alert Table ---------------- */

function renderTable(alerts) {
  const sevFilter  = document.getElementById("f-severity").value;
  const statFilter = document.getElementById("f-status").value;
  const protoFilter= document.getElementById("f-protocol").value;

  const rows = alerts.filter(a =>
    (!sevFilter   || a.severity  === sevFilter) &&
    (!statFilter  || a.status    === statFilter) &&
    (!protoFilter || a.protocol  === protoFilter));

  const tbody = document.querySelector("#alerts-table tbody");
  tbody.innerHTML = "";

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted"
      style="text-align:center;padding:26px">
      No alerts yet — click "Simulate 20 Flows" to generate activity.</td></tr>`;
    return;
  }

  for (const a of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="muted">${(a.timestamp || "").slice(11, 19)}</td>
      <td>${a.source_ip || "-"}</td>
      <td>${a.destination_ip || "-"}</td>
      <td>${a.protocol || "-"}</td>
      <td>${a.alert_type || "-"}</td>
      <td><span class="badge sev-${a.severity}">${a.severity}</span></td>
      <td>${Math.round(a.risk_score || 0)}</td>
      <td><span class="badge st-${a.status}">${a.status}</span></td>`;
    tr.addEventListener("click", () => openAlert(a.alert_id));
    tbody.appendChild(tr);
  }
}

/* ---------------- Investigation Modal ---------------- */

async function openAlert(alertId) {
  currentAlertId = alertId;
  const a = await getJSON(`/api/alerts/${alertId}`);
  const f = a.flow || {};

  document.getElementById("m-title").textContent =
    `Alert ${a.alert_id} — ${a.alert_type}`;

  const notesHtml = (a.notes || []).length
    ? a.notes.map(n => `<div class="note">${escapeHtml(n.note)}
        <span class="meta">${n.analyst} · ${n.created_at}</span></div>`).join("")
    : `<p class="muted">No analyst notes yet.</p>`;

  document.getElementById("m-body").innerHTML = `
    <div class="kv">
      <span class="k">Alert ID</span><span>${a.alert_id}</span>
      <span class="k">Timestamp</span><span>${a.timestamp || "-"}</span>
      <span class="k">Source</span><span>${a.source_ip}:${a.source_port}</span>
      <span class="k">Destination</span><span>${a.destination_ip}:${a.destination_port}</span>
      <span class="k">Protocol</span><span>${a.protocol}</span>
      <span class="k">Severity</span>
        <span><span class="badge sev-${a.severity}">${a.severity}</span></span>
      <span class="k">Status</span>
        <span><span class="badge st-${a.status}">${a.status}</span></span>
      <span class="k">Matched Rules</span><span>${(a.matched_rules || []).join(", ") || "—"}</span>
      <span class="k">Anomaly Score</span><span>${a.anomaly_score ?? "—"}</span>
      <span class="k">ML Score</span><span>${a.ml_score ?? "disabled"}</span>
      <span class="k">Final Risk Score</span><span><b>${a.risk_score}/100</b> (${a.classification})</span>
    </div>

    <div class="section-title">Reason</div>
    <p>${escapeHtml(a.description || "")}</p>

    <div class="section-title">Traffic Statistics</div>
    <div class="kv">
      <span class="k">Packets</span><span>${f.packet_count ?? "-"}</span>
      <span class="k">Bytes</span><span>${f.byte_count ?? "-"}</span>
      <span class="k">Duration (s)</span><span>${f.duration_seconds ?? "-"}</span>
      <span class="k">Connections</span><span>${f.connection_count ?? "-"}</span>
      <span class="k">Failed Connections</span><span>${f.failed_connection_count ?? "-"}</span>
      <span class="k">SYN Count</span><span>${f.syn_count ?? "-"}</span>
      <span class="k">Unique Dest Ports</span><span>${f.unique_destination_ports ?? "-"}</span>
      <span class="k">Packets/sec</span><span>${f.packets_per_second ?? "-"}</span>
      <span class="k">Bytes/sec</span><span>${f.bytes_per_second ?? "-"}</span>
    </div>

    <div class="section-title">Recommended Investigation Steps</div>
    <ul class="steps">
      ${(a.recommended_investigation_steps || []).map(s => `<li>${s}</li>`).join("")}
    </ul>

    <div class="section-title">Analyst Notes</div>
    ${notesHtml}

    <div class="section-title">Update Status</div>
    <div class="actions">
      <button class="btn" onclick="setStatus('NEW')">NEW</button>
      <button class="btn" onclick="setStatus('INVESTIGATING')">INVESTIGATING</button>
      <button class="btn" onclick="setStatus('RESOLVED')">RESOLVED</button>
      <button class="btn" onclick="setStatus('FALSE_POSITIVE')">FALSE POSITIVE</button>
    </div>

    <div class="section-title">Add Note</div>
    <textarea id="note-input" placeholder="Describe your findings..."></textarea>
    <div class="actions">
      <button class="btn primary" onclick="addNote()">Save Note</button>
    </div>
  `;

  document.getElementById("modal").classList.remove("hidden");
}

async function setStatus(status) {
  if (!currentAlertId) return;
  try {
    await sendJSON(`/api/alerts/${currentAlertId}/status`, "PUT", { status });
    await openAlert(currentAlertId);
    await refreshAll();
  } catch (e) { alert(`Error: ${e.message}`); }
}

async function addNote() {
  if (!currentAlertId) return;
  const input = document.getElementById("note-input");
  const text = input.value.trim();
  if (!text) return;
  try {
    await sendJSON(`/api/alerts/${currentAlertId}/notes`, "POST",
                   { note: text, analyst: "soc-analyst" });
    await openAlert(currentAlertId);
  } catch (e) { alert(`Error: ${e.message}`); }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;",
       '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------------- Simulate Button ---------------- */

async function simulate() {
  const btn = document.getElementById("simulate-btn");
  btn.disabled = true; btn.textContent = "Simulating...";
  try {
    await sendJSON("/api/simulate/tick", "POST", { count: 20, mode: "mixed" });
    await refreshAll();
  } catch (e) {
    alert(`Simulation failed: ${e.message}`);
  } finally {
    btn.disabled = false; btn.textContent = "▶ Simulate 20 Flows";
  }
}

/* ---------------- Refresh loop ---------------- */

async function refreshAll() {
  try {
    await Promise.all([loadStats(), loadCharts()]);
    document.getElementById("last-updated").textContent =
      "Updated " + new Date().toLocaleTimeString();
  } catch (e) {
    console.error("Refresh failed:", e);
    document.getElementById("last-updated").textContent = "API unavailable";
  }
}

/* ---------------- Wire up ---------------- */

document.getElementById("simulate-btn").addEventListener("click", simulate);
document.getElementById("refresh-btn").addEventListener("click", refreshAll);
document.getElementById("m-close").addEventListener("click", () =>
  document.getElementById("modal").classList.add("hidden"));

["f-severity", "f-status", "f-protocol"].forEach(id =>
  document.getElementById(id).addEventListener("change", loadCharts));

window.setStatus = setStatus;
window.addNote = addNote;

refreshAll();
setInterval(refreshAll, POLL_MS);