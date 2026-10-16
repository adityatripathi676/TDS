const metricsGrid = document.getElementById("metricsGrid");
const alertsList = document.getElementById("alertsList");
const eventsList = document.getElementById("eventsList");
const baselineGrid = document.getElementById("baselineGrid");
const alertCountBadge = document.getElementById("alertCountBadge");
const resetBtn = document.getElementById("resetBtn");
const scanBtn = document.getElementById("scanBtn");
const startMonitorBtn = document.getElementById("startMonitorBtn");
const stopMonitorBtn = document.getElementById("stopMonitorBtn");
const systemOverview = document.getElementById("systemOverview");
const monitorStatus = document.getElementById("monitorStatus");
const monitorStateBadge = document.getElementById("monitorStateBadge");
const suspiciousProcesses = document.getElementById("suspiciousProcesses");
const topProcesses = document.getElementById("topProcesses");

const metricLabels = {
  total_events: "Events",
  total_alerts: "Alerts",
  critical_alerts: "Critical",
  high_alerts: "High",
  medium_alerts: "Medium",
  benign_events: "Benign",
  top_event_type: "Top Event",
};

async function getJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function renderMetrics(metrics) {
  metricsGrid.innerHTML = Object.entries(metricLabels)
    .map(([key, label]) => `
      <article class="metric">
        <span class="label">${label}</span>
        <span class="value">${metrics[key] ?? 0}</span>
      </article>
    `)
    .join("");
}

function renderAlerts(alerts) {
  alertCountBadge.textContent = alerts.length;
  alertsList.innerHTML = alerts.length
    ? alerts.map((alert) => `
      <div class="item">
        <div class="item-top">
          <div class="title">${alert.summary}</div>
          <span class="pill ${alert.severity}">${alert.severity}</span>
        </div>
        <div class="meta">Host: ${alert.host} | Score: ${alert.score}</div>
        <div class="meta">MITRE: ${(alert.mitre_tags || []).join(", ")}</div>
        <div class="muted">${(alert.reasons || []).join("; ")}</div>
      </div>
    `).join("")
    : `<div class="item"><div class="muted">No alerts yet. Run a simulation to populate the dashboard.</div></div>`;
}

function renderEvents(events) {
  eventsList.innerHTML = events.length
    ? events.map((event) => `
      <div class="item">
        <div class="item-top">
          <div class="title">${event.event_type}</div>
          <span class="pill low">${event.host}</span>
        </div>
        <div class="meta">User: ${event.user} | Process: ${event.process_name || "n/a"}</div>
        <div class="muted">${JSON.stringify(event.metadata)}</div>
      </div>
    `).join("")
    : `<div class="item"><div class="muted">No events yet.</div></div>`;
}

function renderBaseline(baseline) {
  baselineGrid.innerHTML = Object.entries(baseline)
    .map(([name, stats]) => `
      <div class="baseline-card">
        <strong>${name.replaceAll("_", " ")}</strong>
        <div class="meta">Mean: ${stats.mean}</div>
        <div class="meta">Std Dev: ${stats.std}</div>
      </div>
    `)
    .join("");
}

function renderSystem(snapshot) {
  const tiles = [
    ["Host", snapshot.hostname],
    ["CPU", `${snapshot.cpu_percent}%`],
    ["Memory", `${snapshot.memory_percent}%`],
    ["Disk", `${snapshot.disk_percent}%`],
    ["Connections", snapshot.active_connections],
    ["Processes", snapshot.total_processes],
  ];
  systemOverview.innerHTML = tiles
    .map(([label, value]) => `
      <div class="overview-tile">
        <span class="label">${label}</span>
        <span class="value">${value}</span>
      </div>
    `)
    .join("");
}

function renderMonitorStatus(status, snapshot) {
  monitorStateBadge.textContent = status.enabled ? "Running" : "Stopped";
  monitorStateBadge.className = `badge ${status.enabled ? "" : "neutral"}`.trim();
  monitorStatus.innerHTML = `
    <div class="item">
      <div class="kv"><strong>Scans Completed</strong><span>${status.scans_completed}</span></div>
      <div class="kv"><strong>Events Generated</strong><span>${status.events_generated}</span></div>
      <div class="kv"><strong>Alerts Generated</strong><span>${status.alerts_generated}</span></div>
      <div class="kv"><strong>Interval</strong><span>${status.interval_seconds}s</span></div>
      <div class="meta tiny">Last scan: ${status.last_scan_time || snapshot.scan_time || "n/a"}</div>
    </div>
  `;
}

function renderProcessList(target, rows, emptyText) {
  target.innerHTML = rows.length
    ? rows.map((row) => `
      <div class="item">
        <div class="item-top">
          <div class="title">${row.name}</div>
          <span class="pill low">PID ${row.pid}</span>
        </div>
        <div class="meta">User: ${row.username}</div>
        <div class="meta">CPU: ${row.cpu_percent}% | Memory: ${row.memory_percent}%</div>
      </div>
    `).join("")
    : `<div class="item"><div class="muted">${emptyText}</div></div>`;
}

async function refreshDashboard() {
  const [metrics, alerts, events, baseline, system, status] = await Promise.all([
    getJson("/api/metrics"),
    getJson("/api/alerts"),
    getJson("/api/events"),
    getJson("/api/baseline"),
    getJson("/api/system"),
    getJson("/api/monitor/status"),
  ]);
  renderMetrics(metrics);
  renderAlerts(alerts);
  renderEvents(events);
  renderBaseline(baseline);
  renderSystem(system);
  renderMonitorStatus(status, system);
  renderProcessList(
    suspiciousProcesses,
    system.suspicious_processes || [],
    "No suspicious process names were detected in the latest scan."
  );
  renderProcessList(
    topProcesses,
    system.top_processes || [],
    "No process data is available yet."
  );
}

async function simulate(mode) {
  await getJson(`/api/simulate?mode=${mode}&count=5`, { method: "POST" });
  await refreshDashboard();
}

document.querySelectorAll("[data-mode]").forEach((button) => {
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await simulate(button.dataset.mode);
    } finally {
      button.disabled = false;
    }
  });
});

resetBtn.addEventListener("click", async () => {
  resetBtn.disabled = true;
  try {
    await getJson("/api/reset", { method: "POST" });
    await refreshDashboard();
  } finally {
    resetBtn.disabled = false;
  }
});

scanBtn.addEventListener("click", async () => {
  scanBtn.disabled = true;
  try {
    await getJson("/api/monitor/scan", { method: "POST" });
    await refreshDashboard();
  } finally {
    scanBtn.disabled = false;
  }
});

startMonitorBtn.addEventListener("click", async () => {
  startMonitorBtn.disabled = true;
  try {
    await getJson("/api/monitor/start", { method: "POST" });
    await refreshDashboard();
  } finally {
    startMonitorBtn.disabled = false;
  }
});

stopMonitorBtn.addEventListener("click", async () => {
  stopMonitorBtn.disabled = true;
  try {
    await getJson("/api/monitor/stop", { method: "POST" });
    await refreshDashboard();
  } finally {
    stopMonitorBtn.disabled = false;
  }
});

refreshDashboard();
setInterval(refreshDashboard, 5000);
