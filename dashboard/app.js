/* ============================================================
   MQTT Honeypot Dashboard — app.js
   Live SSE push + polling fallback.
   ============================================================ */

const API_BASE = "http://127.0.0.1:8000";

// ── DOM refs ──────────────────────────────────────────────────
const pulseDot         = document.getElementById("pulseDot");
const statusText       = document.getElementById("statusText");
const lastUpdateEl     = document.getElementById("lastUpdate");
const totalEventsEl    = document.getElementById("totalEvents");
const totalAlertsEl    = document.getElementById("totalAlerts");
const attackRatioEl    = document.getElementById("attackRatio");
const ratioBarFill     = document.getElementById("ratioBarFill");
const attackChartEl    = document.getElementById("attackChart");
const alertsListEl     = document.getElementById("alertsList");
const eventsTableBody  = document.getElementById("eventsTableBody");
const chartTotalEl     = document.getElementById("chartTotal");
const alertsBadgeEl    = document.getElementById("alertsBadge");
const eventsBadgeEl    = document.getElementById("eventsBadge");
const liveIndicatorEl  = document.getElementById("liveIndicator");

// ── Event buffer ──────────────────────────────────────────────
// We keep a rolling buffer of recent events received via SSE so the
// table can be rebuilt instantly without waiting for the next poll.
const MAX_EVENTS = 60;
let eventBuffer = [];
let alertBuffer = [];
let latestStats = null;
let sseConnected = false;
let pollingTimer = null;

// ── Colour map per attack type ────────────────────────────────
const ATTACK_COLORS = {
  normal:            { bar: "normal",            label: "🟢 Normal" },
  flood:             { bar: "flood",             label: "🔴 Flood" },
  brute_force:       { bar: "brute_force",       label: "🔴 Brute Force" },
  topic_scan:        { bar: "topic_scan",        label: "🟣 Topic Scan" },
  oversized_payload: { bar: "oversized_payload", label: "🟠 Oversized" },
};

// ── Helpers ───────────────────────────────────────────────────
function badgeClass(value) {
  const v = String(value || "").toLowerCase();
  if (v === "high")   return "high";
  if (v === "medium") return "medium";
  return "low";
}

function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString("th-TH", { hour12: false });
}

function fmtDatetime(iso) {
  return new Date(iso).toLocaleString("th-TH", { hour12: false });
}

function nowStr() {
  return new Date().toLocaleTimeString("th-TH", { hour12: false });
}

function setOnline(ok) {
  pulseDot.className = "pulse-dot " + (ok ? "online" : "offline");
  statusText.textContent = ok ? "Connected" : "Backend offline";
  statusText.style.color = ok ? "var(--ok)" : "var(--danger)";
}

function setLiveStatus(connected) {
  if (!liveIndicatorEl) return;
  if (connected) {
    liveIndicatorEl.className = "live-indicator live";
    liveIndicatorEl.innerHTML = '<span class="live-dot"></span>LIVE';
  } else {
    liveIndicatorEl.className = "live-indicator polling";
    liveIndicatorEl.innerHTML = '<span class="live-dot"></span>POLLING';
  }
}

// ── Flash effect for new rows ─────────────────────────────────
function flashElement(el) {
  el.classList.add("flash-new");
  setTimeout(() => el.classList.remove("flash-new"), 1200);
}

// ── Render Stats ──────────────────────────────────────────────
function renderStats(stats) {
  if (!stats) return;
  latestStats = stats;

  // Animate number changes
  animateNumber(totalEventsEl, stats.total_events ?? 0);
  animateNumber(totalAlertsEl, stats.total_alerts ?? 0);

  const ratio = stats.recent_attack_ratio ?? 0;
  const pct   = Math.round(ratio * 100);
  attackRatioEl.textContent = `${pct}%`;
  ratioBarFill.style.width  = `${pct}%`;

  const counts  = stats.attack_type_counts ?? {};
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const total   = entries.reduce((s, [, v]) => s + v, 0);
  chartTotalEl.textContent = `${total} events`;

  if (!entries.length) {
    attackChartEl.innerHTML = `<div class="empty-state">No attack data yet — run the simulator!</div>`;
    return;
  }

  const max = Math.max(...entries.map(([, v]) => v), 1);
  attackChartEl.innerHTML = entries.map(([label, value]) => {
    const width    = Math.max((value / max) * 100, 4);
    const info     = ATTACK_COLORS[label] ?? { bar: "normal", label };
    const nice     = info.label;
    return `
      <div class="chart-row">
        <span class="chart-label" title="${label}">${nice}</span>
        <div class="bar-wrap">
          <div class="bar-fill ${info.bar}" style="width:${width}%"></div>
        </div>
        <span class="chart-value">${value}</span>
      </div>`;
  }).join("");
}

// ── Animate number ────────────────────────────────────────────
function animateNumber(el, target) {
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;
  const diff = target - current;
  const steps = Math.min(Math.abs(diff), 15);
  const stepVal = diff / steps;
  let step = 0;
  const interval = setInterval(() => {
    step++;
    if (step >= steps) {
      el.textContent = target;
      clearInterval(interval);
    } else {
      el.textContent = Math.round(current + stepVal * step);
    }
  }, 30);
}

// ── Render Alerts ─────────────────────────────────────────────
function renderAlerts(alerts) {
  alertsBadgeEl.textContent = alerts.length;
  if (!alerts.length) {
    alertsListEl.innerHTML = `<div class="empty-state">No alerts yet.</div>`;
    return;
  }

  alertsListEl.innerHTML = alerts.map(alert => {
    const sev = (alert.severity ?? "low").toLowerCase();
    return `
      <div class="alert-item severity-${sev}">
        <div class="alert-meta">
          <span class="alert-type">${alert.predicted_attack_type}</span>
          <span class="alert-ip">${alert.src_ip}</span>
          <span class="alert-time">${fmtDatetime(alert.timestamp)}</span>
          <span class="alert-reason" title="${alert.reason}">${alert.reason}</span>
        </div>
        <div class="alert-right">
          <span class="badge ${badgeClass(sev)}">${sev}</span>
          <span class="conf-text">${Math.round(alert.confidence * 100)}%</span>
        </div>
      </div>`;
  }).join("");
}

// ── Render Events Table ───────────────────────────────────────
function renderEvents(events) {
  eventsBadgeEl.textContent = `${events.length} events`;
  if (!events.length) {
    eventsTableBody.innerHTML = `<tr><td colspan="10" class="empty-state">No events yet — run the simulator!</td></tr>`;
    return;
  }

  eventsTableBody.innerHTML = events.map(ev => {
    const isAttack   = ev.is_attack ? "is-attack" : "";
    const predType   = ev.predicted_attack_type ?? "normal";
    const sevClass   = badgeClass(ev.severity);
    const conf       = ev.confidence != null ? Math.round(ev.confidence * 100) + "%" : "—";
    return `
      <tr class="${isAttack}">
        <td>${fmtTime(ev.timestamp)}</td>
        <td class="col-ip">${ev.src_ip}</td>
        <td>${ev.action}</td>
        <td class="col-topic" title="${ev.topic}">${ev.topic}</td>
        <td>${ev.message_rate}</td>
        <td>${ev.topic_count}</td>
        <td>${ev.failed_auth_count}</td>
        <td class="col-pred"><span class="badge ${sevClass}">${predType}</span></td>
        <td><span class="badge ${sevClass}">${ev.severity ?? "low"}</span></td>
        <td>${conf}</td>
      </tr>`;
  }).join("");
}

// ── Prepend a single new event row with animation ─────────────
function prependEventRow(ev) {
  const isAttack   = ev.is_attack ? "is-attack" : "";
  const predType   = ev.predicted_attack_type ?? "normal";
  const sevClass   = badgeClass(ev.severity);
  const conf       = ev.confidence != null ? Math.round(ev.confidence * 100) + "%" : "—";

  // Remove "no events" placeholder if present
  const empty = eventsTableBody.querySelector(".empty-state");
  if (empty) empty.closest("tr").remove();

  const tr = document.createElement("tr");
  tr.className = `${isAttack} row-new`;
  tr.innerHTML = `
    <td>${fmtTime(ev.timestamp)}</td>
    <td class="col-ip">${ev.src_ip}</td>
    <td>${ev.action}</td>
    <td class="col-topic" title="${ev.topic}">${ev.topic}</td>
    <td>${ev.message_rate}</td>
    <td>${ev.topic_count}</td>
    <td>${ev.failed_auth_count}</td>
    <td class="col-pred"><span class="badge ${sevClass}">${predType}</span></td>
    <td><span class="badge ${sevClass}">${ev.severity ?? "low"}</span></td>
    <td>${conf}</td>`;

  eventsTableBody.prepend(tr);
  flashElement(tr);

  // Keep table size bounded
  while (eventsTableBody.children.length > MAX_EVENTS) {
    eventsTableBody.lastChild.remove();
  }

  // Update badge
  eventsBadgeEl.textContent = `${eventsTableBody.children.length} events`;
}

// ── Prepend alert with animation ──────────────────────────────
function prependAlert(ev) {
  if (!ev.is_attack) return;

  const sev = (ev.severity ?? "low").toLowerCase();
  const alertDiv = document.createElement("div");
  alertDiv.className = `alert-item severity-${sev} alert-new`;
  alertDiv.innerHTML = `
    <div class="alert-meta">
      <span class="alert-type">${ev.predicted_attack_type}</span>
      <span class="alert-ip">${ev.src_ip}</span>
      <span class="alert-time">${fmtDatetime(ev.timestamp)}</span>
      <span class="alert-reason" title="${ev.reason}">${ev.reason}</span>
    </div>
    <div class="alert-right">
      <span class="badge ${badgeClass(sev)}">${sev}</span>
      <span class="conf-text">${Math.round(ev.confidence * 100)}%</span>
    </div>`;

  // Remove empty state
  const empty = alertsListEl.querySelector(".empty-state");
  if (empty) empty.remove();

  alertsListEl.prepend(alertDiv);
  flashElement(alertDiv);

  // Keep bounded
  while (alertsListEl.children.length > 20) {
    alertsListEl.lastChild.remove();
  }

  alertsBadgeEl.textContent = alertsListEl.children.length;
}

// ── Fetch & Refresh (full poll — used as fallback) ────────────
async function fetchJson(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function fullRefresh() {
  try {
    const [stats, alerts, events] = await Promise.all([
      fetchJson("/stats"),
      fetchJson("/alerts?limit=15"),
      fetchJson("/events?limit=30"),
    ]);
    renderStats(stats);
    renderAlerts(alerts);
    renderEvents(events);
    setOnline(true);
    lastUpdateEl.textContent = "Last update: " + nowStr();
  } catch (err) {
    console.error(err);
    setOnline(false);
    lastUpdateEl.textContent = "Failed at: " + nowStr();
  }
}

// ── SSE Connection ────────────────────────────────────────────
function connectSSE() {
  const evtSource = new EventSource(`${API_BASE}/stream`);

  evtSource.addEventListener("new_event", (e) => {
    try {
      const data = JSON.parse(e.data);
      const ev   = data.event;

      // Instant UI updates
      prependEventRow(ev);
      prependAlert(ev);
      renderStats(data.stats);

      setOnline(true);
      lastUpdateEl.textContent = "Live update: " + nowStr();
    } catch (err) {
      console.error("[SSE] Parse error:", err);
    }
  });

  evtSource.onopen = () => {
    console.log("[SSE] Connected ✓");
    sseConnected = true;
    setLiveStatus(true);

    // Stop polling when SSE is active
    if (pollingTimer) {
      clearInterval(pollingTimer);
      pollingTimer = null;
    }
  };

  evtSource.onerror = () => {
    console.warn("[SSE] Connection lost — falling back to polling");
    sseConnected = false;
    setLiveStatus(false);
    evtSource.close();

    // Fall back to polling
    if (!pollingTimer) {
      pollingTimer = setInterval(fullRefresh, 3000);
    }

    // Retry SSE after 5 seconds
    setTimeout(connectSSE, 5000);
  };
}

// ── Bootstrap ─────────────────────────────────────────────────
// 1. Do an immediate full refresh to populate the UI
fullRefresh();

// 2. Start SSE for live updates
connectSSE();

// 3. Start polling as initial fallback (will be stopped once SSE connects)
pollingTimer = setInterval(fullRefresh, 5000);
