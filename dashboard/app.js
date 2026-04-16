/* ============================================================
   MQTT Honeypot Dashboard — app.js
   Polls FastAPI every 3 seconds and updates the UI.
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

function setOnline(ok) {
  pulseDot.className = "pulse-dot " + (ok ? "online" : "offline");
  statusText.textContent = ok ? "Connected" : "Backend offline";
  statusText.style.color = ok ? "var(--ok)" : "var(--danger)";
}

// ── Render Stats ──────────────────────────────────────────────
function renderStats(stats) {
  totalEventsEl.textContent = stats.total_events ?? 0;
  totalAlertsEl.textContent = stats.total_alerts ?? 0;

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

// ── Fetch & Refresh ───────────────────────────────────────────
async function fetchJson(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function refresh() {
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
    lastUpdateEl.textContent = "Last update: " + new Date().toLocaleTimeString("th-TH", { hour12: false });
  } catch (err) {
    console.error(err);
    setOnline(false);
    lastUpdateEl.textContent = "Failed at: " + new Date().toLocaleTimeString("th-TH", { hour12: false });
  }
}

refresh();
setInterval(refresh, 3000);
