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
const MAX_EVENTS = 60;
let eventBuffer = [];
let alertBuffer = [];
let latestStats = null;
let sseConnected = false;
let pollingTimer = null;

// New globals for UI state
window.allEventsMap = new Map();
window.devicesMap = new Map();

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

// ── Payload formatting & Syntax Highlighting ──────────────────
function syntaxHighlight(json) {
  if (typeof json != 'string') {
    json = JSON.stringify(json, undefined, 2);
  }
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let cls = 'json-number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'json-key';
      } else {
        cls = 'json-string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'json-boolean';
    } else if (/null/.test(match)) {
      cls = 'json-null';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

function formatPayload(payloadStr) {
  if (!payloadStr) return { html: "<i>(empty payload)</i>", isJson: false };
  try {
    const obj = JSON.parse(payloadStr);
    const pretty = JSON.stringify(obj, null, 2);
    return { html: syntaxHighlight(pretty), isJson: true };
  } catch (e) {
    const escaped = payloadStr.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return { html: escaped, isJson: false };
  }
}

function getPayloadPreview(payload) {
  if (!payload) return "-";
  const str = String(payload).replace(/\s+/g, ' ');
  if (str.length > 40) return str.substring(0, 37) + "...";
  return str;
}

// ── Modal Logic ───────────────────────────────────────────────
const payloadModal = document.getElementById("payloadModal");
const modalCloseBtn = document.getElementById("modalCloseBtn");
const modalMeta = document.getElementById("modalMeta");
const modalPayloadContent = document.getElementById("modalPayloadContent");

if (eventsTableBody && payloadModal) {
  eventsTableBody.addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    if (!tr) return;
    const evtId = tr.getAttribute("data-id");
    if (!evtId) return;
    
    const ev = window.allEventsMap.get(evtId);
    if (!ev) return;
    
    const sevClass = badgeClass(ev.severity);
    const predType = ev.predicted_attack_type ?? "normal";
    modalMeta.innerHTML = `
      <span class="label">Client ID</span><span class="val">${ev.client_id || 'unknown'}</span>
      <span class="label">Topic</span><span class="val">${ev.topic || '/'}</span>
      <span class="label">Timestamp</span><span class="val">${fmtDatetime(ev.timestamp)}</span>
      <span class="label">Classification</span><span class="val"><span class="badge ${sevClass}">${predType}</span></span>
      <span class="label">Severity</span><span class="val"><span class="badge ${sevClass}">${ev.severity ?? "low"}</span></span>
    `;
    
    const { html } = formatPayload(ev.payload);
    modalPayloadContent.innerHTML = html;
    
    payloadModal.classList.add("active");
  });

  modalCloseBtn.addEventListener("click", () => payloadModal.classList.remove("active"));
  payloadModal.addEventListener("click", (e) => {
    if (e.target === payloadModal) payloadModal.classList.remove("active");
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") payloadModal.classList.remove("active");
  });
}

// ── Device Panel Logic ────────────────────────────────────────
function updateDevices(events) {
  events.forEach(ev => {
    if (!ev.client_id) return;
    
    // If this client is flagged as an attacker, remove it from the Device Panel entirely!
    if (ev.is_attack) {
      window.devicesMap.delete(ev.client_id);
      return; 
    }
    
    const existing = window.devicesMap.get(ev.client_id) || { client_id: ev.client_id, timestamp: ev.timestamp, topic: ev.topic };
    
    // Always update timestamp to the latest
    const evTime = new Date(ev.timestamp).getTime();
    const existingTime = new Date(existing.timestamp).getTime();
    if (evTime >= existingTime) {
      existing.timestamp = ev.timestamp;
      existing.topic = ev.topic;
    }
    
    // Store specific payloads so they aren't overwritten by heartbeats/status
    if (ev.topic.includes("/vibration")) {
      existing.vibration_payload = ev.payload;
    } else if (ev.topic.includes("/door/status")) {
      existing.door_payload = ev.payload;
    } else {
      // Keep track of whatever else (like heartbeats)
      existing.last_payload = ev.payload;
    }

    window.devicesMap.set(ev.client_id, existing);
  });
}

function renderDevicePanel() {
  const panel = document.getElementById("devicePanel");
  const countBadge = document.getElementById("deviceCount");
  if (!panel) return;
  
  if (countBadge) countBadge.textContent = `${window.devicesMap.size} devices`;
  
  if (window.devicesMap.size === 0) {
    panel.innerHTML = '<div class="empty-state">No devices seen yet.</div>';
    return;
  }
  
  const now = Date.now();
  let html = "";
  
  const devices = Array.from(window.devicesMap.values())
    .sort((a, b) => a.client_id.localeCompare(b.client_id));
    
  devices.forEach(ev => {
    const timeDiff = Math.max(0, Math.floor((now - new Date(ev.timestamp).getTime()) / 1000));
    const isOnline = timeDiff < 15;
    const badgeCls = isOnline ? "online" : "offline";
    const badgeTxt = isOnline ? "ONLINE" : "OFFLINE";
    
    // Parse Payload for Visuals
    let visualHtml = "";
    if (ev.door_payload || ev.client_id.includes("door")) {
      const payloadToUse = ev.door_payload || "WAITING...";
      const isOpen = payloadToUse === "OPEN";
      const isClosed = payloadToUse === "CLOSED";
      let statusClass = "door-unknown";
      let icon = "🚪";
      
      if (isOpen) {
        statusClass = "door-open";
        icon = "🔓";
      } else if (isClosed) {
        statusClass = "door-closed";
        icon = "🔒";
      }
      
      visualHtml = `
        <div class="door-status ${statusClass}">
          <span class="door-icon">${icon}</span>
          <span class="door-text">${payloadToUse}</span>
        </div>
      `;
    } else if (ev.vibration_payload || ev.client_id.includes("machine")) {
      const payloadToUse = ev.vibration_payload;
      if (payloadToUse) {
        try {
          const data = JSON.parse(payloadToUse);
          if (data.magnitude !== undefined) {
             const mag = parseFloat(data.magnitude).toFixed(2);
             const pct = Math.min(100, Math.max(0, (mag / 3) * 100)); // Map 0-3g to 0-100%
             const magClass = mag > 1.5 ? "mag-alert" : "mag-normal";
             visualHtml = `
              <div class="vibration-gauge">
                <div class="vibration-values">
                  <span>X: ${parseFloat(data.x).toFixed(2)}</span>
                  <span>Y: ${parseFloat(data.y).toFixed(2)}</span>
                  <span>Z: ${parseFloat(data.z).toFixed(2)}</span>
                </div>
                <div class="gauge-wrap">
                  <div class="gauge-fill ${magClass}" style="width: ${pct}%"></div>
                  <div class="gauge-threshold" style="left: 50%"></div>
                </div>
                <div class="gauge-label">Magnitude: <strong>${mag} g</strong></div>
              </div>
             `;
          } else {
             visualHtml = `<div class="device-payload">${formatPayload(payloadToUse).html}</div>`;
          }
        } catch (e) {
          visualHtml = `<div class="device-payload">${formatPayload(payloadToUse).html}</div>`;
        }
      } else {
        visualHtml = `<div class="device-payload">${formatPayload(ev.last_payload).html}</div>`;
      }
    } else {
       visualHtml = `<div class="device-payload">${formatPayload(ev.last_payload).html}</div>`;
    }
    
    html += `
      <div class="device-card">
        <div class="device-header">
          <span class="device-title" title="${ev.client_id}">${ev.client_id}</span>
          <span class="device-badge ${badgeCls}">${badgeTxt}</span>
        </div>
        <div class="device-meta">
          <div class="device-meta-row">
            <span>Last seen:</span>
            <span class="device-meta-val">${timeDiff}s ago</span>
          </div>
          <div class="device-meta-row">
            <span>Topic:</span>
            <span class="device-meta-val" title="${ev.topic}">${ev.topic}</span>
          </div>
        </div>
        ${visualHtml}
      </div>
    `;
  });
  
  panel.innerHTML = html;
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
  
  window.allEventsMap.clear();
  updateDevices(events);
  renderDevicePanel();
  
  if (!events.length) {
    eventsTableBody.innerHTML = `<tr><td colspan="9" class="empty-state">No events yet — run the simulator!</td></tr>`;
    return;
  }

  eventsTableBody.innerHTML = events.map(ev => {
    const evtId = ev.raw_event_id ? String(ev.raw_event_id) : String(ev.timestamp) + (ev.client_id || 'un');
    window.allEventsMap.set(evtId, ev);
    
    const isAttack   = ev.is_attack ? "is-attack" : "";
    const predType   = ev.predicted_attack_type ?? "normal";
    const sevClass   = badgeClass(ev.severity);
    const conf       = ev.confidence != null ? Math.round(ev.confidence * 100) + "%" : "—";
    return `
      <tr class="${isAttack}" data-id="${evtId}">
        <td>${fmtTime(ev.timestamp)}</td>
        <td class="col-client" title="${ev.client_id}">${ev.client_id}</td>
        <td class="col-topic" title="${ev.topic}">${ev.topic}</td>
        <td class="payload-preview" title="${String(ev.payload).replace(/"/g, '&quot;')}"><code>${getPayloadPreview(ev.payload)}</code></td>
        <td>${ev.message_rate}</td>
        <td>${ev.failed_auth_count}</td>
        <td class="col-pred"><span class="badge ${sevClass}">${predType}</span></td>
        <td><span class="badge ${sevClass}">${ev.severity ?? "low"}</span></td>
        <td>${conf}</td>
      </tr>`;
  }).join("");
}

// ── Prepend a single new event row with animation ─────────────
function prependEventRow(ev) {
  const evtId = ev.raw_event_id ? String(ev.raw_event_id) : String(ev.timestamp) + (ev.client_id || 'un');
  window.allEventsMap.set(evtId, ev);
  
  updateDevices([ev]);
  renderDevicePanel();

  const isAttack   = ev.is_attack ? "is-attack" : "";
  const predType   = ev.predicted_attack_type ?? "normal";
  const sevClass   = badgeClass(ev.severity);
  const conf       = ev.confidence != null ? Math.round(ev.confidence * 100) + "%" : "—";

  const empty = eventsTableBody.querySelector(".empty-state");
  if (empty) empty.closest("tr").remove();

  const tr = document.createElement("tr");
  tr.className = `${isAttack} row-new`;
  tr.setAttribute("data-id", evtId);
  tr.innerHTML = `
    <td>${fmtTime(ev.timestamp)}</td>
    <td class="col-client" title="${ev.client_id}">${ev.client_id}</td>
    <td class="col-topic" title="${ev.topic}">${ev.topic}</td>
    <td class="payload-preview" title="${String(ev.payload).replace(/"/g, '&quot;')}"><code>${getPayloadPreview(ev.payload)}</code></td>
    <td>${ev.message_rate}</td>
    <td>${ev.failed_auth_count}</td>
    <td class="col-pred"><span class="badge ${sevClass}">${predType}</span></td>
    <td><span class="badge ${sevClass}">${ev.severity ?? "low"}</span></td>
    <td>${conf}</td>`;

  eventsTableBody.prepend(tr);
  flashElement(tr);

  while (eventsTableBody.children.length > MAX_EVENTS) {
    const lastId = eventsTableBody.lastElementChild.getAttribute("data-id");
    if (lastId) window.allEventsMap.delete(lastId);
    eventsTableBody.lastChild.remove();
  }

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

  const empty = alertsListEl.querySelector(".empty-state");
  if (empty) empty.remove();

  alertsListEl.prepend(alertDiv);
  flashElement(alertDiv);

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

    if (!pollingTimer) {
      pollingTimer = setInterval(fullRefresh, 3000);
    }

    setTimeout(connectSSE, 5000);
  };
}

// ── Bootstrap ─────────────────────────────────────────────────
fullRefresh();
connectSSE();
pollingTimer = setInterval(fullRefresh, 5000);
setInterval(renderDevicePanel, 1000);
