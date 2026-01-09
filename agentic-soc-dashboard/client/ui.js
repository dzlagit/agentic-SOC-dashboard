function escapeHtml(v) { // escape HTML special characters
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function timeStr(ts) {
  if (!ts) return "—";

  const d = new Date(ts);

  let h = d.getHours();
  const m = d.getMinutes().toString().padStart(2, "0");
  const s = d.getSeconds().toString().padStart(2, "0");

  const ampm = h >= 12 ? "PM" : "AM";
  h = ((h + 11) % 12) + 1;

  return `${h}:${m}:${s} ${ampm}`;
}


function sevRank(sev) { // get numeric rank of severity
  const s = String(sev || "LOW").toUpperCase();
  if (s === "CRITICAL") return 4;
  if (s === "HIGH") return 3;
  if (s === "MEDIUM") return 2;
  return 1;
}

function toArrayMaybeSet(v) { // convert value to array if it's a Set or single value
  if (!v) return [];
  if (Array.isArray(v)) return v;
  if (v instanceof Set) return Array.from(v);
  return [];
}

function emit(name, detail) { // emit custom event on window
  window.dispatchEvent(new CustomEvent(name, { detail }));
}

function deriveInvestigationStatus(inv) { // derive investigation status from its properties and actions
  const override = inv?.statusOverride;
  if (override) return String(override).toUpperCase();

  const actions = Array.isArray(inv?.actions) ? inv.actions : [];
  const has = (a) => actions.some((x) => String(x?.type || x).toUpperCase() === a);

  const closed = Boolean(inv?.closedTs) || has("CLOSE");
  const reopened = Boolean(inv?.reopenedTs) || has("REOPEN") || String(inv?.status || "").toUpperCase() === "REOPENED";

  if (reopened) return "REOPENED";
  if (closed) return "CLOSED";

  const contained =
    has("BLOCK_IP") ||
    has("DISABLE_USER") ||
    has("FORCE_PASSWORD_RESET") ||
    has("REVOKE_SESSIONS") ||
    has("CONTAIN");

  if (contained) return "CONTAINED";

  const monitoring = has("ACK") || has("ACKNOWLEDGE") || has("ASSIGN") || Boolean(inv?.ackTs) || Boolean(inv?.assignedTo);
  if (monitoring) return "MONITORING";

  const s = String(inv?.status || "OPEN").toUpperCase();
  if (["OPEN", "MONITORING", "CONTAINED", "CLOSED", "REOPENED"].includes(s)) return s;
  return "OPEN";
}

function statusLabel(status) { // get human-readable label for investigation status
  const s = String(status || "OPEN").toUpperCase();
  if (s === "REOPENED") return "Reopened";
  if (s === "CLOSED") return "Closed";
  if (s === "CONTAINED") return "Contained";
  if (s === "MONITORING") return "Monitoring";
  return "Open";
}

function badgeHtml(kind, value) { // generate HTML for badge of given kind and value
  const v = String(value || "").toUpperCase();
  const cls = `${kind}-badge ${kind}-${v.toLowerCase()}`;
  return `<span class="${cls}">${escapeHtml(kind === "sev" ? v : statusLabel(v))}</span>`;
}

function summarizeAlert(a) { // summarize alert explanation
  const exp = String(a?.explanation || "");
  if (exp.length <= 100) return exp;
  return exp.slice(0, 100) + "…";
}

function stableId(obj, fallback) { // generate stable ID for object based on its id property or fallback
  return String(obj?.id || fallback || "");
}

const uiState = {
  selectedAlertId: null,
  selectedInvestigationId: null,
};

export function renderAlerts(alerts) { // render recent alerts list
  const root = document.getElementById("alerts");
  if (!root) return;

  root.innerHTML = "";

  const latest = [...alerts].slice(-12).reverse();
  for (const a of latest) {
    const div = document.createElement("div");
    div.className = "alert";
    div.innerHTML = `
      <div class="top">
        <span>${escapeHtml(String(a.severity || "LOW").toUpperCase())} — ${escapeHtml(a.type)}</span>
        <span>${escapeHtml(timeStr(a.ts))}</span>
      </div>
      <div class="meta">
        <div><strong>IP:</strong> ${escapeHtml(a.ip)}</div>
        <div><strong>User:</strong> ${escapeHtml(a.user)}</div>
        <div style="margin-top:6px">${escapeHtml(a.explanation)}</div>
      </div>
    `;
    root.appendChild(div);
  }
}

export function renderKPIs(alerts) { // render KPI counts for alerts by severity
  const elCritical = document.getElementById("kpiCritical");
  const elHigh = document.getElementById("kpiHigh");
  const elMedium = document.getElementById("kpiMedium");
  const elLow = document.getElementById("kpiLow");
  if (!elCritical || !elHigh || !elMedium || !elLow) return;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  for (const a of alerts) {
    const sev = String(a.severity || "LOW").toUpperCase();
    if (sev === "CRITICAL") counts.CRITICAL++;
    else if (sev === "HIGH") counts.HIGH++;
    else if (sev === "MEDIUM") counts.MEDIUM++;
    else counts.LOW++;
  }

  elCritical.innerText = String(counts.CRITICAL);
  elHigh.innerText = String(counts.HIGH);
  elMedium.innerText = String(counts.MEDIUM);
  elLow.innerText = String(counts.LOW);
}

export function renderInvestigations(investigations) { // render recent investigations list
  const body = document.getElementById("investigationsBody");
  if (!body) return;

  body.innerHTML = "";

  const rows = [...investigations]
    .sort((a, b) => (b.lastSeenTs || b.createdTs) - (a.lastSeenTs || a.createdTs))
    .slice(0, 5);

  for (const inv of rows) {
    const created = timeStr(inv.createdTs);
    const status = deriveInvestigationStatus(inv);
    const title = inv.title || `Suspicious activity from ${inv.entity}`;

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(created)}</td>
      <td>${escapeHtml(title)} <span class="soft">(${escapeHtml(inv.count)} hits)</span></td>
      <td>${badgeHtml("sev", inv.severity)}</td>
      <td>${escapeHtml(inv.entity)}</td>
    `;
    body.appendChild(tr);
  }
}

function getAlertsControls() { // get references to alerts page controls
  return {
    search: document.getElementById("alertsSearch"),
    severity: document.getElementById("alertsSeverity"),
    sort: document.getElementById("alertsSort"),
    tableBody: document.getElementById("alertsTableBody"),
    details: document.getElementById("alertDetails"),
    detailsMeta: document.getElementById("alertDetailsMeta"),
  };
}

function getInvestigationsControls() { // get references to investigations page controls
  return {
    search: document.getElementById("invSearch"),
    severity: document.getElementById("invSeverity"),
    status: document.getElementById("invStatus"),
    sort: document.getElementById("invSort"),
    tableBody: document.getElementById("invTableBody"),
    details: document.getElementById("invDetails"),
    detailsMeta: document.getElementById("invDetailsMeta"),
  };
}

function filterSortAlerts(allAlerts, controls) { // filter and sort alerts based on controls
  const q = String(controls.search?.value || "").trim().toLowerCase();
  const sev = String(controls.severity?.value || "ALL").toUpperCase();
  const sort = String(controls.sort?.value || "NEWEST").toUpperCase();

  let arr = [...allAlerts];

  if (sev !== "ALL") {
    arr = arr.filter((a) => String(a.severity || "LOW").toUpperCase() === sev);
  }

  if (q) {
    arr = arr.filter((a) => {
      const blob = [
        a.type,
        a.user,
        a.ip,
        a.explanation,
        a.severity,
        timeStr(a.ts),
      ]
        .join(" ")
        .toLowerCase();
      return blob.includes(q);
    });
  }

  if (sort === "OLDEST") arr.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  else if (sort === "SEV_DESC") arr.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (b.ts || 0) - (a.ts || 0));
  else if (sort === "SEV_ASC") arr.sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.ts || 0) - (a.ts || 0));
  else arr.sort((a, b) => (b.ts || 0) - (a.ts || 0));

  return arr;
}

function renderAlertDetails(alert) { // render details of selected alert
  const controls = getAlertsControls();
  if (!controls.details || !controls.detailsMeta) return;

  if (!alert) {
    controls.detailsMeta.textContent = "Select an alert";
    controls.details.innerHTML = `<div class="muted">No alert selected.</div>`;
    return;
  }

  controls.detailsMeta.textContent = `${String(alert.severity || "LOW").toUpperCase()} · ${alert.type}`;

  controls.details.innerHTML = `
    <div class="details-grid">
      <div class="details-row"><div class="muted">Time</div><div>${escapeHtml(timeStr(alert.ts))}</div></div>
      <div class="details-row"><div class="muted">Severity</div><div>${badgeHtml("sev", alert.severity)}</div></div>
      <div class="details-row"><div class="muted">Type</div><div>${escapeHtml(alert.type)}</div></div>
      <div class="details-row"><div class="muted">User</div><div>${escapeHtml(alert.user)}</div></div>
      <div class="details-row"><div class="muted">IP</div><div>${escapeHtml(alert.ip)}</div></div>
      <div class="details-block">
        <div class="muted" style="margin-bottom:6px;">Explanation</div>
        <div>${escapeHtml(alert.explanation)}</div>
      </div>
  `;

  controls.details.querySelectorAll("[data-alert-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const action = btn.getAttribute("data-alert-action");
      emit("soc:alertAction", { action, alertId: alert.id, ip: alert.ip, user: alert.user, ts: Date.now() });
    });
  });
}

export function renderAlertsPage(alerts) { // render alerts page with filtering and selection
  const c = getAlertsControls();
  if (!c.tableBody) return;

  const filtered = filterSortAlerts(alerts, c);

  const frag = document.createDocumentFragment();
  const selected = uiState.selectedAlertId;

  for (const a of filtered.slice(0, 500)) {
    const id = stableId(a, `A-${a.ts}-${a.type}-${a.ip}`);
    const tr = document.createElement("tr");
    tr.dataset.alertId = id;
    tr.className = id === selected ? "row-selected" : "";

    tr.innerHTML = `
      <td>${escapeHtml(timeStr(a.ts))}</td>
      <td>${badgeHtml("sev", a.severity)}</td>
      <td>${escapeHtml(a.type)}</td>
      <td>${escapeHtml(a.user)}</td>
      <td>${escapeHtml(a.ip)}</td>
      <td title="${escapeHtml(a.explanation)}">${escapeHtml(summarizeAlert(a))}</td>
    `;

    tr.addEventListener("click", () => {
      uiState.selectedAlertId = id;

      const found = filtered.find((x) => stableId(x, `A-${x.ts}-${x.type}-${x.ip}`) === id) || null;
      renderAlertDetails(found);

      c.tableBody.querySelectorAll("tr").forEach((row) => row.classList.remove("row-selected"));
      tr.classList.add("row-selected");
    });

    frag.appendChild(tr);
  }

  c.tableBody.innerHTML = "";
  c.tableBody.appendChild(frag);

  if (uiState.selectedAlertId) {
    const found =
      filtered.find((x) => stableId(x, `A-${x.ts}-${x.type}-${x.ip}`) === uiState.selectedAlertId) || null;
    renderAlertDetails(found);
  } else {
    renderAlertDetails(null);
  }
}

export function bindAlertsPageControls(onChange) { // bind event listeners to alerts page controls
  const c = getAlertsControls();
  if (!c.search || !c.severity || !c.sort) return;

  const fire = () => onChange?.();

  c.search.addEventListener("input", fire);
  c.severity.addEventListener("change", fire);
  c.sort.addEventListener("change", fire);
}

function filterSortInvestigations(allInv, controls) { // filter and sort investigations based on controls
  const q = String(controls.search?.value || "").trim().toLowerCase();
  const sev = String(controls.severity?.value || "ALL").toUpperCase();
  const status = String(controls.status?.value || "ALL").toUpperCase();
  const sort = String(controls.sort?.value || "LAST_SEEN").toUpperCase();

  let arr = [...allInv].map((inv) => ({
    ...inv,
    __status: deriveInvestigationStatus(inv),
    __victims: toArrayMaybeSet(inv.victims),
  }));

  if (sev !== "ALL") {
    arr = arr.filter((i) => String(i.severity || "LOW").toUpperCase() === sev);
  }

  if (status !== "ALL") {
    arr = arr.filter((i) => String(i.__status || "OPEN").toUpperCase() === status);
  }

  if (q) {
    arr = arr.filter((i) => {
      const blob = [
        i.entity,
        i.title,
        i.__victims.join(","),
        i.severity,
        i.__status,
      ]
        .join(" ")
        .toLowerCase();
      return blob.includes(q);
    });
  }

  if (sort === "CREATED") arr.sort((a, b) => (b.createdTs || 0) - (a.createdTs || 0));
  else if (sort === "SEV_DESC") arr.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (b.lastSeenTs || 0) - (a.lastSeenTs || 0));
  else if (sort === "SEV_ASC") arr.sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.lastSeenTs || 0) - (a.lastSeenTs || 0));
  else arr.sort((a, b) => (b.lastSeenTs || b.createdTs || 0) - (a.lastSeenTs || a.createdTs || 0));

  return arr;
}

function renderInvestigationDetails(inv) { // render details of selected investigation
  const c = getInvestigationsControls();
  if (!c.details || !c.detailsMeta) return;

  if (!inv) {
    c.detailsMeta.textContent = "Select a case";
    c.details.innerHTML = `<div class="muted">No investigation selected.</div>`;
    return;
  }

  const status = deriveInvestigationStatus(inv);
  const victims = toArrayMaybeSet(inv.victims);
  const types = inv.typeCounts || {};
  const typeLines = Object.entries(types)
    .sort((a, b) => (b[1] || 0) - (a[1] || 0))
    .slice(0, 8)
    .map(([k, v]) => `<div class="details-row"><div class="muted">${escapeHtml(k)}</div><div>${escapeHtml(v)}</div></div>`)
    .join("");

  c.detailsMeta.textContent = `${inv.entity} · ${statusLabel(status)}`;

  const actions = Array.isArray(inv.actions) ? inv.actions : [];
  const actionLines = actions
    .slice()
    .reverse()
    .slice(0, 12)
    .map((a) => {
      const t = String(a?.type || a).toUpperCase();
      const who = a?.by ? ` · ${escapeHtml(a.by)}` : "";
      const ts = a?.ts ? ` · ${escapeHtml(timeStr(a.ts))}` : "";
      return `<div class="soft" style="margin-bottom:6px;">${escapeHtml(t)}${who}${ts}</div>`;
    })
    .join("") || `<div class="muted">No actions recorded yet.</div>`;

  c.details.innerHTML = `
    <div class="details-grid">
      <div class="details-row"><div class="muted">Attacker</div><div>${escapeHtml(inv.entity)}</div></div>
      <div class="details-row"><div class="muted">Severity</div><div>${badgeHtml("sev", inv.severity)}</div></div>
      <div class="details-row"><div class="muted">Status</div><div>${badgeHtml("status", status)}</div></div>
      <div class="details-row"><div class="muted">Created</div><div>${escapeHtml(timeStr(inv.createdTs))}</div></div>
      <div class="details-row"><div class="muted">Last seen</div><div>${escapeHtml(timeStr(inv.lastSeenTs || inv.createdTs))}</div></div>
      <div class="details-row"><div class="muted">Hits</div><div>${escapeHtml(inv.count)}</div></div>

      <div class="details-block">
        <div class="muted" style="margin-bottom:6px;">Victims</div>
        <div>${victims.length ? victims.map((v) => `<span class="chip">${escapeHtml(v)}</span>`).join(" ") : `<span class="muted">—</span>`}</div>
      </div>

      <div class="details-block">
        <div class="muted" style="margin-bottom:6px;">Top detections</div>
        <div>${typeLines || `<div class="muted">—</div>`}</div>
      </div>

      <div class="details-block">
        <div class="muted" style="margin-bottom:6px;">Actions</div>
        <div>${actionLines}</div>
      </div>

      <div class="details-actions">
        <button class="btn" data-inv-action="ACK">Acknowledge</button>
        <button class="btn" data-inv-action="BLOCK_IP">Block IP</button>
        <button class="btn" data-inv-action="DISABLE_USER">Disable user</button>
        <button class="btn" data-inv-action="FORCE_PASSWORD_RESET">Force password reset</button>
        <button class="btn danger" data-inv-action="CLOSE">Close case</button>
      </div>
      <div class="muted" style="font-size:12px;">
        Status is derived from actions (Open → Monitoring → Contained → Closed, with Reopened on recurrence).
      </div>
    </div>
  `;

  c.details.querySelectorAll("[data-inv-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const action = btn.getAttribute("data-inv-action");
      emit("soc:investigationAction", { action, investigationId: inv.id, attackerIp: inv.entity, ts: Date.now() });
    });
  });
}

export function renderInvestigationsPage(investigations) { // render investigations page with filtering and selection
  const c = getInvestigationsControls();
  if (!c.tableBody) return;

  const filtered = filterSortInvestigations(investigations, c);
  const selected = uiState.selectedInvestigationId;

  const frag = document.createDocumentFragment();

  for (const inv of filtered.slice(0, 500)) {
    const id = stableId(inv, inv.entity);
    const status = deriveInvestigationStatus(inv);
    const victims = toArrayMaybeSet(inv.victims);

    const tr = document.createElement("tr");
    tr.dataset.investigationId = id;
    tr.className = id === selected ? "row-selected" : "";

    tr.innerHTML = `
      <td>${escapeHtml(timeStr(inv.lastSeenTs || inv.createdTs))}</td>
      <td>${badgeHtml("sev", inv.severity)}</td>
      <td>${escapeHtml(inv.entity)}</td>
      <td>${escapeHtml(victims.slice(0, 3).join(", "))}${victims.length > 3 ? ` <span class="soft">+${victims.length - 3}</span>` : ""}</td>
      <td>${escapeHtml(inv.count)}</td>
      <td>${badgeHtml("status", status)}</td>
    `;

    tr.addEventListener("click", () => {
      uiState.selectedInvestigationId = id;

      const found = filtered.find((x) => stableId(x, x.entity) === id) || null;
      renderInvestigationDetails(found);

      c.tableBody.querySelectorAll("tr").forEach((row) => row.classList.remove("row-selected"));
      tr.classList.add("row-selected");
    });

    frag.appendChild(tr);
  }

  c.tableBody.innerHTML = "";
  c.tableBody.appendChild(frag);

  if (uiState.selectedInvestigationId) {
    const found =
      filtered.find((x) => stableId(x, x.entity) === uiState.selectedInvestigationId) || null;
    renderInvestigationDetails(found);
  } else {
    renderInvestigationDetails(null);
  }
}

export function bindInvestigationsPageControls(onChange) { // bind event listeners to investigations page controls
  const c = getInvestigationsControls();
  if (!c.search || !c.severity || !c.status || !c.sort) return;

  const fire = () => onChange?.();

  c.search.addEventListener("input", fire);
  c.severity.addEventListener("change", fire);
  c.status.addEventListener("change", fire);
  c.sort.addEventListener("change", fire);
}
