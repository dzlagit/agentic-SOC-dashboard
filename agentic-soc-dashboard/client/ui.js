// client/ui.js

function truncate(str, n) {
  if (!str) return "";
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}

function sevRank(sev) {
  const s = (sev || "LOW").toUpperCase();
  if (s === "CRITICAL") return 4;
  if (s === "HIGH") return 3;
  if (s === "MEDIUM") return 2;
  return 1;
}

/* ================= OVERVIEW ALERTS ================= */

export function renderAlerts(alerts) {
  const root = document.getElementById("alerts");
  if (!root) return;

  root.innerHTML = "";

  const latest = alerts.slice(-12).reverse();
  for (const a of latest) {
    const div = document.createElement("div");
    div.className = "alert";
    div.innerHTML = `
      <div class="top">
        <span>${a.severity} — ${a.type}</span>
        <span>${new Date(a.ts).toLocaleTimeString()}</span>
      </div>
      <div class="meta">
        <div><strong>IP:</strong> ${a.ip}</div>
        <div><strong>User:</strong> ${a.user}</div>
        <div style="margin-top:6px">${a.explanation}</div>
      </div>
    `;
    root.appendChild(div);
  }
}

export function renderKPIs(alerts) {
  const elCritical = document.getElementById("kpiCritical");
  const elHigh = document.getElementById("kpiHigh");
  const elMedium = document.getElementById("kpiMedium");
  const elLow = document.getElementById("kpiLow");
  if (!elCritical || !elHigh || !elMedium || !elLow) return;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  for (const a of alerts) {
    const sev = (a.severity || "LOW").toUpperCase();
    if (sev === "CRITICAL") counts.CRITICAL++;
    else if (sev === "HIGH") counts.HIGH++;
    else if (sev === "MEDIUM") counts.MEDIUM++;
    else counts.LOW++;
  }

  elCritical.innerText = counts.CRITICAL;
  elHigh.innerText = counts.HIGH;
  elMedium.innerText = counts.MEDIUM;
  elLow.innerText = counts.LOW;
}

export function renderInvestigations(investigations) {
  const body = document.getElementById("investigationsBody");
  if (!body) return;

  body.innerHTML = "";

  const rows = [...investigations]
    .sort((a, b) => (b.lastSeenTs || b.createdTs) - (a.lastSeenTs || a.createdTs))
    .slice(0, 25);

  for (const inv of rows) {
    const created = new Date(inv.createdTs).toLocaleTimeString();
    const title = truncate(inv.title, 42);
    const entity = inv.entity || "";
    const victims = inv.victims ? Array.from(inv.victims).join(", ") : "";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${created}</td>
      <td>${title} <span class="soft">(${inv.count} hits)</span></td>
      <td>${inv.severity}</td>
      <td>${entity}${victims ? ` <span class="soft">→ ${truncate(victims, 24)}</span>` : ""}</td>
    `;
    body.appendChild(tr);
  }
}

/* ================= ALERTS PAGE ================= */

let alertsPageBound = false;
let selectedAlertKey = null;

function keyForAlert(a) {
  return `${a.ts}|${a.type}|${a.ip}|${a.user}|${a.severity}`;
}

function renderAlertDetails(a) {
  const meta = document.getElementById("alertDetailsMeta");
  const root = document.getElementById("alertDetails");
  if (!meta || !root) return;

  if (!a) {
    meta.textContent = "Select an alert";
    root.innerHTML = `<div class="muted">No alert selected.</div>`;
    return;
  }

  meta.textContent = `${a.severity} · ${a.type}`;

  root.innerHTML = `
    <div class="details-row"><div class="label">Time</div><div class="value">${new Date(a.ts).toLocaleString()}</div></div>
    <div class="details-row"><div class="label">Severity</div><div class="value">${a.severity}</div></div>
    <div class="details-row"><div class="label">Type</div><div class="value">${a.type}</div></div>
    <div class="details-row"><div class="label">User</div><div class="value">${a.user}</div></div>
    <div class="details-row"><div class="label">IP</div><div class="value">${a.ip}</div></div>
    <div class="details-row"><div class="label">Explanation</div><div class="value">${a.explanation || ""}</div></div>
  `;
}

export function bindAlertsPageControls(onChange) {
  if (alertsPageBound) return;
  alertsPageBound = true;

  const search = document.getElementById("alertsSearch");
  const sev = document.getElementById("alertsSeverity");
  const sort = document.getElementById("alertsSort");

  const handler = () => onChange?.();

  if (search) search.addEventListener("input", handler);
  if (sev) sev.addEventListener("change", handler);
  if (sort) sort.addEventListener("change", handler);
}

export function renderAlertsPage(alerts) {
  const body = document.getElementById("alertsTableBody");
  const searchEl = document.getElementById("alertsSearch");
  const sevEl = document.getElementById("alertsSeverity");
  const sortEl = document.getElementById("alertsSort");
  if (!body || !searchEl || !sevEl || !sortEl) return;

  const q = (searchEl.value || "").trim().toLowerCase();
  const sevFilter = (sevEl.value || "ALL").toUpperCase();
  const sortMode = (sortEl.value || "NEWEST").toUpperCase();

  let list = [...alerts];

  if (sevFilter !== "ALL") {
    list = list.filter((a) => (a.severity || "LOW").toUpperCase() === sevFilter);
  }

  if (q) {
    list = list.filter((a) => {
      const hay = [a.ip, a.user, a.type, a.severity, a.explanation]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }

  list.sort((a, b) => {
    if (sortMode === "OLDEST") return (a.ts || 0) - (b.ts || 0);
    if (sortMode === "SEV_DESC") return sevRank(b.severity) - sevRank(a.severity) || (b.ts || 0) - (a.ts || 0);
    if (sortMode === "SEV_ASC") return sevRank(a.severity) - sevRank(b.severity) || (b.ts || 0) - (a.ts || 0);
    return (b.ts || 0) - (a.ts || 0);
  });

  body.innerHTML = "";

  if (list.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6" class="muted">No alerts match your filters.</td>`;
    body.appendChild(tr);
    renderAlertDetails(null);
    selectedAlertKey = null;
    return;
  }

  let selected = null;

  for (const a of list.slice(0, 200)) {
    const k = keyForAlert(a);

    const tr = document.createElement("tr");
    tr.className = "row-click";
    if (selectedAlertKey && k === selectedAlertKey) tr.classList.add("selected-row");

    tr.innerHTML = `
      <td>${new Date(a.ts).toLocaleTimeString()}</td>
      <td><span class="pill sev-${(a.severity || "LOW").toLowerCase()}">${a.severity}</span></td>
      <td>${a.type}</td>
      <td>${a.user}</td>
      <td>${a.ip}</td>
      <td class="muted">${truncate(a.explanation, 90)}</td>
    `;

    tr.addEventListener("click", () => {
      selectedAlertKey = k;
      renderAlertsPage(alerts);
    });

    body.appendChild(tr);

    if (selectedAlertKey && k === selectedAlertKey) selected = a;
  }

  if (!selectedAlertKey) {
    selectedAlertKey = keyForAlert(list[0]);
    selected = list[0];
    renderAlertsPage(alerts);
    return;
  }

  renderAlertDetails(selected);
}

/* ================= INVESTIGATIONS PAGE ================= */

let invPageBound = false;
let selectedInvKey = null;

function keyForInvestigation(inv) {
  return `${inv.entity}|${inv.createdTs}|${inv.severity}|${inv.title}`;
}

function inferStage(inv) {
  const t = (inv.title || "").toLowerCase();

  // simple, explainable heuristics (good for coursework)
  if (t.includes("exfil")) return "Exfiltration";
  if (t.includes("sensitive") || t.includes("file")) return "Collection";
  if (t.includes("brute") || t.includes("auth")) return "Credential access";
  if (t.includes("recon") || t.includes("scan") || t.includes("port")) return "Reconnaissance";
  return "Activity";
}

function renderInvDetails(inv) {
  const meta = document.getElementById("invDetailsMeta");
  const root = document.getElementById("invDetails");
  if (!meta || !root) return;

  if (!inv) {
    meta.textContent = "Select a case";
    root.innerHTML = `<div class="muted">No investigation selected.</div>`;
    return;
  }

  const created = new Date(inv.createdTs).toLocaleString();
  const lastSeen = new Date(inv.lastSeenTs || inv.createdTs).toLocaleString();
  const victimsArr = inv.victims ? Array.from(inv.victims) : [];
  const victims = victimsArr.length ? victimsArr.join(", ") : "—";
  const stage = inferStage(inv);

  meta.textContent = `${inv.severity} · ${inv.entity}`;

  root.innerHTML = `
    <div class="details-row"><div class="label">Attacker (entity)</div><div class="value">${inv.entity}</div></div>
    <div class="details-row"><div class="label">Severity</div><div class="value">${inv.severity}</div></div>
    <div class="details-row"><div class="label">Status</div><div class="value">${inv.status || "OPEN"}</div></div>
    <div class="details-row"><div class="label">Stage</div><div class="value">${stage}</div></div>
    <div class="details-row"><div class="label">Created</div><div class="value">${created}</div></div>
    <div class="details-row"><div class="label">Last seen</div><div class="value">${lastSeen}</div></div>
    <div class="details-row"><div class="label">Title</div><div class="value">${inv.title}</div></div>
    <div class="details-row"><div class="label">Hits</div><div class="value">${inv.count}</div></div>
    <div class="details-row"><div class="label">Victims</div><div class="value">${victims}</div></div>

    <div class="divider"></div>

    <div class="muted" style="line-height:1.4">
      This case aggregates alerts for a single attacker entity (IP). The inferred stage is derived from the investigation title
      and represents the most likely phase of the campaign (recon → credential access → collection → exfiltration).
    </div>
  `;
}

export function bindInvestigationsPageControls(onChange) {
  if (invPageBound) return;
  invPageBound = true;

  const search = document.getElementById("invSearch");
  const sev = document.getElementById("invSeverity");
  const status = document.getElementById("invStatus");
  const sort = document.getElementById("invSort");

  const handler = () => onChange?.();

  if (search) search.addEventListener("input", handler);
  if (sev) sev.addEventListener("change", handler);
  if (status) status.addEventListener("change", handler);
  if (sort) sort.addEventListener("change", handler);
}

export function renderInvestigationsPage(investigations) {
  const body = document.getElementById("invTableBody");
  const searchEl = document.getElementById("invSearch");
  const sevEl = document.getElementById("invSeverity");
  const statusEl = document.getElementById("invStatus");
  const sortEl = document.getElementById("invSort");
  if (!body || !searchEl || !sevEl || !statusEl || !sortEl) return;

  const q = (searchEl.value || "").trim().toLowerCase();
  const sevFilter = (sevEl.value || "ALL").toUpperCase();
  const statusFilter = (statusEl.value || "ALL").toUpperCase();
  const sortMode = (sortEl.value || "LAST_SEEN").toUpperCase();

  let list = [...investigations];

  if (sevFilter !== "ALL") {
    list = list.filter((inv) => (inv.severity || "LOW").toUpperCase() === sevFilter);
  }

  if (statusFilter !== "ALL") {
    list = list.filter((inv) => (inv.status || "OPEN").toUpperCase() === statusFilter);
  }

  if (q) {
    list = list.filter((inv) => {
      const victims = inv.victims ? Array.from(inv.victims).join(" ") : "";
      const hay = [inv.entity, inv.title, victims, inv.severity, inv.status]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }

  list.sort((a, b) => {
    const aLast = a.lastSeenTs || a.createdTs || 0;
    const bLast = b.lastSeenTs || b.createdTs || 0;

    if (sortMode === "CREATED") return (b.createdTs || 0) - (a.createdTs || 0);
    if (sortMode === "SEV_DESC") return sevRank(b.severity) - sevRank(a.severity) || (bLast - aLast);
    if (sortMode === "SEV_ASC") return sevRank(a.severity) - sevRank(b.severity) || (bLast - aLast);
    // LAST_SEEN default
    return bLast - aLast;
  });

  body.innerHTML = "";

  if (list.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6" class="muted">No investigations match your filters.</td>`;
    body.appendChild(tr);
    renderInvDetails(null);
    selectedInvKey = null;
    return;
  }

  let selected = null;

  for (const inv of list.slice(0, 200)) {
    const k = keyForInvestigation(inv);
    const lastSeenTs = inv.lastSeenTs || inv.createdTs;
    const lastSeen = new Date(lastSeenTs).toLocaleTimeString();
    const victimsArr = inv.victims ? Array.from(inv.victims) : [];
    const victims = victimsArr.length ? truncate(victimsArr.join(", "), 32) : "—";

    const tr = document.createElement("tr");
    tr.className = "row-click";
    if (selectedInvKey && k === selectedInvKey) tr.classList.add("selected-row");

    tr.innerHTML = `
      <td>${lastSeen}</td>
      <td><span class="pill sev-${(inv.severity || "LOW").toLowerCase()}">${inv.severity}</span></td>
      <td>${inv.entity}</td>
      <td class="muted">${victims}</td>
      <td>${inv.count}</td>
      <td>${inv.status || "OPEN"}</td>
    `;

    tr.addEventListener("click", () => {
      selectedInvKey = k;
      renderInvestigationsPage(investigations);
    });

    body.appendChild(tr);

    if (selectedInvKey && k === selectedInvKey) selected = inv;
  }

  if (!selectedInvKey) {
    selectedInvKey = keyForInvestigation(list[0]);
    selected = list[0];
    renderInvestigationsPage(investigations);
    return;
  }

  renderInvDetails(selected);
}
