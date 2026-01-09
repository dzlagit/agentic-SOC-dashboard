import { agentStep, getAgentState } from "./socAgent.js";
import {
  renderAlerts,
  renderKPIs,
  renderInvestigations,
  renderAlertsPage,
  bindAlertsPageControls,
  renderInvestigationsPage,
  bindInvestigationsPageControls,
} from "./ui.js";
import { renderTrends } from "./trends.js";
import { settings, updateSettings, resetSettings } from "./settings.js";

let since = 0;

const BASE = "http://localhost:3001";
const API = `${BASE}/events`;
const RESET_API = `${BASE}/reset`;
const POLICY_API = `${BASE}/policy`;

let paused = false;

const policy = { // current policy state
  blockedIps: new Set(),
  disabledUsers: new Set(),
  passwordResetUsers: new Set(),
};

window.socPolicy = policy;

let policySig = "";

function makePolicySig(p) { // simple signature to detect changes
  const a = [...(p.blockedIps || [])].sort().join(",");
  const b = [...(p.disabledUsers || [])].sort().join(",");
  const c = [...(p.passwordResetUsers || [])].sort().join(",");
  return `${a}||${b}||${c}`;
}

function emitPolicyChanged() { // notify UI of policy changes
  window.dispatchEvent(
    new CustomEvent("soc:policyChanged", {
      detail: {
        blockedIps: Array.from(policy.blockedIps),
        disabledUsers: Array.from(policy.disabledUsers),
        passwordResetUsers: Array.from(policy.passwordResetUsers),
      },
    })
  );
}

function syncPolicyFromServer(p) { // update local policy from server data
  if (!p) return;
  const sig = makePolicySig(p);
  if (sig === policySig) return;
  policySig = sig;

  policy.blockedIps.clear();
  policy.disabledUsers.clear();
  policy.passwordResetUsers.clear();

  for (const ip of p.blockedIps || []) policy.blockedIps.add(ip);
  for (const u of p.disabledUsers || []) policy.disabledUsers.add(u);
  for (const u of p.passwordResetUsers || []) policy.passwordResetUsers.add(u);

  emitPolicyChanged();
}

async function postJson(url, body) { // helper to POST JSON and parse response
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error ? String(data.error) : `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

async function fetchPolicy() { // initial fetch of policy from server
  const res = await fetch(POLICY_API);
  const data = await res.json().catch(() => ({}));
  if (data?.policy) syncPolicyFromServer(data.policy);
}

function isEventBlocked(e) { // check if event is blocked by current policy
  if (!e) return true;
  if (policy.blockedIps.has(e.ip)) return true;
  if (policy.disabledUsers.has(e.user)) return true;
  return false;
}

function isUserSelectingText() { // detect if user is selecting text
  const sel = window.getSelection?.();
  return !!sel && !sel.isCollapsed;
}

function isActiveEditable() { // detect if an input or editable element is focused
  const el = document.activeElement;
  if (!el) return false;
  const tag = (el.tagName || "").toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select" || tag === "button") return true;
  if (el.isContentEditable) return true;
  return false;
}

let uiHoveringInteractive = false;

function bindHoverFreeze() { // detect if user is hovering over interactive UI elements
  document.addEventListener(
    "pointerover",
    (e) => {
      const t = e.target;
      if (!(t instanceof Element)) return;

      const inAlerts =
        t.closest("#page-alerts .alerts-table-wrap") ||
        t.closest("#page-alerts #alertDetailsCard") ||
        t.closest("#page-alerts .alerts-controls");

      const inInv =
        t.closest("#page-investigations .inv-table-wrap") ||
        t.closest("#page-investigations #invDetailsCard") ||
        t.closest("#page-investigations .alerts-controls");

      uiHoveringInteractive = !!(inAlerts || inInv);
    },
    true
  );

  document.addEventListener(
    "pointerout",
    (e) => {
      const t = e.relatedTarget;
      if (!(t instanceof Element)) {
        uiHoveringInteractive = false;
        return;
      }

      const stillInAlerts =
        t.closest("#page-alerts .alerts-table-wrap") ||
        t.closest("#page-alerts #alertDetailsCard") ||
        t.closest("#page-alerts .alerts-controls");

      const stillInInv =
        t.closest("#page-investigations .inv-table-wrap") ||
        t.closest("#page-investigations #invDetailsCard") ||
        t.closest("#page-investigations .alerts-controls");

      uiHoveringInteractive = !!(stillInAlerts || stillInInv);
    },
    true
  );
}

const ROUTES = ["overview", "alerts", "investigations", "settings"];

function getRouteFromHash() { // parse route from URL hash
  const raw = (location.hash || "#overview").replace("#", "").trim().toLowerCase();
  return ROUTES.includes(raw) ? raw : "overview";
}

function setActiveRoute(route) { // update UI to reflect active route
  for (const r of ROUTES) {
    const el = document.getElementById(`page-${r}`);
    if (!el) continue;
    el.classList.toggle("active", r === route);
  }

  document.querySelectorAll(".nav-item[data-route]").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === route);
  });
}

function initRouter() { // initialize routing based on URL hash
  setActiveRoute(getRouteFromHash());
  window.addEventListener("hashchange", () => {
    setActiveRoute(getRouteFromHash());
    renderCurrentView(true);
  });
}

let settingsBound = false;
let settingsEditing = false;

function setText(id, value) { // set text content of an element
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

function setInputValue(id, value) { // set value of an input element
  const el = document.getElementById(id);
  if (el) el.value = String(value);
}

function getNum(id) { // get numeric value from an input element
  const el = document.getElementById(id);
  if (!el) return NaN;
  return Number(el.value);
}

function setStatus(msg) { // set status message in settings UI
  const el = document.getElementById("settingsStatus");
  if (!el) return;
  el.textContent = msg || "";
  if (msg) setTimeout(() => (el.textContent = ""), 1600);
}

function syncSettingsFormFromState() { // sync settings form inputs from current settings state
  setInputValue("setWindow", settings.windowSeconds);
  setInputValue("setDedup", settings.dedupSeconds);
  setInputValue("setBrute", settings.bruteForceFails);
  setInputValue("setRecon", settings.reconConnAttempts);
  setInputValue("setReads", settings.sensitiveReads);
  setInputValue("setExfil", settings.exfilBytes);

  setText("valWindow", settings.windowSeconds);
  setText("valDedup", settings.dedupSeconds);
  setText("valBrute", settings.bruteForceFails);
  setText("valRecon", settings.reconConnAttempts);
  setText("valReads", settings.sensitiveReads);
  setText("valExfil", settings.exfilBytes);
}

function isSettingsControlFocused() { // check if any settings input is focused
  const a = document.activeElement;
  if (!a) return false;
  const ids = new Set(["setWindow", "setDedup", "setBrute", "setRecon", "setReads", "setExfil"]);
  return ids.has(a.id);
}

function bindSettingsUI() { // bind event listeners to settings UI controls
  if (settingsBound) return;
  settingsBound = true;

  const ids = [
    ["setWindow", "valWindow"],
    ["setDedup", "valDedup"],
    ["setBrute", "valBrute"],
    ["setRecon", "valRecon"],
    ["setReads", "valReads"],
    ["setExfil", "valExfil"],
  ];

  for (const [inputId, labelId] of ids) {
    const input = document.getElementById(inputId);
    if (!input) continue;

    input.addEventListener("pointerdown", () => (settingsEditing = true));
    input.addEventListener("focus", () => (settingsEditing = true));

    input.addEventListener("input", () => {
      setText(labelId, input.value);
    });

    input.addEventListener("pointerup", () => (settingsEditing = false));
    input.addEventListener("blur", () => (settingsEditing = false));
  }

  const btnApply = document.getElementById("btnApplySettings");
  if (btnApply) {
    btnApply.addEventListener("click", () => {
      updateSettings({
        windowSeconds: getNum("setWindow"),
        dedupSeconds: getNum("setDedup"),
        bruteForceFails: getNum("setBrute"),
        reconConnAttempts: getNum("setRecon"),
        sensitiveReads: getNum("setReads"),
        exfilBytes: getNum("setExfil"),
      });

      settingsEditing = false;
      syncSettingsFormFromState();
      setStatus("Saved.");
      renderCurrentView(false);
    });
  }

  const btnReset = document.getElementById("btnResetSettings");
  if (btnReset) {
    btnReset.addEventListener("click", () => {
      resetSettings();
      settingsEditing = false;
      syncSettingsFormFromState();
      setStatus("Restored defaults.");
      renderCurrentView(false);
    });
  }
}

function ensureArray(obj, key) { // ensure obj[key] is an array
  if (!obj[key]) obj[key] = [];
  if (!Array.isArray(obj[key])) obj[key] = [];
  return obj[key];
}

function findInvestigation(state, investigationId, attackerIp) { // find investigation by id or attacker IP
  if (attackerIp && state.investigationsByIp?.get) {
    const byIp = state.investigationsByIp.get(attackerIp);
    if (byIp) return byIp;
  }

  if (investigationId) {
    const byId = state.investigations.find((x) => String(x.id) === String(investigationId));
    if (byId) return byId;
  }

  if (attackerIp) {
    return state.investigations.find((x) => String(x.entity) === String(attackerIp)) || null;
  }

  return null;
}

function findAlert(state, alertId) { // find alert by id
  if (!alertId) return null;
  return state.alerts.find((a) => String(a.id) === String(alertId)) || null;
}

function applyInvestigationAction(inv, actionType, meta = {}) { // apply action to an investigation
  const ts = Date.now();
  const actions = ensureArray(inv, "actions");
  actions.push({ type: actionType, ts, by: "Analyst", ...meta });

  inv.lastSeenTs = ts;

  if (actionType === "ACK") inv.ackTs = ts;
  if (actionType === "ASSIGN") inv.assignedTo = "Analyst";
  if (actionType === "CLOSE") inv.closedTs = ts;
  if (actionType === "REOPEN") inv.reopenedTs = ts;
}

function applyAlertAction(alert, actionType, meta = {}) { // apply action to an alert
  const ts = Date.now();
  const actions = ensureArray(alert, "actions");
  actions.push({ type: actionType, ts, by: "Analyst", ...meta });

  if (actionType === "ACK") {
    alert.status = "ACKNOWLEDGED";
    alert.ackTs = ts;
  }
  if (actionType === "ASSIGN") {
    alert.assignedTo = "Analyst";
    if (!alert.status) alert.status = "NEW";
  }
  if (actionType === "CLOSE") {
    alert.status = "CLOSED";
    alert.closedTs = ts;
  }
}

async function enforcePolicyAction(action, { ip, user } = {}) { // enforce a policy action via server API
  const a = String(action || "").toUpperCase();

  if (a === "BLOCK_IP" && ip) { // block an IP address
    policy.blockedIps.add(ip);
    emitPolicyChanged();
    const data = await postJson(`${BASE}/policy/block-ip`, { ip });
    if (data?.policy) syncPolicyFromServer(data.policy);
    return;
  }

  if (a === "DISABLE_USER" && user) { // disable a user account
    policy.disabledUsers.add(user);
    emitPolicyChanged();
    const data = await postJson(`${BASE}/policy/disable-user`, { user });
    if (data?.policy) syncPolicyFromServer(data.policy);
    return;
  }

  if (a === "FORCE_PASSWORD_RESET" && user) { // force password reset for a user
    policy.passwordResetUsers.add(user);
    emitPolicyChanged();
    const data = await postJson(`${BASE}/policy/force-password-reset`, { user });
    if (data?.policy) syncPolicyFromServer(data.policy);
    return;
  }
}

let alertsBound = false;
let invBound = false;

function renderCurrentView(forceSyncSettings = false) { // render the current view based on route
  const state = getAgentState();
  const route = getRouteFromHash();

  if (route === "overview") {
    renderKPIs(state.alerts);
    renderAlerts(state.alerts);
    renderInvestigations(state.investigations);
    renderTrends(state.events);
    return;
  }

  if (route === "alerts") {
    if (!alertsBound) {
      bindAlertsPageControls(() => renderAlertsPage(state.alerts));
      alertsBound = true;
    }
    renderAlertsPage(state.alerts);
    return;
  }

  if (route === "investigations") {
    if (!invBound) {
      bindInvestigationsPageControls(() => renderInvestigationsPage(state.investigations));
      invBound = true;
    }
    renderInvestigationsPage(state.investigations);
    return;
  }

  if (route === "settings") {
    bindSettingsUI();
    const editing = settingsEditing || isSettingsControlFocused();
    if (forceSyncSettings || !editing) syncSettingsFormFromState();
    return;
  }
}

function shouldFreezeRender(route) { // determine if rendering should be frozen based on user interaction
  if (route === "settings") {
    return settingsEditing || isSettingsControlFocused() || isUserSelectingText();
  }
  if (route === "alerts" || route === "investigations") {
    return uiHoveringInteractive || isActiveEditable() || isUserSelectingText();
  }
  return false;
}

function bindActionWiring() { // bind event listeners for alert and investigation actions
  window.addEventListener("soc:alertAction", async (e) => {
    const d = e.detail || {};
    const state = getAgentState();

    const action = String(d.action || "").toUpperCase();
    const alert = findAlert(state, d.alertId);
    if (!alert) return;

    if (action === "ACK" || action === "ASSIGN" || action === "CLOSE") {
      applyAlertAction(alert, action, { ip: d.ip, user: d.user });
      renderCurrentView(false);
      return;
    }

    if (action === "BLOCK_IP") {
      try {
        await enforcePolicyAction(action, { ip: d.ip });
      } catch (err) {
        console.error(err);
      }
      renderCurrentView(false);
      return;
    }

    if (
      action === "DISABLE_USER" ||
      action === "FORCE_PASSWORD_RESET"
    ) {
      try {
        await enforcePolicyAction(action, { user: d.user });
      } catch (err) {
        console.error(err);
      }
      renderCurrentView(false);
      return;
    }
  });

  window.addEventListener("soc:investigationAction", async (e) => {
    const d = e.detail || {};
    const state = getAgentState();

    const action = String(d.action || "").toUpperCase();
    const inv = findInvestigation(state, d.investigationId, d.attackerIp);
    if (!inv) return;

    if (["ACK", "ASSIGN", "CLOSE", "REOPEN"].includes(action)) {
      applyInvestigationAction(inv, action);
      renderCurrentView(false);
      return;
    }

    if (action === "BLOCK_IP") {
      applyInvestigationAction(inv, action);
      try {
        await enforcePolicyAction(action, { ip: inv.entity });
      } catch (err) {
        console.error(err);
      }
      renderCurrentView(false);
      return;
    }

    if (
      action === "DISABLE_USER" ||
      action === "FORCE_PASSWORD_RESET"
    ) {
      applyInvestigationAction(inv, action);
      const victims =
        inv.victims instanceof Set
          ? Array.from(inv.victims)
          : Array.isArray(inv.victims)
          ? inv.victims
          : [];

      try {
        for (const u of victims) {
          await enforcePolicyAction(action, { user: u });
        }
      } catch (err) {
        console.error(err);
      }

      renderCurrentView(false);
      return;
    }
  });
}

async function poll() { // poll server for new events and update state
  if (paused) return;

  const res = await fetch(`${API}?since=${since}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);

  const data = await res.json().catch(() => ({}));
  if (data?.policy) syncPolicyFromServer(data.policy);

  const incoming = Array.isArray(data.events) ? data.events : [];

  if (incoming.length > 0) {
    since = data.latestId;

    const filtered = incoming.filter((e) => !isEventBlocked(e));
    if (filtered.length > 0) agentStep(filtered);

    const route = getRouteFromHash();
    if (!shouldFreezeRender(route)) {
      renderCurrentView(false);
    }
  }
}

function initControls() { // initialize UI control event listeners
  const btnPause = document.getElementById("btnPause");
  if (btnPause) {
    btnPause.addEventListener("click", () => {
      paused = !paused;
      btnPause.textContent = paused ? "Resume" : "Pause";
    });
  }

  const btnReset = document.getElementById("btnReset"); // reset all data and state
  if (btnReset) {
    btnReset.addEventListener("click", async () => {
      try {
        const res = await fetch(RESET_API, { method: "POST" });
        const data = await res.json().catch(() => ({}));
        if (data?.policy) syncPolicyFromServer(data.policy);
        else {
          policy.blockedIps.clear();
          policy.disabledUsers.clear();
          policy.passwordResetUsers.clear();
          policySig = "";
          emitPolicyChanged();
        }
      } catch (err) {
        console.error(err);
      }

      since = 0;

      const state = getAgentState();
      state.events.length = 0;
      state.alerts.length = 0;
      state.investigations.length = 0;

      if (state.investigationsByIp?.clear) state.investigationsByIp.clear();
      if (state.authFailsByIp?.clear) state.authFailsByIp.clear();
      if (state.reconByIp?.clear) state.reconByIp.clear();
      if (state.sensitiveReadsByIp?.clear) state.sensitiveReadsByIp.clear();
      if (state.exfilByIp?.clear) state.exfilByIp.clear();
      if (state.lastAlertKeyTs?.clear) state.lastAlertKeyTs.clear();
      if (state.stageByIpUser?.clear) state.stageByIpUser.clear();

      alertsBound = false;
      invBound = false;

      renderCurrentView(false);
    });
  }
}

initRouter();
initControls();
bindHoverFreeze();
bindActionWiring();
fetchPolicy().catch((e) => console.error(e));
renderCurrentView(true);

setInterval(() => {
  poll().catch((e) => console.error(e));
}, 900);
