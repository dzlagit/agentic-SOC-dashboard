// client/main.js

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
const API = "http://localhost:3001/events";
const RESET_API = "http://localhost:3001/reset";

let paused = false;

/* ---------------- Routing ---------------- */

const ROUTES = ["overview", "alerts", "investigations", "settings"];

function getRouteFromHash() {
  const raw = (location.hash || "#overview").replace("#", "").trim().toLowerCase();
  return ROUTES.includes(raw) ? raw : "overview";
}

function setActiveRoute(route) {
  for (const r of ROUTES) {
    const el = document.getElementById(`page-${r}`);
    if (!el) continue;
    el.classList.toggle("active", r === route);
  }

  document.querySelectorAll(".nav-item[data-route]").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === route);
  });
}

function initRouter() {
  setActiveRoute(getRouteFromHash());
  window.addEventListener("hashchange", () => {
    setActiveRoute(getRouteFromHash());
    renderCurrentView(true);
  });
}

/* ---------------- Settings UI ---------------- */

let settingsBound = false;
let settingsEditing = false; // user is currently interacting with sliders/inputs

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

function setInputValue(id, value) {
  const el = document.getElementById(id);
  if (el) el.value = String(value);
}

function getNum(id) {
  const el = document.getElementById(id);
  if (!el) return NaN;
  return Number(el.value);
}

function setStatus(msg) {
  const el = document.getElementById("settingsStatus");
  if (!el) return;
  el.textContent = msg || "";
  if (msg) setTimeout(() => (el.textContent = ""), 1600);
}

function syncSettingsFormFromState() {
  // sliders
  setInputValue("setWindow", settings.windowSeconds);
  setInputValue("setDedup", settings.dedupSeconds);
  setInputValue("setBrute", settings.bruteForceFails);
  setInputValue("setRecon", settings.reconConnAttempts);
  setInputValue("setReads", settings.sensitiveReads);
  setInputValue("setExfil", settings.exfilBytes);

  // value labels
  setText("valWindow", settings.windowSeconds);
  setText("valDedup", settings.dedupSeconds);
  setText("valBrute", settings.bruteForceFails);
  setText("valRecon", settings.reconConnAttempts);
  setText("valReads", settings.sensitiveReads);
  setText("valExfil", settings.exfilBytes);
}

function isSettingsControlFocused() {
  const a = document.activeElement;
  if (!a) return false;
  const ids = new Set(["setWindow", "setDedup", "setBrute", "setRecon", "setReads", "setExfil"]);
  return ids.has(a.id);
}

function bindSettingsUI() {
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

    // when user starts interacting, we stop auto-syncing values
    input.addEventListener("pointerdown", () => {
      settingsEditing = true;
    });

    input.addEventListener("focus", () => {
      settingsEditing = true;
    });

    // live label update while dragging
    input.addEventListener("input", () => {
      setText(labelId, input.value);
    });

    // when user finishes interaction, we allow sync again
    input.addEventListener("pointerup", () => {
      settingsEditing = false;
    });

    input.addEventListener("blur", () => {
      // if they tabbed away, let future sync happen
      settingsEditing = false;
    });
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

      // after apply, reflect canonical clamped values
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

/* ---------------- Render ---------------- */

function renderCurrentView(forceSyncSettings = false) {
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
    bindAlertsPageControls(() => renderAlertsPage(state.alerts));
    renderAlertsPage(state.alerts);
    return;
  }

  if (route === "investigations") {
    bindInvestigationsPageControls(() => renderInvestigationsPage(state.investigations));
    renderInvestigationsPage(state.investigations);
    return;
  }

  if (route === "settings") {
    bindSettingsUI();

    // Only sync values if:
    // - we just navigated here (forceSyncSettings), or
    // - user isn't actively editing (prevents sliders snapping back)
    const editing = settingsEditing || isSettingsControlFocused();
    if (forceSyncSettings || !editing) {
      syncSettingsFormFromState();
    }

    return;
  }
}

/* ---------------- Poll ---------------- */

async function poll() {
  if (paused) return;

  const res = await fetch(`${API}?since=${since}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);

  const data = await res.json();
  if (data.events.length > 0) {
    since = data.latestId;
    agentStep(data.events);

    // Keep UI live, but do NOT stomp Settings interactions
    renderCurrentView(false);
  }
}

/* ---------------- Controls ---------------- */

function initControls() {
  const btnPause = document.getElementById("btnPause");
  if (btnPause) {
    btnPause.addEventListener("click", () => {
      paused = !paused;
      btnPause.textContent = paused ? "Resume" : "Pause";
    });
  }

  const btnReset = document.getElementById("btnReset");
  if (btnReset) {
    btnReset.addEventListener("click", async () => {
      await fetch(RESET_API, { method: "POST" });
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

      renderCurrentView(false);
    });
  }
}

initRouter();
initControls();

// first paint: force sync settings if user starts on settings
renderCurrentView(true);

setInterval(() => {
  poll().catch((e) => console.error(e));
}, 900);
