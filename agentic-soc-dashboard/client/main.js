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

let since = 0;
const API = "http://localhost:3001/events";
const RESET_API = "http://localhost:3001/reset";

let paused = false;

/* ---------------- Routing ---------------- */

const ROUTES = ["overview", "alerts", "investigations", "entities", "settings"];

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
    renderCurrentView();
  });
}

/* ---------------- Render ---------------- */

function renderCurrentView() {
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

  // other pages next
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
    renderCurrentView();
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

      renderCurrentView();
    });
  }
}

initRouter();
initControls();
renderCurrentView();

setInterval(() => {
  poll().catch((e) => console.error(e));
}, 900);
