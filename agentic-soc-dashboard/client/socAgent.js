// client/socAgent.js
import { settings } from "./settings.js";

const state = {
  events: [],
  alerts: [],

  investigations: [],
  investigationsByIp: new Map(), // attacker ip -> investigation object

  // Rolling windows / memory
  authFailsByIp: new Map(), // ip -> timestamps[]
  reconByIp: new Map(), // ip -> { ports: Map(port -> lastTs) }
  sensitiveReadsByIp: new Map(), // ip -> timestamps[]
  exfilByIp: new Map(), // ip -> { items: [{ts, bytes}] }

  // Cooldowns to prevent spam
  lastAlertKeyTs: new Map(), // `${alertType}|${ip}|${user}` -> ts

  // Correlation memory per (ip,user)
  stageByIpUser: new Map(), // `${ip}|${user}` -> stage timestamps
};

function pruneOld(tsArray, cutoff) {
  while (tsArray.length && tsArray[0] < cutoff) tsArray.shift();
}

function pruneExfilItems(items, cutoff) {
  while (items.length && items[0].ts < cutoff) items.shift();
}

function makeAlert({ ts, ip, user, type, severity, explanation }) {
  return {
    id: `A-${ts}-${type}-${ip}`,
    ts,
    type,
    severity,
    ip,
    user,
    explanation,
  };
}

function cooldownOk(alertType, ip, user, ts, cooldownMs) {
  const key = `${alertType}|${ip}|${user || "-"}`;
  const last = state.lastAlertKeyTs.get(key) || 0;
  if (ts - last < cooldownMs) return false;
  state.lastAlertKeyTs.set(key, ts);
  return true;
}

function upsertInvestigation(attackerIp, alert) {
  let inv = state.investigationsByIp.get(attackerIp);

  if (!inv) {
    inv = {
      id: `I-${attackerIp}`,
      createdTs: alert.ts,
      lastSeenTs: alert.ts,
      title: `Suspicious activity from ${attackerIp}`,
      severity: alert.severity,
      entity: attackerIp,
      status: "OPEN",
      count: 1,
      victims: new Set([alert.user]),
      typeCounts: {},
    };

    inv.typeCounts[alert.type] = 1;

    state.investigationsByIp.set(attackerIp, inv);
    state.investigations.push(inv);
    return;
  }

  inv.lastSeenTs = alert.ts;
  inv.count += 1;
  inv.victims.add(alert.user);
  inv.typeCounts[alert.type] = (inv.typeCounts[alert.type] || 0) + 1;

  // Severity escalation (preserve existing behaviour)
  if (alert.severity === "CRITICAL") inv.severity = "CRITICAL";
  else if (alert.severity === "HIGH" && inv.severity !== "CRITICAL") inv.severity = "HIGH";
  else if (alert.severity === "MEDIUM" && !["HIGH", "CRITICAL"].includes(inv.severity)) inv.severity = "MEDIUM";
}

// ---- Correlation helper: track stages per (ip,user) ----
function markStage(ip, user, stageName, ts) {
  const key = `${ip}|${user}`;
  const obj = state.stageByIpUser.get(key) || {};
  obj[stageName] = ts;
  state.stageByIpUser.set(key, obj);
}

function getStages(ip, user) {
  return state.stageByIpUser.get(`${ip}|${user}`) || {};
}

function maybeCorrelateConfirmedCompromise(ip, user, ts) {
  // Multi-stage correlation: bruteForce -> anomalousLogin -> (fileSpike or exfil)
  // Use a correlation horizon that scales with the window (but never too tiny)
  const horizonMs = Math.max(60_000, settings.windowSeconds * 2 * 1000);

  const s = getStages(ip, user);

  const bf = s.bruteForceTs;
  const al = s.anomalousLoginTs;
  const fs = s.fileSpikeTs;
  const ex = s.exfilSpikeTs;

  if (!bf || !al) return;

  const within = (a, b) => Math.abs(a - b) <= horizonMs;

  const hasPost = (fs && within(fs, al)) || (ex && within(ex, al));
  const consistent = within(bf, al) && hasPost;

  if (!consistent) return;

  const alertType = "Confirmed Account Compromise (Multi-stage)";
  // Dedup: at least horizon, but respect user setting too
  const cooldownMs = Math.max(horizonMs, settings.dedupSeconds * 1000);
  if (!cooldownOk(alertType, ip, user, ts, cooldownMs)) return;

  const explanation =
    `Multi-stage correlation for (${user}): brute-force activity from ${ip} followed by ` +
    `a successful login and post-compromise behaviour (sensitive file access and/or exfil). ` +
    `This pattern strongly indicates account compromise.`;

  const alert = makeAlert({
    ts,
    ip,
    user,
    type: alertType,
    severity: "CRITICAL",
    explanation,
  });

  state.alerts.push(alert);
  upsertInvestigation(ip, alert);
}

// =======================
// DETECTORS ("TOOLS")
// =======================

// 1) Recon / port scanning suspected
function reconDetector(newEvents) {
  const WINDOW_MS = settings.windowSeconds * 1000;
  const DISTINCT_PORTS_THRESH = Math.max(2, Math.min(50, settings.reconConnAttempts));

  for (const e of newEvents) {
    if (e.type !== "net_conn_attempt") continue;

    const record = state.reconByIp.get(e.ip) || { ports: new Map() };
    record.ports.set(String(e.meta?.port ?? "unknown"), e.ts);

    // prune ports older than window
    const cutoff = e.ts - WINDOW_MS;
    for (const [p, ts] of record.ports.entries()) {
      if (ts < cutoff) record.ports.delete(p);
    }

    state.reconByIp.set(e.ip, record);

    if (record.ports.size >= DISTINCT_PORTS_THRESH) {
      const alertType = "Reconnaissance Suspected";
      const cooldownMs = Math.max(20_000, settings.dedupSeconds * 1000);
      if (!cooldownOk(alertType, e.ip, e.user, e.ts, cooldownMs)) continue;

      const portsList = Array.from(record.ports.keys()).slice(0, 10).join(", ");
      const explanation =
        `IP ${e.ip} attempted connections to ${record.ports.size} distinct ports within ` +
        `${settings.windowSeconds}s (${portsList}). This resembles reconnaissance / service probing.`;

      const alert = makeAlert({
        ts: e.ts,
        ip: e.ip,
        user: e.user,
        type: alertType,
        severity: "MEDIUM",
        explanation,
      });

      state.alerts.push(alert);
      upsertInvestigation(e.ip, alert);
    }
  }
}

// 2) Brute force / credential stuffing
function bruteForceDetector(newEvents) {
  const WINDOW_MS = settings.windowSeconds * 1000;
  const THRESH = settings.bruteForceFails;

  for (const e of newEvents) {
    if (e.type !== "auth_fail") continue;

    const arr = state.authFailsByIp.get(e.ip) || [];
    arr.push(e.ts);

    pruneOld(arr, e.ts - WINDOW_MS);
    state.authFailsByIp.set(e.ip, arr);

    if (arr.length < THRESH) continue;

    const alertType = "Brute Force Suspected";
    const cooldownMs = Math.max(30_000, settings.dedupSeconds * 1000);
    if (!cooldownOk(alertType, e.ip, e.user, e.ts, cooldownMs)) continue;

    const explanation =
      `Detected ${arr.length} failed logins from IP ${e.ip} within ${settings.windowSeconds} seconds ` +
      `(threshold=${THRESH}). Likely brute-force or credential stuffing against account ${e.user}.`;

    const alert = makeAlert({
      ts: e.ts,
      ip: e.ip,
      user: e.user,
      type: alertType,
      severity: "HIGH",
      explanation,
    });

    state.alerts.push(alert);
    upsertInvestigation(e.ip, alert);

    markStage(e.ip, e.user, "bruteForceTs", e.ts);
    maybeCorrelateConfirmedCompromise(e.ip, e.user, e.ts);
  }
}

// 3) Anomalous login source (success from attacker / non-home context)
function anomalousLoginDetector(newEvents) {
  for (const e of newEvents) {
    if (e.type !== "auth_success") continue;
    if (!e.meta?.attack) continue;

    const alertType = "Anomalous Login Source";
    const cooldownMs = Math.max(45_000, settings.dedupSeconds * 1000);
    if (!cooldownOk(alertType, e.ip, e.user, e.ts, cooldownMs)) continue;

    const explanation =
      `Successful authentication for ${e.user} from IP ${e.ip} marked as attack traffic. ` +
      `Because users normally authenticate from their stable home IP, this indicates a likely compromised login.`;

    const alert = makeAlert({
      ts: e.ts,
      ip: e.ip,
      user: e.user,
      type: alertType,
      severity: "HIGH",
      explanation,
    });

    state.alerts.push(alert);
    upsertInvestigation(e.ip, alert);

    markStage(e.ip, e.user, "anomalousLoginTs", e.ts);
    maybeCorrelateConfirmedCompromise(e.ip, e.user, e.ts);
  }
}

// 4) Sensitive file access spike
function sensitiveFileDetector(newEvents) {
  const WINDOW_MS = settings.windowSeconds * 1000;
  const THRESH = settings.sensitiveReads;

  for (const e of newEvents) {
    if (e.type !== "file_read_sensitive") continue;
    if (!e.meta?.attack) continue;

    const arr = state.sensitiveReadsByIp.get(e.ip) || [];
    arr.push(e.ts);

    pruneOld(arr, e.ts - WINDOW_MS);
    state.sensitiveReadsByIp.set(e.ip, arr);

    if (arr.length < THRESH) continue;

    const alertType = "Sensitive File Access Pattern";
    const cooldownMs = Math.max(45_000, settings.dedupSeconds * 1000);
    if (!cooldownOk(alertType, e.ip, e.user, e.ts, cooldownMs)) continue;

    const explanation =
      `Observed ${arr.length} sensitive file reads from IP ${e.ip} within ${settings.windowSeconds} seconds ` +
      `(threshold=${THRESH}). In combination with attack-tagged traffic, this suggests post-compromise collection activity.`;

    const alert = makeAlert({
      ts: e.ts,
      ip: e.ip,
      user: e.user,
      type: alertType,
      severity: "HIGH",
      explanation,
    });

    state.alerts.push(alert);
    upsertInvestigation(e.ip, alert);

    markStage(e.ip, e.user, "fileSpikeTs", e.ts);
    maybeCorrelateConfirmedCompromise(e.ip, e.user, e.ts);
  }
}

// 5) Exfiltration burst (bytes out)
function exfilDetector(newEvents) {
  const WINDOW_MS = settings.windowSeconds * 1000;
  const BYTES_THRESH = settings.exfilBytes;

  for (const e of newEvents) {
    if (e.type !== "net_bytes_out") continue;
    if (!e.meta?.attack) continue;

    const record = state.exfilByIp.get(e.ip) || { items: [] };
    record.items.push({ ts: e.ts, bytes: Number(e.meta?.bytes || 0) });

    pruneExfilItems(record.items, e.ts - WINDOW_MS);
    state.exfilByIp.set(e.ip, record);

    const sum = record.items.reduce((acc, it) => acc + it.bytes, 0);
    if (sum < BYTES_THRESH) continue;

    const alertType = "Possible Data Exfiltration";
    const cooldownMs = Math.max(60_000, settings.dedupSeconds * 1000);
    if (!cooldownOk(alertType, e.ip, e.user, e.ts, cooldownMs)) continue;

    const explanation =
      `Outbound transfer volume from IP ${e.ip} reached ~${sum.toLocaleString()} bytes in ` +
      `${settings.windowSeconds} seconds (threshold=${BYTES_THRESH.toLocaleString()}). ` +
      `This resembles data exfiltration following compromise.`;

    const alert = makeAlert({
      ts: e.ts,
      ip: e.ip,
      user: e.user,
      type: alertType,
      severity: "CRITICAL",
      explanation,
    });

    state.alerts.push(alert);
    upsertInvestigation(e.ip, alert);

    markStage(e.ip, e.user, "exfilSpikeTs", e.ts);
    maybeCorrelateConfirmedCompromise(e.ip, e.user, e.ts);
  }
}

// =======================
// AGENT LOOP STEP
// =======================

export function agentStep(newEvents) {
  state.events.push(...newEvents);
  if (state.events.length > 4000) state.events.splice(0, 900);

  reconDetector(newEvents);
  bruteForceDetector(newEvents);
  anomalousLoginDetector(newEvents);
  sensitiveFileDetector(newEvents);
  exfilDetector(newEvents);

  // Bound output sizes
  if (state.alerts.length > 600) state.alerts.splice(0, 150);
  if (state.investigations.length > 80) state.investigations.splice(0, 20);
}

export function getAgentState() {
  return state;
}
