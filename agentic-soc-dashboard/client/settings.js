// client/settings.js
// Functional, persisted detection-policy knobs for the SOC agent.
// Stored in localStorage so it survives refreshes.

const STORAGE_KEY = "agentic_soc_settings_v1";

export const DEFAULT_SETTINGS = Object.freeze({
  // Rolling correlation window (how far back the agent looks)
  windowSeconds: 60,

  // Deduplicate identical alerts within this cooldown (prevents spam)
  dedupSeconds: 20,

  // Thresholds (within window)
  bruteForceFails: 8,        // auth_fail count
  reconConnAttempts: 6,      // net_conn_attempt count
  sensitiveReads: 4,         // file_read_sensitive count
  exfilBytes: 300_000,       // sum(net_bytes_out.bytes)

  // Escalation policy (how many distinct triggers to escalate severity)
  escalateToHigh: 1,
  escalateToCritical: 2,
});

function clamp(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, x));
}

function sanitize(input) {
  const s = input || {};
  return {
    windowSeconds: clamp(s.windowSeconds ?? DEFAULT_SETTINGS.windowSeconds, 15, 300),
    dedupSeconds: clamp(s.dedupSeconds ?? DEFAULT_SETTINGS.dedupSeconds, 0, 300),

    bruteForceFails: clamp(s.bruteForceFails ?? DEFAULT_SETTINGS.bruteForceFails, 3, 50),
    reconConnAttempts: clamp(s.reconConnAttempts ?? DEFAULT_SETTINGS.reconConnAttempts, 3, 50),
    sensitiveReads: clamp(s.sensitiveReads ?? DEFAULT_SETTINGS.sensitiveReads, 1, 50),
    exfilBytes: clamp(s.exfilBytes ?? DEFAULT_SETTINGS.exfilBytes, 50_000, 5_000_000),

    escalateToHigh: clamp(s.escalateToHigh ?? DEFAULT_SETTINGS.escalateToHigh, 1, 10),
    escalateToCritical: clamp(
      s.escalateToCritical ?? DEFAULT_SETTINGS.escalateToCritical,
      1,
      10
    ),
  };
}

function loadSettings() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw);
    return sanitize({ ...DEFAULT_SETTINGS, ...parsed });
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

// Important: keep a stable object reference so other modules can import and read live.
export const settings = loadSettings();

export function saveSettings() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // ignore
  }
}

export function updateSettings(partial) {
  const next = sanitize({ ...settings, ...(partial || {}) });
  for (const k of Object.keys(next)) settings[k] = next[k];
  saveSettings();
  return settings;
}

export function resetSettings() {
  for (const k of Object.keys(DEFAULT_SETTINGS)) settings[k] = DEFAULT_SETTINGS[k];
  saveSettings();
  return settings;
}
