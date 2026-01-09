const STORAGE_KEY = "agentic_soc_settings_v1";

export const DEFAULT_SETTINGS = Object.freeze({
  windowSeconds: 90,
  dedupSeconds: 60,
  bruteForceFails: 8,        // auth_fail count
  reconConnAttempts: 7,      // net_conn_attempt count
  sensitiveReads: 6,         // file_read_sensitive count
  exfilBytes: 450000,       // sum(net_bytes_out.bytes)
  escalateToHigh: 3,
  escalateToCritical: 6,
});

function clamp(n, min, max) { // clamp number n to range [min, max]
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, x));
}

function sanitize(input) { // sanitize settings object
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

function loadSettings() { // load settings from localStorage
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw);
    return sanitize({ ...DEFAULT_SETTINGS, ...parsed });
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}
export const settings = loadSettings();

export function saveSettings() { // save settings to localStorage
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // ignore write errors - note to self: do not catch errors here as will break because settings is const unless changed
  }
}

export function updateSettings(partial) { // update settings with partial object
  const next = sanitize({ ...settings, ...(partial || {}) });
  for (const k of Object.keys(next)) settings[k] = next[k];
  saveSettings();
  return settings;
}

export function resetSettings() { // reset settings to defaults
  for (const k of Object.keys(DEFAULT_SETTINGS)) settings[k] = DEFAULT_SETTINGS[k];
  saveSettings();
  return settings;
}
