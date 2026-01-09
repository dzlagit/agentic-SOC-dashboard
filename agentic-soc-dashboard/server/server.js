const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

let nextId = 1;
const events = [];

function now() {
  return Date.now();
}

const USERS = ["user1", "user2", "user3", "user4", "user5"];

const IPS = [ // sample IP addresses
  "203.0.113.10",
  "198.51.100.23",
  "192.0.2.44",
  "203.0.113.77",
  "198.51.100.99",
];

const RECON_PORTS = [ // ports commonly used for reconnaissance
  { port: 22, service: "ssh" },
  { port: 80, service: "http" },
  { port: 443, service: "https" },
  { port: 3389, service: "rdp" },
  { port: 8080, service: "http-alt" },
];

const policy = { // in-memory policy state
  blockedIps: new Set(),
  disabledUsers: new Set(),
  passwordResetUsers: new Set(),
};

function policyJson() { // serialize policy to JSON-friendly format
  return {
    blockedIps: Array.from(policy.blockedIps),
    disabledUsers: Array.from(policy.disabledUsers),
    passwordResetUsers: Array.from(policy.passwordResetUsers),
  };
}

function pushEvent(type, user, ip, meta = {}) { // push new event to events array
  events.push({
    id: nextId++,
    ts: now(),
    type,
    user,
    ip,
    meta,
  });

  if (events.length > 7000) events.splice(0, 1500);
}

function shuffled(arr) { // return a shuffled copy of arr
  return [...arr].sort(() => Math.random() - 0.5);
}

const ipPool = shuffled(IPS);
const userHomeIp = new Map(USERS.map((u, i) => [u, ipPool[i % ipPool.length]]));

console.log("User -> Home IP mapping:");
for (const u of USERS) console.log(`  ${u} -> ${userHomeIp.get(u)}`);

function isBlockedIp(ip) { // check if IP is blocked by policy
  return policy.blockedIps.has(ip);
}

function isDisabledUser(user) { // check if user is disabled by policy
  return policy.disabledUsers.has(user);
}

function isPasswordResetRequired(user) { // check if user requires password reset by policy
  return policy.passwordResetUsers.has(user);
}

const attackerHistory = [];
const attackerHistorySet = new Set();
const ATTACKER_HISTORY_MAX = 40;

function randInt(min, max) { // random integer in [min, max]
  return Math.floor(min + Math.random() * (max - min + 1));
}

function genPublicIp() { // generate a random public IP address
  const a = randInt(11, 223);
  const b = randInt(0, 255);
  const c = randInt(0, 255);
  const d = randInt(1, 254);

  if (a === 10) return genPublicIp();
  if (a === 127) return genPublicIp();
  if (a === 0) return genPublicIp();
  if (a === 169 && b === 254) return genPublicIp();
  if (a === 172 && b >= 16 && b <= 31) return genPublicIp();
  if (a === 192 && b === 168) return genPublicIp();
  if (a >= 224) return genPublicIp();

  return `${a}.${b}.${c}.${d}`;
}

function getRotatingAttackerIp() { // get a rotating attacker IP address
  for (let attempts = 0; attempts < 60; attempts++) {
    const ip = genPublicIp();
    if (isBlockedIp(ip)) continue;
    if (attackerHistorySet.has(ip)) continue;

    attackerHistory.push(ip);
    attackerHistorySet.add(ip);

    while (attackerHistory.length > ATTACKER_HISTORY_MAX) {
      const old = attackerHistory.shift();
      attackerHistorySet.delete(old);
    }

    return ip;
  }

  for (const ip of attackerHistory) {
    if (!isBlockedIp(ip)) return ip;
  }

  return "8.8.8.8";
}

setInterval(() => { // generate benign user activity
  const user = USERS[Math.floor(Math.random() * USERS.length)];
  const ip = userHomeIp.get(user);

  if (isDisabledUser(user)) {
    pushEvent("policy_block", user, ip, { home: true, reason: "user_disabled", action: "DISABLE_USER" });
    return;
  }

  if (isBlockedIp(ip)) {
    pushEvent("policy_block", user, ip, { home: true, reason: "ip_blocked", action: "BLOCK_IP" });
    return;
  }

  if (isPasswordResetRequired(user)) {
    pushEvent("policy_block", user, ip, { home: true, reason: "password_reset_required", action: "FORCE_PASSWORD_RESET" });
    return;
  }

  const r = Math.random();
  const homeMeta = { home: true };

  if (r < 0.35) pushEvent("auth_success", user, ip, { ...homeMeta, service: "vpn" });
  else if (r < 0.55) pushEvent("auth_fail", user, ip, { ...homeMeta, service: "vpn" });
  else if (r < 0.8) pushEvent("file_read_sensitive", user, ip, { ...homeMeta, file: "/hr/payroll.csv" });
  else
    pushEvent("net_bytes_out", user, ip, {
      ...homeMeta,
      bytes: Math.floor(3000 + Math.random() * 18000),
    });
}, 1600);

function scheduleAttackSequence(victim, attackerIp) { // schedule a sequence of attack events
  if (isBlockedIp(attackerIp)) {
    pushEvent("policy_block", victim, attackerIp, { attack: true, reason: "ip_blocked", action: "BLOCK_IP", suppressed: "attack_sequence" });
    return;
  }

  if (isDisabledUser(victim)) {
    pushEvent("policy_block", victim, attackerIp, { attack: true, reason: "user_disabled", action: "DISABLE_USER", suppressed: "attack_sequence" });
    return;
  }

  if (isPasswordResetRequired(victim)) {
    pushEvent("policy_block", victim, attackerIp, { attack: true, reason: "password_reset_required", action: "FORCE_PASSWORD_RESET", suppressed: "attack_sequence" });
    return;
  }

  for (let i = 0; i < 6; i++) {
    setTimeout(() => {
      if (isBlockedIp(attackerIp) || isDisabledUser(victim) || isPasswordResetRequired(victim)) return;
      const pick = RECON_PORTS[Math.floor(Math.random() * RECON_PORTS.length)];
      pushEvent("net_conn_attempt", victim, attackerIp, { attack: true, port: pick.port, service: pick.service });
    }, i * 220);
  }

  setTimeout(() => {
    for (let i = 0; i < 8; i++) {
      setTimeout(() => {
        if (isBlockedIp(attackerIp) || isDisabledUser(victim) || isPasswordResetRequired(victim)) return;
        pushEvent("auth_fail", victim, attackerIp, { attack: true, service: "vpn" });
      }, i * 250);
    }
  }, 1600);

  setTimeout(() => {
    if (isBlockedIp(attackerIp) || isDisabledUser(victim) || isPasswordResetRequired(victim)) return;
    pushEvent("auth_success", victim, attackerIp, { attack: true, service: "vpn" });
  }, 5200);

  setTimeout(() => {
    if (isBlockedIp(attackerIp) || isDisabledUser(victim) || isPasswordResetRequired(victim)) return;

    const files = ["/hr/payroll.csv", "/finance/budget.xlsx", "/customers/export.json"];
    const bursts = 5 + Math.floor(Math.random() * 3);

    for (let i = 0; i < bursts; i++) {
      const file = files[Math.floor(Math.random() * files.length)];
      pushEvent("file_read_sensitive", victim, attackerIp, { attack: true, file });
    }
  }, 6000);

  setTimeout(() => {
    if (isBlockedIp(attackerIp) || isDisabledUser(victim) || isPasswordResetRequired(victim)) return;

    for (let i = 0; i < 8; i++) {
      pushEvent("net_bytes_out", victim, attackerIp, {
        attack: true,
        bytes: 150000 + Math.floor(Math.random() * 60000),
      });
    }
  }, 7600);
}

setInterval(() => { // schedule attack every 45 seconds
  const victim = USERS[Math.floor(Math.random() * USERS.length)];
  const attackerIp = getRotatingAttackerIp();
  scheduleAttackSequence(victim, attackerIp);
}, 45000);

app.get("/events", (req, res) => { // get events since a given ID
  const since = Number(req.query.since || 0);
  const newEvents = events.filter((e) => e.id > since);
  res.json({ events: newEvents, latestId: nextId - 1, policy: policyJson() });
});

app.get("/policy", (req, res) => { // get current policy
  res.json({ ok: true, policy: policyJson() });
});

app.post("/policy/block-ip", (req, res) => { // block an IP address
  const ip = String(req.body?.ip || "").trim();
  if (!ip) return res.status(400).json({ ok: false, error: "Missing ip" });

  policy.blockedIps.add(ip); 
  pushEvent("policy_change", "-", ip, { action: "BLOCK_IP" });
  res.json({ ok: true, policy: policyJson() });
});

app.post("/policy/disable-user", (req, res) => { // disable a user
  const user = String(req.body?.user || "").trim();
  if (!user) return res.status(400).json({ ok: false, error: "Missing user" });

  policy.disabledUsers.add(user);
  pushEvent("policy_change", user, userHomeIp.get(user) || "-", { action: "DISABLE_USER" });
  res.json({ ok: true, policy: policyJson() });
});

app.post("/policy/force-password-reset", (req, res) => { // require password reset for a user
  const user = String(req.body?.user || "").trim();
  if (!user) return res.status(400).json({ ok: false, error: "Missing user" });

  policy.passwordResetUsers.add(user);
  pushEvent("policy_change", user, userHomeIp.get(user) || "-", { action: "FORCE_PASSWORD_RESET" });
  res.json({ ok: true, policy: policyJson() });
});

app.post("/reset", (req, res) => { // reset events and policy
  events.length = 0;
  nextId = 1;

  policy.blockedIps.clear();
  policy.disabledUsers.clear();
  policy.passwordResetUsers.clear();

  attackerHistory.length = 0;
  attackerHistorySet.clear();

  res.json({ ok: true, policy: policyJson() });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Telemetry server running: http://localhost:${PORT}`);
});
