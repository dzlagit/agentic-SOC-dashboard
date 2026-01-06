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
const IPS = ["203.0.113.10", "198.51.100.23", "192.0.2.44", "203.0.113.77"];

// External attacker IPs (separate from normal user home IPs)
const ATTACKER_IPS = ["45.155.205.12", "91.214.124.77", "185.220.101.9"];

// A small set of ports/services for recon simulation
const RECON_PORTS = [
  { port: 22, service: "ssh" },
  { port: 80, service: "http" },
  { port: 443, service: "https" },
  { port: 3389, service: "rdp" },
  { port: 8080, service: "http-alt" },
];

function pushEvent(type, user, ip, meta = {}) {
  events.push({
    id: nextId++,
    ts: now(),
    type,
    user,
    ip,
    meta,
  });

  // keep memory bounded
  if (events.length > 6000) events.splice(0, 1200);
}

// ---- Stable mapping: each user gets a consistent "home IP" (per run) ----
function shuffled(arr) {
  return [...arr].sort(() => Math.random() - 0.5);
}

const ipPool = shuffled(IPS);
const userHomeIp = new Map(USERS.map((u, i) => [u, ipPool[i % ipPool.length]]));

console.log("User -> Home IP mapping:");
for (const u of USERS) {
  console.log(`  ${u} -> ${userHomeIp.get(u)}`);
}

// ---- Normal background noise (uses HOME IP per user) ----
setInterval(() => {
  const user = USERS[Math.floor(Math.random() * USERS.length)];
  const ip = userHomeIp.get(user);

  const r = Math.random();

  // Mark normal events as home traffic
  const homeMeta = { home: true };

  if (r < 0.35) pushEvent("auth_success", user, ip, { ...homeMeta, service: "vpn" });
  else if (r < 0.55) pushEvent("auth_fail", user, ip, { ...homeMeta, service: "vpn" });
  else if (r < 0.8)
    pushEvent("file_read_sensitive", user, ip, { ...homeMeta, file: "/hr/payroll.csv" });
  else
    pushEvent("net_bytes_out", user, ip, {
      ...homeMeta,
      bytes: Math.floor(3000 + Math.random() * 18000),
    });
}, 900);

// ---- Multi-stage attack run ----
// Sequence: Recon -> Brute force -> Success -> Sensitive file access -> Exfil
setInterval(() => {
  const victim = USERS[Math.floor(Math.random() * USERS.length)];
  const attackerIp = ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];

  // 1) Recon (port/service probing)
  for (let i = 0; i < 6; i++) {
    setTimeout(() => {
      const pick = RECON_PORTS[Math.floor(Math.random() * RECON_PORTS.length)];
      pushEvent("net_conn_attempt", victim, attackerIp, {
        attack: true,
        port: pick.port,
        service: pick.service,
      });
    }, i * 220);
  }

  // 2) Brute force burst
  setTimeout(() => {
    for (let i = 0; i < 10; i++) {
      setTimeout(() => {
        pushEvent("auth_fail", victim, attackerIp, { attack: true, service: "vpn" });
      }, i * 250);
    }
  }, 1600);

  // 3) Compromised login success
  setTimeout(() => {
    pushEvent("auth_success", victim, attackerIp, { attack: true, service: "vpn" });
  }, 5200);

  // 4) Sensitive file access spike (collection)
  setTimeout(() => {
    const files = ["/hr/payroll.csv", "/finance/budget.xlsx", "/customers/export.json"];
    const bursts = 5 + Math.floor(Math.random() * 3); // 5–7 reads
    for (let i = 0; i < bursts; i++) {
      const file = files[Math.floor(Math.random() * files.length)];
      pushEvent("file_read_sensitive", victim, attackerIp, { attack: true, file });
    }
  }, 6000);

  // 5) Exfiltration spike
  setTimeout(() => {
    for (let i = 0; i < 8; i++) {
      pushEvent("net_bytes_out", victim, attackerIp, {
        attack: true,
        bytes: 150000 + Math.floor(Math.random() * 60000),
      });
    }
  }, 7600);
}, 28000);

// ---- API: incremental event fetch ----
app.get("/events", (req, res) => {
  const since = Number(req.query.since || 0);
  const newEvents = events.filter((e) => e.id > since);
  res.json({ events: newEvents, latestId: nextId - 1 });
});

// ---- API: reset telemetry ----
app.post("/reset", (req, res) => {
  events.length = 0;
  nextId = 1;
  res.json({ ok: true });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Telemetry server running: http://localhost:${PORT}`);
});
