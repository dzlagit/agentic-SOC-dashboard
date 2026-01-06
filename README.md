# Agentic SOC Dashboard (Cybersecurity Threat Monitoring)

A real-time **Security Operations Centre (SOC) dashboard** that simulates enterprise telemetry and applies an **agentic detection workflow** to generate alerts, group incidents into investigations, and visualise attack vs baseline activity.

Built to demonstrate practical SOC concepts (triage, escalation, campaigns) with a clean, modern UI and explainable detection logic.

## Highlights

- **Real-time telemetry pipeline**: simulated events streamed into the UI (auth, recon, sensitive access, exfil).
- **Agentic escalation**: detection logic promotes suspicious patterns into **alerts** and groups them into **investigations** (campaign-level view).
- **SOC-style triage UX**:
  - Alerts queue with **search / severity filter / sorting**
  - Click-to-view **full alert details** panel
  - Investigations queue grouped by attacker entity (IP) with case-level details
- **Threat vs baseline analytics**:
  - D3 trends show **attack-tagged activity** vs **home-IP baseline auth success**
  - “Threat Pressure” metric normalises threat volume against baseline
  - Suppresses incomplete time bins to avoid misleading end-of-series dips
- **Polished UI**: SPA routing, consistent layout, scroll-safe panels, product-like design.

## Tech Stack

- **Frontend**: Vanilla JS (ES modules), D3.js, HTML/CSS (SPA hash routing)
- **Backend**: Node.js + Express (telemetry simulator API)
- **Detection**: Agent-style rules + stateful correlation (campaign grouping)

## Architecture Overview

1. **Telemetry server** emits security-relevant events (normal user activity + multi-stage attack runs).
2. **SOC agent** consumes events, maintains rolling state, and:
   - raises alerts with explanations (triage-friendly)
   - groups alerts by attacker entity into investigations (campaigns)
3. **Dashboard UI** renders:
   - alert queue + details view
   - investigations queue + details view
   - threat vs baseline trend charts

## Getting Started

### Prerequisites
- Node.js (LTS recommended)

### Run the telemetry server
```bash
npm install
node server.js
