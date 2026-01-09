# Agentic SOC Dashboard (Cybersecurity Simulation)

A high-fidelity Security Operations Centre (SOC) Simulation and SOAR (Security Orchestration, Automation, and Response) platform. This application streams live enterprise telemetry and utilizes a stateful detection engine to identify multi-stage attacks, manage investigations, and enforce security policies.



## Core Functionalities

### 1. Advanced Detection Engine (socAgent.js)
Unlike static dashboards, this project features a stateful correlation engine that identifies attack patterns across time windows:
* **Multi-Stage Correlation:** Detects "Confirmed Compromises" by linking disparate events (Brute Force → Recon → Sensitive File Access).
* **Dynamic Thresholding:** Uses configurable rolling windows and deduplication logic to prevent alert fatigue.
* **Heuristic Detectors:** Includes dedicated logic for Reconnaissance (port scanning), Brute Force, and Data Exfiltration.

### 2. Interactive SOC Workflow
* **Incident Triage:** A master-detail interface for alerts including severity filtering, search, and sorting.
* **Investigation Management:** Automatically groups related alerts by attacker IP into "Campaigns," allowing analysts to track the entire lifecycle of an intrusion.
* **SOAR Integration:** Real-time "Response" capabilities—analysts can block IPs or disable users directly from the dashboard, which synchronizes with the backend policy engine.

### 3. Real-Time Data Visualization
* **D3.js Analytics:** Live-updating trend charts visualizing "Threat Pressure" (attack volume vs. baseline activity).
* **KPI Tracking:** Real-time counters for Critical, High, Medium, and Low severity incidents.



## Tech Stack

* **Frontend:** Vanilla JavaScript (ES6+ Modules), D3.js for data visualization, CSS3 Grid/Flexbox.
* **Backend:** Node.js & Express (Telemetry & Policy API).
* **State Management:** Custom client-side state machine with render-freeze protection during user interaction.

## Architecture Overview

1. **Mock Telemetry Server:** Generates a mix of "noise" (normal user behavior) and "signals" (coordinated attack sequences).
2. **Detection Agent:** Processes the event stream, maintains a rolling history, and promotes patterns to Alerts.
3. **Policy Engine:** Handles orchestration commands (blocking/resetting) to simulate real-world network defense.
4. **Responsive UI:** A Single Page Application (SPA) using hash-routing for seamless navigation between Overview, Alerts, Investigations, and Settings.



## Getting Started

### Prerequisites
* **Node.js** (v16.x or higher)

### Installation & Execution
1. **Clone the repository** and navigate to the project folder.
2. **Start the Telemetry Server:**
   ```bash
   node server.js
