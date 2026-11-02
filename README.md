# NetGuard — Network Intrusion Detection, Prevention & Forensic Correlation Platform

An end-to-end network intrusion detection, prevention, and forensic correlation system designed for Windows environments. Processes live network interfaces (Npcap) and offline PCAP/PCAPng files through a complete analysis pipeline:
**Packet Ingestion → Flow Reconstruction → Behavioral Feature Windows → Dual-Engine Detection (Rules + Isolation Forest ML) → Alert Deduplication → Union-Find Incident Correlation → 0–100 Prioritization Scoring → Windows Defender Firewall Active Containment → SOC Dashboard & Forensic Reporting.**

---

## Key Highlights & Verification Status

- **Automated Test Suite:** **160 / 160 PASSED (100%)** across 29 test files (`pytest`).
- **Live Packet Capture:** Npcap + Scapy integration with interface discovery, pause/resume, bounded queue backpressure, dropped packets accounting, and rolling PCAP evidence persistence.
- **Active OS Prevention:** Genuine Windows Defender Firewall rule management via PowerShell NetSecurity (`New-NetFirewallRule`), supporting Monitor, Manual, and Automatic modes with safe IP filters and lease expiry.
- **Authentic Dataset Benchmarking:** Built-in evaluation pipeline for **CIC-IDS2017** and **UNSW-NB15** with schema translation, confusion matrix, precision/recall/F1 metrics, and CLI runner (`evaluate_dataset.py`).
- **Controlled Lab Attack Generator:** Programmatic Scapy generator (`scripts/demo_traffic.py`) for Scenarios A through F (Normal, Port Scan, Brute Force, DNS Anomaly, Outbound Transfer, Correlated Multi-Stage).
- **Threat Intelligence:** AbuseIPDB reputation lookups with RFC1918 private IP protection, in-memory TTL caching, and offline fallback.
- **Forensic Admissibility:** Stable 1-based frame numbers matching Wireshark, copyable display filters, chronological event timelines, and exportable HTML/JSON reports.

---

## Architecture Overview

```
                      Physical / Virtual NIC (Npcap)  OR  Offline PCAP / PCAPng
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  ingest/pcap_reader.py & capture/live_capture │  1-based frame numbers, SHA-256,
                      │  ingest/flow_builder.py                       │  bounded queue, bidirectional flows
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  features/window_features.py                 │  9-dimensional behavioral vectors
                      │  (extract_window_features_for_capture)       │  across 20-second tumbling windows
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  detection/                                  │
                      │   port_scan.py    – Vertical Reconnaissance  │  Deterministic rules (confidence 0.6–0.9)
                      │   brute_force.py  – Short Auth Bursts        │  +
                      │   dns_anomaly.py  – Burst / Tunneling / DGA  │  Isolation Forest ML Anomaly
                      │   outbound.py     – Abnormal Exfiltration    │  (99th percentile baseline threshold)
                      │   iforest.py      – Unsupervised ML Anomaly  │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  correlation/dedup.py                        │  Hash-key deduplication & CIDR allowlist
                      │  correlation/engine.py (Union-Find)          │  Same-Source (600s) + Lateral Pivot (900s)
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  scoring/scorer.py                           │  0–100 heuristic prioritization score
                      │  evidence/wireshark.py & timeline.py         │  Wireshark filters, chronological timeline
                      │  firewall/windows_fw.py                      │  Windows Defender Firewall active blocking
                      │  threat_intel/abuseipdb.py                   │  AbuseIPDB reputation caching
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │  netguard/web/app.py (Flask Dashboard)       │  Live Monitor, Traffic Forensics, Alerts,
                      │  SQLite Database (14 tables, WAL mode)       │  Incidents, Firewall UI, Evaluation, Reports
                      └──────────────────────────────────────────────┘
```

---

## Installation & Setup

### 1. Requirements
- **OS:** Windows 10 / Windows 11 x64 (Primary), or Linux
- **Python:** Python 3.10 to 3.14
- **Npcap:** Version 1.70+ with WinPcap API-compatible mode enabled (for live capture)

### 2. Install Python Dependencies
```powershell
cd D:\netguard\is_project2\is_project
pip install -r requirements.txt
```

### 3. Verify Npcap (For Live Sniffing)
Download and install Npcap from [https://npcap.com/#download](https://npcap.com/#download). Ensure **"WinPcap API-compatible Mode"** and **"Support loopback traffic"** are checked.

---

## Quick Start & Usage

### 1. Launch the SOC Dashboard
Open an elevated terminal (for firewall & NIC access) and run:
```powershell
python netguard/web/app.py
```
Open your browser at **`http://127.0.0.1:5000`**.

### 2. Run the Full Automated Test Suite
```powershell
python -m pytest tests/ -v
```
*Expected Result:* **160 passed in ~51s (100% pass rate across 29 test files)**.

### 3. Run Controlled Attack Traffic Generator (Scenarios A through F)
```powershell
# Scenario A: Normal Web & DNS Browsing (Benign)
python scripts/demo_traffic.py --scenario A --pcap data/captures/demo_scenario_a.pcap

# Scenario B: Vertical Port Scan (Reconnaissance)
python scripts/demo_traffic.py --scenario B --pcap data/captures/demo_scenario_b.pcap

# Scenario C: Repeated Authentication Connection Bursts (Access Attempt)
python scripts/demo_traffic.py --scenario C --pcap data/captures/demo_scenario_c.pcap

# Scenario D: DNS High-Rate / Long Labels / NXDOMAIN (Possible Exploitation)
python scripts/demo_traffic.py --scenario D --pcap data/captures/demo_scenario_d.pcap

# Scenario E: Abnormal Outbound Data Volume (Possible Exfiltration)
python scripts/demo_traffic.py --scenario E --pcap data/captures/demo_scenario_e.pcap

# Scenario F: Correlated Multi-Stage Incident (Full Kill Chain)
python scripts/demo_traffic.py --scenario F --pcap data/captures/demo_scenario_f.pcap
```

### 4. Run Authentic Dataset Benchmark (CIC-IDS2017)
```powershell
python evaluate_dataset.py --csv tests/data/datasets/cic_ids2017_sample.csv --dataset CIC-IDS2017
```

---

## Documentation Library

Detailed engineering, operational, and academic guides are available in the `docs/` folder:

| Document | Purpose |
| :--- | :--- |
| **[`docs/architecture.md`](docs/architecture.md)** | Deep architectural diagrams, flow math, and module specifications. |
| **[`docs/windows_setup_guide.md`](docs/windows_setup_guide.md)** | Step-by-step Windows, Npcap, Wireshark, and unprivileged mode setup. |
| **[`docs/demonstration_guide.md`](docs/demonstration_guide.md)** | Step-by-step laboratory guide for Scenarios A–F and active firewall containment. |
| **[`docs/dataset_guide.md`](docs/dataset_guide.md)** | Authoritative dataset profiles (CIC-IDS2017, UNSW-NB15), schema mapping, and metrics. |
| **[`docs/objective_mapping.md`](docs/objective_mapping.md)** | Traceability matrix mapping syllabus objectives to modules and verification tests. |
| **[`docs/viva_defense.md`](docs/viva_defense.md)** | Comprehensive oral examination Q&A guide covering architecture, ML, and defense. |
| **[`docs/results.md`](docs/results.md)** | Documented test suite results, confusion matrix, and throughput benchmarks. |

---

## Detection Rules & Thresholds

| Rule Name | Stage | Primary Thresholds | Default Confidence |
| :--- | :--- | :--- | :---: |
| **Vertical Port Scan** | Reconnaissance | $\ge 15$ distinct destination ports, $\ge 70\%$ failed flow ratio | `0.90` |
| **Brute-Force Bursts** | Access Attempt | Service ports (21, 22, 23, 3389, 5900), $\ge 10$ attempts, $\ge 50\%$ short flows ($\le 5\text{s}$) | `0.70` |
| **DNS Anomaly** | Possible Exploitation | $\ge 60$ queries/window OR label length $\ge 40$ chars OR $\ge 50\%$ NXDOMAIN responses | `0.60` |
| **Abnormal Outbound** | Possible Exfiltration | Volume $\ge 1\text{ MB}$ OR upload ratio $\ge 20:1$ OR non-standard port transfer $\ge 200\text{ KB}$ | `0.60` |
| **Isolation Forest ML** | Anomaly | Anomaly score exceeding 99th-percentile baseline threshold across 9 host-window features | `0.50` |

---

## Academic & Technical Disclaimers

1. **Heuristic Score Nature**: The 0–100 incident score is a triage prioritization metric to rank an analyst's queue; it is not a statistical probability of compromise.
2. **Connection Pattern Heuristic**: Brute-force detection identifies rapid connection attempts on authentication ports. It does not inspect encrypted TLS/SSH credentials.
3. **Encrypted Payloads**: Operates on packet headers, flow statistics, and DNS query names. It does not perform active TLS decryption or SSL inspection.
4. **Safety Filter**: Firewall prevention strictly protects loopback (`127.0.0.1`), host interface IPs, default gateways, and local DNS resolvers from being blocked.
