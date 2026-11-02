#!/usr/bin/env python
"""
verify_iforest.py

Quick sanity‑check that the Isolation‑Forest detector works end‑to‑end:

1️⃣ Generate a DNS‑anomaly PCAP (Scenario D) using the demo traffic generator.
2️⃣ Ingest the PCAP → host‑window feature rows.
3️⃣ Load the trained baseline model.
4️⃣ Score the windows and print any alerts.
"""

import pathlib, sys

# 1️⃣ Generate the malicious PCAP
from scripts.demo_traffic import generate_scenario_d_dns_anomaly
from scapy.utils import wrpcap

SRC_IP = "10.0.0.5"
PCAP_PATH = pathlib.Path("data/uploads/dns_anomaly_demo.pcap")
PCAP_PATH.parent.mkdir(parents=True, exist_ok=True)
wrpcap(PCAP_PATH, generate_scenario_d_dns_anomaly(SRC_IP))
print(f"[+] PCAP written to {PCAP_PATH}")

# 2️⃣ Ingest + feature extraction
from netguard.ingest.pcap_reader import ingest_pcap
from netguard.features.window_features import build_features

rows = ingest_pcap(PCAP_PATH)
feature_rows = build_features(rows)
print(f"[+] Extracted {len(feature_rows)} host‑window feature rows")
if not feature_rows:
    sys.exit("No feature rows – something went wrong in extraction.")
print("[+] First feature row keys:", list(feature_rows[0].keys()))

# 3️⃣ Load the trained baseline model
from netguard.detection.iforest import load_model_bundle
model_bundle = load_model_bundle("default_baseline")
print("[+] Model loaded – version:", model_bundle.get("model_version"))
print("[+] Calibrated threshold:", model_bundle.get("threshold"))

# 4️⃣ Score the windows
from netguard.detection.iforest import score_windows_with_model
findings, _ = score_windows_with_model(feature_rows, model_bundle)

print("\n=== Isolation‑Forest Results ===")
print(f"Total windows scored : {len(feature_rows)}")
print(f"ML alerts generated  : {len(findings)}")
if findings:
    for f in findings:
        print("-"*70)
        print(f"Host: {f.src_ip}")
        print(f"Score: {f.details['score']:.4f} (threshold {f.details['threshold']:.4f})")
        print(f"Severity: {f.severity}")
        print(f"Dominant family: {f.details.get('dominant_family')}")
        print(f"Summary: {f.summary}")
else:
    print("No anomalies detected – the UI would show ‘No ML Anomalies Detected’.")

