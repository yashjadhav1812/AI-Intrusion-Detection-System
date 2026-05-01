#!/usr/bin/env python3
"""
Real-time packet sniffer for AI IDS
Captures live packets from en0 (WiFi), extracts features,
feeds to ML model, and sends results to Flask app via API.
Run with: sudo python3 sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, get_if_list
import numpy as np
import pandas as pd
import pickle
import requests
import time
import os
import sys
from collections import defaultdict
from datetime import datetime

# ── Config ────────────────────────────────────────────────────
INTERFACE     = "en0"          # WiFi interface — change if needed (run get_if_list())
MODEL_PATH    = "model/ids_model.pkl"
FLASK_URL     = "http://127.0.0.1:5000"
WINDOW_SEC    = 5              # analyze flows every 5 seconds (was 2 — too short)
MIN_PACKETS   = 3              # minimum packets to analyze a flow (was 2)
FLOW_TIMEOUT  = 30             # expire flows older than 30s with no new packets

# ── Load Model ────────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    print(f"ERROR: Model not found at {MODEL_PATH}")
    print("Run train_model.py first!")
    sys.exit(1)

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# ── Print available interfaces so you can pick the right one ──
print("\nAvailable interfaces on this machine:")
for iface in get_if_list():
    print(f"  {iface}")
print()

print("=" * 60)
print("  AI Intrusion Detection System — Real Packet Sniffer")
print("=" * 60)
print(f"  Interface : {INTERFACE}")
print(f"  Model     : {MODEL_PATH}")
print(f"  Classes   : {list(model.classes_)}")
print(f"  Flask     : {FLASK_URL}")
print(f"  Window    : {WINDOW_SEC}s  |  Min packets: {MIN_PACKETS}")
print("=" * 60)
print("  Listening for live network traffic...")
print("  Press Ctrl+C to stop\n")

FEATURES = [
    "protocol", "flow_duration", "total_forward_packets",
    "total_backward_packets", "total_forward_packets_length",
    "total_backward_packets_length", "forward_packet_length_mean",
    "backward_packet_length_mean", "forward_packets_per_second",
    "backward_packets_per_second", "forward_iat_mean",
    "backward_iat_mean", "flow_iat_mean",
    "flow_packets_per_seconds", "flow_bytes_per_seconds"
]

# ── Flow tracker ──────────────────────────────────────────────
flows = defaultdict(lambda: {
    "start_time": None, "last_time": None,
    "fwd_packets": [], "bwd_packets": [],
    "fwd_times": [], "bwd_times": [],
    "all_times": []
})

# ── Live stats counters ───────────────────────────────────────
stats = {"total": 0, "attacks": 0, "benign": 0, "raw_packets": 0}

def get_time():
    return datetime.now().strftime("%H:%M:%S")

def extract_features(flow, src_ip, proto):
    """Extract the 15 CIC-IDS features from a captured flow."""
    fwd       = flow["fwd_packets"]
    bwd       = flow["bwd_packets"]
    fwd_times = flow["fwd_times"]
    bwd_times = flow["bwd_times"]
    all_times  = flow["all_times"]

    if len(all_times) < 2:
        return None

    duration = (flow["last_time"] - flow["start_time"]) * 1_000_000  # microseconds
    if duration <= 0:
        duration = 1

    total_fwd     = len(fwd)
    total_bwd     = len(bwd)
    total_fwd_len = sum(fwd)
    total_bwd_len = sum(bwd)
    fwd_mean      = np.mean(fwd) if fwd else 0
    bwd_mean      = np.mean(bwd) if bwd else 0

    # Inter-arrival times in microseconds (matching CIC-IDS format)
    fwd_iats  = [(fwd_times[i] - fwd_times[i-1]) * 1e6
                 for i in range(1, len(fwd_times))] if len(fwd_times) > 1 else [0]
    bwd_iats  = [(bwd_times[i] - bwd_times[i-1]) * 1e6
                 for i in range(1, len(bwd_times))] if len(bwd_times) > 1 else [0]
    all_iats  = [(all_times[i] - all_times[i-1]) * 1e6
                 for i in range(1, len(all_times))]  if len(all_times) > 1 else [0]

    fwd_iat_mean  = np.mean(fwd_iats)
    bwd_iat_mean  = np.mean(bwd_iats)
    flow_iat_mean = np.mean(all_iats)

    dur_sec            = duration / 1_000_000
    flow_pkts_per_sec  = (total_fwd + total_bwd) / dur_sec if dur_sec > 0 else 0
    flow_bytes_per_sec = (total_fwd_len + total_bwd_len) / dur_sec if dur_sec > 0 else 0
    fwd_pkts_per_sec   = total_fwd / dur_sec if dur_sec > 0 else 0
    bwd_pkts_per_sec   = total_bwd / dur_sec if dur_sec > 0 else 0

    return {
        "protocol":                      proto,
        "flow_duration":                 duration,
        "total_forward_packets":         total_fwd,
        "total_backward_packets":        total_bwd,
        "total_forward_packets_length":  total_fwd_len,
        "total_backward_packets_length": total_bwd_len,
        "forward_packet_length_mean":    fwd_mean,
        "backward_packet_length_mean":   bwd_mean,
        "forward_packets_per_second":    fwd_pkts_per_sec,
        "backward_packets_per_second":   bwd_pkts_per_sec,
        "forward_iat_mean":              fwd_iat_mean,
        "backward_iat_mean":             bwd_iat_mean,
        "flow_iat_mean":                 flow_iat_mean,
        "flow_packets_per_seconds":      flow_pkts_per_sec,
        "flow_bytes_per_seconds":        flow_bytes_per_sec,
    }

def analyze_flow(src_ip, flow, proto):
    """Run ML model on extracted features and notify Flask."""
    feats = extract_features(flow, src_ip, proto)
    if feats is None:
        return

    df = pd.DataFrame([feats])[FEATURES]
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    prediction = model.predict(df)[0]
    proba      = model.predict_proba(df)[0]
    confidence = round(max(proba) * 100, 1)
    is_attack  = str(prediction).upper() != "BENIGN"

    stats["total"] += 1
    if is_attack:
        stats["attacks"] += 1
    else:
        stats["benign"] += 1

    proto_name = "UDP" if proto == 17 else "TCP"
    status     = "ATTACK" if is_attack else "NORMAL"
    icon       = "🚨" if is_attack else "✅"
    total_pkts = feats["total_forward_packets"] + feats["total_backward_packets"]

    # Rich output line with real feature values for demo verification
    print(
        f"[{get_time()}] {icon} {status:<6} | {src_ip:<16} | {proto_name} | "
        f"Pkts: {total_pkts:>4} (↑{feats['total_forward_packets']} ↓{feats['total_backward_packets']}) | "
        f"Bytes/s: {feats['flow_bytes_per_seconds']:>10.1f} | "
        f"Pkts/s: {feats['flow_packets_per_seconds']:>6.1f} | "
        f"IAT µs: {feats['flow_iat_mean']:>10.0f} | "
        f"{prediction} ({confidence}%)"
    )
    print(f"           [Stats] Raw pkts: {stats['raw_packets']} | "
          f"Flows: {stats['total']} | 🚨 {stats['attacks']} | ✅ {stats['benign']}\n")

    # Send to Flask app
    try:
        payload = {
            "src_ip":     src_ip,
            "prediction": str(prediction),
            "is_attack":  is_attack,
            "confidence": confidence,
            "protocol":   proto,
            "fwd_pkts":   int(feats["total_forward_packets"]),       # raw count, not rate
            "bwd_pkts":   int(feats["total_backward_packets"]),      # raw count
            "fwd_pps":    round(feats["forward_packets_per_second"], 2),
            "flow_bytes": round(feats["flow_bytes_per_seconds"], 2),
        }
        requests.post(f"{FLASK_URL}/api/live_packet", json=payload, timeout=1)

        if is_attack:
            requests.post(f"{FLASK_URL}/api/block",
                          json={"ip": src_ip, "auto": True}, timeout=1)
    except Exception:
        pass  # Flask might not be running; sniffer still works standalone

last_analyze = time.time()

def packet_callback(pkt):
    global last_analyze

    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst
    now      = time.time()

    stats["raw_packets"] += 1

    # Determine protocol and payload length
    if pkt.haslayer(TCP):
        proto   = 6
        pkt_len = len(pkt[TCP].payload)
    elif pkt.haslayer(UDP):
        proto   = 17
        pkt_len = len(pkt[UDP].payload)
    else:
        return

    # Skip loopback, multicast, and unresolved IPs
    if (src_ip.startswith("127.") or
            src_ip.startswith("224.") or
            src_ip.startswith("239.") or
            src_ip == "0.0.0.0"):
        return

    # Flow direction: forward = src→dst, backward = reply
    flow_key = (src_ip, dst_ip, proto)
    rev_key  = (dst_ip, src_ip, proto)

    if rev_key in flows:
        flow = flows[rev_key]
        if flow["start_time"] is None:
            flow["start_time"] = now
        flow["last_time"] = now
        flow["bwd_packets"].append(pkt_len)
        flow["bwd_times"].append(now)
        flow["all_times"].append(now)
    else:
        flow = flows[flow_key]
        if flow["start_time"] is None:
            flow["start_time"] = now
        flow["last_time"] = now
        flow["fwd_packets"].append(pkt_len)
        flow["fwd_times"].append(now)
        flow["all_times"].append(now)

    # Every WINDOW_SEC: analyze flows with enough packets
    if now - last_analyze >= WINDOW_SEC:
        last_analyze = now
        to_delete = []
        for key, flow in list(flows.items()):
            total_pkts = len(flow["fwd_packets"]) + len(flow["bwd_packets"])
            age        = now - (flow["start_time"] or now)

            if total_pkts >= MIN_PACKETS:
                analyze_flow(key[0], flow, key[2])
                to_delete.append(key)
            elif age > FLOW_TIMEOUT:
                to_delete.append(key)  # expire stale flows

        for key in to_delete:
            del flows[key]

# ── Start sniffing ────────────────────────────────────────────
try:
    sniff(
        iface=INTERFACE,
        filter="ip and (tcp or udp)",
        prn=packet_callback,
        store=False
    )
except KeyboardInterrupt:
    print(f"\n\nSniffer stopped.")
    print(f"Session summary — Raw packets: {stats['raw_packets']} | "
          f"Flows: {stats['total']} | 🚨 Attacks: {stats['attacks']} | ✅ Benign: {stats['benign']}")
except PermissionError:
    print("\nERROR: Permission denied! Run with: sudo python3 sniffer.py")
except Exception as e:
    print(f"\nERROR: {e}")
    print(f"Available interfaces: {get_if_list()}")
    print("Update INTERFACE at the top of sniffer.py")
