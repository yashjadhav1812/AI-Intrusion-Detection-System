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
import threading
import queue
from collections import defaultdict
from datetime import datetime

# ── Config ────────────────────────────────────────────────────
INTERFACE    = "en0"               # WiFi — change if needed
MODEL_PATH   = "model/ids_model.pkl"
FLASK_URL    = "http://127.0.0.1:5000"
FLOW_TIMEOUT = 5                   # expire flows with no activity after 5s

# ── Load Model ────────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    print(f"ERROR: Model not found at {MODEL_PATH}")
    print("Run train_model.py first!")
    sys.exit(1)

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

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
print(f"  Mode      : Per-packet instant analysis")
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

# ── Stats ─────────────────────────────────────────────────────
stats = {"total": 0, "attacks": 0, "benign": 0, "raw_packets": 0}
stats_lock = threading.Lock()

def get_time():
    return datetime.now().strftime("%H:%M:%S")

# ── Non-blocking HTTP sender ───────────────────────────────────
# All Flask POSTs go into this queue — a background thread drains it.
# The packet callback and ML thread are NEVER blocked waiting on HTTP.
_send_q = queue.Queue(maxsize=1000)

def _sender_worker():
    session = requests.Session()   # persistent TCP connection to Flask
    while True:
        try:
            url, payload = _send_q.get(timeout=1)
            try:
                session.post(url, json=payload, timeout=0.8)
            except Exception:
                pass   # Flask down or slow — drop silently
            _send_q.task_done()
        except queue.Empty:
            continue

threading.Thread(target=_sender_worker, daemon=True).start()

def send_async(path, payload):
    """Queue a Flask POST — returns immediately, never blocks."""
    try:
        _send_q.put_nowait((f"{FLASK_URL}{path}", payload))
    except queue.Full:
        pass

# ── ML analysis queue ─────────────────────────────────────────
# packet_callback puts raw flow snapshots here instantly.
# A dedicated ML thread reads, runs inference, sends to Flask.
# The scapy capture thread is NEVER blocked by ML or HTTP.
_ml_q = queue.Queue(maxsize=2000)

def _ml_worker():
    while True:
        try:
            item = _ml_q.get(timeout=1)
            try:
                _run_ml(item)
            except Exception as e:
                print(f"[ML ERROR] {e}")
            _ml_q.task_done()
        except queue.Empty:
            continue

def _run_ml(item):
    src_ip = item["src_ip"]
    proto  = item["proto"]
    fwd    = item["fwd_packets"]
    bwd    = item["bwd_packets"]
    ft     = item["fwd_times"]
    bt     = item["bwd_times"]
    at     = item["all_times"]

    # Need at least 2 timestamps to compute IAT
    if len(at) < 2:
        return

    start    = at[0]
    end      = at[-1]
    duration = (end - start) * 1_000_000   # microseconds
    if duration <= 0:
        duration = 1

    total_fwd     = len(fwd)
    total_bwd     = len(bwd)
    total_fwd_len = sum(fwd)
    total_bwd_len = sum(bwd)
    fwd_mean      = float(np.mean(fwd)) if fwd else 0.0
    bwd_mean      = float(np.mean(bwd)) if bwd else 0.0

    fwd_iats = [(ft[i]-ft[i-1])*1e6 for i in range(1, len(ft))] if len(ft) > 1 else [0]
    bwd_iats = [(bt[i]-bt[i-1])*1e6 for i in range(1, len(bt))] if len(bt) > 1 else [0]
    all_iats = [(at[i]-at[i-1])*1e6 for i in range(1, len(at))] if len(at) > 1 else [0]

    dur_sec  = duration / 1_000_000
    flow_pps = (total_fwd + total_bwd) / dur_sec if dur_sec > 0 else 0
    flow_bps = (total_fwd_len + total_bwd_len) / dur_sec if dur_sec > 0 else 0
    fwd_pps  = total_fwd / dur_sec if dur_sec > 0 else 0
    bwd_pps  = total_bwd / dur_sec if dur_sec > 0 else 0

    feats = {
        "protocol":                      proto,
        "flow_duration":                 duration,
        "total_forward_packets":         total_fwd,
        "total_backward_packets":        total_bwd,
        "total_forward_packets_length":  total_fwd_len,
        "total_backward_packets_length": total_bwd_len,
        "forward_packet_length_mean":    fwd_mean,
        "backward_packet_length_mean":   bwd_mean,
        "forward_packets_per_second":    fwd_pps,
        "backward_packets_per_second":   bwd_pps,
        "forward_iat_mean":              float(np.mean(fwd_iats)),
        "backward_iat_mean":             float(np.mean(bwd_iats)),
        "flow_iat_mean":                 float(np.mean(all_iats)),
        "flow_packets_per_seconds":      flow_pps,
        "flow_bytes_per_seconds":        flow_bps,
    }

    df = pd.DataFrame([feats])[FEATURES]
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    prediction = model.predict(df)[0]
    proba      = model.predict_proba(df)[0]
    confidence = round(float(max(proba)) * 100, 1)
    is_attack  = str(prediction).upper() != "BENIGN"

    with stats_lock:
        stats["total"] += 1
        if is_attack: stats["attacks"] += 1
        else:         stats["benign"]  += 1

    proto_name = "UDP" if proto == 17 else "TCP"
    icon       = "🚨" if is_attack else "✅"
    status     = "ATTACK" if is_attack else "NORMAL"

    print(
        f"[{get_time()}] {icon} {status:<6} | {src_ip:<16} | {proto_name} | "
        f"Pkts: {total_fwd+total_bwd} (↑{total_fwd} ↓{total_bwd}) | "
        f"Bytes/s: {flow_bps:>10.1f} | Pkts/s: {flow_pps:>6.1f} | "
        f"{prediction} ({confidence}%)"
    )
    with stats_lock:
        print(f"           [Stats] Raw: {stats['raw_packets']} | "
              f"Flows: {stats['total']} | 🚨 {stats['attacks']} | ✅ {stats['benign']}\n")

    # Send to Flask — non-blocking via queue
    send_async("/api/live_packet", {
        "src_ip":     src_ip,
        "prediction": str(prediction),
        "is_attack":  is_attack,
        "confidence": confidence,
        "protocol":   proto,
        "fwd_pkts":   total_fwd,
        "bwd_pkts":   total_bwd,
        "fwd_pps":    round(fwd_pps, 2),
        "flow_bytes": round(flow_bps, 2),
    })

    if is_attack:
        send_async("/api/block", {"ip": src_ip, "auto": True})

# Start ML worker thread
threading.Thread(target=_ml_worker, daemon=True).start()

# ── Flow tracker ──────────────────────────────────────────────
flows      = {}
flows_lock = threading.Lock()

def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return

    ip  = pkt[IP]
    src = ip.src
    dst = ip.dst
    now = time.time()

    with stats_lock:
        stats["raw_packets"] += 1

    if pkt.haslayer(TCP):
        proto   = 6
        pkt_len = len(pkt[TCP].payload)
    elif pkt.haslayer(UDP):
        proto   = 17
        pkt_len = len(pkt[UDP].payload)
    else:
        return

    # Skip loopback / multicast
    if src.startswith(("127.", "224.", "239.")) or src == "0.0.0.0":
        return

    fwd_key = (src, dst, proto)
    rev_key = (dst, src, proto)

    with flows_lock:
        # Expire stale flows
        stale = [k for k, v in flows.items() if now - v["last_time"] > FLOW_TIMEOUT]
        for k in stale:
            del flows[k]

        # Determine direction
        if rev_key in flows:
            key       = rev_key
            direction = "bwd"
        else:
            key       = fwd_key
            direction = "fwd"

        if key not in flows:
            flows[key] = {
                "start_time":  now,
                "last_time":   now,
                "fwd_packets": [],
                "bwd_packets": [],
                "fwd_times":   [],
                "bwd_times":   [],
                "all_times":   [],
            }

        f              = flows[key]
        f["last_time"] = now
        f["all_times"].append(now)

        if direction == "fwd":
            f["fwd_packets"].append(pkt_len)
            f["fwd_times"].append(now)
        else:
            f["bwd_packets"].append(pkt_len)
            f["bwd_times"].append(now)

        # Snapshot the current flow state immediately — no timer, no batch wait
        snapshot = {
            "src_ip":      key[0],
            "proto":       key[2],
            "fwd_packets": list(f["fwd_packets"]),
            "bwd_packets": list(f["bwd_packets"]),
            "fwd_times":   list(f["fwd_times"]),
            "bwd_times":   list(f["bwd_times"]),
            "all_times":   list(f["all_times"]),
        }

    # Push to ML queue — returns in microseconds, never blocks capture thread
    try:
        _ml_q.put_nowait(snapshot)
    except queue.Full:
        pass

# ── Start sniffing ────────────────────────────────────────────
try:
    sniff(
        iface=INTERFACE,
        filter="ip and (tcp or udp)",
        prn=packet_callback,
        store=False
    )
except KeyboardInterrupt:
    with stats_lock:
        print(f"\n\nSniffer stopped.")
        print(f"Session summary — Raw: {stats['raw_packets']} | "
              f"Flows: {stats['total']} | 🚨 {stats['attacks']} | ✅ {stats['benign']}")
except PermissionError:
    print("\nERROR: Permission denied! Run with: sudo python3 sniffer.py")
except Exception as e:
    print(f"\nERROR: {e}")
    print(f"Available interfaces: {get_if_list()}")
    print("Update INTERFACE at the top of sniffer.py")
