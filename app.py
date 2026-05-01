from flask import Flask, render_template, request, jsonify
import numpy as np
import pandas as pd
import pickle
import os
import subprocess
from collections import deque
import threading

app = Flask(__name__)

MODEL_PATH = "model/ids_model.pkl"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("Model file not found. Run train_model.py first.")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("Model loaded successfully.")
print("Classes:", model.classes_)

FEATURES = [
    "protocol", "flow_duration", "total_forward_packets",
    "total_backward_packets", "total_forward_packets_length",
    "total_backward_packets_length", "forward_packet_length_mean",
    "backward_packet_length_mean", "forward_packets_per_second",
    "backward_packets_per_second", "forward_iat_mean",
    "backward_iat_mean", "flow_iat_mean",
    "flow_packets_per_seconds", "flow_bytes_per_seconds"
]

FEATURE_LABELS = {
    "protocol":                      ("Protocol",                  "6=TCP, 17=UDP (e.g. 17)"),
    "flow_duration":                 ("Flow Duration",             "Duration microseconds (e.g. 50)"),
    "total_forward_packets":         ("Total Forward Packets",     "Packets sent forward (e.g. 1)"),
    "total_backward_packets":        ("Total Backward Packets",    "Packets sent backward (e.g. 500)"),
    "total_forward_packets_length":  ("Fwd Packets Length",        "Total bytes forward (e.g. 60)"),
    "total_backward_packets_length": ("Bwd Packets Length",        "Total bytes backward (e.g. 200000)"),
    "forward_packet_length_mean":    ("Fwd Packet Length Mean",    "Avg forward packet size (e.g. 60)"),
    "backward_packet_length_mean":   ("Bwd Packet Length Mean",    "Avg backward packet size (e.g. 400)"),
    "forward_packets_per_second":    ("Fwd Packets/Second",        "Forward packet rate (e.g. 2000)"),
    "backward_packets_per_second":   ("Bwd Packets/Second",        "Backward packet rate (e.g. 20000)"),
    "forward_iat_mean":              ("Fwd IAT Mean",              "Avg fwd inter-arrival time (e.g. 10)"),
    "backward_iat_mean":             ("Bwd IAT Mean",              "Avg bwd inter-arrival time (e.g. 10)"),
    "flow_iat_mean":                 ("Flow IAT Mean",             "Avg flow inter-arrival time (e.g. 10)"),
    "flow_packets_per_seconds":      ("Flow Packets/Second",       "Total flow packet rate (e.g. 50000)"),
    "flow_bytes_per_seconds":        ("Flow Bytes/Second",         "Total flow byte rate (e.g. 2000000)"),
}

# ── Live packet store ─────────────────────────────────────────
live_packets = deque(maxlen=200)  # store last 200 real packets
lock = threading.Lock()

# ── pf firewall helpers ───────────────────────────────────────
BLOCKED_FILE = "/etc/pf.blocked.conf"

def pf_block(ip):
    """Add IP to pf blocklist — actually blocks traffic on Mac firewall."""
    try:
        with open(BLOCKED_FILE, "r") as f:
            ips = set(f.read().splitlines())
        if ip in ips:
            return True, "Already blocked"
        ips.add(ip)
        with open(BLOCKED_FILE, "w") as f:
            f.write("\n".join(ips))
        subprocess.run(
            ["sudo", "pfctl", "-t", "blocked_ips", "-T", "add", ip],
            capture_output=True, timeout=5
        )
        return True, f"IP {ip} blocked successfully"
    except Exception as e:
        return False, str(e)

def pf_unblock(ip):
    """Remove IP from pf blocklist."""
    try:
        with open(BLOCKED_FILE, "r") as f:
            ips = set(f.read().splitlines())
        ips.discard(ip)
        with open(BLOCKED_FILE, "w") as f:
            f.write("\n".join(ips))
        subprocess.run(
            ["sudo", "pfctl", "-t", "blocked_ips", "-T", "delete", ip],
            capture_output=True, timeout=5
        )
        return True, f"IP {ip} unblocked successfully"
    except Exception as e:
        return False, str(e)

def pf_get_blocked():
    """Get current list of blocked IPs."""
    try:
        result = subprocess.run(
            ["sudo", "pfctl", "-t", "blocked_ips", "-T", "show"],
            capture_output=True, text=True, timeout=5
        )
        ips = [ip.strip() for ip in result.stdout.splitlines() if ip.strip()]
        return ips
    except:
        return []

# ── Routes ────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html", features=FEATURES, labels=FEATURE_LABELS)

@app.route("/monitor")
def monitor():
    return render_template("monitor.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        values = []
        for feature in FEATURES:
            val = request.form.get(feature)
            if val is None or val.strip() == "":
                return render_template("index.html",
                    prediction_text="error",
                    prediction_detail=f"Missing value for: {feature}",
                    features=FEATURES, labels=FEATURE_LABELS)
            values.append(float(val))

        input_df = pd.DataFrame([values], columns=FEATURES)
        prediction = model.predict(input_df)[0]
        proba = model.predict_proba(input_df)[0]
        confidence = round(max(proba) * 100, 1)

        if str(prediction).upper() == "BENIGN":
            result = "normal"
            detail = f"No threats found. Traffic looks clean. ({confidence}% confidence)"
        else:
            result = "intrusion"
            detail = f"Attack type: {prediction} detected! ({confidence}% confidence)"

        return render_template("index.html",
            prediction_text=result,
            prediction_detail=detail,
            features=FEATURES, labels=FEATURE_LABELS)

    except Exception as e:
        return render_template("index.html",
            prediction_text="error",
            prediction_detail=str(e),
            features=FEATURES, labels=FEATURE_LABELS)

# ── Real blocking API routes ──────────────────────────────────
@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "message": "No IP provided"})
    success, message = pf_block(ip)
    return jsonify({"success": success, "message": message, "ip": ip})

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "message": "No IP provided"})
    success, message = pf_unblock(ip)
    return jsonify({"success": success, "message": message, "ip": ip})

@app.route("/api/blocked_ips", methods=["GET"])
def api_blocked_ips():
    ips = pf_get_blocked()
    return jsonify({"blocked_ips": ips, "count": len(ips)})

@app.route("/api/predict", methods=["POST"])
def api_predict():
    try:
        data = request.get_json()
        values = [float(data[f]) for f in FEATURES]
        input_df = pd.DataFrame([values], columns=FEATURES)
        prediction = model.predict(input_df)[0]
        proba = model.predict_proba(input_df)[0]
        confidence = round(max(proba) * 100, 1)
        is_attack = str(prediction).upper() != "BENIGN"
        return jsonify({
            "prediction": str(prediction),
            "is_attack": is_attack,
            "confidence": confidence,
            "result": "Intrusion Detected" if is_attack else "Normal Traffic"
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# ── Live packet receiver from sniffer.py ─────────────────────
@app.route("/api/live_packet", methods=["POST"])
def live_packet():
    """Receives real packet data from sniffer.py."""
    try:
        data = request.get_json()
        src_ip = data.get("src_ip", "")

        # Check firewall status separately from ML prediction
        # This way NORMAL traffic from a blocked IP shows correctly
        blocked_ips = pf_get_blocked()

        entry = {
            "src_ip":     src_ip,
            "prediction": data.get("prediction", ""),    # real ML label e.g. BENIGN / DrDoS_DNS
            "is_attack":  data.get("is_attack", False),  # real ML result
            "is_blocked": src_ip in blocked_ips,         # firewall status — separate flag!
            "confidence": data.get("confidence", 0),
            "protocol":   data.get("protocol", 0),
            "fwd_pkts":   data.get("fwd_pkts", data.get("fwd_pps", 0)),
            "bwd_pkts":   data.get("bwd_pkts", 0),
            "fwd_pps":    data.get("fwd_pps", 0),
            "flow_bytes": data.get("flow_bytes", 0),
        }
        with lock:
            live_packets.appendleft(entry)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/api/live_feed", methods=["GET"])
def live_feed():
    """Monitor page polls this to get real packets."""
    with lock:
        packets = list(live_packets)
        live_packets.clear()

    # Add a display_status field so monitor.html can show the right badge:
    # - "BLOCKED"  → IP is in firewall (regardless of ML result)
    # - "ATTACK"   → ML detected attack, not yet blocked
    # - "NORMAL"   → ML says benign, not blocked
    for p in packets:
        if p.get("is_blocked"):
            p["display_status"] = "BLOCKED"
        elif p.get("is_attack"):
            p["display_status"] = "ATTACK"
        else:
            p["display_status"] = "NORMAL"

    return jsonify({"packets": packets})

# ── Start app ─────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
