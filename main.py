import json
import pandas as pd
import numpy as np
import time
import os
import threading
from fastapi import FastAPI
from fastapi.responses import FileResponse

# =========================
# INIT
# =========================
app = FastAPI()

print("🚀 Starting AI Firewall System...")

# =========================
# SETTINGS
# =========================
LOG_FILE = "/var/log/suricata/eve.json"
SEQUENCE_LENGTH = 10

sequence_buffer = []
attack_counter = {}
blocked_ips = set()
data_store = []

# =========================
# BLOCK IP
# =========================
def block_ip(ip):
    if ip in blocked_ips:
        return

    print(f"🚨 Blocking IP: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    blocked_ips.add(ip)

# =========================
# PROCESS LOG LINE
# =========================
def process_line(line):
    try:
        log = json.loads(line)
    except:
        return

    if "flow" not in log:
        return

    src_ip = log.get("src_ip", "unknown")

    # Skip IPv6
    if ":" in src_ip:
        return

    # =========================
    # FAKE AI PREDICTION (TEMP)
    # =========================
    # Random score simulation
    final_score = np.random.random()

    if final_score > 0.7:
        status = "ATTACK"
    elif final_score > 0.4:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    print(f"🌐 {src_ip} | {status} | {final_score:.3f}")

    # =========================
    # STORE DATA
    # =========================
    record = {
        "ip": src_ip,
        "final": float(final_score),
        "status": status,
        "time": time.strftime("%H:%M:%S")
    }

    data_store.append(record)

    if len(data_store) > 1000:
        data_store.pop(0)

    # =========================
    # AUTO BLOCK
    # =========================
    if status == "ATTACK":
        attack_counter[src_ip] = attack_counter.get(src_ip, 0) + 1

        if attack_counter[src_ip] >= 3:
            block_ip(src_ip)

# =========================
# MONITOR LOG FILE
# =========================
def monitor():
    print("📂 Reading logs...")

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                process_line(line)
    except:
        print("❌ Log file not found")

    print("🚀 Real-time monitoring started")

    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)

        idle = 0

        while True:
            line = f.readline()

            if not line:
                idle += 1
                if idle % 25 == 0:
                    print("⏳ Waiting for new logs...")
                time.sleep(0.2)
                continue

            idle = 0
            process_line(line)

# =========================
# START FIREWALL THREAD
# =========================
@app.on_event("startup")
def startup():
    threading.Thread(target=monitor, daemon=True).start()

# =========================
# API ROUTES
# =========================
@app.get("/data")
def get_data():
    return data_store[-100:]

@app.get("/")
def dashboard():
    return FileResponse("index.html")
