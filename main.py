from fastapi import FastAPI
from fastapi.responses import FileResponse
import json
import numpy as np
import time
import os
import threading
import random

app = FastAPI()

print("🚀 Starting AI Firewall System...")

# =========================
# SETTINGS
# =========================
LOG_FILE = "/var/log/suricata/eve.json"

data_store = []
attack_counter = {}
blocked_ips = set()

# Detect if running in Railway (no log file)
USE_FAKE = not os.path.exists(LOG_FILE)

# =========================
# BLOCK IP (LOCAL ONLY)
# =========================
def block_ip(ip):
    if USE_FAKE:
        return  # skip in cloud

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

    if ":" in src_ip:
        return

    # Fake AI score
    final_score = np.random.random()

    if final_score > 0.7:
        status = "ATTACK"
    elif final_score > 0.4:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    print(f"🌐 {src_ip} | {status} | {final_score:.3f}")

    record = {
        "ip": src_ip,
        "final": float(final_score),
        "status": status,
        "time": time.strftime("%H:%M:%S")
    }

    data_store.append(record)

    if len(data_store) > 1000:
        data_store.pop(0)

    if status == "ATTACK":
        attack_counter[src_ip] = attack_counter.get(src_ip, 0) + 1
        if attack_counter[src_ip] >= 3:
            block_ip(src_ip)

# =========================
# REAL MONITOR (LOCAL)
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
# FAKE DATA (CLOUD MODE)
# =========================
def fake_generator():
    print("⚡ Running in CLOUD mode (fake data)...")

    while True:
        status = random.choices(
            ["NORMAL", "SUSPICIOUS", "ATTACK"],
            weights=[0.7, 0.2, 0.1]
        )[0]

        record = {
            "ip": f"192.168.1.{random.randint(1,255)}",
            "final": round(random.uniform(0.1, 1.0), 3),
            "status": status,
            "time": time.strftime("%H:%M:%S")
        }

        data_store.append(record)

        if len(data_store) > 1000:
            data_store.pop(0)

        time.sleep(2)

# =========================
# START SYSTEM
# =========================
@app.on_event("startup")
def startup():
    if USE_FAKE:
        threading.Thread(target=fake_generator, daemon=True).start()
    else:
        threading.Thread(target=monitor, daemon=True).start()

# =========================
# API ROUTES
# =========================
@app.get("/")
def dashboard():
    return FileResponse("index.html")

@app.get("/data")
def get_data():
    return data_store[-100:]

@app.get("/incidents")
def get_incidents():
    recent = data_store[-200:]   # only scan recent logs

    return [
        r for r in recent
        if r["status"] in ["ATTACK", "SUSPICIOUS"]
    ][-50:]

@app.get("/stats")
def get_stats():
    normal = suspicious = attack = 0

    for r in data_store[-200:]:  # only recent data
        if r["status"] == "NORMAL":
            normal += 1
        elif r["status"] == "SUSPICIOUS":
            suspicious += 1
        elif r["status"] == "ATTACK":
            attack += 1

    return {
        "normal": normal,
        "suspicious": suspicious,
        "attack": attack
    }

@app.get("/latest")
def get_latest():
    if not data_store:
        return {}
    return data_store[-1]
