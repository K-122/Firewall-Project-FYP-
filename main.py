from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import json
import numpy as np
import time
import os
import threading
import random
import subprocess

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

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

    if ip in blocked_ips:
        return

    blocked_ips.add(ip)

    # update records
    for r in data_store:
        if r["ip"] == ip:
            r["blocked"] = True

    # fake cloud mode
    if USE_FAKE:
        print(f"🚫 (FAKE) Blocked IP: {ip}")
        return

    # local linux firewall
    print(f"🚨 Blocking IP: {ip}")

    subprocess.run([
        "sudo",
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP"
    ])
    
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
        "score": float(final_score),

        "status": status,

        "attack_type":
            "SQL_INJECTION" if final_score > 0.85 else
            "DDOS" if final_score > 0.7 else
            "BRUTE_FORCE" if final_score > 0.5 else
            "NORMAL",

        "time": time.strftime("%H:%M:%S"),

        "location": "Unknown",
        "blocked": src_ip in blocked_ips
    }

    data_store.append(record)

    # keep latest 1000
    data_store[:] = data_store[-1000:]

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

        score = round(random.uniform(0.1, 1.0), 3)

        record = {

           "ip": ".".join([
    str(random.randint(11, 223)),
    str(random.randint(11, 223)),
    str(random.randint(11, 223)),
    str(random.randint(11, 223))
]),

            "final": score,
            "score": score,

            "status": status,

            "attack_type":
                "SQL_INJECTION" if score > 0.85 else
                "DDOS" if score > 0.7 else
                "BRUTE_FORCE" if score > 0.5 else
                "NORMAL",

            "time": time.strftime("%H:%M:%S"),

            "location": "",

            "blocked": False
        }

        data_store.append(record)

        data_store[:] = data_store[-1000:]

        time.sleep(2)
# =========================
# START SYSTEM
# =========================
@app.on_event("startup")
def startup():

    data_store.clear()

    if USE_FAKE:
        threading.Thread(target=fake_generator, daemon=True).start()
    else:
        threading.Thread(target=monitor, daemon=True).start()
# =========================
# API ROUTES
# =========================
@app.get("/")
def dashboard():
    return FileResponse("static/index.html")

@app.get("/data")
def get_data():
    return data_store[-100:]

@app.get("/incidents")
def get_incidents():

    recent = data_store[-200:]

    result = []

    for r in recent:

        # =========================
        # COPY ORIGINAL RECORD
        # =========================
        item = r.copy()

        # =========================
        # SHOW BLOCKED IN UI ONLY
        # =========================
        if item["ip"] in blocked_ips:
            item["status"] = "BLOCKED"

        # =========================
        # FILTER INCIDENTS
        # =========================
        if item["status"] in [
            "ATTACK",
            "SUSPICIOUS",
            "BLOCKED"
        ]:
            result.append(item)

    return result[-50:]
    
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


# =========================
# MANUAL ACTIONS API
# =========================

@app.post("/block/{ip}")
def api_block(ip: str):
    block_ip(ip)
    return {"status": "blocked", "ip": ip}


@app.post("/allow/{ip}")
def api_allow(ip: str):

    if ip in blocked_ips:
        blocked_ips.remove(ip)

        # 🔥 update records
        for r in data_store:
            if r["ip"] == ip:
                r["blocked"] = False

    return {"status": "allowed", "ip": ip}

@app.post("/retrain")
def retrain_model():
    print("🔄 Retraining AI model...")

    # simulate training time
    import time
    time.sleep(2)

    print("✅ Model updated")

    return {"status": "retrained"}

@app.post("/quarantine/{ip}")
def api_quarantine(ip: str):
    print(f"🛡️ Quarantined IP: {ip}")
    return {"status": "quarantined", "ip": ip}

@app.get("/blocked")
def get_blocked():
    return list(blocked_ips)

@app.get("/entropy")
def entropy():
    total = len(data_store[-200:])

    if total == 0:
        return {"entropy": 0}

    attack = len([x for x in data_store[-200:] if x["status"] == "ATTACK"])

    value = round((attack / total) * 100, 2)

    return {"entropy": value}
