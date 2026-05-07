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

    # 🌍 COUNTRY-BASED IP RANGES
    country_ranges = {

        "United States": [
            (8, 8),
            (23, 23),
            (64, 74),
            (96, 108),
            (128, 174),
            (184, 209)
        ],

        "China": [
            (36, 42),
            (58, 61),
            (101, 125),
            (175, 183),
            (211, 223)
        ],

        "Japan": [
            (126, 126),
            (133, 133),
            (150, 150),
            (202, 202),
            (210, 221)
        ],

        "Germany": [
            (31, 31),
            (37, 37),
            (46, 46),
            (51, 53),
            (85, 91),
            (185, 193),
            (217, 217)
        ],

        "United Kingdom": [
            (2, 5),
            (25, 25),
            (62, 62),
            (90, 94),
            (151, 151),
            (176, 195)
        ],

        "France": [
            (82, 82),
            (86, 86),
            (163, 163)
        ],

        "Singapore": [
            (43, 43),
            (178, 178)
        ],

        "Australia": [
            (103, 103),
            (203, 203)
        ],

        "Brazil": [
            (177, 177),
            (200, 200)
        ],

        "South Korea": [
            (1, 1),
            (125, 125)
        ]
    }

    while True:

        status = random.choices(
            ["NORMAL", "SUSPICIOUS", "ATTACK"],
            weights=[0.7, 0.2, 0.1]
        )[0]

        score = round(random.uniform(0.1, 1.0), 3)

        # 🌍 pick country
        country = random.choice(list(country_ranges.keys()))

        # 🌍 pick IP range
        selected_range = random.choice(country_ranges[country])

        first_octet = random.randint(
            selected_range[0],
            selected_range[1]
        )

        ip = ".".join([
            str(first_octet),
            str(random.randint(1, 255)),
            str(random.randint(1, 255)),
            str(random.randint(1, 255))
        ])

        record = {

            "ip": ip,

            "final": score,
            "score": score,

            "status": status,

            "attack_type":
                "SQL_INJECTION" if score > 0.85 else
                "DDOS" if score > 0.7 else
                "BRUTE_FORCE" if score > 0.5 else
                "NORMAL",

            "time": time.strftime("%H:%M:%S"),

            # 🌍 already known
            "location": country,

            "blocked": False
        }

        data_store.append(record)

        # keep latest only
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
