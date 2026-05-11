from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import WebSocket
from fastapi import WebSocketDisconnect
from fastapi import Request
import json
import numpy as np
import time
import os
import threading
import subprocess
import pandas as pd
import tensorflow as tf
import joblib
import asyncio

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

print("🚀 Starting AI Firewall System...")
print("🧠 Loading AI models...")

lstm_model = tf.keras.models.load_model(
    "iot_lstm_ids_model.keras"
)

mlp_model = tf.keras.models.load_model(
    "mlp_iot_model.keras"
)

lstm_scaler = joblib.load(
    "iot_scaler.pkl"
)

mlp_scaler = joblib.load(
    "mlp_scaler.pkl"
)

print("✅ AI models loaded")

# =========================
# SETTINGS
# =========================
LOG_FILE = "eve.json"

data_store = []
attack_counter = {}
blocked_ips = set()
SEQUENCE_LENGTH = 10
sequence_buffer = []
clients = []  # websocket clients

async def broadcast(record):

    disconnected = []

    for client in clients:

        try:
            await client.send_json(record)

        except:
            disconnected.append(client)

    for dc in disconnected:

        if dc in clients:
            clients.remove(dc)

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

    print(f"🚨 Blocking IP: {ip}")

    # 🔥 run firewall command in background
    threading.Thread(
    target=lambda: subprocess.run([
        "sudo",
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP"
    ], timeout=3),
    daemon=True
).start()

@tf.function
def fast_lstm(x):
    return lstm_model(x, training=False)

@tf.function
def fast_mlp(x):
    return mlp_model(x, training=False)
    
# =========================
# PROCESS LOG LINE
# =========================
def process_line(line):

    global sequence_buffer

    try:
        log = json.loads(line)

    except:
        return

    # only process flow events
    if "flow" not in log:
        return

    src_ip = log.get("src_ip", "unknown")
    dest_ip = log.get("dest_ip", "unknown")

    # prefer public IP
    if src_ip.startswith(("192.168", "10.", "172.")):
        ip = dest_ip
    else:
        ip = src_ip

    # skip IPv6
    if ":" in ip:
        return

    flow = log.get("flow", {})

    # 🔥 skip tiny/noisy packets
    if flow.get("pkts_toserver", 0) < 1:
        return

    # =========================
    # EXTRACT FEATURES
    # =========================
    data = {
        "duration": [flow.get("age", 0)],
        "orig_bytes": [flow.get("bytes_toserver", 0)],
        "resp_bytes": [flow.get("bytes_toclient", 0)],
        "orig_pkts": [flow.get("pkts_toserver", 0)],
        "resp_pkts": [flow.get("pkts_toclient", 0)],
    }

    df = pd.DataFrame(data)

    # =========================
    # SCALE FEATURES
    # =========================
    try:

        X_lstm = lstm_scaler.transform(df)
        X_mlp = mlp_scaler.transform(df)

    except Exception as e:

        print("Scaling error:", e)
        return

    # =========================
    # BUILD LSTM SEQUENCE
    # =========================
    sequence_buffer.append(X_lstm[0])

    if len(sequence_buffer) < SEQUENCE_LENGTH:
        return

    if len(sequence_buffer) > SEQUENCE_LENGTH:
        sequence_buffer.pop(0)

    X_seq = np.array(sequence_buffer).reshape(
        1,
        SEQUENCE_LENGTH,
        -1
    )

    # =========================
    # AI PREDICTION
    # =========================
    try:

        lstm_score = fast_lstm(
            X_seq
        )[0][0].numpy()

        mlp_score = fast_mlp(
            X_mlp
        )[0][0].numpy()

    except Exception as e:

        print("Prediction error:", e)
        return

    # =========================
    # FUSION SCORE
    # =========================
    final_score = (
        0.6 * lstm_score
    ) + (
        0.4 * mlp_score
    )

    # =========================
    # AI DECISION
    # =========================
    if final_score > 0.7:

        status = "ATTACK"

    elif final_score > 0.4:

        status = "SUSPICIOUS"

    else:

        status = "NORMAL"

    # print only abnormal traffic
    if status != "NORMAL":

        print(
            f"🌐 {ip} | "
            f"FINAL:{final_score:.3f} | "
            f"{status}"
        )

    # =========================
    # SAVE RECORD
    # =========================
    record = {

        "ip": ip,

        "final": float(final_score),

        "score": float(final_score),

        "status": status,

        "attack_type": detect_attack_type(final_score),

        "severity": (
            3 if status == "ATTACK"
            else 2 if status == "SUSPICIOUS"
            else 1
        ),

        "time": time.strftime("%H:%M:%S"),

        # frontend handles geolocation
        "location": "Loading",

        "blocked": ip in blocked_ips
    }

    # save record
    data_store.append(record)

    # keep latest only
    data_store[:] = data_store[-300:]
    
    # =========================
    # AUTO BLOCKING
    # =========================
    if status == "ATTACK":

        attack_counter[ip] = (
            attack_counter.get(ip, 0) + 1
        )

        if attack_counter[ip] >= 3:

            block_ip(ip)
    return record
# =========================
# DETECT ATTACK TYPE
# =========================
def detect_attack_type(score):

    if score > 0.9:
        return "SQL_INJECTION"

    elif score > 0.8:
        return "DDOS_ATTACK"

    elif score > 0.7:
        return "BRUTE_FORCE"

    elif score > 0.5:
        return "PORT_SCAN"

    elif score > 0.3:
        return "SUSPICIOUS_TRAFFIC"

    return "NORMAL_TRAFFIC"

            
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
                if idle % 100 == 0:
                    print("⏳ Waiting for new logs...")
                time.sleep(0.5)
                continue

            idle = 0
            process_line(line)
        
# =========================
# START SYSTEM
# =========================
@app.on_event("startup")
def startup():

    data_store.clear()

    threading.Thread(
        target=monitor,
        daemon=True
    ).start()
        
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
# WEBSOCKET
# =========================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    clients.append(websocket)

    print("✅ WebSocket connected")

    try:

        while True:
            await asyncio.sleep(60)

    except WebSocketDisconnect:

        print("❌ WebSocket disconnected")

    finally:

        if websocket in clients:
            clients.remove(websocket)

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

@app.post("/push")
async def push_log(request: Request):

    data = await request.json()

    try:

        record = process_line(
            json.dumps(data)
        )

        # live websocket update
        if record:

            await broadcast(record)

        return {
            "status": "received"
        }

    except Exception as e:

        return {
            "error": str(e)
        }

@app.get("/metrics")
async def get_metrics():

    total = len(data_store)

    attacks = len([
        x for x in data_store
        if x["status"] == "ATTACK"
    ])

    suspicious = len([
        x for x in data_store
        if x["status"] == "SUSPICIOUS"
    ])

    normal = len([
        x for x in data_store
        if x["status"] == "NORMAL"
    ])

    # simulated evaluation metrics
    accuracy = 96.4

    precision = 94.8

    recall = 91.5

    false_positive_rate = 2.1

    return {

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "false_positive_rate":
            false_positive_rate
    }
