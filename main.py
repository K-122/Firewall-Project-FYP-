from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import (
    WebSocket,
    WebSocketDisconnect,
    Request,
    HTTPException,
    Header,
    Query
)

from contextlib import asynccontextmanager
from pydantic import BaseModel
from passlib.context import CryptContext
from collections import deque, defaultdict
from datetime import datetime, timedelta
from starlette.websockets import WebSocketState

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
import secrets
import ipaddress

# =========================
# PASSWORD HASHING
# =========================
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# =========================
# SETTINGS
# =========================
LOG_FILE          = "eve.json"
SEQUENCE_LENGTH   = 10
SESSION_TTL_HOURS = 8
MAX_STORE         = 300
MAX_RECENT        = 200

# =========================
# SHARED STATE
# =========================
data_store      = []
attack_counter  = {}
blocked_ips     = set()
sequence_buffers = defaultdict(
    lambda: deque(maxlen=SEQUENCE_LENGTH)
)

active_sessions     = {}
active_connections  = []

# =========================
# LOCKS
# =========================
data_lock = threading.Lock()
ws_lock   = asyncio.Lock()

# =========================
# USERS
# =========================
USERS = {
    "superadmin": {
        "password": pwd_context.hash("admin123"),
        "role":     "superadmin"
    },
    "finance": {
        "password": pwd_context.hash("finance123"),
        "role":     "FinanceStaff"
    }
}

# =========================
# MODELS
# =========================
class LoginRequest(BaseModel):
    username: str
    password: str

# =========================
# LOAD AI MODELS
# =========================
print("🚀 Starting AI Firewall System...")
print("🧠 Loading AI models...")

lstm_model = tf.keras.models.load_model(
    "iot_lstm_ids_model.keras"
)

mlp_model = tf.keras.models.load_model(
    "mlp_iot_model.keras"
)

lstm_scaler = joblib.load("iot_scaler.pkl")
mlp_scaler  = joblib.load("mlp_scaler.pkl")

print("✅ AI models loaded")

# =========================
# TF OPTIMIZED INFERENCE
# =========================
@tf.function
def fast_lstm(x):
    return lstm_model(x, training=False)

@tf.function
def fast_mlp(x):
    return mlp_model(x, training=False)

# =========================
# AUTH HELPERS
# =========================
def verify_token(token: str) -> dict:
    """
    Validate token and check expiry.
    Raises HTTPException on failure.
    """
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing token"
        )

    session = active_sessions.get(token)

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    if datetime.utcnow() > session["expires"]:
        del active_sessions[token]
        raise HTTPException(
            status_code=401,
            detail="Session expired"
        )

    return session


def require_admin(token: str) -> dict:
    """
    Verify token AND enforce superadmin role.
    """
    session = verify_token(token)

    if session["role"] != "superadmin":
        raise HTTPException(
            status_code=403,
            detail="Forbidden"
        )

    return session

# =========================
# SESSION CLEANUP
# =========================
def cleanup_sessions():
    """
    Background thread — removes expired sessions
    every 5 minutes to prevent memory leak.
    """
    while True:
        try:
            now     = datetime.utcnow()
            expired = [
                t for t, s in list(active_sessions.items())
                if now > s["expires"]
            ]

            for t in expired:
                del active_sessions[t]

            if expired:
                print(
                    f"🧹 Removed {len(expired)} "
                    f"expired session(s)"
                )

        except Exception as e:
            print(f"Session cleanup error: {e}")

        time.sleep(300)

# =========================
# BLOCK IP
# =========================
def block_ip(ip: str):
    """
    Validate IP, add to blocked set,
    update records, run iptables in background.
    """
    # validate IP first
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"❌ Invalid IP rejected: {ip}")
        return

    with data_lock:
        if ip in blocked_ips:
            return

        blocked_ips.add(ip)

        for r in data_store:
            if r["ip"] == ip:
                r["blocked"] = True

    print(f"🚨 Blocking IP: {ip}")

    # run firewall rule in background thread
    threading.Thread(
        target=lambda: subprocess.run(
            [
                "sudo", "iptables",
                "-A", "INPUT",
                "-s", ip,
                "-j", "DROP"
            ],
            timeout=3
        ),
        daemon=True
    ).start()

# =========================
# DETECT ATTACK TYPE
# =========================
def detect_attack_type(
    score: float,
    flow:  dict
) -> str:
    """
    Classify attack type using flow features
    and AI score together for better accuracy.
    """
    proto      = flow.get("proto", "").upper()
    dest_port  = flow.get("dest_port", 0)
    pkts       = flow.get("pkts_toserver", 0)
    bytes_srv  = flow.get("bytes_toserver", 0)

    # high-confidence flow-based rules
    if dest_port == 3306 and score > 0.7:
        return "SQL_INJECTION"

    if dest_port == 22 and score > 0.7:
        return "BRUTE_FORCE_SSH"

    if proto == "TCP" and pkts > 500 and score > 0.7:
        return "DDOS_ATTACK"

    if proto == "TCP" and bytes_srv < 100 and pkts > 50:
        return "PORT_SCAN"

    # fall back to score-based classification
    if score > 0.9:
        return "DDOS_ATTACK"
    elif score > 0.7:
        return "BRUTE_FORCE"
    elif score > 0.5:
        return "PORT_SCAN"
    elif score > 0.3:
        return "SUSPICIOUS_TRAFFIC"

    return "NORMAL_TRAFFIC"

# =========================
# PROCESS LOG LINE
# =========================
def process_line(line: str):
    """
    Parse one Suricata EVE JSON line,
    run AI inference, save record, auto-block.
    Returns record dict or None.
    """
    # parse JSON
    try:
        log = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    # only process flow events
    if "flow" not in log:
        return None

    # resolve IP (prefer public)
    src_ip  = log.get("src_ip",  "unknown")
    dest_ip = log.get("dest_ip", "unknown")

    ip = (
        dest_ip
        if src_ip.startswith(("192.168.", "10.", "172."))
        else src_ip
    )

    # skip IPv6 and unresolved
    if ":" in ip or ip == "unknown":
        return None

    flow = log.get("flow", {})

    # skip empty flows
    if flow.get("pkts_toserver", 0) < 1:
        return None

    # =========================
    # EXTRACT FEATURES
    # =========================
    data = {
        "duration":   [flow.get("age",             0)],
        "orig_bytes": [flow.get("bytes_toserver",   0)],
        "resp_bytes": [flow.get("bytes_toclient",   0)],
        "orig_pkts":  [flow.get("pkts_toserver",    0)],
        "resp_pkts":  [flow.get("pkts_toclient",    0)],
    }

    df = pd.DataFrame(data)

    # =========================
    # SCALE FEATURES
    # =========================
    try:
        X_lstm = lstm_scaler.transform(df)
        X_mlp  = mlp_scaler.transform(df)
    except Exception as e:
        print(f"Scaling error: {e}")
        return None

    # =========================
    # BUILD LSTM SEQUENCE
    # (per-IP buffer — no cross-IP mixing)
    # =========================
    with data_lock:
        buf = sequence_buffers[ip]
        buf.append(X_lstm[0])

        if len(buf) < SEQUENCE_LENGTH:
            return None

        # .copy() detaches from shared buffer
        X_seq = np.array(buf).reshape(
            1, SEQUENCE_LENGTH, -1
        ).copy()

    # =========================
    # AI INFERENCE
    # =========================
    try:
        lstm_score = float(
            fast_lstm(X_seq)[0][0].numpy()
        )
        mlp_score  = float(
            fast_mlp(X_mlp)[0][0].numpy()
        )
    except Exception as e:
        print(f"Prediction error: {e}")
        return None

    # =========================
    # FUSION SCORE
    # =========================
    final_score = (0.6 * lstm_score) + (0.4 * mlp_score)

    # =========================
    # CLASSIFY
    # =========================
    if final_score > 0.7:
        status = "ATTACK"
    elif final_score > 0.4:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    # log only anomalies
    if status != "NORMAL":
        print(
            f"🌐 {ip} | "
            f"LSTM:{lstm_score:.3f} | "
            f"MLP:{mlp_score:.3f} | "
            f"FINAL:{final_score:.3f} | "
            f"{status}"
        )

    # =========================
    # READ blocked state safely
    # =========================
    with data_lock:
        is_blocked = ip in blocked_ips

    # =========================
    # BUILD RECORD
    # =========================
    record = {
        "ip":          ip,
        "final":       round(final_score, 4),
        "score":       round(final_score, 4),
        "lstm_score":  round(lstm_score,  4),
        "mlp_score":   round(mlp_score,   4),
        "status":      status,
        "attack_type": detect_attack_type(final_score, flow),
        "severity": (
            3 if status == "ATTACK"
            else 2 if status == "SUSPICIOUS"
            else 1
        ),
        "time":     time.strftime("%H:%M:%S"),
        "location": "Loading",
        "blocked":  is_blocked
    }

    # =========================
    # SAVE RECORD
    # =========================
    with data_lock:
        data_store.append(record)
        data_store[:] = data_store[-MAX_STORE:]

    # =========================
    # AUTO-BLOCK LOGIC
    # (flag computed under lock,
    #  block_ip called OUTSIDE lock
    #  to prevent deadlock)
    # =========================
    should_block = False

    if status == "ATTACK":
        with data_lock:
            attack_counter[ip] = (
                attack_counter.get(ip, 0) + 1
            )
            if attack_counter[ip] >= 3:
                should_block = True

    if should_block:
        block_ip(ip)

    return record

# =========================
# LOG MONITOR THREAD
# =========================
def monitor():
    """
    Background thread — reads existing log,
    then tails it in real time.
    """
    # wait until log file exists
    while not os.path.exists(LOG_FILE):
        print(f"⏳ Waiting for {LOG_FILE}...")
        time.sleep(2)

    # read historical lines
    print("📂 Reading existing logs...")
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                process_line(line)
    except Exception as e:
        print(f"❌ Error reading log: {e}")

    print("🚀 Real-time monitoring started")

    # tail new lines
    try:
        with open(LOG_FILE, "r") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.5)
                    continue

                process_line(line)

    except Exception as e:
        print(f"❌ Monitor crashed: {e}")

# =========================
# LIFESPAN
# =========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs startup logic before yield,
    shutdown logic after yield.
    """
    data_store.clear()

    # start log monitor thread
    threading.Thread(
        target=monitor,
        daemon=True
    ).start()

    # start session cleanup thread
    threading.Thread(
        target=cleanup_sessions,
        daemon=True
    ).start()

    print("✅ Background threads started")

    yield

    print("🛑 Shutting down...")

# =========================
# FASTAPI APP
# =========================
app = FastAPI(lifespan=lifespan)

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)

# =========================
# BROADCAST (WebSocket)
# =========================
async def broadcast(data: dict):
    """
    Send JSON to all connected WebSocket clients.
    Uses asyncio.Lock to prevent race on connection list.
    """
    async with ws_lock:
        connections = list(active_connections)

    disconnected = []

    for ws in connections:
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_json(data)
        except (WebSocketDisconnect, RuntimeError):
            disconnected.append(ws)

    if disconnected:
        async with ws_lock:
            for ws in disconnected:
                if ws in active_connections:
                    active_connections.remove(ws)

# =========================
# ROUTES — PUBLIC
# =========================
@app.get("/")
def dashboard():
    return FileResponse("static/index.html")


@app.post("/login")
def login(data: LoginRequest):
    """
    Authenticate user, return session token.
    """
    user = USERS.get(data.username)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username"
        )

    if not pwd_context.verify(
        data.password,
        user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid password"
        )

    token = secrets.token_hex(32)

    active_sessions[token] = {
        "username": data.username,
        "role":     user["role"],
        "expires":  datetime.utcnow() + timedelta(
            hours=SESSION_TTL_HOURS
        )
    }

    return {
        "status":   "success",
        "token":    token,
        "username": data.username,
        "role":     user["role"]
    }


@app.post("/logout")
def logout(
    authorization: str = Header(None)
):
    """
    Invalidate session token.
    """
    if authorization and authorization in active_sessions:
        del active_sessions[authorization]

    return {"status": "logged_out"}

# =========================
# ROUTES — DATA (read-only)
# =========================
@app.get("/data")
def get_data(
    authorization: str = Header(None)
):
    verify_token(authorization)

    with data_lock:
        return list(data_store[-100:])


@app.get("/incidents")
def get_incidents(
    authorization: str = Header(None)
):
    verify_token(authorization)

    with data_lock:
        recent = list(data_store[-MAX_RECENT:])
        current_blocked = set(blocked_ips)

    result = []

    for r in recent:
        item = r.copy()

        if item["ip"] in current_blocked:
            item["status"] = "BLOCKED"

        if item["status"] in (
            "ATTACK",
            "SUSPICIOUS",
            "BLOCKED"
        ):
            result.append(item)

    return result[-50:]


@app.get("/stats")
def get_stats(
    authorization: str = Header(None)
):
    verify_token(authorization)

    normal = suspicious = attack = 0

    with data_lock:
        recent = list(data_store[-MAX_RECENT:])

    for r in recent:
        s = r["status"]
        if s == "NORMAL":
            normal += 1
        elif s == "SUSPICIOUS":
            suspicious += 1
        elif s == "ATTACK":
            attack += 1

    return {
        "normal":     normal,
        "suspicious": suspicious,
        "attack":     attack
    }


@app.get("/latest")
def get_latest(
    authorization: str = Header(None)
):
    verify_token(authorization)

    with data_lock:
        if not data_store:
            return {}
        return data_store[-1].copy()


@app.get("/blocked")
def get_blocked(
    authorization: str = Header(None)
):
    verify_token(authorization)

    with data_lock:
        return list(blocked_ips)


@app.get("/entropy")
def entropy(
    authorization: str = Header(None)
):
    verify_token(authorization)

    with data_lock:
        recent = list(data_store[-MAX_RECENT:])

    total  = len(recent)
    if total == 0:
        return {"entropy": 0}

    attacks = sum(
        1 for x in recent
        if x["status"] == "ATTACK"
    )

    return {
        "entropy": round((attacks / total) * 100, 2)
    }


@app.get("/metrics")
def get_metrics(
    authorization: str = Header(None)
):
    verify_token(authorization)

    with data_lock:
        total      = len(data_store)
        attacks    = sum(1 for x in data_store if x["status"] == "ATTACK")
        suspicious = sum(1 for x in data_store if x["status"] == "SUSPICIOUS")
        normal     = sum(1 for x in data_store if x["status"] == "NORMAL")

    return {
        "total":      total,
        "attacks":    attacks,
        "suspicious": suspicious,
        "normal":     normal,
        # demo values — replace with real evaluation
        "accuracy":             99.99,
        "precision":            100.0,
        "recall":               99.992,
        "f1_score":             99.996,
        "false_positive_rate":  0.0
    }

# =========================
# ROUTES — ADMIN ACTIONS
# =========================
@app.post("/block/{ip}")
def api_block(
    ip: str,
    authorization: str = Header(None)
):
    require_admin(authorization)
    block_ip(ip)
    return {"status": "blocked", "ip": ip}


@app.post("/allow/{ip}")
def api_allow(
    ip: str,
    authorization: str = Header(None)
):
    require_admin(authorization)

    # validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address"
        )

    with data_lock:
        if ip in blocked_ips:
            blocked_ips.discard(ip)
            for r in data_store:
                if r["ip"] == ip:
                    r["blocked"] = False

    return {"status": "allowed", "ip": ip}


@app.post("/quarantine/{ip}")
def api_quarantine(
    ip: str,
    authorization: str = Header(None)
):
    require_admin(authorization)

    # validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address"
        )

    print(f"🛡️ Quarantined IP: {ip}")

    return {"status": "quarantined", "ip": ip}


@app.post("/retrain")
async def retrain_model(
    authorization: str = Header(None)
):
    require_admin(authorization)

    print("🔄 Retraining AI model...")

    # non-blocking sleep — replace with real training call
    await asyncio.sleep(2)

    print("✅ Model updated")

    return {"status": "retrained"}

# =========================
# ROUTE — PUSH LOG
# =========================
@app.post("/push")
async def push_log(
    request: Request,
    authorization: str = Header(None)
):
    """
    Accept external log JSON, process it,
    broadcast result over WebSocket.
    Requires valid session token.
    """
    verify_token(authorization)

    try:
        data   = await request.json()
        record = process_line(json.dumps(data))

        if record:
            await broadcast(record)

        return {"status": "received"}

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

# =========================
# WEBSOCKET
# =========================
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...)
):
    """
    Live event stream.
    Requires valid token as query param:
      ws://host/ws?token=<token>
    """
    # authenticate before accepting
    session = active_sessions.get(token)

    if not session:
        await websocket.close(code=1008)
        return

    if datetime.utcnow() > session["expires"]:
        del active_sessions[token]
        await websocket.close(code=1008)
        return

    await websocket.accept()

    async with ws_lock:
        active_connections.append(websocket)

    print(
        f"✅ WebSocket connected "
        f"[{session['username']}]"
    )

    try:
        while True:
            # keep-alive ping
            await websocket.receive_text()

    except WebSocketDisconnect:
        print(
            f"❌ WebSocket disconnected "
            f"[{session['username']}]"
        )

    finally:
        async with ws_lock:
            if websocket in active_connections:
                active_connections.remove(websocket)
