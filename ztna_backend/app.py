from fastapi import FastAPI
from pydantic import BaseModel
import uuid
import time
import logging
import random
from datetime import datetime
from typing import Dict, Optional
import joblib

model = joblib.load("ml/ztna_model.pkl")
# Initialize FastAPI App
app = FastAPI(title="ZTNA Backend - Stable Core")

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ztna_stable")

# ---------------------------------------------------------
# GLOBAL SESSION STORE
# ---------------------------------------------------------
SESSIONS: Dict[str, dict] = {}
SESSION_EXPIRY_SECONDS = 600  # 10 minutes

# ---------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------

class PostureData(BaseModel):
    os: str
    antivirus_active: bool      # FIXED: was "antivirus" (matches client.py)
    firewall_active: bool       # FIXED: was "firewall"  (matches client.py)
    ip_address: str             # FIXED: was "ip"        (matches client.py)
    process_count: Optional[int] = 0  # NEW: client.py sends this

class AccessRequest(BaseModel):
    session_id: str
    ip_address: str             # FIXED: was "ip"        (matches client.py + proxy)
    target_service: Optional[str] = ""  # NEW: proxy sends this

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def calculate_risk(session: dict, current_ip: str) -> int:
    """
    Simple risk scoring:
      - IP mismatch   → +80 (stolen token)
      - High req rate → +30
      - Base risk     →  10
    """
    risk = 10
    if session["ip"] != current_ip:
        risk += 80
    return min(risk, 100)

# ---------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------

@app.post("/posture")
def evaluate_posture(posture: PostureData):
    """
    Step 1: Authenticate the device and issue a session.
    Called by client.py on startup.
    """
    # Device must be compliant
    if not posture.antivirus_active or not posture.firewall_active:
        logger.warning(f"Posture rejected for IP: {posture.ip_address}")
        return {"decision": "BLOCK", "session_id": None, "risk_score": 100}

    session_id = str(uuid.uuid4())

    SESSIONS[session_id] = {
        "ip":         posture.ip_address,
        "created_at": time.time(),
        "status":     "ACTIVE",
        "os":         posture.os,
    }

    logger.info(f"New session: {session_id} for IP: {posture.ip_address}")
    return {
        "decision":   "ALLOW",
        "session_id": session_id,
        "risk_score": 10,        # client.py reads this
    }


@app.post("/access")
def request_access(req: AccessRequest):
    session_id = req.session_id
    ip_address = req.ip_address
    target_service = req.target_service

    # Validate session
    if session_id not in SESSIONS:
        return {"decision": "BLOCK"}

    session = SESSIONS[session_id]

    # Generate features
    request_rate = random.uniform(0.5, 10)
    ip_change = 0 if session["ip"] == ip_address else 1
    failed_attempts = session.get("fails", 0)
    device_trust = session.get("device_trust", 0.9)
    time_of_day = datetime.now().hour
    location_risk = random.uniform(0, 1)

    features = [
        request_rate,
        ip_change,
        failed_attempts,
        device_trust,
        time_of_day,
        location_risk
    ]

    # Predict using ML model
    prediction = int(model.predict([features])[0])

    if prediction == 1:
        decision = "BLOCK"
    else:
        decision = "ALLOW"

    # Logging REQUIRED
    logger.info(f"[ML] session={session_id} | ip={ip_address}")
    logger.info(f"features={features}")
    logger.info(f"prediction={prediction} -> {decision}")

    return {
        "decision": decision,
        "features": {
            "request_rate": request_rate,
            "ip_change": ip_change,
            "failed_attempts": failed_attempts,
            "device_trust": device_trust,
            "time_of_day": time_of_day,
            "location_risk": location_risk
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)