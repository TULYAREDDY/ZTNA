# ZTNA-ML: Zero Trust Network Access with Machine Learning

## 1. Problem Statement

Traditional VPN-based security assumes that once a user is inside the network, they are trusted. This creates major risks:

* No verification after login
* Session hijacking allows full access
* Tools like ngrok expose internal services
* No behavioral monitoring
* All-or-nothing access control

This project addresses these issues using a **Zero Trust approach**, where every request is verified before access is granted.

---

## 2. Solution Overview

This system is built using three components:

1. Proxy (Policy Enforcement Point)

   * Intercepts all HTTP requests
   * Sends session details to backend
   * Blocks or allows requests

2. Backend (Policy Decision Point)

   * Validates sessions
   * Generates features
   * Uses ML model to decide access

3. Machine Learning Model

   * Classifies requests as safe or malicious
   * Based on behavioral patterns

---

## 3. System Architecture

Client → Proxy → Backend → ML Model → Decision → Proxy → Internet

---

## 4. Features

* Session-based authentication
* ML-based behavioral analysis
* Real-time access control
* IP mismatch detection (stolen session)
* Session expiry handling
* Attack simulation support
* Fail-safe blocking (default BLOCK)

---

## 5. Tech Stack

* Python
* FastAPI (Backend)
* Socket Programming (Proxy)
* scikit-learn (ML)
* pandas, numpy
* joblib

---

## 6. Machine Learning Integration

### Features Used

* request_rate
* ip_change
* failed_attempts
* device_trust
* time_of_day
* location_risk

### Model

* RandomForestClassifier
* Output:

  * 0 → ALLOW
  * 1 → BLOCK

### How ML is used

For every request:

1. Backend generates feature values
2. Features are passed to model
3. Model predicts SAFE or ATTACK
4. Decision sent to proxy
5. Proxy enforces decision

---

## 7. Setup Instructions

### Backend

```
cd ztna_backend
python app.py
```

---

### Proxy (Ubuntu VM)

```
cd ztna_proxy
python3 proxy.py
```

---

### Create Session

```
python client.py
```

Copy session ID.

---

### Test System

```
curl -x http://localhost:9090 http://httpbin.org/get \
-H "X-Session-ID: <SESSION_ID>"
```

---

## 8. Expected Results

* Normal request → 200 OK
* Suspicious behavior → sometimes ALLOW
* Attack behavior → 403 Forbidden

---

## 9. Demo Flow

1. Run backend and proxy
2. Generate session
3. Send request → ALLOW
4. Simulate attack → BLOCK

---


