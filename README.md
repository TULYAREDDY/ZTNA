# Sentinel ZTNA

> *Replace the VPN, not the network.*

Sentinel is a Zero Trust Network Access framework that issues a fresh
ALLOW · MONITOR · BLOCK verdict on every request, blends an auditable
rule engine with a calibrated machine-learned risk model, and streams
the full decision pipeline to a live console.

It replaces the implicit trust of a VPN tunnel with continuous,
identity- and behaviour-aware authorization at the request layer.

## Contents

- [Why](#why)
- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Demo flow](#demo-flow)
- [Risk decision pipeline](#risk-decision-pipeline)
- [Machine learning](#machine-learning)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Roadmap](#roadmap)
- [Team](#team)

## Why

VPNs were designed for a perimeter network that no longer exists. Once
authenticated, a VPN client gets broad network reachability with no
continuous verification, which means a single stolen credential is a
ticket to lateral movement across the intranet.

| Failure mode of VPNs | Consequence |
|---|---|
| Implicit trust after login | One stolen credential = full intranet access |
| All-or-nothing reachability | Violates least privilege |
| No continuous verification | Compromise undetected for hours |
| Static authentication | No reaction to behavioural anomalies |
| No device posture validation | Unmanaged BYOD reaches production |

Sentinel addresses each by re-authorising every request, scoring it on
behavioural plus posture features, and shipping the verdict back to a
fail-closed proxy.

## What it does

- **Replaces the VPN tunnel** with a lightweight HTTP proxy (Policy
  Enforcement Point) that gates every request on a fresh policy
  decision from the backend.
- **Validates device posture** at session creation using a 100-point
  trust budget across antivirus, firewall, encryption, patching, MDM,
  screen-lock, and geography.
- **Scores every request** using a hybrid engine that blends
  deterministic rule contributions with a machine-learned probability
  of attack.
- **Adapts dynamically**, raising or lowering risk in response to
  behaviour: ALLOW under 45, MONITOR 45–69, BLOCK 70+.
- **Streams verdicts in real time** through a WebSocket to a React
  console where every decision is visible with its full list of
  reasons.
- **Lets you revoke** any session with one click; subsequent requests
  on that session are denied at the door.

Every component is **fail-closed**: if the proxy cannot reach the
decision engine, it denies.

## Architecture

```
                ┌──────────────────────────┐
   browser ───▶ │  PEP — Sentinel Proxy    │  :9090
                │  HTTP forward gateway    │
                └──────────┬───────────────┘
                           │ POST /api/access
                           ▼
            ┌──────────────────────────────────┐
            │  PDP — FastAPI Decision Engine   │  :8000
            │   ┌──────────┬─────────────┐     │
            │   │  rules   │   ML model  │     │
            │   └────┬─────┴──────┬──────┘     │
            │        └── blend ──┘             │
            │             │                    │
            │  ALLOW · MONITOR · BLOCK         │
            └──────────┬───────────────────────┘
                       │ WebSocket /api/ws/events
                       ▼
            ┌──────────────────────────┐
            │  React Console (Vite)    │  :5173
            │  KPIs · feed · attack    │
            │  lab · ML insights       │
            └──────────────────────────┘
```

Three independent processes:

| Service | Port | Responsibility |
|---|---|---|
| `backend` | 8000 | Policy Decision Point — posture, access, sessions, lab, analytics, WebSocket |
| `proxy` | 9090 | Policy Enforcement Point — fail-closed HTTP forward gateway, calls `/api/access` per request |
| `frontend` | 5173 | Operator console — live feed, sessions, attack lab, ML insights |

## Repository layout

```
.
├── backend/                       FastAPI Policy Decision Point
│   ├── app/
│   │   ├── api/                   posture · access · sessions · lab · analytics · websocket
│   │   ├── core/                  config · structured logging
│   │   ├── ml/                    feature engineering · dataset generator · training pipeline
│   │   ├── models/                pydantic schemas
│   │   └── services/              risk_engine · ml_service · session_store · event_bus · posture_validator
│   ├── Dockerfile
│   └── requirements.txt
├── proxy/                         Policy Enforcement Point (fail-closed HTTP gateway)
│   ├── ztna_proxy.py
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                      React + Vite + TS console
│   ├── src/
│   │   ├── components/            ui · layout · panels
│   │   ├── hooks/                 useEventStream · usePoll
│   │   ├── pages/                 Dashboard · Sessions · Lab · ML
│   │   └── lib/                   api client · helpers
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
├── docker-compose.yml
├── Makefile
├── .env.example
└── README.md
```

## Quick start

### Prerequisites

- Python 3.11+ (Python 3.14 supported)
- Node 20+
- `make` (optional but convenient)

### Option A — Make targets (local)

```bash
make install       # creates venvs and installs deps
make demo          # ensures the ML model exists, then runs backend + frontend
```

`make train` regenerates the dataset and retrains the classifier. On
first boot the backend auto-trains if artifacts are missing; Docker
images also train during the build step.

In another terminal, optionally:

```bash
make proxy         # runs the PEP on :9090
```

Open [http://localhost:5173](http://localhost:5173).

### Option B — Plain commands

If you prefer not to use `make`:

```bash
# backend
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m app.ml.train
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# frontend (new terminal)
cd frontend
npm install
npm run dev

# proxy (optional, new terminal)
cd proxy
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python ztna_proxy.py
```

### Option C — Docker Compose

```bash
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080) for the dashboard;
point HTTP clients at `http://localhost:9090` for the proxy.

## Demo flow

1. Run `make demo` (or compose). The console at
   [http://localhost:5173](http://localhost:5173) should show **stream
   live**.
2. Open the **Attack Lab** card.
3. Click **Normal Baseline**: green ALLOWs flow into the live feed.
4. Click **Token Theft**: the decisions chart spikes red BLOCKs as the
   rule engine catches the IP mismatch and the ML probability climbs.
5. Click **Brute Force**: posture rejects most attempts at the door
   before the model even sees them.
6. Switch to **ML Insights** to see the model comparison table, ROC,
   PR, calibration curves, permutation feature importance, and the
   F1-optimal threshold.
7. Switch to **Sessions** and revoke one with a click; subsequent
   requests on that session ID are denied.

## Risk decision pipeline

For every `/api/access` call:

1. **Session validation.** The session must exist and be `ACTIVE` —
   not revoked, not idle-expired beyond the configured TTL.
2. **Feature extraction.** Eight raw features are computed:
   `request_rate`, `ip_change`, `failed_attempts`, `device_trust`,
   `time_of_day`, `location_risk`, `posture_score`, `session_age_min`.
3. **Rule component.** A deterministic, auditable score (0–100) is
   produced from explicit contributions, e.g.
   `ip_mismatch_session_hijack_suspected` adds 60,
   `failed_attempts >= 3` adds 25.
4. **ML component.** The trained classifier emits a calibrated
   probability of attack.
5. **Blend.** `risk = 0.6 · rule + 0.4 · 100 · p_ml`. A confluence
   bonus of 6 is added when both signals agree (rule ≥ 60 and
   `p_ml` ≥ 0.5) — two independent detectors agreeing is much
   stronger than either alone.
6. **Threshold.** `< 45` ALLOW, `[45, 70)` MONITOR, `≥ 70` BLOCK.
7. **Verdict.** Logged with the list of reasons that produced it.
   Every decision is auditable.

The hybrid design is deliberate: a purely ML decision is unauditable,
a purely rule-based decision misses emergent anomalies. Together they
provide explainability and adaptivity.

## Machine learning

### Pipeline

The training script under `backend/app/ml/train.py` runs an end-to-end
pipeline:

1. **Dataset.** Loads or generates 20 000 synthetic ZTNA records with a
   stable hash recorded in metadata.
2. **Feature engineering** (`backend/app/ml/features.py`):
   `log1p(request_rate)` to tame the heavy-tailed lognormal source, and
   cyclical `(sin, cos)` encoding for `time_of_day` so hour 23 and
   hour 0 are neighbours instead of 23 units apart.
3. **Model comparison** under 5-fold stratified cross-validation across
   four families: Logistic Regression, Random Forest, Gradient
   Boosting, MLP. Scored by F1, ROC-AUC, PR-AUC.
4. **Hyperparameter search.** Randomized search (20 iterations, F1
   scoring) over the winning family.
5. **Probability calibration.** `CalibratedClassifierCV` with sigmoid
   (Platt) — sklearn tree-based probabilities are not calibrated by
   default, and the runtime engine treats `p_ml` as a continuous risk
   signal.
6. **Threshold selection.** F1-optimal threshold from the held-out PR
   curve. Default 0.5 is rarely correct under class imbalance.
7. **Permutation importance** (not Gini, which is biased toward
   continuous high-cardinality features).
8. **Artifacts** are exported under `backend/app/ml/artifacts/`:
   `model.joblib`, `metrics.json`, `confusion_matrix.png`,
   `feature_importance.png`, `roc_curve.png`, `pr_curve.png`.

`metrics.json` carries enough metadata for reproducibility: training
timestamp, dataset hash, sklearn version, Python version, CV folds,
seed.

### Synthetic dataset

Public IDS datasets (NSL-KDD, CICIDS-2017/2018) describe network
*flow* features (bytes, packet sizes, TCP flags). Sentinel operates one
layer higher, at the **session/identity** layer, on features public
datasets do not capture jointly (posture score, session age, request
rate per session ID). So the dataset is synthesised — explicit
generative process, grounded in MITRE ATT&CK.

| Persona | Weight | Label | Pattern |
|---|---:|---:|---|
| `normal_user` | 62 % | benign | work-hours, low rate, trusted device |
| `power_user` | 12 % | benign | bursty rate, high trust |
| `off_hours` | 6 % | benign | late-night legitimate access |
| `travelling` | 6 % | benign | mobile / hotel network — high `location_risk` |
| `forgetful` | 4 % | benign | fat-fingered password — high `failed_attempts` |
| `hijacked` (T1078) | 5 % | attack | session reuse from a different IP |
| `brute_force` (T1110) | 3 % | attack | rapid attempts, low-trust device |
| `recon` (T1595) | 2 % | attack | low-and-slow probing |

The benign personas deliberately overlap with attack personas on
specific features — a travelling user produces high `location_risk`, a
forgetful user produces high `failed_attempts`. This forces the
classifier to learn multivariate boundaries instead of a single feature
threshold, which is what a real ZTNA model has to do.

Labels are derived from the persona, not the features.

## API reference

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/posture` | Validate device posture and issue a session |
| POST | `/api/access` | Per-request decision (called by the PEP) |
| GET | `/api/sessions?active_only=` | List sessions |
| GET | `/api/sessions/{id}` | Session detail |
| POST | `/api/sessions/revoke` | Revoke a session |
| GET | `/api/analytics/snapshot` | KPIs and decision timeline |
| GET | `/api/analytics/ml` | Trained model metrics |
| GET | `/api/analytics/events?limit=` | Recent events |
| GET | `/api/lab/scenarios` | List demo scenarios |
| POST | `/api/lab/run/{key}` | Fire a scenario |
| WS | `/api/ws/events` | Real-time event stream |
| GET | `/api/health` | Healthcheck |

OpenAPI documentation is available at
[http://localhost:8000/docs](http://localhost:8000/docs) when the
backend is running.

## Configuration

All settings are read from environment variables prefixed with
`ZTNA_`. See [.env.example](.env.example) for the full list. The most
relevant ones:

| Variable | Default | Purpose |
|---|---|---|
| `ZTNA_API_HOST` | `0.0.0.0` | Backend bind host |
| `ZTNA_API_PORT` | `8000` | Backend bind port |
| `ZTNA_SESSION_TTL_SECONDS` | `1800` | Idle session timeout |
| `ZTNA_SESSION_HARD_TTL_SECONDS` | `28800` | Absolute session lifetime |
| `ZTNA_MAX_FAILED_ATTEMPTS` | `5` | Lockout threshold |
| `ZTNA_RISK_MONITOR_THRESHOLD` | `45` | MONITOR floor |
| `ZTNA_RISK_BLOCK_THRESHOLD` | `70` | BLOCK floor |
| `ZTNA_PDP_URL` | `http://localhost:8000/api/access` | PEP target |
| `ZTNA_LISTEN` | `0.0.0.0:9090` | PEP bind address |

## Roadmap

- mTLS between PEP and PDP
- Pluggable session store (Redis) for multi-PDP HA
- OPA-style policy authoring DSL on top of the rule engine
- Sequence model (LSTM) for behavioural drift over a 30-minute window
- IdP integration (OIDC) for real user identities
- WireGuard fallback for legacy non-HTTP services

## Team

| Name | USN | Department |
|---|---|---|
| Yash Saraogi | 1RV23CS297 | CSE-E |
| Vineeth Rao | 1RV23CS288 | CSE-E |
| Tulya Reddy Y | 1RV23CS296 | CSE-E |

Department of Computer Science, R V College of Engineering, Bengaluru — Experiential Learning Phase 1.
