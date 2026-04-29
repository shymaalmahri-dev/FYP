# ELAI

ELAI is an explainable AI cybersecurity platform that detects suspicious network traffic, explains why it was flagged, and surfaces alerts in a SOC-style dashboard.

## What This Project Does

The platform combines four main parts:

1. `code/`
   Builds datasets from PCAP traffic, generates synthetic traffic, and trains the Random Forest model.
2. `FYP/`
   Runs live packet capture, extracts features, applies multilayer threat detection, and posts alerts to the dashboard.
3. `explainable_ai/`
   Stores raw alerts, computes SHAP-based explanations, and generates analyst-style incident summaries with Ollama or deterministic fallbacks.
4. `elai-dashboard/`
   Express + tRPC + Socket.IO + React dashboard for viewing alerts, explanations, deep analysis, and SOC actions.

## Active Architecture

The current active runtime path is:

1. Packet capture and multilayer detection happen in `FYP/inference.py`.
2. Alerts are structured by `explainable_ai/alert_collector.py`.
3. SHAP explanations and LLM summaries are generated in `explainable_ai/`.
4. The inference engine posts alerts directly to `POST /api/alerts` on the dashboard server.
5. The dashboard stores alerts in MySQL, broadcasts them over Socket.IO, and renders them in the React UI.

Direct dashboard alert posting is the primary ingestion path.

File-based ingestion from `explainable_ai/alerts/*.json` still exists for backfill/demo support, but it is disabled by default and only runs when `ENABLE_FILE_ALERT_INGESTION=true`.

## Main Runtime Flow

1. Capture live packets from the protected interface.
2. Extract packet and short-window behavioral features.
3. Run three detection layers:
   - ML traffic classification
   - payload inspection
   - behavior analysis
4. Create an alert when suspicious activity is detected.
5. Attach SHAP explanation data and LLM/fallback explanation text.
6. Send the alert to the dashboard API.
7. Persist the alert to MySQL and broadcast it to connected dashboard clients.
8. Let analysts review the alert, block IPs, and request deeper analysis.

## Key Files

- `code/createfile.py`
- `code/synthetic_data.py`
- `code/train.py`
- `FYP/inference.py`
- `FYP/test_inference_traffic.py`
- `explainable_ai/shap_analyzer.py`
- `explainable_ai/incident_generator.py`
- `elai-dashboard/server/index.ts`
- `elai-dashboard/server/routers/threats.ts`
- `elai-dashboard/client/src/pages/Dashboard.tsx`

## Setup

### 1. Python prerequisites

Install the Python packages required by:

- `scapy`
- `pandas`
- `joblib`
- `shap`
- `scikit-learn`
- `ollama` Python client

You also need the trained model artifacts already present in:

- `FYP/edge_ai_artifacts/`
- `explainable_ai/model_artifacts/`

### 2. Dashboard prerequisites

In `elai-dashboard/`, install dependencies:

```powershell
npm install
```

Copy the dashboard environment template first:

```powershell
cd elai-dashboard
Copy-Item .env.example .env
```

Required environment variables:

- `DATABASE_URL`
- `OAUTH_SERVER_URL` if auth flows are used
- `BUILT_IN_FORGE_API_KEY` and related Forge variables only for optional AI helpers
- `ENABLE_FILE_ALERT_INGESTION=true` only if you want JSON-file backfill ingestion
- `OLLAMA_BASE_URL` and `OLLAMA_MODEL` for deep-analysis health checks and generation

### 3. Ollama

For full LLM-generated analysis, install Ollama and pull the model:

```powershell
ollama pull llama3
```

Without Ollama, deep analysis still works, but it returns deterministic fallback summaries.

## Run Order

### Train or rebuild model artifacts

```powershell
cd code
python synthetic_data.py
python createfile.py
python train.py
```

Move or copy the generated artifacts into the locations expected by `FYP/` and `explainable_ai/` if you retrain the model.

### Start the dashboard

```powershell
cd elai-dashboard
npm run dev
```

### Start live inference

```powershell
cd FYP
python inference.py
```

### Optional traffic test

```powershell
cd FYP
python test_inference_traffic.py
```

## Verification

Useful checks:

```powershell
cd elai-dashboard
npm run check
```

```powershell
cd elai-dashboard
node -e "fetch('http://localhost:4000/api/trpc/system.status?input=%7B%7D').then(r=>r.text()).then(console.log)"
```

```powershell
cd explainable_ai
python incident_generator.py --attack-type SYN_Flood --attacker-ip 1.2.3.4 --verbosity brief
```

```powershell
cd elai-dashboard
node check-db.js
```

## Known External Dependencies

These are outside the codebase and must be working for the full platform to behave end to end:

- MySQL database connectivity
- packet capture permissions and interface access
- Ollama runtime plus downloaded model
- correct local network environment for live testing

## Archived / Legacy Pieces

Some older or unused files were archived to reduce confusion. They are preserved for reference, but they are not part of the active runtime path.

## New Operational Features

- `.env.example` templates exist at the repo root and inside `elai-dashboard/`
- The dashboard exposes a status query through `system.status`
- SOC exports now generate downloadable CSV and PDF files
