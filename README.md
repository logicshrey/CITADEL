# CITADEL

CITADEL is a dark web threat and exposure intelligence platform built around a FastAPI backend and a React/Vite frontend. It ingests live-source findings, normalizes and enriches them, filters noise, consolidates related evidence into exposure cases, streams updates in real time, and now exports executive-grade PDF intelligence reports.

## Stack

- Backend: `FastAPI`, `Pydantic`, `requests`, `reportlab`
- Frontend: `React`, `Vite`, `Recharts`, `Axios`, `Framer Motion`
- Intelligence: `regex`, `spaCy`, `Sentence-BERT`, `scikit-learn`, optional `transformers`
- Persistence: local JSON monitoring store plus optional MongoDB alert storage
- Real-time updates: server-sent events via `/events/stream`

## Active Applications

- `backend/`: active FastAPI backend
- `frontend-react/`: active React/Vite frontend
- `frontend/`: legacy Streamlit interface kept in the repository, but not the primary UI

## What Changed In This Upgrade

- Added strict case and evidence normalization with backward compatibility for legacy stored cases
- Added a modular signal-quality layer for:
  - source trust weighting
  - confidence scoring with reasons
  - event signatures for deduplication
  - noise keyword suppression and spam-aware filtering
- Reduced case fragmentation by tightening merge logic and correlation rules
- Upgraded case payloads to support:
  - structured impacted assets
  - executive summary and technical summary
  - why-this-was-flagged reasoning
  - leak origin metadata
  - cleaner evidence snippets
- Added PDF report export via `/export/report/pdf`
- Updated the React executive dashboard to export filtered PDF reports
- Updated the React monitoring workspace to show structured case summaries, confidence, severity, and evidence previews

## Core Architecture

### Backend Flow

```text
Source collectors / manual analysis
  -> normalization + cleaning
  -> regex / NLP / entity enrichment
  -> signal quality scoring
  -> correlation + prioritization
  -> structured exposure case creation
  -> local monitoring store
  -> SSE updates to the React UI
```

### Main Backend Files

- `backend/main.py`: FastAPI app, routes, SSE endpoint
- `utils/nlp_engine.py`: orchestration, analysis, case building
- `utils/source_intel_service.py`: public-source collection and source aggregation
- `utils/signal_quality.py`: noise suppression, confidence scoring, event signatures
- `utils/case_schema.py`: strict case/evidence/report models and compatibility normalization
- `utils/local_store.py`: local JSON persistence for cases, watchlists, audit, scheduler state
- `utils/reporting.py`: PDF report generation
- `utils/monitoring_runtime.py`: watchlist scheduler and event bus

## Monitoring Data Model

Cases are normalized into a canonical structure that includes:

- `case_id`
- `org_id`
- `category`
- `severity`
- `confidence_score`
- `risk_score`
- `affected_assets`
- `evidence`
- `leak_origin`
- `exposure_summary`
- `technical_summary`
- `recommended_actions`
- `why_this_was_flagged`
- `triage_status`

Legacy fields such as `title`, `summary`, `executive_summary`, `priority`, and `case_status` remain available for backward compatibility.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Install the spaCy model:

```bash
python -m spacy download en_core_web_sm
```

4. Create a `.env` file and configure the providers you want to use.

Example environment values:

```env
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=dark_web_threat_intel
MONGO_COLLECTION=analyses
TELEGRAM_API_ID=<telegram_api_id>
TELEGRAM_API_HASH=<telegram_api_hash>
TELEGRAM_SESSION_STRING=<telethon_string_session>
PASTEBIN_API_KEY=<pastebin_developer_api_key>
DEHASHED_EMAIL=<dehashed_account_email>
DEHASHED_API_KEY=<dehashed_api_key>
GITHUB_TOKEN=<github_personal_access_token>
INTELX_API_KEY=<intelx_api_key>
INTELX_API_BASE=https://free.intelx.io
LEAKIX_API_KEY=<leakix_api_key>
```

## Run The Backend

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

## Run The React Frontend

```bash
cd frontend-react
npm install
npm run dev
```

## Main API Endpoints

- `POST /analyze`
- `POST /collect-intel`
- `GET /alerts`
- `GET /stats`
- `GET /monitoring/stats`
- `GET /cases`
- `GET /cases/{case_id}`
- `PATCH /cases/{case_id}`
- `GET /cases/export`
- `GET /export/report/pdf`
- `GET /watchlists`
- `POST /watchlists`
- `PUT /watchlists/{watchlist_id}`
- `DELETE /watchlists/{watchlist_id}`
- `POST /watchlists/{watchlist_id}/run`
- `GET /audit-events`
- `GET /events/stream`

## PDF Report Export

The PDF reporting endpoint supports executive-friendly filtered exports:

```bash
curl -L "http://127.0.0.1:8001/export/report/pdf?severity=Critical&category=Credential%20Leak"
```

Supported filters:

- `start_date`
- `end_date`
- `severity`
- `category`
- `org_id`

The generated PDF includes:

- cover page
- executive summary
- severity and confidence overview
- detailed case sections
- appendix with entities and source listings

## Running Tests

Targeted regression tests are provided for signal quality, case consolidation, correlation, and PDF generation:

```bash
python -m unittest discover -s tests
```

## Notes

- If MongoDB is unavailable, CITADEL continues to function using the local monitoring store.
- The watchlist scheduler and SSE flow remain backward compatible with the existing React monitoring workspace.
- Report generation uses `reportlab`, which is included in `requirements.txt`.
- The repository still contains a legacy Streamlit app, but the active UI for this system is `frontend-react/`.
