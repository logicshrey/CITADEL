# CITADEL Current Pipeline Audit

## Scope
This document captures the current CITADEL monitoring pipeline as implemented today, before noise-reduction or scoring changes are introduced. It covers:

- source ingestion to normalized findings
- regex and entity extraction
- correlation and scoring
- case generation and persistence
- SSE updates
- current export/report behavior
- root causes of false positives and noise

## Current Architecture Summary

### 1. API entrypoints and orchestration
Primary backend entrypoint: `backend/main.py`

Current high-level runtime wiring:

- `ThreatIntelligenceEngine` from `utils/nlp_engine.py`
- `MonitoringEventBus` from `utils/monitoring_runtime.py`
- `MonitoringScheduler` from `utils/monitoring_runtime.py`

Relevant API routes:

- `POST /analyze`
- `POST /collect-intel`
- `GET /cases`
- `GET /cases/export`
- `GET /export/report/pdf`
- `GET /alerts`
- `GET /watchlists`
- `PATCH /cases/{case_id}`
- `GET /events/stream`

### 2. End-to-end monitoring flow

#### A. Manual analysis flow
`POST /analyze` -> `ThreatIntelligenceEngine.analyze_text()`

Pipeline:

1. raw text received
2. regex pattern matching via `detect_patterns()`
3. multilingual normalization via `normalize_multilingual_text()`
4. slang decoding via `decode_slang()`
5. text cleanup via `clean_text()`
6. spaCy entity extraction via `extract_entities()`
7. regex-driven enrichment via `extract_enriched_entities()`
8. ML classification via model manager
9. semantic similarity against threat templates
10. risk level assignment via `compute_risk_level()`
11. impact estimation via `estimate_impact()`
12. correlation against recent alerts via `correlate_alerts()`
13. alert prioritization via `prioritize_alert()`
14. alert persistence via `MongoManager.insert_analysis()`

Primary modules:

- `utils/nlp_engine.py`
- `utils/intel_enrichment.py`
- `utils/text_utils.py`
- `utils/model_manager.py`
- `utils/db.py`

#### B. External intelligence collection flow
`POST /collect-intel` -> `ThreatIntelligenceEngine.collect_external_intelligence()`

Pipeline:

1. external providers queried by `ExternalIntelligenceService.collect()`
2. each provider returns `RawSourceHit`
3. hits filtered by `_is_relevant_hit()`
4. source hits aggregated into `AggregatedFinding`
5. confidence scored by `score_confidence()`
6. finding promotion gated by `should_promote_finding()`
7. promoted findings re-enter `ThreatIntelligenceEngine._build_external_finding_result()`
8. regex/NLP/correlation/priority rerun on aggregated finding text
9. alert persisted
10. case built by `_build_exposure_case()`
11. case stored through `MongoManager.save_case()` -> `LocalMonitoringStore.save_case()`
12. API emits `case_updated` SSE events for manual collections

Primary modules:

- `utils/source_intel_service.py`
- `utils/signal_quality.py`
- `utils/nlp_engine.py`
- `utils/local_store.py`
- `utils/db.py`

#### C. Watchlist monitoring flow
Scheduler runtime: `utils/monitoring_runtime.py`

Pipeline:

1. `MonitoringScheduler._run_loop()` polls enabled watchlists
2. each watchlist calls `engine.sync_watchlist()`
3. `sync_watchlist()` runs collection with `persist=False`
4. each finding is turned into a case via `_build_exposure_case()`
5. `LocalMonitoringStore.save_case()` creates or merges case
6. scheduler emits `case_updated` SSE events
7. optional webhook payload dispatched
8. scheduler state and audit trail stored in monitoring state

### 3. Storage model

#### Alerts / analyses
Managed by `utils/db.py`

- MongoDB is optional
- alerts/analyses are inserted with `insert_analysis()`
- if Mongo is unavailable, local fallback storage is used

#### Monitoring state
Managed by `utils/local_store.py`
Primary file: `data/monitoring_state.json`

Current persisted top-level sections:

- `alerts`
- `cases`
- `watchlists`
- `audit_events`
- `scheduler`

#### Cases
Cases are always normalized through `normalize_case_record()` from `utils/case_schema.py` before use in monitoring storage.

### 4. SSE update path

- Event producer: `MonitoringEventBus.publish()` in `utils/monitoring_runtime.py`
- Stream endpoint: `GET /events/stream` in `backend/main.py`
- Event types observed:
  - `case_updated`
  - `watchlist_error`
  - heartbeat events

Frontend consumer:

- `frontend-react/src/pages/Feed.jsx` uses `EventSource` against `/events/stream`

## Current Data Formats

### 1. Raw source hit
Defined in `utils/source_intel_service.py`

```python
RawSourceHit(
    source: str,
    text: str,
    date_found: str,
    metadata: dict[str, Any]
)
```

Purpose:

- lowest-level normalized unit returned from Telegram, GitHub, IntelX, LeakIX, Pastebin, Dehashed

### 2. Aggregated finding
Defined in `utils/source_intel_service.py`

Important fields:

- `organization`
- `source`
- `platforms`
- `text`
- `emails`
- `usernames`
- `data_types`
- `data_breakdown`
- `type`
- `risk_score`
- `date_found`
- `volume`
- `estimated_record_count`
- `estimated_records`
- `affected_assets`
- `matched_indicators`
- `source_locations`
- `summary`
- `event_signature`
- `confidence_score`
- `confidence_reasons`
- `source_trust`
- `raw_items`

This is the main handoff object between source aggregation and downstream case generation.

### 3. Analysis / alert result
Produced in `utils/nlp_engine.py`

Important fields:

- `input_text`
- `cleaned_text`
- `threat_type`
- `risk_level`
- `risk_score` (external flow only)
- `confidence_score`
- `patterns`
- `entities`
- `enriched_entities`
- `multilingual_analysis`
- `slang_decoder`
- `semantic_analysis`
- `primary_classification`
- `secondary_classification`
- `correlation`
- `impact_assessment`
- `alert_priority`
- `event_signature`
- `external_intelligence` (external flow only)

### 4. Stored alert document
Persisted by `ThreatIntelligenceEngine.analyze_text()` and `_persist_result_alert()`

Current shape:

```python
{
    "text": ...,
    "source": ...,
    "results": {...},
    "alerts": {
        "threat_type": ...,
        "entities": ...,
        "patterns": ...,
        "risk_level": ...,
        "risk_score": ...,
        "priority": ...,
        "timestamp": ...,
        "source": ...
    },
    "timestamps": {
        "analyzed_at": ...
    }
}
```

### 5. Stored exposure case
Canonical schema defined in `utils/case_schema.py` as `ExposureCase`

Key current fields:

- `case_id`
- `id`
- `created_at`
- `updated_at`
- `org_id`
- `organization`
- `query`
- `category`
- `severity`
- `confidence_score`
- `risk_score`
- `affected_assets`
- `affected_assets_flat`
- `evidence`
- `sources`
- `timeline`
- `leak_origin`
- `exposure_summary`
- `technical_summary`
- `executive_summary`
- `recommended_actions`
- `why_this_was_flagged`
- `confidence_assessment`
- `triage_status`
- `tags`
- `watchlists`
- `matched_indicators`
- `exposed_data_types`
- `event_signature`
- `fingerprint_key`
- `source_count`
- `evidence_count`
- `corroborating_source_count`
- `first_seen`
- `last_seen`
- `confidence_basis`
- `severity_reason`
- `priority`
- `priority_score`
- `risk_level`
- `threat_type`
- `title`
- `summary`
- `case_status`

### 6. Snapshot export format
Provided by `GET /cases/export`
Implemented in `utils/local_store.py`

Current snapshot shape:

```python
{
    "generated_at": ...,
    "cases": [...],
    "watchlists": [...],
    "audit_events": [...],
    "scheduler": {...}
}
```

## Current Regex and Entity Extraction Logic

### 1. Engine-level regex extraction
Implemented in `utils/nlp_engine.py`

Current regex buckets:

- emails
- passwords
- ips
- bitcoin wallets
- credit cards
- telegram handles
- onion links
- domains

Current issue:

- these patterns are broad and mostly syntax-based
- there is no dedicated entity validation layer
- extracted entities are passed forward directly into explanations, scoring, correlation, and case building

### 2. External collection extraction
Implemented in `utils/source_intel_service.py`

Current extraction functions:

- `_extract_emails()`
- `_extract_usernames()`
- `_extract_domains()`
- `_extract_ip_addresses()`
- `_extract_affected_assets()`
- `_extract_matched_indicators()`

Current domain filtering is minimal:

- `_is_valid_domain_candidate()` rejects some file-like suffixes and slash-containing values
- this is helpful but not sufficient for organization-grade filtering

### 3. Enriched entities
Implemented in `utils/intel_enrichment.py`

`extract_enriched_entities()` currently:

- extracts regex domains
- excludes domains only if they are inside an extracted email
- appends EMAIL, HANDLE, WALLET labels directly

Current issue:

- no confidence score
- no validation reason
- no distinction between raw match and validated entity

### 4. Schema normalization of assets
Implemented in `utils/case_schema.py`

`normalize_affected_assets()` infers:

- domains if string contains `.` and not `@` or `:`
- emails if string contains `@`
- IPs if dotted quad digits
- everything else becomes usernames unless token/wallet buckets were already supplied

Current issue:

- downstream normalization infers asset types from string shape, not validated intelligence semantics

## Current Correlation and Scoring Logic

### 1. Confidence scoring
Implemented in `utils/signal_quality.py`

Main inputs:

- query match strength
- matched indicators
- extracted data types
- source locations
- evidence count
- source trust score
- high-signal terms
- likely-noise penalty
- generic mention penalty

Promotion gate:

- `should_promote_finding()` rejects likely noise only when score is below 70
- otherwise a noisy finding can still be promoted if enough weak signals accumulate

### 2. Risk level assignment
Implemented in `utils/nlp_engine.py`

Current logic:

- email + password -> `HIGH`
- certain threat labels + at least 2 regex buckets -> `HIGH`
- any ORG entity or certain threat labels -> `MEDIUM`
- otherwise `LOW`

Current issue:

- weak ORG extraction alone can escalate severity
- multiple weak regex buckets can inflate risk

### 3. Impact estimation
Implemented in `utils/intel_enrichment.py`

Current impact uses heuristics such as:

- `million`
- `bulk`
- `database`
- `records`
- `admin`
- `panel`
- `vpn`
- `rdp`
- `access`
- `kit`
- `campaign`

Current issue:

- keywords are treated as impact evidence without validating context or proof

### 4. Correlation
Implemented in `utils/intel_enrichment.py`

Correlation inputs:

- matching `event_signature`
- shared entities
- shared enriched domains/handles/emails/wallets
- shared slang
- shared source locations
- same threat type

Current issue:

- correlation is based on overlap volume, not evidence strength
- common but non-org-specific entities can still raise campaign score
- result is fed into `prioritize_alert()`, amplifying weak links

### 5. Priority / severity
Implemented in `utils/intel_enrichment.py` and normalized in `utils/case_schema.py`

Priority score currently combines:

- risk base
- confidence component
- impact component
- correlation component

Priority thresholds:

- `>= 85` -> `CRITICAL`
- `>= 65` -> `HIGH`
- `>= 40` -> `MEDIUM`
- else `LOW`

Severity is then derived from priority during case normalization.

Current issue:

- severity is downstream of already-inflated risk/impact/correlation
- cases can become critical from stacked heuristics rather than verified evidence

## Current Export / Reporting State

### 1. JSON snapshot export
Endpoint: `GET /cases/export`

- returns monitoring snapshot JSON
- no formatting layer
- useful for raw state export only

### 2. PDF report export
Endpoint: `GET /export/report/pdf`
Implementation: `utils/reporting.py`
Library: ReportLab

Current PDF sections:

1. cover page
2. executive summary
3. severity / confidence / category overview tables
4. detailed case pages
5. appendix

Frontend integration:

- `frontend-react/src/pages/Dashboard.jsx` triggers PDF export
- `frontend-react/src/services/api.js` downloads a blob from `/export/report/pdf`
- `frontend-react/src/pages/Feed.jsx` still exports JSON snapshot

Current quality assessment:

- PDF export exists and is functional
- report structure is better than JSON-only export
- layout is basic and still depends on current noisy case quality
- executive usefulness is limited by false positives and weak case narratives upstream

## Root Causes of Noise and False Positives

### 1. No dedicated validation layer between extraction and storage
Root cause:

- raw regex hits are treated as entities too early
- there is no mandatory validation stage before enrichment, correlation, and case building

Responsible modules:

- `utils/nlp_engine.py`
- `utils/source_intel_service.py`
- `utils/intel_enrichment.py`
- `utils/case_schema.py`

### 2. Regexes are permissive and string-shape based
Examples of risk:

- filenames can look like emails
- file names or paths can resemble domains
- dotted numeric text can resemble IPs
- handles and domains are extracted without enough context

Responsible modules:

- `utils/nlp_engine.py`
- `utils/source_intel_service.py`
- `utils/intel_enrichment.py`

### 3. Relevance filtering is too permissive for broad source content
Root cause:

- `_is_relevant_hit()` mostly checks for query presence plus generic threat/sensitive signals
- this allows contextual mentions, scan output, code references, or discussion threads to pass

Responsible module:

- `utils/source_intel_service.py`

### 4. Confidence scoring can still promote noisy findings
Root cause:

- weak evidence can stack into a promotable score
- likely noise is only blocked if total score remains under 70

Responsible module:

- `utils/signal_quality.py`

### 5. Correlation rewards overlap, not proof
Root cause:

- shared indicators, slang, or locations can increase correlation without proving the same incident
- correlation score directly boosts priority

Responsible module:

- `utils/intel_enrichment.py`

### 6. Risk and impact scoring overreact to generic heuristics
Root cause:

- ORG extraction alone can force medium risk
- weak keyword context can increase impact
- priority stacks risk + impact + correlation

Responsible modules:

- `utils/nlp_engine.py`
- `utils/intel_enrichment.py`

### 7. Case merge logic can merge weakly related events
Root cause:

- `_find_matching_case()` allows merge on shared assets, shared indicators, source location overlap, or snippet similarity within 72 hours
- this can over-merge unrelated items or preserve noisy associations

Responsible module:

- `utils/local_store.py`

### 8. Asset typing is re-inferred after the fact
Root cause:

- `normalize_affected_assets()` categorizes values based on string shape
- it can preserve low-quality or ambiguous values instead of rejecting them

Responsible module:

- `utils/case_schema.py`

## Exact Files and Responsibilities

### Core orchestration
- `backend/main.py`: API routes, SSE endpoint, export routes, engine/runtime wiring

### Threat analysis and case creation
- `utils/nlp_engine.py`: regex matching, NLP analysis, external finding analysis, risk level, case construction

### External ingestion and initial relevance
- `utils/source_intel_service.py`: source clients, hit filtering, aggregation, extraction of emails/domains/IPs/assets/indicators

### Enrichment, impact, correlation, priority
- `utils/intel_enrichment.py`: enriched entities, multilingual/slang normalization, impact estimation, correlation, alert priority

### Confidence, noise heuristics, signatures
- `utils/signal_quality.py`: source trust, noise detection, generic mention penalty, confidence scoring, promotion gate, event signatures

### Canonical case schema and normalization
- `utils/case_schema.py`: `ExposureCase`, affected asset normalization, evidence normalization, severity derivation

### Persistence and case dedup/merge
- `utils/local_store.py`: monitoring state persistence, case merge logic, watchlists, audit events, snapshot export

### Database facade
- `utils/db.py`: Mongo + local store integration

### Scheduling and real-time updates
- `utils/monitoring_runtime.py`: scheduler loop, case SSE publishing, webhook dispatch

### Reporting/export
- `utils/reporting.py`: case filtering and ReportLab PDF generation

### Frontend report and monitoring consumers
- `frontend-react/src/pages/Dashboard.jsx`: PDF export UI
- `frontend-react/src/pages/Feed.jsx`: monitoring inbox, SSE listener, JSON snapshot export
- `frontend-react/src/services/api.js`: export API calls
- `frontend-react/src/components/CaseDetailPanel.jsx`: case detail rendering

## Audit Conclusions

### What is already present

- source ingestion exists for multiple providers
- case normalization already uses a Pydantic schema
- event signatures and basic merge logic already exist
- SSE updates are already wired end-to-end
- a working ReportLab PDF export endpoint already exists

### What is missing for organization-grade quality

- a strict validation layer for all extracted entities
- mandatory filtering before entities enter cases
- stronger source-content noise suppression
- correlation based on explicit watchlist evidence, not loose overlap
- evidence-based severity and confidence reasoning
- stronger deduplication based on canonicalized event similarity
- cleaner executive summaries backed by validated evidence only

## Recommended Focus Areas For Implementation

1. Insert a validator gate between extraction and storage paths.
2. Replace permissive entity and asset typing with validated typed entities.
3. Introduce a dedicated noise-filter and similarity-dedup stage before case creation.
4. Tighten correlation so case creation requires strong watchlist evidence.
5. Rebuild scoring around evidence strength, not keyword accumulation.
6. Preserve the current API surface where possible, using backward-compatible schema additions.
