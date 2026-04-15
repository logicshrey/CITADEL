# Verification And Sensitive Detection Design

## Scope

This document captures the current CITADEL implementation relevant to verification badges and sensitive-data detection, plus the safest insertion points for adding the new functionality without breaking existing SSE, dashboards, reporting, or API contracts.

The implementation approach must remain:

- modular and additive
- backward compatible with stored cases
- safe for existing report export and case rendering
- performant enough for the real-time monitoring pipeline

## Current Repository Map

### Case schema and normalization

- `utils/case_schema.py`
  - Canonical case model: `ExposureCase`
  - Nested models: `EvidenceItem`, `SourceRecord`, `AffectedAssets`, `LeakOrigin`, `ConfidenceAssessment`
  - Normalization helpers:
    - `normalize_case_record()`
    - `normalize_case_list()`
    - `normalize_evidence_list()`
    - `normalize_source_records()`
    - `flatten_affected_assets()`

This file is the primary compatibility gate for stored and returned cases. New fields must be added here with safe defaults, otherwise they will be dropped during normalization because the model uses `extra="ignore"`.

### Case builder / finalization path

- `utils/nlp_engine.py`
  - `ThreatIntelligenceEngine._build_exposure_case()`
  - This is the main case finalization point where the final persisted case payload is assembled.
  - Existing fields already set here include:
    - `severity`
    - `confidence_score`
    - `confidence_assessment`
    - `why_this_was_flagged`
    - `verification_status`
    - `verified_org_match`
    - `relevance_score`
    - `relevance_reasons`
    - `suppressed_noise`

This is the best insertion point for:

- running sensitive-data detection on evidence snippets
- computing verification badge output
- storing the new optional verification and sensitive-data fields on each case

### Evidence extraction and storage

- `utils/nlp_engine.py`
  - Evidence is created inside `_build_exposure_case()`
  - Evidence items already contain:
    - `cleaned_snippet`
    - `raw_snippet`
    - `raw_excerpt`
    - `summary`
    - `matched_entities`
    - `source_locations`
    - `data_breakdown`

- `utils/case_schema.py`
  - `normalize_evidence_list()` standardizes evidence into `EvidenceItem`

- `utils/local_store.py`
  - `_merge_evidence()` deduplicates evidence on case updates
  - `_case_snippet()` extracts the main snippet for matching / similarity

Current evidence storage is sufficient for masked sensitive-data detection, because the cleaned evidence snippet already exists at the case level and is the safest input for regex-based analysis.

### Relevance and correlation

- `intelligence/relevance_engine/__init__.py`
  - Computes:
    - `relevance_score`
    - `verification_status`
    - `verified_org_match`
    - `relevance_reasons`
    - `suppressed_noise`
    - `suppression_reasons`

- `intelligence/correlation/__init__.py`
  - `assess_correlation()`
  - Decides whether a result should become a case and provides correlation reasoning

- `utils/intel_enrichment.py`
  - `correlate_alerts()` handles related alert/campaign grouping

The new verification badge system should not replace org relevance. It should consume existing relevance outputs plus evidence quality and sensitive-data findings.

### Scoring engine

- `intelligence/scoring/__init__.py`
  - `score_case()`
  - Computes:
    - `severity_score`
    - `severity`
    - `confidence_score`
    - `priority`
    - `risk_level`
    - severity/confidence reasoning

- `utils/signal_quality.py`
  - Signal-level confidence and source trust helpers

The new sensitive-data detector should feed into case severity/risk scoring as an additive input, but confidence must remain evidence-based and must not be forced to 100.

### Persistence and backward compatibility

- `utils/local_store.py`
  - `save_case()`
  - `update_case()`
  - `_find_matching_case()`
  - `get_case_stats()`

- `utils/db.py`
  - database facade used by API and reporting layers

Important caveat:

- `save_case()` merges a defined set of fields during updates, so new fields must be preserved during merge and normalization.

### Report generator

- `utils/reporting.py`
  - Public API:
    - `generate_pdf_report()`
    - `filter_cases()`
  - Main section builders:
    - `_build_report_story()`
    - `_build_executive_summary()`
    - `_build_overview_tables()`
    - `_build_detailed_cases()`
    - `_build_appendix()`

- `backend/main.py`
  - `/export/report/pdf`

- `services/cyber_cell_reporting/__init__.py`
  - attaches the generated PDF to the complaint email workflow

This means PDF changes must remain additive and should not change `filter_cases()` behavior unless strictly necessary.

### Frontend case rendering

- `frontend-react/src/pages/Feed.jsx`
  - case list / case cards rendered inline

- `frontend-react/src/components/CaseDetailPanel.jsx`
  - detailed case view

- `frontend-react/src/components/RiskBadge.jsx`
  - risk styling only, not verification-specific

- `frontend-react/src/pages/Dashboard.jsx`
  - monitoring stats / chart display

The UI already handles optional fields well via guarded rendering, so verification and sensitive-data chips should be added as optional sections rather than replacing current elements.

## Existing Case Structure

Current normalized case structure comes from `ExposureCase` in `utils/case_schema.py`.

Key fields already present and relevant:

- identity / timestamps
  - `case_id`
  - `id`
  - `created_at`
  - `updated_at`
  - `first_seen`
  - `last_seen`

- classification and scoring
  - `category`
  - `severity`
  - `risk_level`
  - `risk_score`
  - `priority`
  - `priority_score`
  - `confidence_score`
  - `confidence_assessment`

- organization relevance / verification-adjacent
  - `verification_status`
  - `verified_org_match`
  - `relevance_score`
  - `relevance_reasons`
  - `suppressed_noise`
  - `suppression_reasons`

- evidence and assets
  - `affected_assets`
  - `evidence`
  - `sources`
  - `matched_indicators`
  - `exposed_data_types`

- analyst and workflow fields
  - `triage_status`
  - `case_status`
  - `owner`
  - `business_unit`
  - `recommended_actions`

## Where Confidence And Severity Are Computed

### Confidence

- Signal confidence:
  - `utils/signal_quality.py`
  - `score_confidence()`

- Case confidence:
  - `intelligence/scoring/__init__.py`
  - `score_case()`

- Confidence is surfaced into final cases through:
  - `utils/nlp_engine.py`
  - `_build_exposure_case()`

### Severity

- Primary severity / risk computation:
  - `intelligence/scoring/__init__.py`
  - `score_case()`

- Severity explanation added during case build:
  - `utils/nlp_engine.py`

### Implication for new logic

Sensitive-data detection should:

- increase risk/severity inputs modestly and additively
- not override source trust or confidence evidence logic
- preserve current severity/confidence flow for cases without sensitive findings

## Where Evidence Snippets Are Stored

Evidence snippets are stored per case in `evidence[]` items and currently include:

- `cleaned_snippet`
- `raw_snippet`
- `raw_excerpt`
- `summary`

The most reliable input for detection is:

1. `cleaned_snippet`
2. fallback `raw_snippet`
3. fallback `raw_excerpt`
4. fallback `summary`

This keeps detection aligned with the human-readable evidence already shown in UI and reports while avoiding unnecessary dependence on raw provider payloads.

## Best Insertion Points For New Modules

### Sensitive detector

Create:

- `intelligence/sensitive_detector/patterns.py`
- `intelligence/sensitive_detector/luhn.py`
- `intelligence/sensitive_detector/models.py`
- `intelligence/sensitive_detector/detector.py`

Best integration point:

- `utils/nlp_engine.py` inside `_build_exposure_case()`

Reason:

- evidence snippets are already assembled there
- the result can be stored directly on the case payload
- no API contract changes are required at the request layer

### Verification engine

Create:

- `intelligence/verification_engine/rules.py`
- `intelligence/verification_engine/models.py`
- `intelligence/verification_engine/verifier.py`

Best integration point:

- `utils/nlp_engine.py` inside `_build_exposure_case()`, after:
  - relevance assessment is available
  - evidence list is available
  - case scoring has already been computed
  - sensitive-data detection output is available

Reason:

- verification requires final case context, not raw hit context only

### Case schema additions

Primary file:

- `utils/case_schema.py`

Required follow-up:

- `utils/local_store.py` merge/update logic
- potentially `utils/db.py` stats if new breakdowns are added

### PDF reporting additions

Primary file:

- `utils/reporting.py`

Best insertion points:

- executive summary / overview:
  - add verification breakdown counts
  - add sensitive-data type summary

- detailed case rendering:
  - add a verification section
  - add a sensitive-data section

### Frontend additions

Primary files:

- `frontend-react/src/pages/Feed.jsx`
- `frontend-react/src/components/CaseDetailPanel.jsx`
- `frontend-react/src/pages/Dashboard.jsx` if new aggregate charts/cards are desired

Best UI pattern:

- render optional chips in existing badge rows
- render optional bordered sections for detailed reasons and masked findings
- do not replace current risk/confidence badges

## Proposed Schema Additions

All additions must be optional and default safely.

### New case fields

- `verification_badge: str | None = None`
  - values: `VERIFIED`, `LIKELY`, `WEAK_SIGNAL`
  - separate from the existing `verification_status` to avoid breaking current org-match semantics

- `verification_score: int = 0`

- `verification_reasons: list[str] = []`

- `sensitive_data_types: list[str] = []`

- `sensitive_findings: list[dict] = []`
  - masked only
  - never store full raw secret values

- `sensitive_risk_score: int = 0`

### New nested model proposal

`SensitiveFinding`

- `finding_type`
- `masked_value`
- `source_evidence_id`
- `source_index`
- `risk_weight`

### Compatibility note

The existing field `verification_status` is already used for organization-match validation and cyber-cell reporting eligibility. To avoid breaking existing behavior, the new badge should either:

1. be stored in a new field `verification_badge`, or
2. keep `verification_status` backward compatible and use a second field for the previous semantics

Recommended approach:

- keep existing `verification_status` unchanged for org-verification compatibility
- add `verification_badge` for the new UI/reporting classification

## Proposed Backend Flow

1. Build evidence list in `_build_exposure_case()`
2. Extract normalized snippet text from each evidence item
3. Run `detect_sensitive_data()` per snippet
4. Cache by snippet hash to avoid repeated regex work
5. Aggregate:
   - `sensitive_data_types`
   - masked findings
   - `sensitive_risk_score`
6. Compute verification result using:
   - `relevance_score`
   - `confidence_score`
   - `severity` / `severity_score`
   - evidence count
   - source trust
   - sensitive-data findings
7. Store the new optional fields on the case payload
8. Normalize and persist via existing store flow

## Performance And Safety Considerations

- Compile regex patterns once in `patterns.py`
- Cache detection results by snippet hash
- Limit scan input length to evidence-sized text, not full raw provider payloads
- Never store raw matches for:
  - tokens
  - API keys
  - PAN
  - Aadhaar
  - credit cards
  - credentials
- Only masked previews may be stored or rendered
- Debug logging must be optional and disabled by default

## Testing Plan

### Sensitive detector tests

- detects PAN
- detects Aadhaar
- detects JWT
- detects AWS access key
- detects card numbers with valid Luhn
- rejects invalid card-like numbers
- never stores raw full values

### Verification engine tests

- `VERIFIED` when high relevance + evidence + strong sensitive proof
- `LIKELY` when moderate confidence/relevance with evidence
- `WEAK_SIGNAL` for weak keyword-only matches or missing evidence

### Integration tests

- case builder emits new fields with safe defaults
- old cases normalize correctly without the new fields
- PDF story renders verification / sensitive sections without raw secrets

## Recommended Implementation Order

1. Add the new models and optional schema fields
2. Build `intelligence/sensitive_detector`
3. Build `intelligence/verification_engine`
4. Integrate both into `_build_exposure_case()`
5. Thread fields through local-store merge/update logic
6. Update scoring additively
7. Update PDF output
8. Update frontend case list/detail rendering
9. Add tests
10. Validate SSE, report export, and dashboards remain intact
