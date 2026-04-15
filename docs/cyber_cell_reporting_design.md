# Cyber Cell Reporting Design

## Goal

Add an enterprise-grade, additive feature that lets an organization preview and send a verified CITADEL exposure report to Cyber Crime Cell authorities by email, with full auditability and strict safety controls.

This feature must:

- preserve existing dashboards, SSE, intelligence pipeline, and API contracts
- keep existing JSON export and PDF export intact
- add new routes only
- require preview before send
- reject unsafe or low-confidence submissions
- log every preview and send action

## Existing Integration Points

### Reporting

- `utils/reporting.py`
  - `filter_cases()`
  - `generate_pdf_report()`
  - existing org/date/severity/category filtering
- `backend/main.py`
  - `GET /export/report/pdf`
  - `GET /cases/export`

### Case storage and schema

- `utils/case_schema.py`
  - canonical case structure via `ExposureCase`
- `utils/local_store.py`
  - persistent JSON storage for `cases`, `watchlists`, `audit_events`
- `utils/db.py`
  - delegates case and audit storage to `LocalMonitoringStore`

### Case retrieval and updates

- `backend/main.py`
  - `GET /cases`
  - `GET /cases/{case_id}`
  - `PATCH /cases/{case_id}`

### SSE and operational events

- `utils/monitoring_runtime.py`
  - `MonitoringEventBus`
  - `MonitoringScheduler`
- `backend/main.py`
  - `GET /events/stream`
  - publishes `case_updated` and `watchlist_error`

### Audit logging

- `utils/local_store.py`
  - `record_audit_event()`
  - `list_audit_events()`
- `backend/main.py`
  - `GET /audit-events`

### Frontend entry points

- `frontend-react/src/pages/Dashboard.jsx`
  - current executive export panel and org/date/severity/category filters
- `frontend-react/src/pages/Feed.jsx`
  - case inbox, selected case state, toast handling, SSE refresh
- `frontend-react/src/components/CaseDetailPanel.jsx`
  - case workflow panel and evidence display
- `frontend-react/src/services/api.js`
  - existing axios API helper pattern

## Auth and Org Access Control Reality

There is currently no backend authentication or tenant-aware org authorization layer in `backend/main.py`.

Because of that, this feature will enforce safe org scoping in a backward-compatible way by:

1. requiring all selected/report-filtered cases to belong to exactly one organization
2. rejecting mixed-org submissions
3. deriving the reporting organization from stored cases, not from arbitrary user text
4. storing `user_id` in audit logs using a safe fallback strategy:
   - request header `X-User-Id` if provided
   - else contact email
   - else `anonymous`

This is not a replacement for auth, but it prevents accidental cross-org report submission in the current codebase.

## New Module Plan

Create:

- `services/cyber_cell_reporting/__init__.py`
- `services/cyber_cell_reporting/complaint_formatter.py`
- `services/cyber_cell_reporting/eligibility_validator.py`
- `services/cyber_cell_reporting/email_sender.py`
- `services/cyber_cell_reporting/audit_logger.py`
- `services/cyber_cell_reporting/preview_store.py`

Supporting updates:

- `utils/config.py`
  - SMTP config
  - reporting enable flag
  - daily rate limit
  - preview TTL
- `backend/main.py`
  - add new preview/send endpoints only
- `utils/local_store.py`
  - add helper methods for cyber-cell daily rate checks if needed
- `frontend-react/src/services/api.js`
  - add preview/send client helpers
- `frontend-react/src/components/CyberCellReportModal.jsx`
  - new modal for preview-confirm-send
- `frontend-react/src/pages/Dashboard.jsx`
  - add report button near executive PDF export
- `frontend-react/src/pages/Feed.jsx`
  - hold modal state for selected case reporting
- `frontend-react/src/components/CaseDetailPanel.jsx`
  - add report trigger button

## New Backend Responsibilities

### 1. `complaint_formatter.py`

Responsibilities:

- generate complaint subject
- generate complaint body using the required Cyber Cell template
- generate plain text attachment content for complaint summary
- expose structured preview metadata for frontend rendering

Inputs:

- organization summary derived from eligible cases
- contact person details
- optional authority location
- optional organization details overrides

Outputs:

- `subject`
- `complaint_body_text`
- optional `complaint_body_html`
- attachment-ready complaint summary text

### 2. `eligibility_validator.py`

Responsibilities:

- validate case-level and submission-level eligibility
- reject mixed-org case selections
- reject low-confidence / low-severity / unverified cases
- require evidence and at least one verified domain or email

Required case checks:

- `verified_org_match == True`
- `confidence_score >= 80`
- `severity in {"High", "Critical"}`
- `len(evidence) > 0`
- at least one verified organization-owned domain or email in `affected_assets`

Return shape:

- `is_eligible`
- `rejection_reasons`
- `eligible_case_ids`
- `rejected_case_ids`
  - each with `case_id` and reasons
- `organization`
- `eligible_cases`
- `report_summary`

### 3. `email_sender.py`

Responsibilities:

- validate reporting is enabled
- validate recipient and cc email formats
- send message using TLS SMTP
- support mock mode for tests

Env config:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM_EMAIL`
- `SMTP_REPLY_TO`
- `SMTP_DEFAULT_CC`
- `REPORTING_ENABLED`
- `REPORTING_MOCK_MODE`

Safety:

- hard fail if `REPORTING_ENABLED` is false
- hard fail on empty recipient list
- dedupe recipients/cc
- reject invalid email format

### 4. `audit_logger.py`

Responsibilities:

- store preview and send actions as audit events
- compute hashes for complaint text and PDF bytes
- centralize audit payload schema

Audit event types:

- `cyber_cell_report_preview`
- `cyber_cell_report_sent`
- `cyber_cell_report_failed`
- `cyber_cell_report_rate_limited`

Stored fields:

- `org_id`
- `user_id`
- `recipients`
- `cc`
- `case_ids`
- `generated_timestamp`
- `send_timestamp`
- `status`
- `error_message`
- `pdf_hash`
- `complaint_hash`
- `preview_id`

### 5. `preview_store.py`

Responsibilities:

- enforce preview-before-send workflow
- store short-lived preview sessions server-side
- bind send requests to a previously generated preview

Reason:

- confirmation checkbox alone is not strong enough for misuse prevention
- preview token lets the backend confirm the user reviewed the exact payload before send

Storage approach:

- in-memory process-local preview cache with timestamp and TTL
- additive only
- suitable for current single-process app architecture

Preview record fields:

- `preview_id`
- request fingerprint
- org_id
- case_ids
- recipients
- cc
- include_json_bundle
- generated_at
- expires_at

## New Additive API Endpoints

### 1. Preview

Route:

- `POST /api/v1/report/cybercell/preview`

Request body:

```json
{
  "case_ids": ["case_1", "case_2"],
  "date_range": {
    "start_date": "2026-04-15T00:00:00+00:00",
    "end_date": "2026-04-16T00:00:00+00:00"
  },
  "severity": ["High", "Critical"],
  "recipients": ["cybercell@example.gov.in"],
  "cc": ["soc@example.org"],
  "authority_location": "Mumbai, India",
  "contact_person_details": {
    "name": "Amit Sharma",
    "designation": "CISO",
    "email": "amit.sharma@example.org",
    "phone": "+91-9000000000"
  },
  "organization_details": {
    "industry": "Banking",
    "registered_address": "Mumbai, India"
  },
  "include_json_bundle": true
}
```

Rules:

- `case_ids` or filter criteria must resolve to at least one case
- recipients required
- preview does not send email
- preview generates a short-lived `preview_id`

Response:

```json
{
  "preview_id": "preview_abc123",
  "subject": "URGENT: Reporting Suspected Data Exposure / Credential Leak – ACME – Generated by CITADEL",
  "complaint_body": "plain text body...",
  "attachments_preview": [
    {"name": "citadel_exposure_report.pdf", "size_bytes": 18293},
    {"name": "citadel_complaint_summary.txt", "size_bytes": 5410},
    {"name": "citadel_evidence_bundle.json", "size_bytes": 3200}
  ],
  "selected_cases": [
    {
      "case_id": "case_1",
      "title": "Acme exposure detected via Dehashed",
      "verification_status": "YES",
      "severity": "High",
      "confidence_score": 92
    }
  ],
  "eligible_cases_count": 1,
  "rejected_cases": [],
  "report_summary": {
    "org_id": "acme.com",
    "severity": "High",
    "confidence_score": 92,
    "first_seen": "2026-04-15T00:00:00+00:00",
    "last_seen": "2026-04-15T00:00:00+00:00",
    "estimated_identifiers": 25
  }
}
```

### 2. Send

Route:

- `POST /api/v1/report/cybercell/send`

Request body:

```json
{
  "preview_id": "preview_abc123",
  "case_ids": ["case_1", "case_2"],
  "date_range": {
    "start_date": "2026-04-15T00:00:00+00:00",
    "end_date": "2026-04-16T00:00:00+00:00"
  },
  "severity": ["High", "Critical"],
  "recipients": ["cybercell@example.gov.in"],
  "cc": ["soc@example.org"],
  "authority_location": "Mumbai, India",
  "contact_person_details": {
    "name": "Amit Sharma",
    "designation": "CISO",
    "email": "amit.sharma@example.org",
    "phone": "+91-9000000000"
  },
  "organization_details": {
    "industry": "Banking",
    "registered_address": "Mumbai, India"
  },
  "include_json_bundle": true,
  "confirmation_flag": true
}
```

Rules:

- `REPORTING_ENABLED` must be true
- `confirmation_flag` must be true
- `preview_id` must exist, match request fingerprint, and be unexpired
- org must pass daily rate limit
- cases must pass eligibility validator again on send

Response:

```json
{
  "status": "sent",
  "audit_id": "audit_123",
  "sent_to": ["cybercell@example.gov.in"],
  "attachment_names": [
    "citadel_exposure_report.pdf",
    "citadel_complaint_summary.txt",
    "citadel_evidence_bundle.json"
  ],
  "timestamp": "2026-04-15T12:00:00+00:00"
}
```

## Security and Abuse Prevention Plan

### Eligibility gate

Only cases passing all rules can be reported:

- verified org match
- confidence >= 80
- severity high/critical
- evidence exists
- verified org domain or email exists

### Same-org enforcement

All resolved cases for one request must share the same `org_id`.

### Preview token requirement

Send must require a fresh preview token generated by the preview endpoint.

### Rate limiting

Limit:

- max 3 send actions per calendar day per `org_id`

Implementation:

- count successful `cyber_cell_report_sent` audit events in `LocalMonitoringStore`
- enforce in `eligibility_validator` or `audit_logger` helper before sending

### Recipient validation

- validate all recipient and cc emails with strict syntax
- dedupe recipients and cc
- reject empty recipients list

### Content validation

- mask evidence snippet to safe preview length
- cap number of cases in one report send
  - recommended maximum: 50
- cap recipient count
  - recommended maximum: 10 total across to/cc

### Feature flag

- `REPORTING_ENABLED=false` disables send endpoint
- preview may still be allowed or may also be blocked depending on implementation preference
  - preferred: preview allowed only when reporting is enabled, so UI behavior is consistent

## Attachment Generation Plan

Required attachments:

1. `citadel_exposure_report.pdf`
   - reuse `utils.reporting.generate_pdf_report()`
2. `citadel_complaint_summary.txt`
   - generated by `complaint_formatter.py`
3. optional `citadel_evidence_bundle.json`
   - normalized case/evidence bundle for selected eligible cases

Implementation:

- write artifacts to temp directory under a dedicated subfolder such as `citadel-cybercell`
- keep generation helper separate from email sending
- return attachment metadata in preview

## Frontend Plan

### New component

- `frontend-react/src/components/CyberCellReportModal.jsx`

Responsibilities:

- recipients input
- cc input
- authority location input/dropdown
- contact person form
- optional organization details form
- preview pane
- attachment preview
- confirmation checkbox
- send button

### Dashboard integration

- add `Report to Cyber Cell` button inside the existing executive export section
- reuse existing org/date/severity/category filter state

### Case detail integration

- add `Report to Cyber Cell` button in `CaseDetailPanel.jsx`
- open modal prefilled with current case id and org context

### Frontend flow

1. user opens modal
2. fills recipients/contact fields
3. clicks preview
4. frontend calls preview endpoint
5. modal shows complaint body, attachments, selected case verification, rejections
6. user checks confirmation box
7. frontend calls send endpoint with `preview_id`
8. success toast shows audit id and timestamp

### API client additions

Add to `frontend-react/src/services/api.js`:

- `previewCyberCellReport(payload)`
- `sendCyberCellReport(payload)`

## SSE Stability Plan

This feature must not alter existing SSE contracts.

Approach:

- do not modify existing `case_updated` payloads
- optionally publish a new additive event type after successful send:
  - `cyber_cell_report_sent`
- frontend does not need SSE support for this feature to work, but it can be added later without breaking current listeners

## Test Plan

### Backend unit tests

- validator rejects unverified cases
- validator rejects low-confidence cases
- validator rejects cases without evidence
- validator rejects cases without org domain/email
- preview endpoint returns expected complaint formatting
- send endpoint creates audit record
- send endpoint enforces confirmation flag
- send endpoint enforces preview token
- send endpoint enforces daily rate limit
- email validation rejects malformed recipient
- SMTP sender supports mock mode

### Frontend tests

If frontend test harness is not present, keep logic isolated and verify by build plus manual runtime checks.

Minimum validation:

- modal opens from dashboard
- modal opens from case detail
- preview request populates body and attachments
- send disabled until confirmation is checked

## Implementation Sequence

### Phase 1

Write this design doc.

### Phase 2

Implement backend preview route and request/response schema.

### Phase 3

Implement backend send route.

### Phase 4

Implement complaint formatting and attachment generation.

### Phase 5

Implement rate limit and audit logging.

### Phase 6

Implement frontend modal, buttons, and preview-confirm-send flow.

### Phase 7

Add tests, verify stability, stop any running terminals, and rerun the app cleanly.
