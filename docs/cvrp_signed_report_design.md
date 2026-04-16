# CVRP Signed Report Design

## Goal

Add a CITADEL Verified Reporting Protocol layer that makes exported and cyber cell reports independently verifiable without changing the current SSE monitoring, dashboards, report export routes, cyber cell workflow, or existing report data contracts.

The implementation must:

- preserve current PDF export and cyber cell flows
- add new routes only for verification
- keep unsigned mode functional when signing is disabled
- avoid exposing sensitive evidence through public verification
- work with the existing file-backed monitoring store when MongoDB is unavailable

## Current Integration Points

### PDF generation

- `utils/reporting.py`
  - `generate_pdf_report()`
  - `_build_pdf()`
  - `_build_report_story()`
- `backend/main.py`
  - `GET /export/report/pdf`

### Cyber cell reporting

- `services/cyber_cell_reporting/__init__.py`
  - `_generate_attachments()`
  - `build_preview()`
  - `send_report()`
- `services/cyber_cell_reporting/audit_logger.py`
  - stores `pdf_hash` and `complaint_hash`

### Persistence

- `utils/local_store.py`
  - durable JSON-backed store for `cases`, `watchlists`, `audit_events`, and scheduler state
- `utils/db.py`
  - DB facade that delegates monitoring persistence to `LocalMonitoringStore`

### Frontend

- `frontend-react/src/App.jsx`
  - flat route registration
- `frontend-react/src/services/api.js`
  - centralized API client
- `frontend-react/src/components/CyberCellReportModal.jsx`
  - cyber cell send UX

## CVRP Design Principles

1. Generate the report PDF with the current reporting engine.
2. Compute the final PDF hash from the exact bytes that will be distributed.
3. Sign a canonical verification payload derived from the report metadata and hashes.
4. Persist a `SignedReportRecord` in durable storage.
5. Add a human-readable verification section and QR code to the PDF.
6. Expose a public verification surface that returns metadata only.
7. Never expose raw evidence or full case details publicly.

## Signed Report Data Model

Create a new record type: `SignedReportRecord`

Suggested storage fields:

- `report_id`
- `org_id`
- `created_by_user_id`
- `created_at`
- `report_type`
- `case_ids`
- `pdf_file_path`
- `pdf_sha256`
- `evidence_sha256`
- `signature_base64`
- `signing_algorithm`
- `public_verification_url`
- `status`
- `expires_at`
- `audit_reference_id`
- `public_key_fingerprint`
- `verification_summary`
  - `case_count`
  - `severity_distribution`
  - `category_distribution`
  - `evidence_summary`
- `metadata`
  - optional room for non-breaking future additions

Storage location:

- add a new `signed_reports` collection inside the existing JSON state managed by `LocalMonitoringStore`
- expose persistence through additive methods in `utils/db.py`
- keep the structure JSON-serializable only

## Canonical Verification Payload

The detached signature should cover a canonical JSON string containing:

- `report_id`
- `org_id`
- `created_at`
- `report_type`
- `case_ids`
- `pdf_sha256`
- `evidence_sha256`
- `public_verification_url`
- `expires_at`

Rules:

- sort keys before serialization
- do not include mutable operational fields such as `status`
- sign UTF-8 bytes of the canonical JSON string

This keeps verification stable without needing full PDF-native signing support.

## Cryptography Approach

### Preferred algorithm

- Ed25519 when supported by the available crypto library

### Fallback

- RSA 2048 with SHA-256

### Environment variables

- `REPORT_SIGNING_ENABLED`
- `REPORT_PRIVATE_KEY_PATH`
- `REPORT_PUBLIC_KEY_PATH`
- `REPORT_SIGNING_DEV_AUTO_GENERATE`
- `REPORT_SIGNED_REPORT_EXPIRY_DAYS`
- `REPORT_VERIFICATION_BASE_URL`
- `REPORT_VERIFICATION_CACHE_TTL_SECONDS`

### Key management behavior

- if signing is disabled, reports still generate normally
- if signing is enabled in development and keys are missing, generate keys automatically
- if signing is enabled in production and keys are missing, do not crash the system; return an unsigned result and log a warning in the report workflow

## Report Generation Integration

`utils/reporting.py` will remain the report renderer and accept optional authenticity metadata.

New optional report context:

- `verification_details`
  - `report_id`
  - `generated_at`
  - `pdf_sha256_short`
  - `signature_short`
  - `verification_url`
  - `verification_qr_image`
  - `signing_algorithm`
  - `public_key_fingerprint_short`
  - `signed`

Rendering behavior:

- keep current cover page and sections intact
- append a new section near the appendix:
  - `Report Authenticity Verification`
- show shortened values only
- embed a QR code that points to the public verification URL
- when signing is disabled, omit the signature block and show nothing new for normal executive exports
- when cyber cell flow is unsigned, show a small warning block in email/report metadata, not a fake signed section

## Verification API

All verification APIs must be additive and public-safe.

### GET `/api/v1/verify/report/{report_id}`

Purpose:

- return public metadata needed for a verification portal

Response shape:

- `report_id`
- `org_name`
- `generated_at`
- `case_count`
- `verification_status`
- `pdf_sha256`
- `signature_base64_masked`
- `public_key_fingerprint`
- `evidence_summary`
- `severity_distribution`
- `expires_at`
- `public_verification_url`

Rules:

- `verification_status` can be `VALID`, `INVALID`, or `EXPIRED`
- do not return raw evidence snippets, emails, usernames, domains, or case bodies

### POST `/api/v1/verify/report/{report_id}/upload`

Purpose:

- allow a cyber cell operator to upload a PDF and confirm it matches the stored report

Flow:

1. load the stored `SignedReportRecord`
2. hash uploaded bytes
3. compare hash with stored `pdf_sha256`
4. verify detached signature using the stored canonical payload and public key
5. return `VALID`, `INVALID`, or `EXPIRED`

Response shape:

- `report_id`
- `verification_status`
- `uploaded_pdf_sha256`
- `stored_pdf_sha256`
- `hash_match`
- `signature_valid`
- `expires_at`
- `message`

## Public Verification Page

Add a new React route:

- `/verify/:reportId`

Page requirements:

- no login required
- simple official presentation
- shows only verification metadata
- supports PDF upload verification

Visible data:

- CVRP title
- verification badge
- organization label if allowed
- generated timestamp
- case count
- severity distribution
- shortened hash
- upload result

Forbidden data:

- raw evidence text
- leaked emails
- detailed case descriptions
- internal remediation notes

## Cyber Cell Reporting Integration

When a cyber cell report is sent:

1. generate the PDF using the existing path
2. compute final hashes
3. create and store a `SignedReportRecord`
4. include QR and verification URL in the distributed PDF
5. include verification URL in the email body
6. write `report_id` into the send audit event

Preview behavior:

- preview may generate the same signed metadata path so the operator can review attachments before send
- send must preserve the preview-before-send workflow and rate limits already in place

Audit additions:

- `report_id`
- `verification_url`
- `signing_algorithm`
- `signature_status`
- `public_key_fingerprint`

These are additive fields only.

## Expiry, Cleanup, and Cache

### Expiry

- default report verification validity window: 30 days
- expired records remain queryable but return `EXPIRED`

### Cleanup

- extend the monitoring scheduler loop with a lightweight signed-report maintenance step
- mark overdue records as expired
- optionally prune orphaned file references if a file no longer exists

### Cache

- keep a small in-memory cache for public verification lookups keyed by `report_id`
- TTL should be configurable and safe to bypass

## Security Model

Public verification must expose only derived metadata. The trust model is:

- report bytes are hashed
- stored verification payload is signed
- public endpoint returns enough metadata for verification
- upload endpoint confirms the caller has the exact PDF bytes that were issued

Non-goals for phase 1:

- full embedded PDF certificate signing
- timestamp authority integration
- revocation service
- authentication overhaul

## Endpoint Summary

- existing routes unchanged:
  - `GET /export/report/pdf`
  - `POST /api/v1/report/cybercell/preview`
  - `POST /api/v1/report/cybercell/send`
- new routes:
  - `GET /api/v1/verify/report/{report_id}`
  - `POST /api/v1/verify/report/{report_id}/upload`

## Compatibility Guardrails

- do not rename or remove any existing routes
- keep `generate_pdf_report()` backward compatible
- keep SSE event names and existing dashboard calls unchanged
- preserve current audit keys and add new fields only
- keep unsigned mode operational when signing is off or key loading fails
- ensure old reports still export even if no signed record exists

## Implementation Sequence

1. Add signing and verification utilities under `security/report_signing/`
2. Add `SignedReportRecord` persistence to the existing monitoring store and DB facade
3. Add orchestration service for report signing, record creation, and verification summaries
4. Extend PDF rendering with an optional CVRP section and QR code
5. Add public verification API routes
6. Add the React verify page and upload UX
7. Integrate cyber cell email and audit logging with `report_id`
8. Add expiry, cleanup, caching, and tests
