# Relevance Filter Audit

## Scope

This audit traces where CITADEL currently:

- extracts entities and impacted assets
- decides whether a source hit is relevant to an organization
- correlates a finding to a watchlist or organization
- assigns confidence, severity, and priority
- builds cases and exposes them to reports/UI

The goal is to explain why semantically bad assets such as service identifiers can still survive into cases and reports even when the output format looks polished.

## Current Pipeline Map

1. Source intelligence is collected and pre-filtered in `utils/source_intel_service.py`.
2. Findings are normalized into external-intelligence results in `utils/nlp_engine.py`.
3. Correlation gating for case creation runs in `intelligence/correlation/__init__.py`.
4. Case severity/confidence/priority are assigned in `intelligence/scoring/__init__.py`.
5. Case payloads are built in `utils/nlp_engine.py` and normalized in `utils/case_schema.py`.
6. Cases are stored and merged in `utils/local_store.py`.
7. UI pages read persisted cases directly, while reports apply a separate report-side worthiness filter in `utils/reporting.py`.

## Where Impacted Assets Come From

### Primary source aggregation

The first impacted asset list is built in `utils/source_intel_service.py`:

- `ExternalIntelligenceService._aggregate_hits()`
- `ExternalIntelligenceService._extract_affected_assets()`
- `ExternalIntelligenceService._extract_matched_indicators()`

Current behavior:

- emails, usernames, domains, and IPs are extracted from raw source hits
- `affected_assets` is assembled before org-specific semantic relevance is fully proven
- `matched_indicators` can include generic extracted values even when they are not organization-owned

### Case payload construction

The case builder in `utils/nlp_engine.py` copies the external-intelligence assets directly:

- `ThreatIntelligenceEngine._build_exposure_case()`

Current behavior:

- `affected_assets = list(external.get("affected_assets", []))`
- `matched_indicators = list(external.get("matched_indicators", []))`

This means low-quality or only loosely relevant assets can enter the case payload before final normalization.

### Case normalization

Structured asset typing is applied in `utils/case_schema.py`:

- `flatten_affected_assets()`
- `normalize_affected_assets()`
- `normalize_case_record()`

Current behavior:

- domains are inferred from strings containing `.` but not `@` or `:`
- emails are inferred from strings containing `@`
- IPs are validated from flat assets and matched indicators
- everything else becomes `usernames`

This is useful for formatting, but it is not a true organization relevance decision. It mostly normalizes shape, not ownership.

## Why False Assets Are Being Accepted

### 1. Email validation is syntactic, not semantic

Current email validation lives in `intelligence/validators/__init__.py`:

- `validate_entity()`
- `_validate_email()`

Current risk:

- a string can pass as an email because it has a valid shape
- there is no dedicated rejection for service-style domains like `.service`, `.local`, `.internal`, or host/service identifiers such as `modprobe@fuse.service`
- there is no semantic check that the address belongs to the monitored organization

Result:

- system identifiers can survive as "valid" emails if they look syntactically correct

### 2. Domain extraction still admits semantically unrelated domains

Domain extraction and validation currently appear in:

- `utils/nlp_engine.py` via `REGEX_PATTERNS["domains"]`
- `utils/source_intel_service.py` via `DOMAIN_PATTERN`
- `intelligence/validators/__init__.py` via `_validate_domain()`

Current risk:

- syntactically valid public-looking domains can be retained even when they are unrelated to the organization
- file-like strings and unrelated dump context can still seed asset lists upstream
- report and normalization layers later organize these values instead of proving ownership

### 3. Relevance is enforced inconsistently across layers

There are three different relevance gates today:

- ingestion-time source-hit filtering in `utils/source_intel_service.py`
- case-creation correlation in `intelligence/correlation/__init__.py`
- report-side filtering in `utils/reporting.py`

These gates do not use the same rules or the same data model.

Result:

- a finding can pass source filtering but still be weak for organization ownership
- a case can be saved and shown in the UI even if the report later suppresses it
- PDF and UI can disagree about what is a credible case

### 4. Weak query matching can still be treated as strong enough

Current org/watchlist matching logic is in `intelligence/correlation/__init__.py`:

- `assess_correlation()`
- `_match_domain_entities()`
- `_match_tracked_entity()`
- `_build_tracked_entities()`

Current risk:

- for non-domain queries, `query_normalized in text` contributes to entity and keyword match weights
- `_match_tracked_entity()` accepts plain text substring presence
- `strong_watchlist_match` can become true from a direct query mention in text, not just verified org assets

Result:

- keyword-only or substring-only evidence can be treated as meaningful organization linkage if combined with other generic signals

### 5. Asset typing is not the same as asset relevance

`utils/case_schema.py` correctly categorizes values into domains/emails/IPs/usernames/tokens/wallets, but it does not decide whether those assets actually belong to the monitored organization.

Result:

- technically valid but semantically unrelated values can look trustworthy once formatted into the report

## Where Severity and Confidence Are Assigned

### Source/finding-level confidence

Initial finding confidence is computed in:

- `utils/source_intel_service.py`
- `utils/signal_quality.py`

Relevant functions:

- `score_confidence()`
- `should_promote_finding()`

Current behavior:

- this stage checks whether a raw source finding should be promoted
- it is useful as a noise filter, but it is not a true organization-relevance engine

### Case-level correlation score

Case-creation gating is assigned in:

- `intelligence/correlation/__init__.py`
- `assess_correlation()`

Current behavior:

- combines entity match weight, keyword weight, source trust, and evidence clarity
- requires validated entities, but not all validated entities are org-owned
- currently treats direct query mention in text as meaningful support

### Case-level severity/confidence/priority

Final case scoring is assigned in:

- `intelligence/scoring/__init__.py`
- `score_case()`

Current behavior:

- severity is increased for credentials, tokens, database indicators, verified asset count, source trust, and correlation score
- confidence is computed from correlation score, validated entity count, source trust, and exposure type hints
- `verified_asset_count` is currently based on `matched_watchlist_entities`, which can still include weak text/query matches

Current risk:

- if correlation is inflated by weak query mentions or loosely relevant entities, severity/confidence can also inflate
- this is why keyword-only evidence can still look too strong

## What Rule Currently Maps a Case to an Organization

### Ingestion-time source relevance

The first org mapping rule is in:

- `utils/source_intel_service.py`
- `ExternalIntelligenceService._is_relevant_hit()`

Current behavior:

- domain queries: accepts exact domain match or email-domain match, plus threat/sensitive signal checks
- org-name queries: accepts plain org name presence in the source text, plus threat/sensitive signal checks

Current risk:

- org-name queries rely on plain string presence in source text
- this is not enough to prove the extracted assets belong to the organization

### External-intelligence result organization field

The organization label is set in:

- `utils/source_intel_service.py` during aggregated finding creation
- `utils/nlp_engine.py` in `_build_external_finding_result()`
- `utils/nlp_engine.py` in `_build_exposure_case()`

Current behavior:

- the case organization is effectively taken from `external.get("organization")` or the original query

Current risk:

- once a weakly matched finding is accepted upstream, the case is labeled with the query organization even if the evidence mostly contains unrelated assets

## Where Weak Cases Still Reach UI or Reports

### UI / case list

Persisted cases are listed from storage and are not filtered by a dedicated suppression flag.

Relevant area:

- `utils/local_store.py`
- case listing and merge flow

Current risk:

- once a case is saved, the UI can still surface it even if it is weak
- there is no first-class `suppressed_noise` or `org_relevance_failed` state in the current case schema

### Reports

Report filtering is currently handled in:

- `utils/reporting.py`
- `filter_cases()`
- `_is_report_worthy_case()`

Current behavior:

- filters by org/date/severity/category
- also applies a report-only noise filter
- requires non-empty assets from domains/emails/IPs/tokens/wallets

Current risk:

- report filtering is separate from case creation filtering
- weak cases may still exist in storage/UI even if excluded from PDF
- report logic can hide junk, but it does not fix the upstream relevance problem

## Root Cause Summary

The false-positive asset problem comes from four combined issues:

1. entity validators mostly check syntax and basic plausibility, not organizational ownership
2. source-hit relevance and case correlation still allow weak query or substring matches
3. case building copies upstream affected assets before a dedicated org-relevance pass exists
4. reporting and UI use different suppression/filtering behavior, which hides some noise but does not prevent it from being stored

## Required Design Direction

To fix this without breaking the current pipeline, CITADEL needs a dedicated organization relevance layer that runs after extraction but before case scoring/reporting.

That layer should:

- build an organization profile from watchlist/config/query context
- score each asset for org ownership/relevance
- reject semantic fake emails and service identifiers
- downgrade keyword-only matches unless backed by verified org assets
- mark weak/no-asset findings as suppressed noise
- expose explainable reasons for every keep/reject decision

## Files Audited

- `utils/nlp_engine.py`
- `utils/source_intel_service.py`
- `utils/case_schema.py`
- `utils/local_store.py`
- `utils/reporting.py`
- `intelligence/correlation/__init__.py`
- `intelligence/scoring/__init__.py`
- `intelligence/validators/__init__.py`
- `utils/signal_quality.py`
