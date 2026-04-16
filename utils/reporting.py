from __future__ import annotations

import io
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from utils.case_schema import flatten_affected_assets, normalize_case_list


REPORT_TITLE = "CITADEL Exposure Intelligence Report"
REPORT_NOISE_PATTERNS = (
    "apache server status",
    "apache status",
    "directory listing",
    "found 28 files trough .ds_store spidering",
    "server uptime",
    "self-serve purchase",
    "usage analytics",
    "economic index",
    "real interactions with the ai assistant",
)
REPORT_NOISE_ASSETS = {"db.php", "index.php", "readme.md", "robots.txt", "sitemap.xml"}


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def filter_cases(
    cases: list[dict[str, Any]],
    *,
    start_date: str | None = None,
    end_date: str | None = None,
    severity: list[str] | None = None,
    category: list[str] | None = None,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    normalized_cases = normalize_case_list(cases)
    severity_filter = {item.lower() for item in (severity or []) if str(item).strip()}
    category_filter = {item.lower() for item in (category or []) if str(item).strip()}
    start_bound = _parse_iso(start_date) if start_date else None
    end_bound = _parse_iso(end_date) if end_date else None
    org_filter = str(org_id or "").strip().lower()

    filtered: list[dict[str, Any]] = []
    for case in normalized_cases:
        if case.get("suppressed_noise"):
            continue
        if org_filter and str(case.get("org_id") or "").strip().lower() != org_filter:
            continue
        if severity_filter and str(case.get("severity") or "").strip().lower() not in severity_filter:
            continue
        if category_filter and str(case.get("category") or "").strip().lower() not in category_filter:
            continue
        case_time = _parse_iso(case.get("last_seen")) or _parse_iso(case.get("created_at"))
        if start_bound and case_time and case_time < start_bound:
            continue
        if end_bound and case_time and case_time > end_bound:
            continue
        if not _is_report_worthy_case(case):
            continue
        filtered.append(case)

    filtered.sort(key=lambda item: item.get("last_seen", ""), reverse=True)
    return filtered


def generate_pdf_report(
    cases: list[dict[str, Any]],
    *,
    start_date: str | None = None,
    end_date: str | None = None,
    severity: list[str] | None = None,
    category: list[str] | None = None,
    org_id: str | None = None,
    verification_details: dict[str, Any] | None = None,
) -> Path:
    filtered_cases = filter_cases(
        cases,
        start_date=start_date,
        end_date=end_date,
        severity=severity,
        category=category,
        org_id=org_id,
    )
    temp_dir = Path(tempfile.gettempdir()) / "citadel-reports"
    temp_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    file_path = temp_dir / f"citadel-exposure-report-{timestamp}.pdf"
    _build_pdf(
        file_path,
        filtered_cases,
        start_date=start_date,
        end_date=end_date,
        org_id=org_id,
        verification_details=verification_details,
    )
    return file_path


def _build_pdf(
    file_path: Path,
    cases: list[dict[str, Any]],
    *,
    start_date: str | None,
    end_date: str | None,
    org_id: str | None,
    verification_details: dict[str, Any] | None = None,
) -> None:
    elements = _build_report_story(
        cases=cases,
        start_date=start_date,
        end_date=end_date,
        org_id=org_id,
        verification_details=verification_details,
    )
    doc = SimpleDocTemplate(
        str(file_path),
        pagesize=A4,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.85 * inch,
        bottomMargin=0.7 * inch,
    )
    doc.build(elements, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)


def _build_report_story(
    *,
    cases: list[dict[str, Any]],
    start_date: str | None,
    end_date: str | None,
    org_id: str | None,
    verification_details: dict[str, Any] | None = None,
) -> list[Any]:
    doc = SimpleDocTemplate(
        "citadel-preview.pdf",
        pagesize=A4,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.85 * inch,
        bottomMargin=0.7 * inch,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CitadelTitle", fontSize=24, leading=28, alignment=TA_CENTER, textColor=colors.HexColor("#0F172A")))
    styles.add(ParagraphStyle(name="CitadelHeading", fontSize=16, leading=20, textColor=colors.HexColor("#0F172A"), spaceAfter=10))
    styles.add(ParagraphStyle(name="CitadelBody", fontSize=10, leading=14, textColor=colors.HexColor("#334155")))
    styles.add(ParagraphStyle(name="CitadelSmall", fontSize=8, leading=11, textColor=colors.HexColor("#64748B")))
    styles.add(ParagraphStyle(name="CitadelTableCell", fontSize=8.6, leading=11, textColor=colors.HexColor("#334155")))
    styles.add(ParagraphStyle(name="CitadelTableHeader", fontSize=8.8, leading=11, textColor=colors.white))

    elements: list[Any] = []
    summary = _summarize_cases(cases)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    report_org = _resolve_report_org_label(org_id=org_id, summary=summary)
    date_range = f"{start_date or 'Beginning'} to {end_date or 'Now'}"

    elements.extend(
        [
            Spacer(1, 1.2 * inch),
            Paragraph("CITADEL", styles["CitadelHeading"]),
            Paragraph(REPORT_TITLE, styles["CitadelTitle"]),
            Spacer(1, 0.3 * inch),
            Paragraph(f"<b>Organization:</b> {report_org}", styles["CitadelBody"]),
            Paragraph(f"<b>Date range:</b> {date_range}", styles["CitadelBody"]),
            Paragraph(f"<b>Generated:</b> {generated_at}", styles["CitadelBody"]),
            Spacer(1, 0.45 * inch),
            Paragraph("Executive-ready exposure intelligence briefing with consolidated evidence and remediation guidance.", styles["CitadelBody"]),
            PageBreak(),
        ]
    )

    elements.extend(_build_executive_summary(styles, summary, cases))
    elements.append(PageBreak())
    elements.extend(_build_overview_tables(styles, summary))
    elements.append(PageBreak())
    elements.extend(_build_case_summary_table(styles, cases))
    elements.append(PageBreak())
    elements.extend(_build_detailed_cases(styles, cases))
    elements.append(PageBreak())
    elements.extend(_build_recommended_actions_section(styles, cases))
    elements.append(PageBreak())
    elements.extend(_build_appendix(styles, cases))
    if verification_details:
        elements.append(PageBreak())
        elements.extend(_build_verification_section(styles, verification_details))

    return elements


def _summarize_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counter = Counter()
    confidence_counter = Counter()
    category_counter = Counter()
    verification_counter = Counter()
    sensitive_counter = Counter()
    source_counter = Counter()
    domain_counter = Counter()
    email_counter = Counter()
    orgs = Counter()

    for case in cases:
        severity_counter[case.get("severity", "Low")] += 1
        category_counter[case.get("category", "Unknown")] += 1
        verification_counter[case.get("verification_badge", "WEAK_SIGNAL")] += 1
        orgs[case.get("org_id") or case.get("organization") or "unknown-org"] += 1
        confidence = int(case.get("confidence_score", 0) or 0)
        if confidence >= 80:
            confidence_counter["80-100"] += 1
        elif confidence >= 60:
            confidence_counter["60-79"] += 1
        elif confidence >= 40:
            confidence_counter["40-59"] += 1
        else:
            confidence_counter["0-39"] += 1

        for source in case.get("sources", []):
            source_counter[source.get("source", "Unknown")] += 1
        affected_assets = case.get("affected_assets", {})
        for domain in affected_assets.get("domains", []):
            domain_counter[domain] += 1
        for email in affected_assets.get("emails", []):
            email_counter[email] += 1
        for sensitive_type in case.get("sensitive_data_types", []):
            sensitive_counter[sensitive_type] += 1

    return {
        "total_cases": len(cases),
        "severity_distribution": dict(severity_counter),
        "confidence_distribution": dict(confidence_counter),
        "category_distribution": dict(category_counter),
        "verification_distribution": dict(verification_counter),
        "sensitive_distribution": dict(sensitive_counter),
        "top_category": category_counter.most_common(1)[0][0] if category_counter else "None",
        "top_domains": [value for value, _ in domain_counter.most_common(5)],
        "top_emails": [value for value, _ in email_counter.most_common(5)],
        "top_sensitive_types": [value for value, _ in sensitive_counter.most_common(6)],
        "top_sources": [value for value, _ in source_counter.most_common(5)],
        "orgs": [value for value, _ in orgs.most_common(3)],
        "org_count": len(orgs),
    }


def _resolve_report_org_label(*, org_id: str | None, summary: dict[str, Any]) -> str:
    if org_id:
        return str(org_id)
    orgs = list(summary.get("orgs", []))
    org_count = int(summary.get("org_count", 0) or 0)
    if not orgs:
        return "All monitored organizations"
    if org_count <= 1:
        return orgs[0]
    return f"Multiple organizations ({org_count})"


def _build_executive_summary(styles: Any, summary: dict[str, Any], cases: list[dict[str, Any]]) -> list[Any]:
    elements = [Paragraph("Executive Summary", styles["CitadelHeading"])]
    critical = summary["severity_distribution"].get("Critical", 0)
    high = summary["severity_distribution"].get("High", 0)
    medium = summary["severity_distribution"].get("Medium", 0)
    low = summary["severity_distribution"].get("Low", 0)
    verified = summary["verification_distribution"].get("VERIFIED", 0)
    likely = summary["verification_distribution"].get("LIKELY", 0)
    weak = summary["verification_distribution"].get("WEAK_SIGNAL", 0)
    narrative = (
        f"CITADEL identified {summary['total_cases']} consolidated exposure case(s) in the selected reporting window. "
        f"The current mix includes {critical} critical, {high} high, {medium} medium, and {low} low severity cases. "
        f"The most common exposure category is {summary['top_category']}. "
        f"Verification currently breaks down into {verified} verified, {likely} likely, and {weak} weak-signal case(s). "
        f"Most frequently impacted domains include {', '.join(summary['top_domains'][:3]) or 'none identified'}, "
        f"while the most common source platforms are {', '.join(summary['top_sources'][:3]) or 'none identified'}. "
        f"Sensitive data indicators most often include {', '.join(summary['top_sensitive_types'][:4]) or 'none identified'}."
    )
    elements.append(Paragraph(narrative, styles["CitadelBody"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(
        _styled_table(
            [
                ["Metric", "Value"],
                ["Total cases", str(summary["total_cases"])],
                ["Top exposure category", summary["top_category"]],
                ["Verification breakdown", f"Verified {verified} | Likely {likely} | Weak {weak}"],
                ["Sensitive data summary", ", ".join(summary["top_sensitive_types"][:6]) or "None"],
                ["Top impacted domains", ", ".join(summary["top_domains"][:5]) or "None"],
                ["Top impacted emails", ", ".join(summary["top_emails"][:5]) or "None"],
                ["Top sources", ", ".join(summary["top_sources"][:5]) or "None"],
            ],
            styles=styles,
            col_widths=_table_col_widths(7.0 * inch, [0.28, 0.72]),
        )
    )
    if not cases:
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph("No cases matched the selected filters.", styles["CitadelBody"]))
    return elements


def _build_overview_tables(styles: Any, summary: dict[str, Any]) -> list[Any]:
    elements = [Paragraph("Exposure Risk Overview", styles["CitadelHeading"])]
    elements.append(Paragraph("Severity and confidence distributions are shown below to support executive triage and trend review.", styles["CitadelBody"]))
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            [["Severity", "Count"], *[[label, str(value)] for label, value in summary["severity_distribution"].items()]]
            or [["Severity", "Count"], ["None", "0"]],
            styles=styles,
            col_widths=_table_col_widths(4.2 * inch, [0.68, 0.32]),
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            [["Confidence band", "Count"], *[[label, str(value)] for label, value in summary["confidence_distribution"].items()]]
            or [["Confidence band", "Count"], ["None", "0"]],
            styles=styles,
            col_widths=_table_col_widths(4.2 * inch, [0.68, 0.32]),
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            [["Category", "Count"], *[[label, str(value)] for label, value in summary["category_distribution"].items()]]
            or [["Category", "Count"], ["None", "0"]],
            styles=styles,
            col_widths=_table_col_widths(4.2 * inch, [0.68, 0.32]),
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            [["Verification badge", "Count"], *[[label, str(value)] for label, value in summary["verification_distribution"].items()]]
            or [["Verification badge", "Count"], ["None", "0"]],
            styles=styles,
            col_widths=_table_col_widths(4.2 * inch, [0.68, 0.32]),
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            [["Sensitive type", "Count"], *[[label, str(value)] for label, value in summary["sensitive_distribution"].items()]]
            or [["Sensitive type", "Count"], ["None", "0"]],
            styles=styles,
            col_widths=_table_col_widths(4.2 * inch, [0.68, 0.32]),
        )
    )
    return elements


def _build_detailed_cases(styles: Any, cases: list[dict[str, Any]]) -> list[Any]:
    elements = [Paragraph("Detailed Cases", styles["CitadelHeading"])]
    if not cases:
        elements.append(Paragraph("No detailed cases are available for the chosen filters.", styles["CitadelBody"]))
        return elements

    for index, case in enumerate(cases):
        if index:
            elements.append(PageBreak())
        elements.append(Paragraph(case.get("title", "Exposure case"), styles["CitadelHeading"]))
        elements.append(
            Paragraph(
                f"<b>Severity:</b> {case.get('severity', 'Low')} | "
                f"<b>Severity score:</b> {case.get('severity_score', case.get('priority_score', 0))} | "
                f"<b>Confidence:</b> {case.get('confidence_score', 0)} | "
                f"<b>Category:</b> {case.get('category', 'Unknown')}",
                styles["CitadelBody"],
            )
        )
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph(case.get("exposure_summary") or case.get("executive_summary") or case.get("summary", ""), styles["CitadelBody"]))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Impacted Assets", styles["CitadelHeading"]))
        if not flatten_affected_assets(case.get("affected_assets")):
            elements.append(
                Paragraph(
                    "No verified organization-owned assets were identified. This case is a weak signal requiring manual verification.",
                    styles["CitadelBody"],
                )
            )
            elements.append(Spacer(1, 0.1 * inch))
        elements.append(
            _styled_table(
                [
                    ["Asset type", "Values"],
                    ["Domains", ", ".join(case.get("affected_assets", {}).get("domains", [])) or "None"],
                    ["Emails", ", ".join(case.get("affected_assets", {}).get("emails", [])) or "None"],
                    ["IPs", ", ".join(case.get("affected_assets", {}).get("ips", [])) or "None"],
                    ["Usernames", ", ".join(case.get("affected_assets", {}).get("usernames", [])) or "None"],
                    ["Tokens", ", ".join(_mask_list(case.get("affected_assets", {}).get("tokens", []))) or "None"],
                    ["Wallets", ", ".join(case.get("affected_assets", {}).get("wallets", [])) or "None"],
                ],
                styles=styles,
                col_widths=_table_col_widths(7.0 * inch, [0.22, 0.78]),
            )
        )
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Verification Status", styles["CitadelHeading"]))
        verification_reasons = case.get("relevance_reasons", []) or case.get("suppression_reasons", [])
        elements.append(
            _styled_table(
                [
                    ["Field", "Value"],
                    ["Verified Org Match", "YES" if case.get("verified_org_match") else "NO"],
                    ["Verification status", case.get("verification_status") or ("YES" if case.get("verified_org_match") else "NO")],
                    ["Badge", case.get("verification_badge", "WEAK_SIGNAL")],
                    ["Verification score", str(case.get("verification_score", 0))],
                    ["Relevance score", str(case.get("relevance_score", 0))],
                    [
                        "Reason",
                        " | ".join((case.get("verification_reasons", []) or verification_reasons)[:5])
                        or "No verification rationale was captured.",
                    ],
                ],
                styles=styles,
                col_widths=_table_col_widths(7.0 * inch, [0.24, 0.76]),
            )
        )
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Sensitive Data Detected", styles["CitadelHeading"]))
        sensitive_rows = [["Field", "Value"]]
        sensitive_rows.append(["Types", ", ".join(case.get("sensitive_data_types", [])) or "None"])
        sensitive_rows.append(["Risk boost", str(case.get("sensitive_risk_score", 0) or 0)])
        masked_findings = case.get("sensitive_findings", [])[:6]
        sensitive_rows.append(
            [
                "Masked findings",
                " | ".join(
                    f"{item.get('finding_type', 'Sensitive')}: {item.get('masked_value', 'masked')}" for item in masked_findings
                )
                or "No masked sensitive findings were captured.",
            ]
        )
        elements.append(
            _styled_table(
                sensitive_rows,
                styles=styles,
                col_widths=_table_col_widths(7.0 * inch, [0.24, 0.76]),
            )
        )
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Evidence", styles["CitadelHeading"]))
        evidence_rows = [["Source", "Snippet", "Timestamp"]]
        for evidence in case.get("evidence", [])[:5]:
            evidence_rows.append(
                [
                    evidence.get("source_platform") or evidence.get("source") or "Unknown",
                    (evidence.get("cleaned_snippet") or evidence.get("legacy_summary") or evidence.get("raw_snippet") or "")[:220],
                    evidence.get("timestamp") or "Unknown",
                ]
            )
        if len(evidence_rows) == 1:
            evidence_rows.append(["None", "No evidence captured", "N/A"])
        elements.append(
            _styled_table(
                evidence_rows,
                styles=styles,
                col_widths=_table_col_widths(7.0 * inch, [0.18, 0.54, 0.28]),
            )
        )
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Leak Source Information", styles["CitadelHeading"]))
        elements.append(
            _styled_table(
                [
                    ["Field", "Value"],
                    ["Platform", case.get("leak_origin", {}).get("platform") or "Unknown"],
                    ["Channel/User", case.get("leak_origin", {}).get("channel_or_user") or "Unknown"],
                    ["Post URL", case.get("leak_origin", {}).get("post_url") or "Unknown"],
                    ["Source list", ", ".join(source.get("source", "Unknown") for source in case.get("sources", [])) or "None"],
                ],
                styles=styles,
                col_widths=_table_col_widths(7.0 * inch, [0.24, 0.76]),
            )
        )
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Correlation Reason", styles["CitadelHeading"]))
        for reason in case.get("correlation_reason", [])[:6]:
            elements.append(Paragraph(f"- {reason}", styles["CitadelBody"]))
        if not case.get("correlation_reason"):
            elements.append(Paragraph("- Correlation details were not captured for this case.", styles["CitadelBody"]))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Timeline", styles["CitadelHeading"]))
        for event in case.get("timeline", [])[:6]:
            elements.append(
                Paragraph(
                    f"- {event.get('timestamp', 'Unknown')}: {event.get('message', event.get('event_type', 'timeline event'))}",
                    styles["CitadelBody"],
                )
            )
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Recommended Actions", styles["CitadelHeading"]))
        for action in case.get("recommended_actions", [])[:8]:
            elements.append(Paragraph(f"- {action}", styles["CitadelBody"]))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Why This Was Flagged", styles["CitadelHeading"]))
        reasons = case.get("why_flagged") or case.get("why_this_was_flagged", [])
        for reason in reasons[:8]:
            elements.append(Paragraph(f"- {reason}", styles["CitadelBody"]))
    return elements


def _build_case_summary_table(styles: Any, cases: list[dict[str, Any]]) -> list[Any]:
    elements = [Paragraph("Case Summary Table", styles["CitadelHeading"])]
    rows = [["Case", "Severity", "Confidence", "Category", "Assets"]]
    for case in cases[:20]:
        asset_preview = ", ".join((case.get("affected_assets_flat") or flatten_affected_assets(case.get("affected_assets")))[:3]) or "None"
        rows.append(
            [
                case.get("title", "Exposure case")[:60],
                str(case.get("severity", "Low")),
                str(case.get("confidence_score", 0)),
                str(case.get("category", "Unknown")),
                asset_preview[:70],
            ]
        )
    if len(rows) == 1:
        rows.append(["None", "N/A", "0", "None", "None"])
    elements.append(
        _styled_table(
            rows,
            styles=styles,
            col_widths=_table_col_widths(7.0 * inch, [0.42, 0.11, 0.11, 0.16, 0.20]),
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(Paragraph("This table highlights the most relevant filtered cases included in the report window.", styles["CitadelBody"]))
    return elements


def _build_recommended_actions_section(styles: Any, cases: list[dict[str, Any]]) -> list[Any]:
    elements = [Paragraph("Recommended Actions", styles["CitadelHeading"])]
    aggregated_actions = Counter()
    for case in cases:
        for action in case.get("recommended_actions", []):
            aggregated_actions[action] += 1

    if not aggregated_actions:
        elements.append(Paragraph("No recommended actions are available for the selected cases.", styles["CitadelBody"]))
        return elements

    elements.append(
        Paragraph(
            "Prioritize the following remediation themes across the selected cases. Counts indicate how often the action appeared across filtered cases.",
            styles["CitadelBody"],
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    rows = [["Recommended action", "Cases"]]
    for action, count in aggregated_actions.most_common(12):
        rows.append([action, str(count)])
    elements.append(
        _styled_table(
            rows,
            styles=styles,
            col_widths=_table_col_widths(7.0 * inch, [0.82, 0.18]),
        )
    )
    return elements


def _build_appendix(styles: Any, cases: list[dict[str, Any]]) -> list[Any]:
    elements = [Paragraph("Appendix", styles["CitadelHeading"])]
    elements.append(Paragraph("Raw entities and source listings for audit and verification.", styles["CitadelBody"]))
    raw_entities = Counter()
    source_rows = [["Case", "Source", "Locations"]]
    for case in cases:
        appendix_entities = _appendix_entities(case)
        for entity in appendix_entities:
            raw_entities[entity] += 1
        for source in case.get("sources", []):
            source_rows.append(
                [
                    case.get("title", "Exposure case"),
                    source.get("source", "Unknown"),
                    ", ".join(source.get("source_locations", [])) or "None",
                ]
            )
    entity_rows = [["Entity", "Count"]]
    for entity, count in raw_entities.most_common(25):
        entity_rows.append([entity, str(count)])
    if len(entity_rows) == 1:
        entity_rows.append(["None", "0"])
    if len(source_rows) == 1:
        source_rows.append(["None", "None", "None"])
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            entity_rows,
            styles=styles,
            col_widths=_table_col_widths(7.0 * inch, [0.8, 0.2]),
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            source_rows,
            styles=styles,
            col_widths=_table_col_widths(7.0 * inch, [0.42, 0.16, 0.42]),
        )
    )
    return elements


def _build_verification_section(styles: Any, verification_details: dict[str, Any]) -> list[Any]:
    elements = [Paragraph("Report Authenticity Verification", styles["CitadelHeading"])]
    if verification_details.get("signed"):
        elements.append(
            Paragraph(
                "Use the report identifier, QR code, and public verification portal to validate authenticity without accessing internal evidence.",
                styles["CitadelBody"],
            )
        )
    else:
        elements.append(
            Paragraph(
                "This report was generated without an active signing key. The public verification portal can still identify the record, but the report is unsigned.",
                styles["CitadelBody"],
            )
        )
    elements.append(Spacer(1, 0.15 * inch))
    rows = [
        ["Field", "Value"],
        ["Report ID", verification_details.get("report_id") or "Unavailable"],
        ["Generated timestamp", verification_details.get("generated_at") or "Unavailable"],
        ["PDF SHA256 hash", verification_details.get("pdf_sha256_short") or "Available on verification portal"],
        ["Digital signature", verification_details.get("signature_short") or "Unsigned"],
        ["Signing algorithm", verification_details.get("signing_algorithm") or "Unsigned"],
        ["Key fingerprint", verification_details.get("public_key_fingerprint_short") or "Unavailable"],
        ["Verification URL", verification_details.get("verification_url") or "Unavailable"],
    ]
    if verification_details.get("warning"):
        rows.append(["Warning", verification_details.get("warning")])
    elements.append(
        _styled_table(
            rows,
            styles=styles,
            col_widths=_table_col_widths(7.0 * inch, [0.28, 0.72]),
        )
    )
    qr_image = _build_verification_qr_image(verification_details.get("verification_url"))
    if qr_image is not None:
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(qr_image)
    return elements


def _build_verification_qr_image(url: Any) -> Image | None:
    verification_url = str(url or "").strip()
    if not verification_url:
        return None
    try:
        import qrcode
    except Exception:
        return None
    qr = qrcode.QRCode(box_size=4, border=1)
    qr.add_data(verification_url)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    qr_image = Image(buffer, width=1.5 * inch, height=1.5 * inch)
    qr_image.hAlign = "LEFT"
    return qr_image


def _styled_table(rows: list[list[str]], *, styles: Any, col_widths: list[float]) -> Table:
    table = Table(
        _wrap_table_rows(rows, styles),
        colWidths=col_widths,
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=True,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _wrap_table_rows(rows: list[list[Any]], styles: Any) -> list[list[Paragraph]]:
    wrapped_rows: list[list[Paragraph]] = []
    for row_index, row in enumerate(rows):
        style = styles["CitadelTableHeader"] if row_index == 0 else styles["CitadelTableCell"]
        wrapped_rows.append([_paragraph_cell(cell, style) for cell in row])
    return wrapped_rows


def _paragraph_cell(value: Any, style: Any) -> Paragraph:
    text = str(value or "").strip() or "None"
    safe_text = escape(text).replace("\n", "<br/>")
    return Paragraph(safe_text, style)


def _table_col_widths(total_width: float, weights: list[float]) -> list[float]:
    divisor = sum(weights) or 1
    return [total_width * (weight / divisor) for weight in weights]


def _is_report_worthy_case(case: dict[str, Any]) -> bool:
    if case.get("suppressed_noise"):
        return False
    summary_blob = " ".join(
        str(case.get(field) or "")
        for field in ("title", "summary", "technical_summary", "exposure_summary", "executive_summary")
    ).lower()
    if any(pattern in summary_blob for pattern in REPORT_NOISE_PATTERNS):
        return False

    assets = case.get("affected_assets", {}) or {}
    valid_assets = [
        *assets.get("domains", []),
        *assets.get("emails", []),
        *assets.get("ips", []),
        *assets.get("tokens", []),
        *assets.get("wallets", []),
    ]
    if not valid_assets and not assets.get("usernames", []):
        return False

    normalized_assets = {str(asset or "").strip().lower() for asset in flatten_affected_assets(assets)}
    if normalized_assets and normalized_assets.issubset(REPORT_NOISE_ASSETS):
        return False
    return True


def _appendix_entities(case: dict[str, Any]) -> list[str]:
    assets = case.get("affected_assets", {}) or {}
    appendix_values = [
        *assets.get("domains", []),
        *assets.get("emails", []),
        *assets.get("ips", []),
        *assets.get("wallets", []),
        *[finding.get("masked_value", "") for finding in case.get("sensitive_findings", []) if isinstance(finding, dict)],
    ]
    if appendix_values:
        return appendix_values
    return flatten_affected_assets(case.get("affected_assets"))


def _mask_list(values: list[str]) -> list[str]:
    return [_mask_text(value) for value in values if str(value or "").strip()]


def _mask_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 4:
        return "*" * len(text)
    if text.isdigit():
        return f"{text[:2]}{'*' * max(0, len(text) - 6)}{text[-4:]}"
    return f"{text[:4]}{'*' * max(4, len(text) - 8)}{text[-4:]}"


def _draw_header_footer(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(colors.HexColor("#0F172A"))
    canvas.drawString(doc.leftMargin, A4[1] - 35, REPORT_TITLE)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(doc.leftMargin, 20, "CITADEL")
    canvas.drawRightString(A4[0] - doc.rightMargin, 20, f"Page {doc.page}")
    canvas.restoreState()
