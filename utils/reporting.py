from __future__ import annotations

import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from utils.case_schema import flatten_affected_assets, normalize_case_list


REPORT_TITLE = "CITADEL Exposure Intelligence Report"


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
    _build_pdf(file_path, filtered_cases, start_date=start_date, end_date=end_date, org_id=org_id)
    return file_path


def _build_pdf(file_path: Path, cases: list[dict[str, Any]], *, start_date: str | None, end_date: str | None, org_id: str | None) -> None:
    doc = SimpleDocTemplate(
        str(file_path),
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

    elements: list[Any] = []
    summary = _summarize_cases(cases)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    report_org = org_id or summary["orgs"][0] if summary["orgs"] else "All monitored organizations"
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
    elements.extend(_build_detailed_cases(styles, cases))
    elements.append(PageBreak())
    elements.extend(_build_appendix(styles, cases))

    doc.build(elements, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)


def _summarize_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counter = Counter()
    confidence_counter = Counter()
    category_counter = Counter()
    source_counter = Counter()
    domain_counter = Counter()
    email_counter = Counter()
    orgs = Counter()

    for case in cases:
        severity_counter[case.get("severity", "Low")] += 1
        category_counter[case.get("category", "Unknown")] += 1
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

    return {
        "total_cases": len(cases),
        "severity_distribution": dict(severity_counter),
        "confidence_distribution": dict(confidence_counter),
        "category_distribution": dict(category_counter),
        "top_category": category_counter.most_common(1)[0][0] if category_counter else "None",
        "top_domains": [value for value, _ in domain_counter.most_common(5)],
        "top_emails": [value for value, _ in email_counter.most_common(5)],
        "top_sources": [value for value, _ in source_counter.most_common(5)],
        "orgs": [value for value, _ in orgs.most_common(3)],
    }


def _build_executive_summary(styles: Any, summary: dict[str, Any], cases: list[dict[str, Any]]) -> list[Any]:
    elements = [Paragraph("Executive Summary", styles["CitadelHeading"])]
    critical = summary["severity_distribution"].get("Critical", 0)
    high = summary["severity_distribution"].get("High", 0)
    medium = summary["severity_distribution"].get("Medium", 0)
    low = summary["severity_distribution"].get("Low", 0)
    narrative = (
        f"CITADEL identified {summary['total_cases']} consolidated exposure case(s) in the selected reporting window. "
        f"The current mix includes {critical} critical, {high} high, {medium} medium, and {low} low severity cases. "
        f"The most common exposure category is {summary['top_category']}. "
        f"Most frequently impacted domains include {', '.join(summary['top_domains'][:3]) or 'none identified'}, "
        f"while the most common source platforms are {', '.join(summary['top_sources'][:3]) or 'none identified'}."
    )
    elements.append(Paragraph(narrative, styles["CitadelBody"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(
        _styled_table(
            [
                ["Metric", "Value"],
                ["Total cases", str(summary["total_cases"])],
                ["Top exposure category", summary["top_category"]],
                ["Top impacted domains", ", ".join(summary["top_domains"][:5]) or "None"],
                ["Top impacted emails", ", ".join(summary["top_emails"][:5]) or "None"],
                ["Top sources", ", ".join(summary["top_sources"][:5]) or "None"],
            ]
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
            or [["Severity", "Count"], ["None", "0"]]
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            [["Confidence band", "Count"], *[[label, str(value)] for label, value in summary["confidence_distribution"].items()]]
            or [["Confidence band", "Count"], ["None", "0"]]
        )
    )
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(
        _styled_table(
            [["Category", "Count"], *[[label, str(value)] for label, value in summary["category_distribution"].items()]]
            or [["Category", "Count"], ["None", "0"]]
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
                f"<b>Confidence:</b> {case.get('confidence_score', 0)} | "
                f"<b>Category:</b> {case.get('category', 'Unknown')}",
                styles["CitadelBody"],
            )
        )
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph(case.get("exposure_summary") or case.get("executive_summary") or case.get("summary", ""), styles["CitadelBody"]))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph("Impacted Assets", styles["CitadelHeading"]))
        elements.append(
            _styled_table(
                [
                    ["Asset type", "Values"],
                    ["Domains", ", ".join(case.get("affected_assets", {}).get("domains", [])) or "None"],
                    ["Emails", ", ".join(case.get("affected_assets", {}).get("emails", [])) or "None"],
                    ["IPs", ", ".join(case.get("affected_assets", {}).get("ips", [])) or "None"],
                    ["Usernames", ", ".join(case.get("affected_assets", {}).get("usernames", [])) or "None"],
                    ["Tokens", ", ".join(case.get("affected_assets", {}).get("tokens", [])) or "None"],
                    ["Wallets", ", ".join(case.get("affected_assets", {}).get("wallets", [])) or "None"],
                ]
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
        elements.append(_styled_table(evidence_rows))
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
                ]
            )
        )
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
        for reason in case.get("why_this_was_flagged", [])[:8]:
            elements.append(Paragraph(f"- {reason}", styles["CitadelBody"]))
    return elements


def _build_appendix(styles: Any, cases: list[dict[str, Any]]) -> list[Any]:
    elements = [Paragraph("Appendix", styles["CitadelHeading"])]
    elements.append(Paragraph("Raw entities and source listings for audit and verification.", styles["CitadelBody"]))
    raw_entities = Counter()
    source_rows = [["Case", "Source", "Locations"]]
    for case in cases:
        for entity in case.get("matched_indicators", []) or flatten_affected_assets(case.get("affected_assets")):
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
    elements.append(_styled_table(entity_rows))
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(_styled_table(source_rows))
    return elements


def _styled_table(rows: list[list[str]]) -> Table:
    table = Table(rows, repeatRows=1, hAlign="LEFT")
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
