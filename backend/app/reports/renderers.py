"""Report renderers: HTML, PDF, CSV, JSON and XLSX.

PDF uses WeasyPrint when its native dependencies (pango/cairo) are present —
they are in the provided Docker image — and otherwise falls back to a
dependency-free fpdf2 renderer so a PDF is always produced.
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import date, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("prcampus.reports")

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


# Probed once and cached: (available, detail, HTML class or None).
_weasyprint_probe: tuple[bool, str, object | None] | None = None


def weasyprint_available() -> tuple[bool, str]:
    """Report whether WeasyPrint can be used, probing at most once.

    Importing WeasyPrint performs a dlopen of pango/cairo through cffi. On a
    host where those libraries are absent the import raises, and repeating that
    failing dlopen on every render is both wasteful and unstable — it has been
    observed to crash the interpreter after a handful of attempts. The probe is
    therefore performed once and the result cached for the process lifetime.
    """
    global _weasyprint_probe
    if _weasyprint_probe is None:
        try:
            from weasyprint import HTML

            _weasyprint_probe = (True, "WeasyPrint", HTML)
        except Exception as exc:
            logger.info(
                "WeasyPrint is unavailable (%s); PDFs will be rendered with fpdf2.",
                type(exc).__name__,
            )
            _weasyprint_probe = (False, type(exc).__name__, None)
    available, detail, _ = _weasyprint_probe
    return available, detail


# ---------------------------------------------------------------------- HTML
def render_html(context: dict) -> bytes:
    return _env.get_template("report.html").render(**context).encode("utf-8")


# ----------------------------------------------------------------------- PDF
def render_pdf(context: dict) -> tuple[bytes, str]:
    """Return (pdf_bytes, engine_name)."""
    html = render_html(context).decode("utf-8")
    available, _ = weasyprint_available()
    if available and _weasyprint_probe is not None:
        html_class = _weasyprint_probe[2]
        try:
            return html_class(string=html).write_pdf(), "weasyprint"
        except Exception:
            logger.exception("WeasyPrint failed; falling back to the fpdf2 renderer.")
    return _render_pdf_fallback(context), "fpdf2"


def _latin1(text: object) -> str:
    """The fpdf2 core fonts are Latin-1 only."""
    return (
        str(text if text is not None else "")
        .replace("—", "-").replace("–", "-").replace("’", "'")
        .replace("“", '"').replace("”", '"').replace("…", "...").replace("·", "-")
        .replace("⚠", "!").replace("✓", "y").replace("→", "->")
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


_SEVERITY_RGB = {
    "CRITICAL": (185, 28, 28),
    "HIGH": (194, 65, 12),
    "MEDIUM": (161, 98, 7),
    "LOW": (29, 78, 216),
    "INFORMATIONAL": (75, 85, 99),
}


def _render_pdf_fallback(context: dict) -> bytes:
    from fpdf import FPDF

    assessment = context["assessment"]
    counters = context["counters"]

    class Report(FPDF):
        def footer(self) -> None:
            self.set_y(-15)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(107, 114, 128)
            self.cell(
                0, 8,
                _latin1(f"FixNex  ·  {assessment.reference}  ·  Page {self.page_no()}"),
                align="C",
            )

    pdf = Report(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(16, 16, 16)
    width = pdf.w - 32

    def heading(text: str, size: int = 13, top: int = 6) -> None:
        pdf.ln(top)
        pdf.set_font("Helvetica", "B", size)
        pdf.set_text_color(15, 23, 42)
        pdf.multi_cell(width, 7, _latin1(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(226, 232, 240)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(3)

    def body(text: str, size: int = 9) -> None:
        pdf.set_font("Helvetica", "", size)
        pdf.set_text_color(31, 41, 55)
        pdf.multi_cell(width, 4.6, _latin1(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1.5)

    def kv(label: str, value: object) -> None:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(42, 5, _latin1(label), new_x="RIGHT", new_y="TOP")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(31, 41, 55)
        pdf.multi_cell(width - 42, 5, _latin1(value), new_x="LMARGIN", new_y="NEXT")

    # ---------------------------------------------------------------- cover
    pdf.add_page()
    pdf.ln(45)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(37, 99, 235)
    pdf.cell(0, 6, _latin1("FixNex  ·  SECURITY ASSESSMENT REPORT"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(width, 11, _latin1(assessment.name), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(width, 7, _latin1(assessment.client_name or "Internal engagement"),
                   new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_draw_color(15, 23, 42)
    pdf.set_line_width(0.8)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(4)

    for label, value in [
        ("Report reference", assessment.reference),
        ("Engagement type", assessment.engagement_type or "Web application security assessment"),
        ("Period", f"{assessment.start_date or '-'} to {assessment.end_date or 'ongoing'}"),
        ("Status", assessment.status),
        ("Targets assessed", counters["targets"]),
        ("Total findings", counters["findings_total"]),
        ("Generated", context["generated_at"].strftime("%d %B %Y at %H:%M UTC")),
    ]:
        kv(label, value)

    if context.get("contains_demo_data"):
        pdf.ln(4)
        pdf.set_fill_color(255, 251, 235)
        pdf.set_text_color(146, 64, 14)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.multi_cell(
            width, 4.6,
            _latin1(
                "! THIS REPORT CONTAINS SEEDED DEMONSTRATION DATA. Findings marked DEMO were "
                "created by the FixNex demonstration seeder to illustrate the assessment "
                "workflow. They are NOT the results of a real scan against a real system."
            ),
            fill=True, new_x="LMARGIN", new_y="NEXT",
        )

    pdf.ln(4)
    pdf.set_fill_color(248, 250, 252)
    pdf.set_text_color(71, 85, 105)
    pdf.set_font("Helvetica", "", 8)
    pdf.multi_cell(
        width, 4.4,
        _latin1(
            "CONFIDENTIAL. This report contains security vulnerability information about the "
            "systems named above. Distribute only to authorised personnel. All testing was "
            "performed against explicitly authorised targets within a defined scope."
        ),
        fill=True, new_x="LMARGIN", new_y="NEXT",
    )

    # ------------------------------------------------------- scope + method
    pdf.add_page()
    heading("1. Scope", top=0)
    body(
        "Testing was strictly limited to the authorised scope below. FixNex rejects any scan "
        "request for a target that does not match an authorised scope rule."
    )
    for rule in context["scope_rules"]:
        kv(
            "EXCLUDED" if rule.is_exclusion else "AUTHORISED",
            f"{rule.rule_type}: {rule.value}" + (f" ({rule.note})" if rule.note else ""),
        )
    if not context["scope_rules"]:
        body("No scope rules were recorded.")

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, _latin1("Targets"), new_x="LMARGIN", new_y="NEXT")
    for target in context["targets"]:
        kv(target.reference, f"{target.name} - {target.value} ({target.target_type})")

    heading("2. Methodology")
    body(assessment.methodology or "OWASP Web Security Testing Guide informed methodology.")
    body(
        "FixNex orchestrates multiple security tools, normalises their output into a single "
        "finding format, correlates duplicate detections across tools, and then manages each "
        "finding through verification, evidence collection, risk analysis, remediation and "
        "retesting. Scanners used in this assessment: "
        + (", ".join(context["scanners_used"]) or "none recorded") + "."
    )

    heading("3. Executive Summary")
    body(context["executive_summary"])

    pdf.ln(2)
    counts = context["severity_counts"]
    cell_width = width / 5
    pdf.set_font("Helvetica", "B", 16)
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        pdf.set_text_color(*_SEVERITY_RGB[level])
        pdf.cell(cell_width, 9, _latin1(str(counts.get(level, 0))), align="C")
    pdf.ln(9)
    pdf.set_font("Helvetica", "", 6.5)
    pdf.set_text_color(100, 116, 139)
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        pdf.cell(cell_width, 4, _latin1(level), align="C")
    pdf.ln(8)

    heading("4. Risk Overview")
    for label, value in [
        ("Open findings", counters["findings_open"]),
        ("Closed findings", counters["findings_closed"]),
        ("False positives", counters["findings_false_positive"]),
        ("Remediation progress", f"{counters['remediation_progress']}%"),
        ("Past SLA deadline", counters["overdue"]),
    ]:
        kv(label, value)
    pdf.ln(1)
    body(
        "On scoring: each finding carries a CVSS v3.1 base score computed from its vector using "
        "the reference algorithm. The FixNex contextual risk score shown alongside it is a "
        "platform-specific rating that adjusts the CVSS base score for asset criticality, data "
        "sensitivity, exposure and exploitability. It is NOT an official CVSS rating.",
        size=8,
    )

    # ------------------------------------------------------------- findings
    pdf.add_page()
    heading("5. Detailed Findings", top=0)
    if not context["findings"]:
        body("No findings matched the selected report options.")

    for finding in context["findings"]:
        if pdf.get_y() > pdf.h - 70:
            pdf.add_page()
        rgb = _SEVERITY_RGB.get(finding["severity"], (75, 85, 99))
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 4, _latin1(finding["reference"]), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.multi_cell(width, 5.5, _latin1(finding["title"]), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_fill_color(*rgb)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(24, 5, _latin1(finding["severity"]), fill=True, align="C", new_x="RIGHT", new_y="TOP")
        pdf.set_fill_color(226, 232, 240)
        pdf.set_text_color(51, 65, 85)
        cvss = f"CVSS {finding['cvss_score']:.1f}" if finding["cvss_score"] is not None else "CVSS -"
        pdf.cell(24, 5, _latin1(cvss), fill=True, align="C", new_x="RIGHT", new_y="TOP")
        pdf.cell(34, 5, _latin1(f"Risk: {finding['risk_level'] or '-'}"), fill=True, align="C",
                 new_x="RIGHT", new_y="TOP")
        pdf.cell(30, 5, _latin1(finding["status"]), fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
        if finding["data_origin"] == "SEEDED_DEMO":
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(146, 64, 14)
            pdf.cell(0, 4.5, _latin1("[ DEMO DATA - not a real scan result ]"),
                     new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1.5)

        for label, value in [
            ("Target", finding["target"]),
            ("Endpoint", finding["endpoint"]),
            ("Parameter", finding["parameter"]),
            ("Detected by", ", ".join(finding["sources"])),
            ("CVSS vector", finding["cvss_vector"]),
            ("CWE", finding["cwe"]),
            ("CVE", ", ".join(finding["cves"]) if finding["cves"] else None),
            ("Verification", finding["verification_status"]),
            ("Assigned to", finding["assigned_to"]),
            ("Remediation", finding["remediation_status"]),
        ]:
            if value:
                kv(label, value)

        if finding["description"]:
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 4, "DESCRIPTION", new_x="LMARGIN", new_y="NEXT")
            body(finding["description"], size=8.5)

        if finding["remediation"]:
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 4, "RECOMMENDED REMEDIATION", new_x="LMARGIN", new_y="NEXT")
            body(finding["remediation"], size=8.5)

        if finding["evidence"]:
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 4, "EVIDENCE", new_x="LMARGIN", new_y="NEXT")
            for item in finding["evidence"]:
                kv(
                    item["filename"][:24],
                    f"SHA-256 {item['sha256'][:24]}... collected by {item['uploaded_by'] or '-'} "
                    f"on {item['created_at']:%Y-%m-%d %H:%M}",
                )

        for retest in finding["retests"]:
            kv(f"Retest {retest['result']}", f"{retest['summary'] or '-'} ({retest['performed_by'] or '-'})")

        pdf.set_draw_color(226, 232, 240)
        pdf.line(pdf.l_margin, pdf.get_y() + 1, pdf.w - pdf.r_margin, pdf.get_y() + 1)

    # ------------------------------------------------------ false positives
    if context["false_positives"]:
        pdf.add_page()
        heading("6. Reviewed and Dismissed (False Positives)", top=0)
        body(
            "The following scanner results were manually reviewed and determined not to be "
            "genuine issues. They are retained for audit and excluded from the risk figures."
        )
        for fp in context["false_positives"]:
            kv(fp["reference"], f"{fp['title']} - {fp['reason'] or 'no reason recorded'} "
                                f"(verified by {fp['verified_by'] or '-'})")

    # --------------------------------------------------------- audit + end
    if context["audit_summary"]:
        pdf.add_page()
        heading("7. Audit Trail Summary", top=0)
        pdf.set_font("Helvetica", "", 7.5)
        for entry in context["audit_summary"]:
            pdf.set_text_color(100, 116, 139)
            pdf.multi_cell(
                width, 4,
                _latin1(
                    f"{entry['created_at']:%Y-%m-%d %H:%M}  {entry['actor'] or 'system'}  "
                    f"{entry['action']}  -  {entry['description'] or ''}"
                ),
                new_x="LMARGIN", new_y="NEXT",
            )

    heading("Conclusion")
    body(
        f"{counters['findings_total']} finding(s) were recorded across {counters['targets']} "
        f"authorised target(s). {counters['findings_closed']} have been remediated and verified "
        f"closed by retest, and {counters['findings_open']} remain open. Findings should be "
        "remediated in order of contextual risk, addressing Critical and High severity issues "
        "first. A finding is closed in FixNex only after a passing retest."
    )

    output = pdf.output()
    return bytes(output)


# ----------------------------------------------------------------- CSV / JSON
CSV_COLUMNS = [
    "reference", "title", "severity", "cvss_score", "cvss_vector", "risk_score", "risk_level",
    "status", "verification_status", "cwe", "cve", "sources", "target", "endpoint", "parameter",
    "assigned_to", "remediation_status", "sla_status", "sla_due_at", "data_origin", "remediation",
]


def render_csv(context: dict) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for finding in context["findings"]:
        writer.writerow(
            {
                **{key: finding.get(key) for key in CSV_COLUMNS},
                "cve": ", ".join(finding["cves"]),
                "sources": ", ".join(finding["sources"]),
                "sla_due_at": finding["sla_due_at"].isoformat() if finding["sla_due_at"] else "",
            }
        )
    return buffer.getvalue().encode("utf-8")


def _json_default(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def render_json(context: dict) -> bytes:
    assessment = context["assessment"]
    payload = {
        "report": {
            "generated_at": context["generated_at"],
            "generator": "FixNex",
            "contains_demo_data": context["contains_demo_data"],
        },
        "assessment": {
            "reference": assessment.reference,
            "name": assessment.name,
            "client_name": assessment.client_name,
            "status": assessment.status,
            "start_date": assessment.start_date,
            "end_date": assessment.end_date,
            "methodology": assessment.methodology,
        },
        "summary": context["counters"],
        "executive_summary": context["executive_summary"],
        "scope": [
            {"type": r.rule_type, "value": r.value, "is_exclusion": r.is_exclusion, "note": r.note}
            for r in context["scope_rules"]
        ],
        "targets": [
            {
                "reference": t.reference, "name": t.name, "type": t.target_type,
                "value": t.value, "technologies": t.technologies,
            }
            for t in context["targets"]
        ],
        "scanners_used": context["scanners_used"],
        "findings": [
            {key: value for key, value in finding.items() if key != "obj"}
            for finding in context["findings"]
        ],
        "false_positives": context["false_positives"],
        "audit_summary": context["audit_summary"],
    }
    return json.dumps(payload, indent=2, default=_json_default).encode("utf-8")


def render_xlsx(context: dict) -> bytes:
    import pandas as pd

    findings = pd.DataFrame(
        [
            {
                **{key: finding.get(key) for key in CSV_COLUMNS},
                "cve": ", ".join(finding["cves"]),
                "sources": ", ".join(finding["sources"]),
                "sla_due_at": finding["sla_due_at"].replace(tzinfo=None) if finding["sla_due_at"] else None,
            }
            for finding in context["findings"]
        ],
        columns=CSV_COLUMNS,
    )
    summary = pd.DataFrame(
        [{"metric": key, "value": value} for key, value in context["counters"].items() if key != "severity"]
        + [{"metric": f"severity_{k.lower()}", "value": v} for k, v in context["severity_counts"].items()]
    )
    scope = pd.DataFrame(
        [
            {"type": r.rule_type, "value": r.value, "excluded": r.is_exclusion, "note": r.note}
            for r in context["scope_rules"]
        ]
    )
    false_positives = pd.DataFrame(context["false_positives"])

    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        summary.to_excel(writer, sheet_name="Summary", index=False)
        findings.to_excel(writer, sheet_name="Findings", index=False)
        if not scope.empty:
            scope.to_excel(writer, sheet_name="Scope", index=False)
        if not false_positives.empty:
            false_positives.to_excel(writer, sheet_name="False Positives", index=False)
    return buffer.getvalue()
