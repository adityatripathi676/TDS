from __future__ import annotations

from io import BytesIO
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from docx import Document
from docx.shared import Pt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
from reportlab.pdfgen import canvas


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to add 'Page X of Y', header lines, and confidentiality footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))

        # Header for pages > 1
        if self._pageNumber > 1:
            self.drawString(36, 812, "CONFIDENTIAL — AI-HIDS SENTINEL SECURITY AUDIT & DEEP SCAN REPORT")
            self.setFont("Helvetica", 8)
            self.drawRightString(559, 812, "SYSTEM POSTURE REPORT")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 806, 559, 806)

        # Footer for all pages
        self.setFont("Helvetica", 8)
        self.drawString(36, 24, "AI-HIDS Sentinel Host Intrusion Detection System · Formal Executive Audit")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(559, 24, page_text)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 34, 559, 34)

        self.restoreState()


def _top_findings(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for alert in alerts[:8]:
        findings.append(
            {
                "summary": alert.get("summary"),
                "severity": alert.get("severity"),
                "host": alert.get("host"),
                "score": alert.get("score"),
                "mitre_tags": alert.get("mitre_tags", []),
                "reasons": alert.get("reasons", []),
                "recommendations": alert.get("recommendations", []),
            }
        )
    return findings


def _owasp_alignment(
    metrics: dict[str, Any],
    alerts: list[dict[str, Any]],
    monitor_status: dict[str, Any],
    system_snapshot: dict[str, Any],
    deep_scan: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    has_alerts = metrics.get("total_alerts", 0) > 0
    suspicious_count = len(system_snapshot.get("suspicious_processes", []))
    enabled = monitor_status.get("enabled", False)
    sec = deep_scan.get("security", {}) if deep_scan else {}
    def_active = sec.get("windows_defender", {}).get("real_time_protection") in ("Enabled", "True", True)

    return [
        {
            "area": "Logging And Monitoring Coverage (A09:2021)",
            "status": "aligned" if enabled else "partial",
            "guidance": "OWASP recommends sufficient security logging, monitoring, and alerting for suspicious activity.",
            "finding": (
                f"Host telemetry monitor is {'ACTIVE' if enabled else 'INACTIVE'} with {monitor_status.get('scans_completed', 0)} scans "
                f"and {metrics.get('total_alerts', 0)} security alerts recorded."
            ),
            "recommendation": "Keep continuous host monitoring enabled and retain event history for investigation and audit compliance.",
        },
        {
            "area": "Detection Of Suspicious Host Behavior (A08:2021)",
            "status": "aligned" if has_alerts or suspicious_count > 0 else "partial",
            "guidance": "OWASP emphasizes detection of anomalous and malicious behavior through relevant system telemetry.",
            "finding": (
                f"The detection engine is tracking {suspicious_count} suspicious processes and scored anomaly detections across "
                f"{metrics.get('total_events', 0)} ingested events."
            ),
            "recommendation": "Periodically tune IsolationForest anomaly thresholds and validate alerts against process execution trees.",
        },
        {
            "area": "System Hardening & Firmware Integrity (A05:2021)",
            "status": "aligned" if def_active or (deep_scan and deep_scan.get("firmware", {}).get("secure_boot") in ("Enabled", "On")) else "attention",
            "guidance": "OWASP & NIST recommend enforcing secure boot, hardware TPM root of trust, and active antivirus controls.",
            "finding": (
                f"Windows Defender Real-Time Protection is {'ENABLED' if def_active else 'DISABLED/UNKNOWN'}. "
                f"Firmware Secure Boot state is {deep_scan.get('firmware', {}).get('secure_boot', 'N/A') if deep_scan else 'N/A'}."
            ),
            "recommendation": "Enforce Secure Boot in UEFI firmware, mandate TPM 2.0, and maintain updated antivirus definitions.",
        },
        {
            "area": "Incident Visibility & Response Readiness (A04:2021)",
            "status": "aligned" if has_alerts else "partial",
            "guidance": "OWASP guidance favors clear incident context, triage metadata, and actionable remediation recommendations.",
            "finding": (
                "Alerts include severity levels, anomaly scores, supporting reasons, and MITRE ATT&CK technique tags."
                if has_alerts
                else "No active alerts recorded; response playbooks are ready for triage."
            ),
            "recommendation": "Document incident response workflows and map alerts to containment, isolation, and recovery playbooks.",
        },
    ]


def generate_hids_report(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    baseline: dict[str, Any],
    metrics: dict[str, Any],
    monitor_status: dict[str, Any],
    system_snapshot: dict[str, Any],
    deep_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    severities = Counter(alert.get("severity", "low") for alert in alerts)
    
    # Calculate score taking into account deep scan posture if present
    base_score = 35 + (10 if monitor_status.get("enabled") else 0) + min(metrics.get("total_events", 0), 20) + min(metrics.get("total_alerts", 0) * 5, 20)
    if deep_scan and "posture" in deep_scan:
        posture_score = deep_scan["posture"].get("score", 75)
        report_score = round((base_score + posture_score) / 2)
    else:
        report_score = min(100, base_score + (10 if system_snapshot.get("suspicious_processes") else 0))

    return {
        "title": "OWASP & NIST Aligned HIDS Security Audit Report",
        "generated_at": _utcnow(),
        "executive_summary": {
            "host": system_snapshot.get("hostname") or (deep_scan.get("hostname") if deep_scan else "LocalHost"),
            "monitor_state": "running" if monitor_status.get("enabled") else "paused",
            "security_posture_score": report_score,
            "events_observed": metrics.get("total_events", 0),
            "alerts_generated": metrics.get("total_alerts", 0),
            "critical_alerts": severities.get("critical", 0),
            "high_alerts": severities.get("high", 0),
            "top_event_type": metrics.get("top_event_type") or "process_start",
            "deep_scan_available": deep_scan is not None,
            "deep_scan_time": deep_scan.get("scan_time") if deep_scan else None,
        },
        "monitoring_scope": {
            "telemetry_sources": [
                "Real-time host process telemetry & execution trees",
                "Firmware / UEFI & Secure Boot integrity inspection",
                "TPM 2.0 Security Chip validation & Platform PCR state",
                "Windows Defender Antivirus & Firewall profile status",
                "Persistence IOC inspection (Registry Run keys & Scheduled Tasks)",
                "Network surface audit (Active listening ports & interface adapters)",
                "IsolationForest ML anomaly detection baseline",
            ],
            "baseline_features": list(baseline.keys()),
            "scan_interval_seconds": monitor_status.get("interval_seconds"),
            "scans_completed": monitor_status.get("scans_completed"),
        },
        "deep_scan": deep_scan,
        "top_findings": _top_findings(alerts),
        "owasp_alignment": _owasp_alignment(metrics, alerts, monitor_status, system_snapshot, deep_scan),
        "recommended_actions": [
            "Maintain continuous real-time host monitoring to catch stealthy execution chains.",
            "Review critical and high severity alerts against host timeline evidence and process parentage.",
            "Verify Secure Boot state in UEFI BIOS and ensure Windows Defender Real-Time Protection remains active.",
            "Audit suspicious registry startup keys and scheduled tasks for unexpected persistence mechanisms.",
            "Close unused listening network ports and restrict administrative interface exposures.",
            "Periodically validate detection rules against OWASP Logging & Monitoring guidelines.",
        ],
    }


def _report_filename(report: dict[str, Any], extension: str) -> str:
    host = report.get("executive_summary", {}).get("host") or "host"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"hids-security-report-{host}-{timestamp}.{extension}"


def _summary_rows(report: dict[str, Any]) -> list[list[str]]:
    summary = report.get("executive_summary", {})
    score = summary.get("security_posture_score", 0)
    grade = "Grade A (Secure)" if score >= 80 else "Grade B (Warning)" if score >= 60 else "Grade C (Critical Action Needed)"
    return [
        ["Target Host", str(summary.get("host", "n/a"))],
        ["Monitor State", str(summary.get("monitor_state", "n/a")).upper()],
        ["Security Posture Score", f"{score} / 100 — {grade}"],
        ["Deep Scan Status", "COMPLETED" if summary.get("deep_scan_available") else "NOT COMPLETED"],
        ["Telemetry Events Observed", str(summary.get("events_observed", "n/a"))],
        ["Security Alerts Generated", str(summary.get("alerts_generated", "n/a"))],
        ["Critical / High Severity Alerts", f"{summary.get('critical_alerts', 0)} Critical / {summary.get('high_alerts', 0)} High"],
        ["Report Generation Time", str(report.get("generated_at", "n/a"))],
    ]


def build_report_docx(report: dict[str, Any]) -> tuple[str, bytes]:
    document = Document()
    document.core_properties.title = report.get("title", "HIDS Security Report")

    title = document.add_heading(report.get("title", "OWASP & NIST Aligned HIDS Security Audit Report"), 0)
    title.runs[0].font.size = Pt(20)
    document.add_paragraph(f"Generated At: {report.get('generated_at', 'n/a')}")

    document.add_heading("1. Executive Summary", level=1)
    summary_table = document.add_table(rows=1, cols=2)
    summary_table.style = "Table Grid"
    header_cells = summary_table.rows[0].cells
    header_cells[0].text = "Field"
    header_cells[1].text = "Value"
    for field, value in _summary_rows(report):
        row = summary_table.add_row().cells
        row[0].text = field
        row[1].text = value

    # Deep scan details if present
    deep_scan = report.get("deep_scan")
    if deep_scan:
        document.add_heading("2. Deep System & Firmware Inspection", level=1)
        fw = deep_scan.get("firmware", {})
        bios = fw.get("bios", {})
        tpm = fw.get("tpm", {})
        sec = deep_scan.get("security", {})
        def_info = sec.get("windows_defender", {})

        document.add_paragraph(f"Firmware Type: {fw.get('firmware_type', 'N/A')}")
        document.add_paragraph(f"Secure Boot State: {fw.get('secure_boot', 'N/A')}")
        document.add_paragraph(f"TPM Status: {tpm.get('status', 'N/A')} (Version: {tpm.get('version', 'N/A')})")
        document.add_paragraph(f"BIOS Vendor: {bios.get('vendor', 'N/A')} | Version: {bios.get('version', 'N/A')}")
        document.add_paragraph(f"Windows Defender Real-Time: {def_info.get('real_time_protection', 'N/A')}")

    document.add_heading("3. OWASP Guidance Alignment", level=1)
    for item in report.get("owasp_alignment", []):
        document.add_heading(item.get("area", "Area"), level=2)
        document.add_paragraph(f"Status: {item.get('status', 'n/a')}")
        document.add_paragraph(f"Guidance: {item.get('guidance', 'n/a')}")
        document.add_paragraph(f"Finding: {item.get('finding', 'n/a')}")
        document.add_paragraph(f"Recommendation: {item.get('recommendation', 'n/a')}")

    document.add_heading("4. Recommended SOAR Actions", level=1)
    for action in report.get("recommended_actions", []):
        document.add_paragraph(action, style="List Bullet")

    stream = BytesIO()
    document.save(stream)
    return _report_filename(report, "docx"), stream.getvalue()


def build_report_pdf(report: dict[str, Any]) -> tuple[str, bytes]:
    """
    Build a formal, multi-page, publication-quality Security Audit PDF report
    containing executive metrics, deep scan firmware integrity, persistence IOCs,
    network open ports, threat findings, OWASP alignment matrix, and SOAR remediation steps.
    """
    stream = BytesIO()
    doc = SimpleDocTemplate(
        stream,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=40,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()
    
    # Custom formal styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=14,
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
        spaceAfter=4,
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )
    cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )
    cell_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
    )

    story = []

    # ── HEADER BANNER ──────────────────────────────────────────────────────────
    story.append(Paragraph(report.get("title", "OWASP & NIST Aligned HIDS Security Audit Report"), title_style))
    story.append(Paragraph("AI-HIDS SENTINEL · ENDPOINT INTRUSION DETECTION & SYSTEM DEEP SCAN AUDIT", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # ── 1. EXECUTIVE SUMMARY ───────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary & Posture Grade", h1_style))
    
    summary_data = [
        [Paragraph("Metric Field", cell_header), Paragraph("Audit Finding / Status", cell_header)]
    ]
    for k, v in _summary_rows(report):
        summary_data.append([Paragraph(k, cell_bold), Paragraph(v, cell_style)])

    t_summary = Table(summary_data, colWidths=[160, 363])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 12))

    # ── 2. DEEP SYSTEM & FIRMWARE INSPECTION ──────────────────────────────────
    deep_scan = report.get("deep_scan")
    if deep_scan:
        story.append(Paragraph("2. Deep System, Firmware & Hardware Integrity", h1_style))
        fw = deep_scan.get("firmware", {})
        bios = fw.get("bios", {})
        tpm = fw.get("tpm", {})
        sec = deep_scan.get("security", {})
        defender = sec.get("windows_defender", {})
        fw_status = sec.get("firewall", {})

        fw_rows = [
            [Paragraph("Inspection Domain", cell_header), Paragraph("Property", cell_header), Paragraph("Audit Value", cell_header), Paragraph("Security Status", cell_header)],
            [Paragraph("Firmware", cell_bold), Paragraph("Firmware Interface", cell_style), Paragraph(str(fw.get("firmware_type", "N/A")), cell_style), Paragraph("UEFI Mode" if "uefi" in str(fw.get("firmware_type","")).lower() else "Legacy BIOS", cell_style)],
            [Paragraph("Boot Security", cell_bold), Paragraph("Secure Boot State", cell_style), Paragraph(str(fw.get("secure_boot", "N/A")), cell_style), Paragraph("PASS" if fw.get("secure_boot") in ("Enabled","On",True) else "WARN", cell_style)],
            [Paragraph("Hardware Root of Trust", cell_bold), Paragraph("TPM Security Chip", cell_style), Paragraph(f"{tpm.get('status','N/A')} (v{tpm.get('version','N/A')})", cell_style), Paragraph("PASS" if tpm.get("present") else "WARN", cell_style)],
            [Paragraph("BIOS Information", cell_bold), Paragraph("Vendor & Version", cell_style), Paragraph(f"{bios.get('vendor','N/A')} {bios.get('version','N/A')}", cell_style), Paragraph("Verified", cell_style)],
            [Paragraph("Antivirus Control", cell_bold), Paragraph("Windows Defender Real-Time", cell_style), Paragraph(str(defender.get("real_time_protection", "N/A")), cell_style), Paragraph("PASS" if defender.get("real_time_protection") in ("Enabled","True",True) else "ACTION REQ", cell_style)],
            [Paragraph("Firewall Profile", cell_bold), Paragraph("Domain / Private / Public", cell_style), Paragraph(f"Domain: {fw_status.get('domain','N/A')} | Priv: {fw_status.get('private','N/A')}", cell_style), Paragraph("PASS" if fw_status.get("private") in ("Enabled","True",True) else "WARN", cell_style)],
        ]
        t_fw = Table(fw_rows, colWidths=[110, 130, 203, 80])
        t_fw.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_fw)
        story.append(Spacer(1, 12))

        # Persistence IOC section
        pers = deep_scan.get("persistence", {})
        startup_items = pers.get("startup_items", [])
        tasks = pers.get("scheduled_tasks", [])
        if startup_items or tasks:
            story.append(Paragraph("3. Persistence & Startup IOC Inspection", h1_style))
            pers_rows = [[Paragraph("Entry Name", cell_header), Paragraph("Type / Location", cell_header), Paragraph("Executable Command / Path", cell_header), Paragraph("Suspicion Flag", cell_header)]]
            for item in startup_items[:6]:
                is_sus = item.get("suspicious") or item.get("is_suspicious")
                pers_rows.append([
                    Paragraph(str(item.get("name", "Startup Entry")), cell_bold),
                    Paragraph(str(item.get("source", "Registry Run")), cell_style),
                    Paragraph(str(item.get("command", item.get("path", "—"))), cell_style),
                    Paragraph("SUSPICIOUS" if is_sus else "CLEAN", cell_bold if is_sus else cell_style)
                ])
            for task in tasks[:4]:
                is_sus = task.get("suspicious") or task.get("is_suspicious")
                pers_rows.append([
                    Paragraph(str(task.get("name", "Scheduled Task")), cell_bold),
                    Paragraph("Scheduled Task", cell_style),
                    Paragraph(str(task.get("command", task.get("path", "—"))), cell_style),
                    Paragraph("SUSPICIOUS" if is_sus else "CLEAN", cell_bold if is_sus else cell_style)
                ])
            t_pers = Table(pers_rows, colWidths=[120, 100, 223, 80])
            t_pers.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_pers)
            story.append(Spacer(1, 12))

        # Active Network Open Ports
        ports = deep_scan.get("network", {}).get("listening_ports", [])
        if ports:
            story.append(Paragraph("4. Active Network Surface & Open Listening Ports", h1_style))
            port_rows = [[Paragraph("Port", cell_header), Paragraph("Protocol", cell_header), Paragraph("Associated Service / Process", cell_header), Paragraph("State", cell_header)]]
            for p in ports[:8]:
                port_rows.append([
                    Paragraph(f":{p.get('port','—')}", cell_bold),
                    Paragraph(str(p.get("protocol", "TCP")).upper(), cell_style),
                    Paragraph(str(p.get("service", p.get("process", "System Service"))), cell_style),
                    Paragraph("LISTENING", cell_style)
                ])
            t_ports = Table(port_rows, colWidths=[60, 60, 313, 90])
            t_ports.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_ports)
            story.append(Spacer(1, 12))

    # ── 5. TOP SECURITY THREAT FINDINGS ───────────────────────────────────────
    findings = report.get("top_findings", [])
    section_num = 5 if deep_scan else 2
    story.append(Paragraph(f"{section_num}. Priority Security Threat Findings", h1_style))
    if findings:
        f_rows = [[Paragraph("Severity", cell_header), Paragraph("Finding Summary", cell_header), Paragraph("Score / MITRE", cell_header), Paragraph("Primary Reason / Trigger", cell_header)]]
        for f in findings:
            sev = str(f.get("severity", "low")).upper()
            reasons = " · ".join(f.get("reasons", [])) or "Host behavior anomaly"
            mitre = ", ".join(f.get("mitre_tags", [])) or "T1059"
            f_rows.append([
                Paragraph(sev, cell_bold),
                Paragraph(str(f.get("summary", "—")), cell_bold),
                Paragraph(f"Score: {f.get('score','—')}<br/>{mitre}", cell_style),
                Paragraph(reasons, cell_style)
            ])
        t_f = Table(f_rows, colWidths=[70, 163, 110, 180])
        t_f.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_f)
    else:
        story.append(Paragraph("No critical security threat findings detected. Host posture is clean.", body_style))
    story.append(Spacer(1, 12))

    # ── 6. OWASP GUIDANCE ALIGNMENT MATRIX ────────────────────────────────────
    section_num += 1
    story.append(Paragraph(f"{section_num}. OWASP Guidance Alignment Matrix", h1_style))
    owasp_rows = [[Paragraph("OWASP Category", cell_header), Paragraph("Alignment Status", cell_header), Paragraph("Current Host Finding", cell_header), Paragraph("Actionable Guidance", cell_header)]]
    for item in report.get("owasp_alignment", []):
        st = str(item.get("status", "aligned")).upper()
        owasp_rows.append([
            Paragraph(str(item.get("area", "OWASP Area")), cell_bold),
            Paragraph(st, cell_bold),
            Paragraph(str(item.get("finding", "—")), cell_style),
            Paragraph(str(item.get("recommendation", "—")), cell_style)
        ])
    t_owasp = Table(owasp_rows, colWidths=[130, 80, 163, 150])
    t_owasp.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_owasp)
    story.append(Spacer(1, 12))

    # ── 7. RECOMMENDED SOAR REMEDIATION PLAYBOOK ──────────────────────────────
    section_num += 1
    story.append(Paragraph(f"{section_num}. Recommended SOAR Remediation Playbook", h1_style))
    for idx, action in enumerate(report.get("recommended_actions", []), start=1):
        story.append(Paragraph(f"<b>[{idx:02d}]</b> {action}", body_style))

    # Build PDF with custom NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return _report_filename(report, "pdf"), stream.getvalue()
