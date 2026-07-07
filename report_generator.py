"""
Enterprise Report Generator
Generates security reports in JSON, HTML, TXT, CSV, Markdown, and PDF formats.
"""
import json
import csv
import io
from typing import List, Dict, Any
from datetime import datetime
from analyzer_engine import Vulnerability, CodeAnalyzer


class ReportGenerator:
    def __init__(self, analyzer: CodeAnalyzer):
        self.analyzer = analyzer

    def _build_report_data(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        stats = self.analyzer.get_statistics(vulnerabilities)
        score = self.analyzer.calculate_security_score(vulnerabilities)
        grade = self.analyzer.get_security_grade(score)
        return {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'platform': 'Antigravity Secure Code Analysis Platform',
                'total_vulnerabilities': len(vulnerabilities),
                'security_score': score,
                'security_grade': grade,
            },
            'statistics': stats,
            'vulnerabilities': vulnerabilities,
            'score': score,
            'grade': grade,
        }

    # ── JSON ──────────────────────────────────────────────────────────────────
    def generate_json(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        data = self._build_report_data(vulnerabilities)
        report = {
            'metadata': data['metadata'],
            'statistics': data['statistics'],
            'vulnerabilities': [
                {
                    'rule_id': v.rule_id, 'rule_name': v.rule_name,
                    'category': v.category,
                    'severity': v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
                    'file_path': v.file_path, 'line_number': v.line_number,
                    'line_end': v.line_end, 'code_snippet': v.code_snippet,
                    'description': v.description, 'remediation': v.remediation,
                    'match_type': v.match_type,
                    'cwe': getattr(v, 'cwe', ''), 'owasp': getattr(v, 'owasp', ''),
                }
                for v in vulnerabilities
            ]
        }
        json_str = json.dumps(report, indent=2)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
        return json_str

    # ── CSV ───────────────────────────────────────────────────────────────────
    def generate_csv(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        output = io.StringIO()
        fieldnames = [
            'rule_id', 'rule_name', 'category', 'severity',
            'file_path', 'line_number', 'line_end', 'description',
            'remediation', 'match_type', 'cwe', 'owasp'
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for v in vulnerabilities:
            writer.writerow({
                'rule_id': v.rule_id,
                'rule_name': v.rule_name,
                'category': v.category,
                'severity': v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
                'file_path': v.file_path,
                'line_number': v.line_number,
                'line_end': v.line_end or '',
                'description': v.description,
                'remediation': v.remediation,
                'match_type': v.match_type,
                'cwe': getattr(v, 'cwe', ''),
                'owasp': getattr(v, 'owasp', ''),
            })
        csv_str = output.getvalue()
        if output_path:
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                f.write(csv_str)
        return csv_str

    # ── Markdown ──────────────────────────────────────────────────────────────
    def generate_markdown(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        data = self._build_report_data(vulnerabilities)
        stats = data['statistics']
        score = data['score']
        grade = data['grade']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        severity_emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Informational': '🔵'}

        lines = [
            "# 🔒 Security Analysis Report",
            "",
            f"> **Generated:** {now}  ",
            f"> **Platform:** Antigravity Secure Code Analysis Platform  ",
            f"> **Security Score:** {score}/100 — Grade **{grade}**",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Vulnerabilities | {len(vulnerabilities)} |",
            f"| Critical | {stats['by_severity']['Critical']} |",
            f"| High | {stats['by_severity']['High']} |",
            f"| Medium | {stats['by_severity']['Medium']} |",
            f"| Low | {stats['by_severity']['Low']} |",
            f"| Security Score | {score}/100 |",
            f"| Security Grade | {grade} |",
            "",
            "---",
            "",
            "## 🔍 Vulnerability Details",
            "",
        ]

        if not vulnerabilities:
            lines.append("✅ **No vulnerabilities detected! Great job.**")
        else:
            for i, v in enumerate(vulnerabilities, 1):
                sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
                emoji = severity_emoji.get(sev, '⚪')
                line_range = f"{v.line_number}" + (f"–{v.line_end}" if v.line_end else "")
                lines += [
                    f"### {emoji} [{i}] {v.rule_name}",
                    "",
                    f"- **Severity:** `{sev}`",
                    f"- **Category:** `{v.category}`",
                    f"- **Rule ID:** `{v.rule_id}`",
                    f"- **File:** `{v.file_path}`",
                    f"- **Line:** `{line_range}`",
                    f"- **CWE:** `{getattr(v, 'cwe', 'N/A')}`",
                    "",
                    f"**Description:** {v.description}",
                    "",
                    "**Vulnerable Code:**",
                    "```",
                    v.code_snippet,
                    "```",
                    "",
                    f"**✅ Remediation:** {v.remediation}",
                    "",
                    "---",
                    "",
                ]

        md = '\n'.join(lines)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md)
        return md

    # ── HTML ──────────────────────────────────────────────────────────────────
    def generate_html(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        data = self._build_report_data(vulnerabilities)
        stats = data['statistics']
        score = data['score']
        grade = data['grade']

        severity_colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#17a2b8'}
        score_color = '#28a745' if score >= 80 else '#ffc107' if score >= 60 else '#dc3545'

        stats_html = f"""
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value">{len(vulnerabilities)}</div><div class="stat-label">Total Issues</div></div>
            <div class="stat-card"><div class="stat-value" style="color:{severity_colors['Critical']}">{stats['by_severity']['Critical']}</div><div class="stat-label">Critical</div></div>
            <div class="stat-card"><div class="stat-value" style="color:{severity_colors['High']}">{stats['by_severity']['High']}</div><div class="stat-label">High</div></div>
            <div class="stat-card"><div class="stat-value" style="color:{severity_colors['Medium']}">{stats['by_severity']['Medium']}</div><div class="stat-label">Medium</div></div>
            <div class="stat-card"><div class="stat-value" style="color:{severity_colors['Low']}">{stats['by_severity']['Low']}</div><div class="stat-label">Low</div></div>
            <div class="stat-card score-card"><div class="stat-value" style="color:{score_color}">{score}</div><div class="stat-label">Score / 100</div></div>
            <div class="stat-card score-card"><div class="stat-value" style="font-size:2.5em;color:{score_color}">{grade}</div><div class="stat-label">Grade</div></div>
        </div>"""

        vulns_html = ""
        for i, v in enumerate(vulnerabilities, 1):
            sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            sc = severity_colors.get(sev, '#000')
            lr = f"{v.line_number}" + (f"-{v.line_end}" if v.line_end else "")
            vulns_html += f"""
            <div class="vulnerability-card" style="border-left-color:{sc}">
                <div class="vuln-header">
                    <span class="vuln-number">#{i}</span>
                    <span class="vuln-severity" style="background:{sc}">{sev}</span>
                    <span class="vuln-category">{v.category}</span>
                    <span class="vuln-rule-id">{v.rule_id}</span>
                </div>
                <div class="vuln-title">{v.rule_name}</div>
                <div class="vuln-meta">
                    <span><strong>File:</strong> {v.file_path}</span>
                    <span><strong>Line:</strong> {lr}</span>
                    <span><strong>CWE:</strong> {getattr(v,'cwe','N/A')}</span>
                </div>
                <div class="vuln-description"><strong>Description:</strong> {v.description}</div>
                <div class="vuln-code"><pre><code>{self._escape_html(v.code_snippet)}</code></pre></div>
                <div class="vuln-remediation"><strong>✅ Remediation:</strong> {v.remediation}</div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report — Antigravity</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:linear-gradient(135deg,#0f0c29,#302b63,#24243e); padding:20px; color:#333; min-height:100vh; }}
        .container {{ max-width:1100px; margin:0 auto; background:#fff; border-radius:20px; box-shadow:0 20px 60px rgba(0,0,0,.4); overflow:hidden; }}
        .header {{ background:linear-gradient(135deg,#007AFF,#8B5CF6); color:white; padding:40px; text-align:center; }}
        .header h1 {{ font-size:2.5em; margin-bottom:8px; letter-spacing:-0.5px; }}
        .header p {{ opacity:.85; font-size:1.05em; }}
        .content {{ padding:40px; }}
        .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:16px; margin-bottom:40px; }}
        .stat-card {{ background:#f5f7fb; padding:20px; border-radius:14px; text-align:center; box-shadow:0 2px 8px rgba(0,0,0,.07); }}
        .score-card {{ background:linear-gradient(135deg,#e0f7fa,#e8eaf6); }}
        .stat-value {{ font-size:2em; font-weight:800; color:#1a1a2e; margin-bottom:4px; }}
        .stat-label {{ color:#666; font-size:.82em; text-transform:uppercase; letter-spacing:.8px; font-weight:600; }}
        .vulnerability-card {{ background:#f9fafb; border-left:4px solid #007AFF; padding:24px; margin-bottom:24px; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,.06); }}
        .vuln-header {{ display:flex; align-items:center; gap:10px; margin-bottom:12px; flex-wrap:wrap; }}
        .vuln-number {{ background:#007AFF; color:white; padding:4px 12px; border-radius:20px; font-weight:700; font-size:.85em; }}
        .vuln-severity {{ color:white; padding:4px 12px; border-radius:20px; font-weight:700; text-transform:uppercase; font-size:.78em; }}
        .vuln-category {{ background:#e9ecef; padding:4px 12px; border-radius:20px; font-size:.84em; color:#495057; font-weight:600; }}
        .vuln-rule-id {{ background:#f0f0f0; padding:4px 10px; border-radius:8px; font-size:.78em; color:#666; font-family:monospace; }}
        .vuln-title {{ font-size:1.2em; font-weight:700; color:#111; margin-bottom:12px; }}
        .vuln-meta {{ display:flex; gap:20px; margin-bottom:12px; flex-wrap:wrap; font-size:.88em; color:#555; }}
        .vuln-description {{ margin-bottom:12px; line-height:1.6; color:#444; }}
        .vuln-code {{ background:#1a1a2e; color:#e0e0e0; padding:14px; border-radius:10px; margin-bottom:12px; overflow-x:auto; }}
        .vuln-code pre {{ margin:0; font-family:'Courier New',monospace; font-size:.88em; line-height:1.5; }}
        .vuln-remediation {{ background:#d4edda; border-left:4px solid #28a745; padding:14px; border-radius:6px; line-height:1.6; color:#155724; font-size:.92em; }}
        .footer {{ text-align:center; padding:20px; color:#888; font-size:.85em; border-top:1px solid #f0f0f0; }}
        @media(max-width:640px) {{ .header h1 {{ font-size:1.7em; }} .content {{ padding:20px; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Analysis Report</h1>
            <p>Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · Antigravity Secure Code Analysis Platform</p>
        </div>
        <div class="content">
            {stats_html}
            <h2 style="margin:32px 0 20px;color:#1a1a2e;font-size:1.6em;">Vulnerability Findings</h2>
            {vulns_html if vulns_html else '<p style="color:#28a745;font-size:1.2em;text-align:center;padding:40px;">✅ No vulnerabilities detected!</p>'}
        </div>
        <div class="footer">Antigravity Secure Code Analysis Platform · OWASP Top 10 · 26 Languages Supported</div>
    </div>
</body>
</html>"""

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
        return html

    # ── TXT ───────────────────────────────────────────────────────────────────
    def generate_txt(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        data = self._build_report_data(vulnerabilities)
        stats = data['statistics']
        score = data['score']
        grade = data['grade']

        lines = [
            "=" * 80,
            "ANTIGRAVITY SECURE CODE ANALYSIS — SECURITY REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 80,
            f"Total Vulnerabilities : {len(vulnerabilities)}",
            f"Security Score        : {score}/100",
            f"Security Grade        : {grade}",
            "",
            "BY SEVERITY:",
            f"  Critical : {stats['by_severity']['Critical']}",
            f"  High     : {stats['by_severity']['High']}",
            f"  Medium   : {stats['by_severity']['Medium']}",
            f"  Low      : {stats['by_severity']['Low']}",
            "",
            "BY CATEGORY:",
        ]
        for category, count in sorted(stats['by_category'].items()):
            lines.append(f"  {category}: {count}")

        lines += ["", "=" * 80, "DETAILED FINDINGS", "=" * 80, ""]

        for i, v in enumerate(vulnerabilities, 1):
            sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            lr = f"{v.line_number}" + (f"-{v.line_end}" if v.line_end else "")
            lines += [
                f"[{i}] {v.rule_name}",
                f"    Severity    : {sev}",
                f"    Category    : {v.category}",
                f"    Rule ID     : {v.rule_id}",
                f"    File        : {v.file_path}",
                f"    Line(s)     : {lr}",
                f"    CWE         : {getattr(v, 'cwe', 'N/A')}",
                f"    Description : {v.description}",
                "    Code:",
            ]
            for cl in v.code_snippet.split('\n'):
                lines.append(f"      {cl}")
            lines += [f"    Remediation : {v.remediation}", "-" * 80, ""]

        if not vulnerabilities:
            lines.append("✅ No vulnerabilities detected!")

        txt = '\n'.join(lines)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(txt)
        return txt

    # ── PDF ───────────────────────────────────────────────────────────────────
    def generate_pdf(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> bytes:
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            raise ImportError("reportlab is required for PDF generation. Run: pip install reportlab")

        data = self._build_report_data(vulnerabilities)
        stats = data['statistics']
        score = data['score']
        grade = data['grade']

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                topMargin=0.75*inch, bottomMargin=0.75*inch,
                                leftMargin=0.85*inch, rightMargin=0.85*inch)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=22,
                                     textColor=colors.HexColor('#007AFF'), spaceAfter=6, alignment=TA_CENTER)
        h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14,
                                  textColor=colors.HexColor('#1a1a2e'), spaceBefore=16, spaceAfter=6)
        body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, leading=13, spaceAfter=4)
        code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, leading=11,
                                    backColor=colors.HexColor('#1a1a2e'),
                                    textColor=colors.HexColor('#e0e0e0'),
                                    fontName='Courier', leftIndent=8, rightIndent=8, spaceAfter=6)

        sev_colors = {
            'Critical': colors.HexColor('#dc3545'),
            'High': colors.HexColor('#fd7e14'),
            'Medium': colors.HexColor('#ffc107'),
            'Low': colors.HexColor('#17a2b8'),
        }

        story = []

        # Title
        story.append(Paragraph("🔒 Security Analysis Report", title_style))
        story.append(Paragraph(f"Antigravity Secure Code Analysis Platform", styles['Normal']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#007AFF')))
        story.append(Spacer(1, 0.2*inch))

        # Executive Summary Table
        story.append(Paragraph("Executive Summary", h2_style))
        summary_data = [
            ['Metric', 'Value'],
            ['Total Vulnerabilities', str(len(vulnerabilities))],
            ['Critical', str(stats['by_severity']['Critical'])],
            ['High', str(stats['by_severity']['High'])],
            ['Medium', str(stats['by_severity']['Medium'])],
            ['Low', str(stats['by_severity']['Low'])],
            ['Security Score', f"{score}/100"],
            ['Security Grade', grade],
        ]
        table = Table(summary_data, colWidths=[3*inch, 2.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007AFF')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f9fafb'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.3*inch))

        # Findings
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e0e0e0')))
        story.append(Paragraph("Vulnerability Findings", h2_style))

        if not vulnerabilities:
            story.append(Paragraph("✅ No vulnerabilities detected!", body_style))
        else:
            for i, v in enumerate(vulnerabilities, 1):
                sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
                sc = sev_colors.get(sev, colors.black)
                lr = f"{v.line_number}" + (f"–{v.line_end}" if v.line_end else "")

                finding_data = [
                    [f'#{i} — {v.rule_name}', f'Severity: {sev}'],
                    [f'Rule: {v.rule_id}', f'Category: {v.category}'],
                    [f'File: {v.file_path}', f'Line: {lr}'],
                ]
                ft = Table(finding_data, colWidths=[3.5*inch, 2.5*inch])
                ft.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), sc),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8.5),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9fafb')),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(ft)
                story.append(Spacer(1, 4))
                story.append(Paragraph(f"<b>Description:</b> {v.description}", body_style))
                snippet = v.code_snippet[:400] + ('...' if len(v.code_snippet) > 400 else '')
                story.append(Paragraph(snippet.replace('\n', '<br/>'), code_style))
                story.append(Paragraph(f"<b>Remediation:</b> {v.remediation}", body_style))
                story.append(Spacer(1, 0.15*inch))

        doc.build(story)
        pdf_bytes = buf.getvalue()

        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)

        return pdf_bytes

    def _escape_html(self, text: str) -> str:
        return (text.replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))
