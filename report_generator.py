"""
Report Generator
Generates security analysis reports in multiple formats
"""

import json
from typing import List, Dict
from datetime import datetime
from analyzer_engine import Vulnerability, CodeAnalyzer


class ReportGenerator:
    """Generates reports in various formats"""
    
    def __init__(self, analyzer: CodeAnalyzer):
        self.analyzer = analyzer
    
    def generate_json(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        """Generate JSON report"""
        stats = self.analyzer.get_statistics(vulnerabilities)
        score = self.analyzer.calculate_security_score(vulnerabilities)
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'security_score': score
            },
            'statistics': stats,
            'vulnerabilities': [
                {
                    'rule_id': v.rule_id,
                    'rule_name': v.rule_name,
                    'category': v.category,
                    'severity': v.severity.value,
                    'file_path': v.file_path,
                    'line_number': v.line_number,
                    'code_snippet': v.code_snippet,
                    'description': v.description,
                    'remediation': v.remediation,
                    'matched_pattern': v.matched_pattern
                }
                for v in vulnerabilities
            ]
        }
        
        json_str = json.dumps(report, indent=2)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
        
        return json_str
    
    def generate_html(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        """Generate HTML report with professional styling"""
        stats = self.analyzer.get_statistics(vulnerabilities)
        score = self.analyzer.calculate_security_score(vulnerabilities)
        
        # Severity color mapping
        severity_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#17a2b8'
        }
        
        # Generate statistics HTML
        stats_html = f"""
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{len(vulnerabilities)}</div>
                <div class="stat-label">Total Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {severity_colors.get('Critical', '#000')}">{stats['by_severity']['Critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {severity_colors.get('High', '#000')}">{stats['by_severity']['High']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {severity_colors.get('Medium', '#000')}">{stats['by_severity']['Medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {severity_colors.get('Low', '#000')}">{stats['by_severity']['Low']}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card score-card">
                <div class="stat-value" style="font-size: 2.5em; color: {'#28a745' if score >= 80 else '#ffc107' if score >= 60 else '#dc3545'}">{score}</div>
                <div class="stat-label">Security Score</div>
            </div>
        </div>
        """
        
        # Generate vulnerabilities HTML
        vulns_html = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = severity_colors.get(vuln.severity.value, '#000')
            vulns_html += f"""
            <div class="vulnerability-card">
                <div class="vuln-header">
                    <span class="vuln-number">#{i}</span>
                    <span class="vuln-severity" style="background-color: {severity_color}">{vuln.severity.value}</span>
                    <span class="vuln-category">{vuln.category}</span>
                </div>
                <div class="vuln-title">{vuln.rule_name}</div>
                <div class="vuln-meta">
                    <span><strong>File:</strong> {vuln.file_path}</span>
                    <span><strong>Line:</strong> {vuln.line_number}</span>
                    <span><strong>Rule ID:</strong> {vuln.rule_id}</span>
                </div>
                <div class="vuln-description">
                    <strong>Description:</strong> {vuln.description}
                </div>
                <div class="vuln-code">
                    <pre><code>{self._escape_html(vuln.code_snippet)}</code></pre>
                </div>
                <div class="vuln-remediation">
                    <strong>Remediation:</strong> {vuln.remediation}
                </div>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .score-card {{
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        }}
        
        .vulnerability-card {{
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .vuln-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        
        .vuln-number {{
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
        }}
        
        .vuln-severity {{
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.85em;
        }}
        
        .vuln-category {{
            background: #e9ecef;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            color: #495057;
        }}
        
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #333;
            margin-bottom: 15px;
        }}
        
        .vuln-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            flex-wrap: wrap;
            font-size: 0.9em;
            color: #666;
        }}
        
        .vuln-description {{
            margin-bottom: 15px;
            line-height: 1.6;
            color: #495057;
        }}
        
        .vuln-code {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow-x: auto;
        }}
        
        .vuln-code pre {{
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
        }}
        
        .vuln-remediation {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            border-radius: 5px;
            line-height: 1.6;
            color: #155724;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .content {{
                padding: 20px;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Analysis Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="content">
            {stats_html}
            <h2 style="margin-top: 40px; margin-bottom: 20px; color: #333;">Vulnerabilities</h2>
            {vulns_html if vulns_html else '<p style="color: #28a745; font-size: 1.2em; text-align: center; padding: 40px;">✅ No vulnerabilities detected!</p>'}
        </div>
        <div class="footer">
            <p>Generated by Secure Code Analyzer | OWASP Top 10 Compliance</p>
        </div>
    </div>
</body>
</html>"""
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
        
        return html
    
    def generate_txt(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        """Generate plain text report"""
        stats = self.analyzer.get_statistics(vulnerabilities)
        score = self.analyzer.calculate_security_score(vulnerabilities)
        
        lines = []
        lines.append("=" * 80)
        lines.append("SECURITY ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Vulnerabilities: {len(vulnerabilities)}")
        lines.append(f"Security Score: {score}/100")
        lines.append("")
        lines.append("BY SEVERITY:")
        lines.append(f"  Critical: {stats['by_severity']['Critical']}")
        lines.append(f"  High:     {stats['by_severity']['High']}")
        lines.append(f"  Medium:   {stats['by_severity']['Medium']}")
        lines.append(f"  Low:      {stats['by_severity']['Low']}")
        lines.append("")
        lines.append("BY CATEGORY:")
        for category, count in sorted(stats['by_category'].items()):
            lines.append(f"  {category}: {count}")
        lines.append("")
        lines.append("=" * 80)
        lines.append("VULNERABILITIES")
        lines.append("=" * 80)
        lines.append("")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            lines.append(f"[{i}] {vuln.rule_name}")
            lines.append(f"    Severity: {vuln.severity.value}")
            lines.append(f"    Category:  {vuln.category}")
            lines.append(f"    Rule ID:   {vuln.rule_id}")
            lines.append(f"    File:      {vuln.file_path}")
            lines.append(f"    Line:      {vuln.line_number}")
            lines.append(f"    Description: {vuln.description}")
            lines.append("    Code:")
            for code_line in vuln.code_snippet.split('\n'):
                lines.append(f"      {code_line}")
            lines.append(f"    Remediation: {vuln.remediation}")
            lines.append("-" * 80)
            lines.append("")
        
        if not vulnerabilities:
            lines.append("✅ No vulnerabilities detected!")
            lines.append("")
        
        txt = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(txt)
        
        return txt
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

