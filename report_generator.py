"""
Report Generator
Generates security analysis reports in multiple formats including PDF
"""

import json
import tempfile
import os
import re
from typing import List, Dict
from datetime import datetime
from analyzer_engine import Vulnerability, CodeAnalyzer

# Try to import PDF generation libraries
try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon, Circle
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except (ImportError, OSError):
    REPORTLAB_AVAILABLE = False


class TaintFlowDiagram(Flowable):
    """Custom flowable for rendering taint flow diagrams in PDF"""
    
    def __init__(self, taint_data: Dict, width=520, height=200):
        Flowable.__init__(self)
        self.taint_data = taint_data
        self.width = width
        self.height = height
    
    def wrap(self, availWidth, availHeight):
        return self.width, self.height
    
    def draw(self):
        """Draw the taint flow diagram"""
        canvas = self.canv
        data = self.taint_data
        
        # Colors
        source_bg = colors.HexColor('#fef2f2')  # Light red
        source_border = colors.HexColor('#dc2626')  # Red
        prop_bg = colors.HexColor('#fffbeb')  # Light yellow
        prop_border = colors.HexColor('#f59e0b')  # Orange
        sink_bg = colors.HexColor('#fef2f2')  # Light red
        sink_border = colors.HexColor('#dc2626')  # Red
        arrow_color = colors.HexColor('#1e3a8a')  # Dark blue
        text_color = colors.HexColor('#1f2937')  # Dark gray
        
        # Box dimensions
        box_width = 150
        box_height = 70
        y_pos = 80
        
        # Calculate positions for 3 boxes with arrows
        total_width = 3 * box_width + 2 * 40  # 40px for arrows
        start_x = (self.width - total_width) / 2
        
        # Draw title
        canvas.setFont('Helvetica-Bold', 11)
        canvas.setFillColor(colors.HexColor('#1e3a8a'))
        canvas.drawCentredString(self.width/2, self.height - 15, "TAINT DATA FLOW ANALYSIS")
        
        # ===== SOURCE BOX =====
        source_x = start_x
        # Box with shadow
        canvas.setFillColor(colors.HexColor('#e5e7eb'))
        canvas.rect(source_x + 3, y_pos - 3, box_width, box_height, fill=1, stroke=0)
        # Main box
        canvas.setFillColor(source_bg)
        canvas.setStrokeColor(source_border)
        canvas.setLineWidth(2)
        canvas.rect(source_x, y_pos, box_width, box_height, fill=1, stroke=1)
        # Header
        canvas.setFillColor(source_border)
        canvas.rect(source_x, y_pos + box_height - 18, box_width, 18, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 8)
        canvas.drawCentredString(source_x + box_width/2, y_pos + box_height - 12, "[!] TAINT SOURCE")
        # Content
        canvas.setFillColor(text_color)
        canvas.setFont('Helvetica', 7)
        # Source description
        source_desc = data.get('source', 'User Input')[:25]
        canvas.drawString(source_x + 5, y_pos + box_height - 32, source_desc)
        # Line number
        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(colors.HexColor('#6b7280'))
        canvas.drawString(source_x + 5, y_pos + box_height - 44, f"Line {data.get('source_line', '?')}")
        # Code snippet
        canvas.setFont('Courier', 6)
        canvas.setFillColor(colors.HexColor('#059669'))
        source_code = data.get('source_code', '')[:28]
        canvas.drawString(source_x + 5, y_pos + 8, source_code)
        
        # ===== ARROW 1 (Source -> Variable) =====
        arrow1_x = source_x + box_width + 5
        arrow1_end = arrow1_x + 30
        arrow_y = y_pos + box_height/2
        canvas.setStrokeColor(arrow_color)
        canvas.setFillColor(arrow_color)
        canvas.setLineWidth(2)
        canvas.line(arrow1_x, arrow_y, arrow1_end - 8, arrow_y)
        # Arrowhead
        path = canvas.beginPath()
        path.moveTo(arrow1_end - 8, arrow_y - 5)
        path.lineTo(arrow1_end, arrow_y)
        path.lineTo(arrow1_end - 8, arrow_y + 5)
        path.close()
        canvas.drawPath(path, fill=1, stroke=0)
        # Label
        canvas.setFont('Helvetica-Oblique', 6)
        canvas.drawCentredString(arrow1_x + 15, arrow_y + 10, "flows to")
        
        # ===== VARIABLE BOX =====
        var_x = arrow1_end + 5
        # Box with shadow
        canvas.setFillColor(colors.HexColor('#e5e7eb'))
        canvas.rect(var_x + 3, y_pos - 3, box_width, box_height, fill=1, stroke=0)
        # Main box
        canvas.setFillColor(prop_bg)
        canvas.setStrokeColor(prop_border)
        canvas.setLineWidth(2)
        canvas.rect(var_x, y_pos, box_width, box_height, fill=1, stroke=1)
        # Header
        canvas.setFillColor(prop_border)
        canvas.rect(var_x, y_pos + box_height - 18, box_width, 18, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 8)
        canvas.drawCentredString(var_x + box_width/2, y_pos + box_height - 12, "TAINTED VARIABLE")
        # Variable name
        canvas.setFillColor(text_color)
        canvas.setFont('Helvetica-Bold', 9)
        var_name = f"${data.get('variable', 'var')}"
        canvas.drawCentredString(var_x + box_width/2, y_pos + box_height - 35, var_name)
        # Warning
        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(colors.HexColor('#dc2626'))
        canvas.drawCentredString(var_x + box_width/2, y_pos + box_height - 48, "[!] NOT SANITIZED")
        # Propagation info
        canvas.setFont('Courier', 6)
        canvas.setFillColor(colors.HexColor('#059669'))
        prop_code = data.get('propagation_code', '')[:28]
        canvas.drawString(var_x + 5, y_pos + 8, prop_code)
        
        # ===== ARROW 2 (Variable -> Sink) =====
        arrow2_x = var_x + box_width + 5
        arrow2_end = arrow2_x + 30
        canvas.setStrokeColor(arrow_color)
        canvas.setFillColor(arrow_color)
        canvas.setLineWidth(2)
        canvas.line(arrow2_x, arrow_y, arrow2_end - 8, arrow_y)
        # Arrowhead
        path = canvas.beginPath()
        path.moveTo(arrow2_end - 8, arrow_y - 5)
        path.lineTo(arrow2_end, arrow_y)
        path.lineTo(arrow2_end - 8, arrow_y + 5)
        path.close()
        canvas.drawPath(path, fill=1, stroke=0)
        # Label
        canvas.setFont('Helvetica-Oblique', 6)
        canvas.drawCentredString(arrow2_x + 15, arrow_y + 10, "used in")
        
        # ===== SINK BOX =====
        sink_x = arrow2_end + 5
        # Box with shadow
        canvas.setFillColor(colors.HexColor('#e5e7eb'))
        canvas.rect(sink_x + 3, y_pos - 3, box_width, box_height, fill=1, stroke=0)
        # Main box
        canvas.setFillColor(sink_bg)
        canvas.setStrokeColor(sink_border)
        canvas.setLineWidth(2)
        canvas.rect(sink_x, y_pos, box_width, box_height, fill=1, stroke=1)
        # Header
        canvas.setFillColor(sink_border)
        canvas.rect(sink_x, y_pos + box_height - 18, box_width, 18, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 8)
        canvas.drawCentredString(sink_x + box_width/2, y_pos + box_height - 12, "[X] DANGEROUS SINK")
        # Sink description
        canvas.setFillColor(text_color)
        canvas.setFont('Helvetica', 7)
        sink_desc = data.get('sink', 'Dangerous Operation')[:25]
        canvas.drawString(sink_x + 5, y_pos + box_height - 32, sink_desc)
        # Line number
        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(colors.HexColor('#6b7280'))
        canvas.drawString(sink_x + 5, y_pos + box_height - 44, f"Line {data.get('sink_line', '?')}")
        # Code snippet
        canvas.setFont('Courier', 6)
        canvas.setFillColor(colors.HexColor('#dc2626'))
        sink_code = data.get('sink_code', '')[:28]
        canvas.drawString(sink_x + 5, y_pos + 8, sink_code)
        
        # ===== BOTTOM WARNING =====
        canvas.setFont('Helvetica-Bold', 9)
        canvas.setFillColor(colors.HexColor('#dc2626'))
        canvas.drawCentredString(self.width/2, 20, "[!] SECURITY VULNERABILITY: TAINTED DATA REACHES SINK WITHOUT SANITIZATION [!]")
        
        # ===== FILE INFO =====
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.HexColor('#6b7280'))
        file_info = data.get('file_path', 'unknown')
        # Extract just the filename for cleaner display
        if file_info and file_info != 'unknown':
            import os
            file_info = os.path.basename(file_info)
        if len(file_info) > 60:
            file_info = '...' + file_info[-57:]
        canvas.drawCentredString(self.width/2, 5, f"File: {file_info}")


class ReportGenerator:
    """Generates reports in various formats"""
    
    def __init__(self, analyzer: CodeAnalyzer):
        self.analyzer = analyzer
    
    def _parse_taint_info(self, vuln) -> dict:
        """Extract taint flow information from vulnerability with code snippets"""
        info = {
            'source': 'User Input',
            'variable': 'unknown',
            'sink': 'Dangerous Operation',
            'source_line': '?',
            'sink_line': str(vuln.line_number),
            'source_code': '',
            'sink_code': vuln.code_snippet.strip() if vuln.code_snippet else '',
            'propagation_code': '',
            'file_path': vuln.file_path
        }
        
        # Extract variable from matched_pattern
        if 'Taint Flow:' in vuln.matched_pattern:
            info['variable'] = vuln.matched_pattern.replace('Taint Flow: ', '').strip()
        elif vuln.matched_pattern:
            # Try to extract variable from code
            var_match = re.search(r'\$(\w+)', vuln.matched_pattern)
            if var_match:
                info['variable'] = var_match.group(1)
        
        # Parse description for source and sink info
        desc = vuln.description
        if 'from' in desc and 'flows' in desc:
            # "Tainted data from X (line Y) flows through variable 'Z' to W"
            # Extract source
            source_match = re.search(r'from\s+(.+?)\s*\(line\s+(\d+)\)', desc)
            if source_match:
                info['source'] = source_match.group(1).strip()
                info['source_line'] = source_match.group(2)
            
            # Extract sink
            sink_match = re.search(r'to\s+(.+)$', desc)
            if sink_match:
                info['sink'] = sink_match.group(1).strip()
            
            # Extract variable name from description
            var_match = re.search(r"variable\s+['\"]?(\w+)['\"]?", desc)
            if var_match:
                info['variable'] = var_match.group(1)
        
        # Try to extract source code from code snippet
        if vuln.code_snippet:
            lines = vuln.code_snippet.split('\n')
            for line in lines:
                # Look for source patterns
                if re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\[', line):
                    info['source_code'] = line.strip()[:40]
                    break
                if re.search(r'req\.(query|body|params)', line):
                    info['source_code'] = line.strip()[:40]
                    break
            
            # Get sink code (usually the last meaningful line)
            for line in reversed(lines):
                if line.strip() and not line.strip().startswith('//'):
                    info['sink_code'] = line.strip()[:40]
                    break
        
        # Generate propagation code representation
        if info['variable'] and info['variable'] != 'unknown':
            info['propagation_code'] = f"${info['variable']} = tainted_data"
        
        return info

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
            
            # Check if this is a taint-based vulnerability (has data flow info)
            is_taint_vuln = 'TAINT' in vuln.rule_id or 'Data Flow' in vuln.category
            taint_flow_diagram = ""
            
            if is_taint_vuln and 'Taint Flow:' in vuln.matched_pattern:
                # Extract taint information from description and remediation
                var_name = vuln.matched_pattern.replace('Taint Flow: ', '')
                
                # Parse source line from description
                source_line = "Unknown"
                if "line" in vuln.description:
                    import re
                    match = re.search(r'line (\d+)', vuln.description)
                    if match:
                        source_line = match.group(1)
                
                # Extract source and sink from description
                source_desc = "User Input"
                sink_desc = "Dangerous Operation"
                if " from " in vuln.description and " flows " in vuln.description:
                    parts = vuln.description.split(" flows ")
                    if len(parts) >= 2:
                        source_part = parts[0].split(" from ")[-1]
                        sink_desc = parts[1].split(" to ")[-1] if " to " in parts[1] else sink_desc
                        source_desc = source_part.split("(")[0].strip() if "(" in source_part else source_part
                
                # Generate Mermaid diagram
                mermaid_id = f"taintFlow{i}"
                taint_flow_diagram = f"""
                <div class="taint-flow-section">
                    <h4 style="color: #667eea; margin-bottom: 10px;">🔍 Data Flow Analysis</h4>
                    <div class="mermaid" id="{mermaid_id}">
                        graph LR
                            A[🌐 Taint Source<br/>{self._escape_html(source_desc)}<br/>Line {source_line}] -->|Untrusted Data| B[📦 Variable<br/>{self._escape_html(var_name)}<br/>Line {source_line}]
                            B -->|Flows To| C[⚠️ Dangerous Sink<br/>{self._escape_html(sink_desc)}<br/>Line {vuln.line_number}]
                            
                            style A fill:#ff6b6b,stroke:#c92a2a,stroke-width:3px,color:#fff
                            style B fill:#ffd93d,stroke:#f08c00,stroke-width:2px
                            style C fill:#ff6b6b,stroke:#c92a2a,stroke-width:3px,color:#fff
                    </div>
                    <div class="flow-explanation">
                        <strong>🔴 Security Risk:</strong> Untrusted data from <code>{self._escape_html(source_desc)}</code> 
                        flows through variable <code>{self._escape_html(var_name)}</code> without proper sanitization 
                        to <code>{self._escape_html(sink_desc)}</code>, creating a {vuln.rule_name.replace('Taint Analysis: ', '')} vulnerability.
                    </div>
                </div>
                """
            
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
                {taint_flow_diagram}
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
    <title>Security Analysis Report - Taint Flow Visualization</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({{ 
            startOnLoad: true,
            theme: 'default',
            securityLevel: 'loose',
            flowchart: {{
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }}
        }});
    </script>
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
        
        .taint-flow-section {{
            background: #f0f4ff;
            border: 2px solid #667eea;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        
        .taint-flow-section h4 {{
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .mermaid {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            text-align: center;
            min-height: 200px;
        }}
        
        .flow-explanation {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            line-height: 1.6;
            color: #856404;
            margin-top: 15px;
        }}
        
        .flow-explanation code {{
            background: #f8d7da;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #721c24;
            font-weight: bold;
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
    
    def generate_pdf(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        """
        Generate PDF report with proper file handling.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            output_path: Path to save PDF file (optional, creates temp file if not provided)
            
        Returns:
            Path to the generated PDF file
        """
        # Validate and normalize output path
        if output_path:
            output_path = os.path.abspath(output_path)
            # Ensure directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            # Ensure .pdf extension
            if not output_path.lower().endswith('.pdf'):
                output_path += '.pdf'
        
        # Try ReportLab first (more reliable on Windows)
        if REPORTLAB_AVAILABLE:
            try:
                return self._generate_pdf_reportlab(vulnerabilities, output_path)
            except Exception as e:
                print(f"ReportLab PDF generation failed: {e}")
                if WEASYPRINT_AVAILABLE:
                    return self._generate_pdf_weasyprint(vulnerabilities, output_path)
                raise
        elif WEASYPRINT_AVAILABLE:
            return self._generate_pdf_weasyprint(vulnerabilities, output_path)
        else:
            raise ImportError("PDF generation requires 'reportlab' or 'weasyprint'. "
                            "Install with: pip install reportlab")
    
    def _generate_pdf_weasyprint(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        """Generate PDF using WeasyPrint (converts HTML to PDF)"""
        # Generate HTML first
        html_content = self.generate_html(vulnerabilities)
        
        # Create output path if not provided
        if not output_path:
            temp_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False)
            output_path = temp_file.name
            temp_file.close()
        
        # Convert HTML to PDF
        HTML(string=html_content).write_pdf(output_path)
        
        return output_path
    
    def _generate_pdf_reportlab(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> str:
        """Generate PDF using ReportLab"""
        stats = self.analyzer.get_statistics(vulnerabilities)
        score = self.analyzer.calculate_security_score(vulnerabilities)
        
        # Create output path if not provided
        if not output_path:
            temp_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False)
            output_path = temp_file.name
            temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph("[SECURE] Security Analysis Report", title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Summary Statistics
        story.append(Paragraph("Summary", heading_style))
        summary_data = [
            ['Metric', 'Value'],
            ['Total Vulnerabilities', str(len(vulnerabilities))],
            ['Security Score', f"{score}/100"],
            ['Critical', str(stats['by_severity']['Critical'])],
            ['High', str(stats['by_severity']['High'])],
            ['Medium', str(stats['by_severity']['Medium'])],
            ['Low', str(stats['by_severity']['Low'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Vulnerabilities
        story.append(Paragraph("Vulnerabilities", heading_style))
        
        severity_colors = {
            'Critical': colors.HexColor('#dc2626'),
            'High': colors.HexColor('#ea580c'),
            'Medium': colors.HexColor('#d97706'),
            'Low': colors.HexColor('#0284c7')
        }
        
        for i, vuln in enumerate(vulnerabilities, 1):
            # Vulnerability header
            vuln_title = f"[{i}] {vuln.rule_name}"
            story.append(Paragraph(vuln_title, styles['Heading3']))
            
            # Get clean file path display (just filename for readability)
            file_display = vuln.file_path
            if file_display:
                file_display = os.path.basename(file_display)
            
            # Details table
            details_data = [
                ['Severity', vuln.severity.value],
                ['Category', vuln.category],
                ['File', file_display],
                ['Line', str(vuln.line_number)],
                ['Rule ID', vuln.rule_id]
            ]
            
            details_table = Table(details_data, colWidths=[1.5*inch, 4*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(details_table)
            story.append(Spacer(1, 0.1*inch))
            
            # Description
            story.append(Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            # Code snippet
            code_text = vuln.code_snippet.replace('<', '&lt;').replace('>', '&gt;')
            story.append(Paragraph("<b>Code:</b>", styles['Normal']))
            story.append(Paragraph(f"<pre>{code_text}</pre>", styles['Code']))
            story.append(Spacer(1, 0.1*inch))
            
            # Remediation
            story.append(Paragraph(f"<b>Remediation:</b> {vuln.remediation}", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            # Add taint flow diagram for taint-based vulnerabilities
            if 'TAINT' in vuln.rule_id or 'Data Flow' in vuln.category or 'Taint' in vuln.category:
                taint_info = self._parse_taint_info(vuln)
                if taint_info['source'] or taint_info['variable'] != 'unknown' or taint_info['sink']:
                    story.append(Spacer(1, 0.1*inch))
                    # Use the custom TaintFlowDiagram flowable
                    flow_diagram = TaintFlowDiagram(taint_info)
                    story.append(flow_diagram)
            
            story.append(Spacer(1, 0.3*inch))
            
            # Add page break after each vulnerability for better readability
            if i < len(vulnerabilities):
                story.append(PageBreak())
        
        if not vulnerabilities:
            story.append(Paragraph("[OK] No vulnerabilities detected!", styles['Normal']))
        
        # Build PDF with error handling
        try:
            doc.build(story)
        except Exception as e:
            # If build fails, try to clean up and re-raise
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            raise Exception(f"Failed to build PDF: {str(e)}")
        
        # Verify the PDF was created
        if not os.path.exists(output_path):
            raise Exception(f"PDF file was not created at: {output_path}")
        
        return output_path
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

