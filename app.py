import os
import json
import tempfile
import shutil
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import requests as http_requests

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from analyzer_engine import CodeAnalyzer, Vulnerability, Severity, ALL_SUPPORTED_EXTENSIONS, DOCKERFILE_NAMES
from report_generator import ReportGenerator
from secret_detector import scan_content_for_secrets, scan_file_for_secrets, secret_findings_to_vulnerabilities
from dependency_scanner import scan_manifest_file, dependency_findings_to_dicts, is_manifest_file, MANIFEST_FILES

# ── Gemini Configuration ──────────────────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if GEMINI_AVAILABLE and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='frontend/dist', static_url_path='/')
CORS(app)

UPLOAD_FOLDER = tempfile.gettempdir()
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB for ZIP files

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

analyzer = CodeAnalyzer(enable_multi_line=True)
report_generator = ReportGenerator(analyzer)

# Scan history file
HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'scan_history.json')


def _load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_history(entry: dict):
    history = _load_history()
    history.insert(0, entry)
    history = history[:50]  # Keep last 50 scans
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)


def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        'rule_id': v.rule_id, 'rule_name': v.rule_name,
        'category': v.category,
        'severity': v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
        'file_path': v.file_path, 'line_number': v.line_number,
        'line_end': v.line_end, 'code_snippet': v.code_snippet,
        'description': v.description, 'remediation': v.remediation,
        'match_type': v.match_type,
        'cwe': getattr(v, 'cwe', ''), 'owasp': getattr(v, 'owasp', ''),
    }


def _build_vuln_from_dict(v_data: dict) -> Vulnerability:
    return Vulnerability(
        rule_id=v_data['rule_id'], rule_name=v_data['rule_name'],
        category=v_data['category'],
        severity=Severity(v_data['severity']),
        file_path=v_data['file_path'], line_number=v_data['line_number'],
        line_end=v_data.get('line_end'),
        code_snippet=v_data['code_snippet'], description=v_data['description'],
        remediation=v_data['remediation'], matched_pattern='',
        match_type=v_data.get('match_type', 'single-line'),
        cwe=v_data.get('cwe', ''), owasp=v_data.get('owasp', ''),
    )


# ── Static / index ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    try:
        return app.send_static_file('index.html')
    except Exception:
        return jsonify({'error': 'Frontend not built. Run: cd frontend && npm run build'}), 404


# ── Health ────────────────────────────────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'Antigravity Secure Code Analysis Platform',
        'version': '3.0',
        'gemini_available': GEMINI_AVAILABLE,
        'features': {
            'multi_line_analysis': True,
            'secret_detection': True,
            'dependency_scanning': True,
            'zip_upload': True,
            'repo_scanning': True,
            'languages_supported': 26,
            'report_formats': ['json', 'html', 'txt', 'csv', 'markdown', 'pdf'],
        }
    })


# ── Single File Analysis ──────────────────────────────────────────────────────
@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        enable_multi_line = request.form.get('enable_multi_line', 'true').lower() == 'true'
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            analyzer.enable_multi_line = enable_multi_line
            content = open(filepath, 'r', encoding='utf-8', errors='ignore').read()

            # SAST analysis
            vulnerabilities = analyzer.analyze_file(filepath)

            # Secret detection
            secret_findings = scan_file_for_secrets(filepath)
            secret_dicts = secret_findings_to_vulnerabilities(secret_findings)
            for sd in secret_dicts:
                vulnerabilities.append(Vulnerability(
                    rule_id=sd['rule_id'], rule_name=sd['rule_name'],
                    category=sd['category'], severity=Severity(sd['severity']),
                    file_path=sd['file_path'], line_number=sd['line_number'],
                    code_snippet=sd['code_snippet'], description=sd['description'],
                    remediation=sd['remediation'], matched_pattern='', match_type='secret',
                ))

            # Dependency scanning (if it's a manifest file)
            if is_manifest_file(filename):
                dep_findings = scan_manifest_file(filepath)
                dep_dicts = dependency_findings_to_dicts(dep_findings)
                for dd in dep_dicts:
                    vulnerabilities.append(Vulnerability(
                        rule_id=dd['rule_id'], rule_name=dd['rule_name'],
                        category=dd['category'], severity=Severity(dd['severity']),
                        file_path=dd['file_path'], line_number=dd['line_number'],
                        code_snippet=dd['code_snippet'], description=dd['description'],
                        remediation=dd['remediation'], matched_pattern='', match_type='dependency',
                    ))

            stats = analyzer.get_statistics(vulnerabilities, {'files_scanned': 1})
            score = analyzer.calculate_security_score(vulnerabilities)
            grade = analyzer.get_security_grade(score)

            vuln_list = [_vuln_to_dict(v) for v in vulnerabilities]

            _save_history({
                'id': datetime.now().strftime('%Y%m%d%H%M%S'),
                'scan_type': 'single_file',
                'source': filename,
                'timestamp': datetime.now().isoformat(),
                'total': len(vulnerabilities),
                'score': score,
                'grade': grade,
                'critical': stats['by_severity']['Critical'],
                'high': stats['by_severity']['High'],
            })

            return jsonify({
                'success': True, 'filename': filename,
                'statistics': stats, 'security_score': score, 'grade': grade,
                'enable_multi_line': analyzer.enable_multi_line,
                'vulnerabilities': vuln_list,
            })
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Multi-File Upload ─────────────────────────────────────────────────────────
@app.route('/api/analyze-multi', methods=['POST'])
def analyze_multi():
    try:
        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': 'No files provided'}), 400

        all_vulns = []
        file_list = []
        tmp_dir = tempfile.mkdtemp()

        try:
            for file in files:
                if file.filename == '':
                    continue
                filename = secure_filename(file.filename)
                filepath = os.path.join(tmp_dir, filename)
                file.save(filepath)
                file_list.append(filename)

                # SAST
                try:
                    vulns = analyzer.analyze_file(filepath)
                    all_vulns.extend(vulns)
                except Exception:
                    pass
                # Secrets
                secrets = scan_file_for_secrets(filepath)
                for sd in secret_findings_to_vulnerabilities(secrets):
                    all_vulns.append(Vulnerability(
                        rule_id=sd['rule_id'], rule_name=sd['rule_name'],
                        category=sd['category'], severity=Severity(sd['severity']),
                        file_path=filename, line_number=sd['line_number'],
                        code_snippet=sd['code_snippet'], description=sd['description'],
                        remediation=sd['remediation'], matched_pattern='', match_type='secret',
                    ))
                # Dependencies
                if is_manifest_file(filename):
                    for dd in dependency_findings_to_dicts(scan_manifest_file(filepath)):
                        all_vulns.append(Vulnerability(
                            rule_id=dd['rule_id'], rule_name=dd['rule_name'],
                            category=dd['category'], severity=Severity(dd['severity']),
                            file_path=filename, line_number=dd['line_number'],
                            code_snippet=dd['code_snippet'], description=dd['description'],
                            remediation=dd['remediation'], matched_pattern='', match_type='dependency',
                        ))
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        stats = analyzer.get_statistics(all_vulns, {'files_scanned': len(file_list)})
        score = analyzer.calculate_security_score(all_vulns)
        grade = analyzer.get_security_grade(score)

        _save_history({
            'id': datetime.now().strftime('%Y%m%d%H%M%S'),
            'scan_type': 'multi_file',
            'source': f"{len(file_list)} files",
            'timestamp': datetime.now().isoformat(),
            'total': len(all_vulns), 'score': score, 'grade': grade,
            'critical': stats['by_severity']['Critical'],
            'high': stats['by_severity']['High'],
        })

        return jsonify({
            'success': True, 'files_scanned': file_list,
            'statistics': stats, 'security_score': score, 'grade': grade,
            'vulnerabilities': [_vuln_to_dict(v) for v in all_vulns],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── ZIP Upload ────────────────────────────────────────────────────────────────
@app.route('/api/analyze-zip', methods=['POST'])
def analyze_zip():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        filename = secure_filename(file.filename)
        tmp_path = os.path.join(tempfile.gettempdir(), filename)
        file.save(tmp_path)

        try:
            vulns, file_list, extract_dir = analyzer.analyze_zip(tmp_path)

            # Run secret detection and dep scanning on extracted files
            for root, _, files in os.walk(extract_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, extract_dir)
                    # Secrets
                    for sd in secret_findings_to_vulnerabilities(scan_file_for_secrets(fpath)):
                        sd['file_path'] = rel
                        vulns.append(Vulnerability(
                            rule_id=sd['rule_id'], rule_name=sd['rule_name'],
                            category=sd['category'], severity=Severity(sd['severity']),
                            file_path=rel, line_number=sd['line_number'],
                            code_snippet=sd['code_snippet'], description=sd['description'],
                            remediation=sd['remediation'], matched_pattern='', match_type='secret',
                        ))
                    # Deps
                    if is_manifest_file(f):
                        for dd in dependency_findings_to_dicts(scan_manifest_file(fpath)):
                            dd['file_path'] = rel
                            vulns.append(Vulnerability(
                                rule_id=dd['rule_id'], rule_name=dd['rule_name'],
                                category=dd['category'], severity=Severity(dd['severity']),
                                file_path=rel, line_number=dd['line_number'],
                                code_snippet=dd['code_snippet'], description=dd['description'],
                                remediation=dd['remediation'], matched_pattern='', match_type='dependency',
                            ))
            shutil.rmtree(extract_dir, ignore_errors=True)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        stats = analyzer.get_statistics(vulns, {'files_scanned': len(file_list)})
        score = analyzer.calculate_security_score(vulns)
        grade = analyzer.get_security_grade(score)

        _save_history({
            'id': datetime.now().strftime('%Y%m%d%H%M%S'),
            'scan_type': 'zip',
            'source': filename,
            'timestamp': datetime.now().isoformat(),
            'total': len(vulns), 'score': score, 'grade': grade,
            'critical': stats['by_severity']['Critical'],
            'high': stats['by_severity']['High'],
        })

        return jsonify({
            'success': True, 'archive_name': filename,
            'files_scanned': file_list, 'file_count': len(file_list),
            'statistics': stats, 'security_score': score, 'grade': grade,
            'vulnerabilities': [_vuln_to_dict(v) for v in vulns],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Repository Scan ───────────────────────────────────────────────────────────
@app.route('/api/analyze-repo', methods=['POST'])
def analyze_repo():
    try:
        data = request.get_json()
        repo_url = (data or {}).get('url', '').strip()
        if not repo_url:
            return jsonify({'error': 'No repository URL provided'}), 400

        # Basic URL validation
        if not any(host in repo_url for host in ['github.com', 'gitlab.com', 'bitbucket.org']):
            return jsonify({'error': 'Only GitHub, GitLab, and Bitbucket URLs are supported'}), 400

        vulns, file_list, clone_dir = analyzer.analyze_repo(repo_url)

        # Secret + dep scanning
        for root, _, files in os.walk(clone_dir):
            for f in files:
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, clone_dir)
                for sd in secret_findings_to_vulnerabilities(scan_file_for_secrets(fpath)):
                    vulns.append(Vulnerability(
                        rule_id=sd['rule_id'], rule_name=sd['rule_name'],
                        category=sd['category'], severity=Severity(sd['severity']),
                        file_path=rel, line_number=sd['line_number'],
                        code_snippet=sd['code_snippet'], description=sd['description'],
                        remediation=sd['remediation'], matched_pattern='', match_type='secret',
                    ))
                if is_manifest_file(f):
                    for dd in dependency_findings_to_dicts(scan_manifest_file(fpath)):
                        vulns.append(Vulnerability(
                            rule_id=dd['rule_id'], rule_name=dd['rule_name'],
                            category=dd['category'], severity=Severity(dd['severity']),
                            file_path=rel, line_number=dd['line_number'],
                            code_snippet=dd['code_snippet'], description=dd['description'],
                            remediation=dd['remediation'], matched_pattern='', match_type='dependency',
                        ))
        shutil.rmtree(clone_dir, ignore_errors=True)

        stats = analyzer.get_statistics(vulns, {'files_scanned': len(file_list)})
        score = analyzer.calculate_security_score(vulns)
        grade = analyzer.get_security_grade(score)

        _save_history({
            'id': datetime.now().strftime('%Y%m%d%H%M%S'),
            'scan_type': 'repository',
            'source': repo_url,
            'timestamp': datetime.now().isoformat(),
            'total': len(vulns), 'score': score, 'grade': grade,
            'critical': stats['by_severity']['Critical'],
            'high': stats['by_severity']['High'],
        })

        return jsonify({
            'success': True, 'repo_url': repo_url,
            'files_scanned': file_list, 'file_count': len(file_list),
            'statistics': stats, 'security_score': score, 'grade': grade,
            'vulnerabilities': [_vuln_to_dict(v) for v in vulns],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Text / Paste Analysis ─────────────────────────────────────────────────────
@app.route('/api/analyze-text', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({'error': 'No code provided'}), 400

        code = data['code']
        language = data.get('language', 'javascript')
        filename = data.get('filename', f'input.{language}')
        enable_multi_line = data.get('enable_multi_line', True)
        analyzer.enable_multi_line = enable_multi_line

        vulnerabilities = analyzer.analyze_code_string(code, language, filename)

        # Secrets on pasted code
        for sd in secret_findings_to_vulnerabilities(scan_content_for_secrets(code, filename)):
            vulnerabilities.append(Vulnerability(
                rule_id=sd['rule_id'], rule_name=sd['rule_name'],
                category=sd['category'], severity=Severity(sd['severity']),
                file_path=filename, line_number=sd['line_number'],
                code_snippet=sd['code_snippet'], description=sd['description'],
                remediation=sd['remediation'], matched_pattern='', match_type='secret',
            ))

        stats = analyzer.get_statistics(vulnerabilities, {'files_scanned': 1})
        score = analyzer.calculate_security_score(vulnerabilities)
        grade = analyzer.get_security_grade(score)

        return jsonify({
            'success': True, 'filename': filename,
            'statistics': stats, 'security_score': score, 'grade': grade,
            'vulnerabilities': [_vuln_to_dict(v) for v in vulnerabilities],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Scan History ──────────────────────────────────────────────────────────────
@app.route('/api/scan-history', methods=['GET'])
def scan_history():
    return jsonify({'success': True, 'history': _load_history()})


@app.route('/api/scan-history', methods=['DELETE'])
def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    return jsonify({'success': True, 'message': 'History cleared'})


# ── Report Endpoints ──────────────────────────────────────────────────────────
def _parse_vulns_from_request() -> list:
    data = request.get_json()
    return [_build_vuln_from_dict(v) for v in (data or {}).get('vulnerabilities', [])]


def _send_temp_file(content, suffix, download_name, mimetype):
    """Write content to a temp file and send it as a download attachment."""
    import io
    from flask import Response
    if isinstance(content, str):
        # Add BOM for CSV so Excel opens it correctly with UTF-8
        if suffix == '.csv':
            content = '\ufeff' + content
        file_bytes = content.encode('utf-8')
    else:
        file_bytes = content
    response = Response(
        file_bytes,
        status=200,
        mimetype=mimetype,
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{download_name}"'
    response.headers['Content-Length'] = len(file_bytes)
    response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
    return response


@app.route('/api/report/json', methods=['POST'])
def report_json():
    try:
        vulns = _parse_vulns_from_request()
        content = report_generator.generate_json(vulns)
        return _send_temp_file(content, '.json', 'security_report.json', 'application/json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/html', methods=['POST'])
def report_html():
    try:
        vulns = _parse_vulns_from_request()
        content = report_generator.generate_html(vulns)
        return _send_temp_file(content, '.html', 'security_report.html', 'text/html; charset=utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/txt', methods=['POST'])
def report_txt():
    try:
        vulns = _parse_vulns_from_request()
        content = report_generator.generate_txt(vulns)
        return _send_temp_file(content, '.txt', 'security_report.txt', 'text/plain; charset=utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/csv', methods=['POST'])
def report_csv():
    try:
        vulns = _parse_vulns_from_request()
        content = report_generator.generate_csv(vulns)
        return _send_temp_file(content, '.csv', 'security_report.csv', 'text/csv; charset=utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/markdown', methods=['POST'])
def report_markdown():
    try:
        vulns = _parse_vulns_from_request()
        content = report_generator.generate_markdown(vulns)
        return _send_temp_file(content, '.md', 'security_report.md', 'text/plain; charset=utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/pdf', methods=['POST'])
def report_pdf():
    try:
        vulns = _parse_vulns_from_request()
        pdf_bytes = report_generator.generate_pdf(vulns)
        from flask import Response
        response = Response(
            pdf_bytes,
            status=200,
            mimetype='application/pdf',
        )
        response.headers['Content-Disposition'] = 'attachment; filename="security_report.pdf"'
        response.headers['Content-Length'] = len(pdf_bytes)
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── AI Fix ────────────────────────────────────────────────────────────────────
@app.route('/api/ai-fix', methods=['POST'])
def ai_fix():
    try:
        if not GEMINI_AVAILABLE:
            return jsonify({'success': False, 'error': 'google-generativeai not installed'}), 500

        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        code = data.get('code', '')
        description = data.get('description', '')
        remediation = data.get('remediation', '')
        language = data.get('language', 'javascript')

        if not code:
            return jsonify({'success': False, 'error': 'No code provided'}), 400

        prompt = f"""You are an expert security code reviewer. A vulnerability has been detected:

VULNERABILITY: {description}
REMEDIATION GUIDANCE: {remediation}

VULNERABLE CODE ({language}):
```{language}
{code}
```

Provide a corrected, secure version. Rules:
- Same functionality, just secure
- Add brief inline comments explaining the security fix
- Return ONLY the corrected code, no extra explanations outside the code

CORRECTED CODE:"""

        model = None
        for model_name in ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-pro']:
            try:
                model = genai.GenerativeModel(model_name)
                break
            except Exception:
                continue

        if not model:
            # REST fallback
            rest_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
            resp = http_requests.post(rest_url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=30)
            if resp.status_code == 200:
                corrected = resp.json()['candidates'][0]['content']['parts'][0]['text'].strip()
            else:
                return jsonify({'success': False, 'error': 'No Gemini model available'}), 500
        else:
            response = model.generate_content(prompt)
            corrected = response.text.strip()

        # Strip code fences
        if corrected.startswith('```'):
            lines = corrected.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            corrected = '\n'.join(lines)

        return jsonify({'success': True, 'corrected_code': corrected})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── Rules Info ────────────────────────────────────────────────────────────────
@app.route('/api/rules', methods=['GET'])
def get_rules():
    rules_info = [{
        'id': rule.id, 'name': rule.name, 'category': rule.category,
        'severity': rule.severity.value, 'languages': rule.languages,
        'description': rule.description, 'remediation': rule.remediation,
        'has_multi_line_patterns': len(rule.multi_line_patterns) > 0,
    } for rule in analyzer.rules]
    return jsonify({'success': True, 'total_rules': len(rules_info), 'rules': rules_info})


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
