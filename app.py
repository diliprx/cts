"""
Flask Web Application for Secure Code Analyzer
REST API endpoints for file upload and analysis
"""

import os
import tempfile
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
from werkzeug.utils import secure_filename
import json
import requests

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from analyzer_engine import CodeAnalyzer
from report_generator import ReportGenerator

# Gemini API Configuration
GEMINI_API_KEY = "AIzaSyBQiEu-m98MS50sbhoZqrokOuqVq4VEOwY"
if GEMINI_AVAILABLE:
    genai.configure(api_key=GEMINI_API_KEY)
    # Use v1 API instead of v1beta for standard API keys
    import google.generativeai.types as genai_types

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'js', 'jsx', 'mjs', 'ts', 'tsx', 'php', 'phtml', 'txt'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

analyzer = CodeAnalyzer()
report_generator = ReportGenerator(analyzer)


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Serve the main HTML page"""
    html_path = os.path.join(os.path.dirname(__file__), 'index.html')
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Error: index.html not found", 404


@app.route('/style.css')
def style():
    """Serve CSS file"""
    css_path = os.path.join(os.path.dirname(__file__), 'style.css')
    try:
        with open(css_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/css'}
    except FileNotFoundError:
        return "Error: style.css not found", 404


@app.route('/app.js')
def app_js():
    """Serve JavaScript file"""
    js_path = os.path.join(os.path.dirname(__file__), 'app.js')
    try:
        with open(js_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'application/javascript'}
    except FileNotFoundError:
        return "Error: app.js not found", 404


@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    """Analyze uploaded code file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Analyze the file
            vulnerabilities = analyzer.analyze_file(filepath)
            stats = analyzer.get_statistics(vulnerabilities)
            score = analyzer.calculate_security_score(vulnerabilities)
            
            # Prepare response
            response = {
                'success': True,
                'filename': filename,
                'statistics': stats,
                'security_score': score,
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
                        'remediation': v.remediation
                    }
                    for v in vulnerabilities
                ]
            }
            
            return jsonify(response)
        
        finally:
            # Clean up temporary file
            if os.path.exists(filepath):
                os.remove(filepath)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze-text', methods=['POST'])
def analyze_text():
    """Analyze code provided as text"""
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({'error': 'No code provided'}), 400
        
        code = data['code']
        language = data.get('language', 'javascript')
        filename = data.get('filename', 'input.js')
        
        # Analyze the code
        vulnerabilities = analyzer.analyze_code_string(code, language, filename)
        stats = analyzer.get_statistics(vulnerabilities)
        score = analyzer.calculate_security_score(vulnerabilities)
        
        response = {
            'success': True,
            'filename': filename,
            'statistics': stats,
            'security_score': score,
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
                    'remediation': v.remediation
                }
                for v in vulnerabilities
            ]
        }
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/json', methods=['POST'])
def generate_json_report():
    """Generate and download JSON report"""
    try:
        data = request.get_json()
        vulnerabilities_data = data.get('vulnerabilities', [])
        
        # Convert back to Vulnerability objects (simplified for API)
        # In production, you'd want to store session data or use a proper serialization
        from analyzer_engine import Vulnerability, Severity
        
        vulnerabilities = []
        for v_data in vulnerabilities_data:
            vuln = Vulnerability(
                rule_id=v_data['rule_id'],
                rule_name=v_data['rule_name'],
                category=v_data['category'],
                severity=Severity(v_data['severity']),
                file_path=v_data['file_path'],
                line_number=v_data['line_number'],
                code_snippet=v_data['code_snippet'],
                description=v_data['description'],
                remediation=v_data['remediation'],
                matched_pattern=''
            )
            vulnerabilities.append(vuln)
        
        json_report = report_generator.generate_json(vulnerabilities)
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        temp_file.write(json_report)
        temp_file.close()
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name='security_report.json',
            mimetype='application/json'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/html', methods=['POST'])
def generate_html_report():
    """Generate and download HTML report"""
    try:
        data = request.get_json()
        vulnerabilities_data = data.get('vulnerabilities', [])
        
        from analyzer_engine import Vulnerability, Severity
        
        vulnerabilities = []
        for v_data in vulnerabilities_data:
            vuln = Vulnerability(
                rule_id=v_data['rule_id'],
                rule_name=v_data['rule_name'],
                category=v_data['category'],
                severity=Severity(v_data['severity']),
                file_path=v_data['file_path'],
                line_number=v_data['line_number'],
                code_snippet=v_data['code_snippet'],
                description=v_data['description'],
                remediation=v_data['remediation'],
                matched_pattern=''
            )
            vulnerabilities.append(vuln)
        
        html_report = report_generator.generate_html(vulnerabilities)
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8')
        temp_file.write(html_report)
        temp_file.close()
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name='security_report.html',
            mimetype='text/html'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/txt', methods=['POST'])
def generate_txt_report():
    """Generate and download TXT report"""
    try:
        data = request.get_json()
        vulnerabilities_data = data.get('vulnerabilities', [])
        
        from analyzer_engine import Vulnerability, Severity
        
        vulnerabilities = []
        for v_data in vulnerabilities_data:
            vuln = Vulnerability(
                rule_id=v_data['rule_id'],
                rule_name=v_data['rule_name'],
                category=v_data['category'],
                severity=Severity(v_data['severity']),
                file_path=v_data['file_path'],
                line_number=v_data['line_number'],
                code_snippet=v_data['code_snippet'],
                description=v_data['description'],
                remediation=v_data['remediation'],
                matched_pattern=''
            )
            vulnerabilities.append(vuln)
        
        txt_report = report_generator.generate_txt(vulnerabilities)
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
        temp_file.write(txt_report)
        temp_file.close()
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name='security_report.txt',
            mimetype='text/plain'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai-fix', methods=['POST'])
def ai_fix():
    """Generate AI-corrected code using Gemini API"""
    try:
        if not GEMINI_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'Google Generative AI library not installed. Run: pip install google-generativeai'
            }), 500
        
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        code = data.get('code', '')
        description = data.get('description', '')
        remediation = data.get('remediation', '')
        
        if not code:
            return jsonify({'success': False, 'error': 'No code provided'}), 400
        
        # Create prompt for Gemini
        prompt = f"""You are a security code reviewer. A vulnerability has been detected in the following code:

VULNERABILITY DESCRIPTION:
{description}

REMEDIATION GUIDANCE:
{remediation}

VULNERABLE CODE:
```javascript
{code}
```

Please provide a corrected, secure version of this code that fixes the vulnerability. 
- Keep the same functionality
- Follow security best practices
- Include comments explaining the security improvements
- Return ONLY the corrected code, no explanations outside the code comments

CORRECTED CODE:"""
        
        # Generate corrected code using Gemini
        # For standard API, list available models and use the first compatible one
        try:
            # Get list of available models
            available_models = []
            try:
                for model in genai.list_models():
                    if 'generateContent' in model.supported_generation_methods:
                        model_name = model.name.replace('models/', '')
                        available_models.append(model_name)
            except Exception as list_error:
                # If listing fails, try common model names
                available_models = ['gemini-pro', 'gemini-1.5-flash', 'gemini-1.5-pro']
            
            # Try to use a model from available list
            model = None
            model_used = None
            
            # Try each available model
            for model_name in available_models:
                try:
                    model = genai.GenerativeModel(model_name)
                    model_used = model_name
                    # Test with a simple generation to verify it works
                    break
                except Exception as model_error:
                    continue
            
            # If still no model, try common names directly
            if model is None:
                common_models = ['gemini-pro', 'gemini-1.5-flash', 'gemini-1.5-pro']
                for model_name in common_models:
                    try:
                        model = genai.GenerativeModel(model_name)
                        model_used = model_name
                        break
                    except:
                        continue
            
            # If SDK models don't work, try REST API directly
            if model is None:
                # Try REST API as fallback for standard API keys
                try:
                    rest_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
                    rest_payload = {
                        "contents": [{
                            "parts": [{
                                "text": prompt
                            }]
                        }]
                    }
                    rest_response = requests.post(rest_url, json=rest_payload, timeout=30)
                    
                    if rest_response.status_code == 200:
                        rest_data = rest_response.json()
                        if 'candidates' in rest_data and len(rest_data['candidates']) > 0:
                            corrected_code = rest_data['candidates'][0]['content']['parts'][0]['text'].strip()
                            
                            # Clean up the response
                            if corrected_code.startswith('```'):
                                lines = corrected_code.split('\n')
                                if lines[0].startswith('```'):
                                    lines = lines[1:]
                                if lines[-1].strip() == '```':
                                    lines = lines[:-1]
                                corrected_code = '\n'.join(lines)
                            
                            return jsonify({
                                'success': True,
                                'corrected_code': corrected_code
                            })
                    else:
                        # If REST also fails, return error with available info
                        return jsonify({
                            'success': False,
                            'error': f'REST API error ({rest_response.status_code}): {rest_response.text[:200]}'
                        }), 500
                except Exception as rest_error:
                    return jsonify({
                        'success': False,
                        'error': f'No compatible Gemini model found via SDK or REST API. Error: {str(rest_error)}'
                    }), 500
            
            response = model.generate_content(prompt)
            
            corrected_code = response.text.strip()
            
            # Clean up the response (remove markdown code blocks if present)
            if corrected_code.startswith('```'):
                lines = corrected_code.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines[-1].strip() == '```':
                    lines = lines[:-1]
                corrected_code = '\n'.join(lines)
            
            return jsonify({
                'success': True,
                'corrected_code': corrected_code
            })
        except Exception as api_error:
            error_msg = str(api_error)
            # Provide more specific error messages
            if 'API_KEY' in error_msg or 'api_key' in error_msg.lower() or 'invalid' in error_msg.lower():
                return jsonify({
                    'success': False,
                    'error': 'Invalid API key. Please check your Gemini API key configuration.'
                }), 500
            elif 'quota' in error_msg.lower() or 'rate limit' in error_msg.lower():
                return jsonify({
                    'success': False,
                    'error': 'API quota exceeded. Please try again later.'
                }), 500
            else:
                return jsonify({
                    'success': False,
                    'error': f'Gemini API error: {error_msg}'
                }), 500
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500


@app.route('/api/debug/models', methods=['GET'])
def debug_models():
    """Debug endpoint to list available Gemini models"""
    if not GEMINI_AVAILABLE:
        return jsonify({'error': 'Gemini library not installed'}), 500
    
    try:
        available_models = []
        for model in genai.list_models():
            model_info = {
                'name': model.name,
                'display_name': model.display_name,
                'supported_methods': list(model.supported_generation_methods)
            }
            available_models.append(model_info)
        
        return jsonify({
            'success': True,
            'models': available_models
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Secure Code Analyzer',
        'gemini_available': GEMINI_AVAILABLE
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

