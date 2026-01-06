# 🔒 Secure Code Analyzer

A professional static code analysis tool following **OWASP Top 10** standards with both CLI and Web interfaces for JavaScript and PHP security auditing.

## Features

- ✅ **OWASP Top 10 Compliance** - Comprehensive vulnerability detection based on OWASP Top 10 2021
- 🔍 **Multi-Language Support** - Analyzes JavaScript (JS, JSX, TS, TSX) and PHP code
- 🎨 **Dual Interface** - Both command-line (CLI) and modern web application
- 📊 **Multiple Report Formats** - JSON, HTML, and TXT report generation
- 🎯 **Severity Classification** - Critical, High, Medium, Low severity levels
- 📈 **Security Scoring** - Automated security score calculation (0-100)
- 🚀 **Pattern-Based Detection** - Static analysis using regex pattern matching
- 💡 **Remediation Guidance** - Detailed recommendations for each vulnerability

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### CLI Application

#### Interactive Mode

Run without arguments to enter interactive mode:

```bash
python cli_analyzer.py
```

You'll be prompted to:
1. Choose between file or directory analysis
2. Enter the path to analyze
3. Optionally export the report

#### Command-Line Mode

**Analyze a single file:**
```bash
python cli_analyzer.py -f path/to/file.js
```

**Analyze a directory:**
```bash
python cli_analyzer.py -d path/to/directory
```

**Export report:**
```bash
python cli_analyzer.py -f file.js -o report.json
python cli_analyzer.py -f file.js -o report.html
python cli_analyzer.py -f file.js -o report.txt
```

### Web Application

1. Start the Flask server:
```bash
python app.py
```

2. Open your browser and navigate to:
```
http://localhost:5000
```

3. Use the web interface to:
   - Upload files via drag-and-drop
   - Paste code directly
   - View interactive vulnerability reports
   - Export reports in JSON or HTML format

## OWASP Top 10 Coverage

The analyzer detects vulnerabilities in the following categories:

1. **A01: Broken Access Control** - Missing authorization checks
2. **A02: Cryptographic Failures** - Weak hashing algorithms (MD5, SHA1)
3. **A03: Injection** - SQL Injection, XSS, Command Injection
4. **A05: Security Misconfiguration** - Hardcoded secrets, debug mode
5. **A07: Authentication Failures** - Weak session management
6. **A08: Software Integrity Failures** - Unsafe deserialization
7. **A10: SSRF** - Server-Side Request Forgery vulnerabilities

## Example Vulnerabilities Detected

### SQL Injection (JavaScript)
```javascript
// ❌ Vulnerable
query("SELECT * FROM users WHERE id = " + userId);

// ✅ Safe
query("SELECT * FROM users WHERE id = ?", [userId]);
```

### XSS (PHP)
```php
// ❌ Vulnerable
echo $_GET['name'];

// ✅ Safe
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

### Weak Password Hashing
```javascript
// ❌ Vulnerable
const hash = crypto.createHash('md5').update(password).digest('hex');

// ✅ Safe
const hash = await bcrypt.hash(password, 10);
```

## Report Formats

### JSON Report
Structured data format suitable for integration with other tools:
```json
{
  "metadata": {
    "generated_at": "2024-01-01T12:00:00",
    "total_vulnerabilities": 5,
    "security_score": 75.5
  },
  "statistics": { ... },
  "vulnerabilities": [ ... ]
}
```

### HTML Report
Beautiful, professional report with:
- Color-coded severity indicators
- Code snippets with syntax highlighting
- Remediation recommendations
- Statistics and security score

### TXT Report
Plain text format for terminal viewing or logging

## Security Score Calculation

The security score (0-100) is calculated based on:
- **Critical**: 10 points penalty
- **High**: 5 points penalty
- **Medium**: 2 points penalty
- **Low**: 1 point penalty

Higher scores indicate better security posture.

## Project Structure

```
.
├── analyzer_engine.py      # Core analysis engine
├── owasp_rules.py          # OWASP Top 10 vulnerability rules
├── report_generator.py     # Report generation (JSON/HTML/TXT)
├── cli_analyzer.py         # CLI application
├── app.py                  # Flask web application
├── index.html              # Web UI
├── style.css               # Web UI styling
├── app.js                  # Frontend JavaScript
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## Limitations

⚠️ **Important Notes:**

1. **Static Analysis Only** - This tool performs pattern matching and does not execute code
2. **False Positives** - Some patterns may trigger false positives. Always review findings manually
3. **Pattern-Based** - Detection relies on regex patterns and may miss complex vulnerabilities
4. **No Context Awareness** - The analyzer doesn't understand full code context or data flow

## Best Practices

1. **Review All Findings** - Always manually verify detected vulnerabilities
2. **Regular Scans** - Integrate into your CI/CD pipeline for continuous scanning
3. **Combine with Other Tools** - Use alongside dynamic analysis and penetration testing
4. **Keep Rules Updated** - Regularly update OWASP rules as new patterns emerge

## Contributing

Contributions are welcome! Areas for improvement:
- Additional vulnerability patterns
- Support for more languages
- Improved false positive reduction
- Enhanced code context analysis

## License

This project is provided as-is for educational and security auditing purposes.

## Disclaimer

This tool is designed to assist in security auditing but should not be the sole method of security assessment. Always combine static analysis with:
- Code reviews
- Dynamic analysis
- Penetration testing
- Security audits by professionals

## Support

For issues, questions, or contributions, please refer to the project repository.

---

**Made with ❤️ for secure code development**

