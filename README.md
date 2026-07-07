# 🔒 Antigravity Secure Code Analysis Platform

A professional static code analysis tool following **OWASP Top 10** standards with both CLI and Web interfaces. Supports **26 languages** with SAST, secret detection, and dependency scanning.

## Features

- ✅ **OWASP Top 10 Compliance** — Comprehensive vulnerability detection based on OWASP Top 10 2021
- 🌐 **26 Languages** — JavaScript, TypeScript, Python, Java, C, C++, C#, Go, Ruby, PHP, Kotlin, Swift, Scala, Rust, Bash, PowerShell, SQL, HTML, CSS, XML, YAML, JSON, Dockerfile, Terraform, and more
- 🔍 **Multi-Line Analysis** — Detects vulnerabilities spanning multiple lines of code
- 🔑 **Secret Detection** — Finds hardcoded API keys, tokens, and credentials
- 📦 **Dependency Scanning** — Checks manifest files (package.json, requirements.txt, pom.xml, etc.) for vulnerable dependencies
- 🤖 **AI Fix Suggestions** — Gemini-powered automatic vulnerability remediation
- 🎨 **Dual Interface** — Modern React web app and rich CLI (with `rich` library)
- 📊 **Multiple Report Formats** — JSON, HTML, TXT, CSV, Markdown, PDF
- 🎯 **Severity Classification** — Critical, High, Medium, Low severity levels
- 📈 **Security Scoring** — Automated security score calculation (0-100) with letter grade
- 📁 **Multi-File & ZIP Support** — Bulk scan files or entire archive uploads
- 🌍 **Repository Scanning** — Scan public GitHub, GitLab, and Bitbucket repos

## Installation

### Prerequisites

- Python 3.8 or higher
- Node.js 18+ (for frontend development)
- pip (Python package manager)

### Setup

1. Clone or download this repository

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Build the frontend:
```bash
cd frontend
npm install
npm run build
```

## Usage

### CLI Application

#### Interactive Mode
```bash
python cli_analyzer.py
```

#### Analyze a single file:
```bash
python cli_analyzer.py -f path/to/file.js
```

#### Analyze a directory:
```bash
python cli_analyzer.py -d path/to/directory
```

#### Export report:
```bash
python cli_analyzer.py -f file.js -o report.json
python cli_analyzer.py -f file.js -o report.html
python cli_analyzer.py -f file.js -o report.txt
```

#### Custom rules:
```bash
python cli_analyzer.py -f file.js -r custom_rules.json
```

### Web Application

1. Start the Flask server:
```bash
python app.py
```

2. Open your browser to `http://localhost:5000`

3. Scan via:
   - **Single File** — Upload or drag-and-drop a file
   - **Multi-File** — Select multiple files at once
   - **ZIP Archive** — Upload a `.zip`/`.tar.gz` project
   - **Repository** — Enter a public GitHub/GitLab/Bitbucket URL
   - **Paste Code** — Paste code directly for instant analysis

4. Download reports in **JSON, CSV, HTML, Markdown, TXT, or PDF** format.

## OWASP Top 10 Coverage

| Category | Examples |
|----------|----------|
| **A01: Broken Access Control** | Missing authorization checks |
| **A02: Cryptographic Failures** | Weak hashing (MD5, SHA1), hardcoded keys |
| **A03: Injection** | SQLi, XSS, Command Injection, NoSQLi |
| **A05: Security Misconfiguration** | Hardcoded secrets, debug mode |
| **A07: Authentication Failures** | Weak session management |
| **A08: Software Integrity Failures** | Unsafe deserialization |
| **A10: SSRF** | Server-Side Request Forgery |

Plus **best-practice rules** (input validation, error handling) and **secret detection** (API keys, tokens, passwords, JWTs, cloud credentials).

## Report Formats

| Format | Extension | Best For |
|--------|-----------|----------|
| JSON | `.json` | Machine-readable / CI pipelines |
| HTML | `.html` | Sharing in browser |
| CSV | `.csv` | Spreadsheet analysis |
| Markdown | `.md` | Developers / documentation |
| TXT | `.txt` | Terminal / logging |
| PDF | `.pdf` | Printing / formal reports |

## Security Score Calculation

The security score (0-100) with letter grade (A+ to F):
- **Critical**: 10 points penalty each
- **High**: 5 points penalty each
- **Medium**: 2 points penalty each
- **Low**: 1 point penalty each

Higher scores indicate better security posture.

## Project Structure

```
.
├── analyzer_engine.py       # Core SAST analysis engine
├── owasp_rules.py           # OWASP Top 10 vulnerability rules
├── report_generator.py      # Report generation (JSON, HTML, TXT, CSV, MD, PDF)
├── secret_detector.py       # Secret/key detection engine
├── dependency_scanner.py    # Dependency vulnerability scanner
├── cli_analyzer.py          # CLI application (rich terminal UI)
├── app.py                   # Flask web application + API
├── external_rules.json      # Custom user-defined rules
├── requirements.txt         # Python dependencies
├── frontend/                # React + Vite frontend
│   ├── src/pages/Scan.jsx   # Main scan page
│   ├── src/pages/Reports.jsx # Reports history page
│   └── ...
└── README.md                # This file
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze` | POST | Analyze a single file |
| `/api/analyze-multi` | POST | Analyze multiple files |
| `/api/analyze-zip` | POST | Analyze a ZIP archive |
| `/api/analyze-repo` | POST | Scan a remote repository |
| `/api/analyze-text` | POST | Analyze pasted code |
| `/api/report/json` | POST | Generate JSON report |
| `/api/report/html` | POST | Generate HTML report |
| `/api/report/csv` | POST | Generate CSV report |
| `/api/report/markdown` | POST | Generate Markdown report |
| `/api/report/txt` | POST | Generate TXT report |
| `/api/report/pdf` | POST | Generate PDF report |
| `/api/ai-fix` | POST | AI-powered fix suggestion |
| `/api/scan-history` | GET/DELETE | View/clear scan history |
| `/api/rules` | GET | List all active rules |

## Deployment (Render)

Deploy for free on [Render](https://render.com) with auto-deploy on every git push.

### Steps

1. Push this project to a **GitHub** repository.

2. On [Render Dashboard](https://dashboard.render.com), click **New + → Web Service**.

3. Connect your GitHub repo.

4. Use these settings:

   | Setting | Value |
   |---------|-------|
   | **Runtime** | `Python` |
   | **Build Command** | `pip install -r requirements.txt && cd frontend && npm install && npm run build && cd ..` |
   | **Start Command** | `python app.py` |
   | **Plan** | Free |

5. Add an environment variable (optional, for AI fixes):

   | Key | Value |
   |-----|-------|
   | `GEMINI_API_KEY` | your Gemini API key |

6. Click **Deploy**.

### Auto-Updates

Every time you push to GitHub, Render will:
1. Pull the latest code
2. Run the build command (installs Python deps + builds frontend)
3. Restart the server

Your deployed link always reflects the latest changes.

---

## Limitations

⚠️ **Important Notes:**

1. **Static Analysis Only** — Performs pattern matching without code execution
2. **False Positives** — Some patterns may trigger false positives. Always review findings manually
3. **Pattern-Based** — Detection relies on regex patterns and may miss complex vulnerabilities
4. **No Context Awareness** — The analyzer doesn't understand full code context or data flow

## Best Practices

1. **Review All Findings** — Always manually verify detected vulnerabilities
2. **Regular Scans** — Integrate into your CI/CD pipeline for continuous scanning
3. **Combine with Other Tools** — Use alongside dynamic analysis and penetration testing
4. **Keep Rules Updated** — Regularly update OWASP rules as new patterns emerge

## License

This project is provided as-is for educational and security auditing purposes.

## Disclaimer

This tool is designed to assist in security auditing but should not be the sole method of security assessment. Always combine static analysis with:
- Code reviews
- Dynamic analysis
- Penetration testing
- Security audits by professionals
