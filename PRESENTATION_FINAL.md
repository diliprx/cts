# Secure Code Analyzer - Final Presentation 

## Project Title

**Advanced Static Security Analysis Tool with Taint Analysis Engine**

---

## Executive Summary

This project is a **next-generation static code analyzer** that identifies security vulnerabilities in PHP and JavaScript applications using **dual-mode analysis**: traditional regex pattern matching and advanced **taint analysis** (data flow tracking).

The tool automatically detects OWASP Top 10 vulnerabilities, generates professional PDF reports with visual data flow diagrams, and supports individual files, directories, and GitHub repositories.

---

## Problem Statement

Modern web applications face increasing security threats:

- **60%** of data breaches involve web application vulnerabilities
- Traditional static analyzers miss context-sensitive vulnerabilities
- Manual code review is time-consuming and error-prone
- Developers need actionable, visual vulnerability reports

---

## Solution Overview

```
+------------------+     +-------------------+     +------------------+
|   Code Input     |---->|  Analysis Engine  |---->|  Security Report |
+------------------+     +-------------------+     +------------------+
| - Single File    |     | - Taint Analysis  |     | - PDF with Flow  |
| - Directory      |     | - Regex Patterns  |     | - JSON/HTML/TXT  |
| - GitHub Repo    |     | - Cross-File      |     | - Risk Scores    |
| - ZIP Upload     |     | - OWASP Rules     |     | - Remediation    |
+------------------+     +-------------------+     +------------------+
```

---

## Key Features

### 1. Dual Analysis Modes

| Mode       | Description                                  | Best For                          |
| ---------- | -------------------------------------------- | --------------------------------- |
| **TAINT**  | Data flow tracking from sources to sinks     | Injection attacks, SSRF           |
| **REGEX**  | Pattern-based vulnerability detection        | Configuration issues, weak crypto |
| **HYBRID** | Combined approach for comprehensive coverage | Full security audit               |

### 2. Vulnerability Detection Coverage

- **A01** - Broken Access Control
- **A02** - Cryptographic Failures
- **A03** - Injection (SQL, Command, XSS)
- **A05** - Security Misconfiguration
- **A07** - Authentication Failures
- **A10** - Server-Side Request Forgery

### 3. Professional PDF Reports

- Executive summary with security scores
- Visual **taint flow diagrams**
- Code snippets with remediation guidance
- Categorized by severity (Critical/High/Medium/Low)

### 4. Multiple Input Sources

- Single file analysis
- Recursive directory scanning
- Direct GitHub repository cloning
- ZIP file upload and extraction

### 5. Cross-File Taint Tracking

- Tracks data flow across multiple files
- Detects inter-module vulnerabilities
- Visualizes complete attack paths

---

## Technology Stack

| Component      | Technology      | Purpose                 |
| -------------- | --------------- | ----------------------- |
| Backend        | **Python 3.13** | Core analysis engine    |
| Web Framework  | **Flask 3.0**   | REST API server         |
| CLI Interface  | **Rich**        | Interactive terminal UI |
| PDF Generation | **ReportLab**   | Professional reports    |
| Source Control | **Git**         | GitHub integration      |
| Cross-Origin   | **Flask-CORS**  | Browser compatibility   |

---

## Architecture Overview

```
+------------------------------------------------------------------+
|                    SECURE CODE ANALYZER                          |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------+  +------------------+  +------------------+ |
|  |   CLI Interface  |  |   Web Interface  |  |   REST API       | |
|  |  cli_analyzer.py |  |   index.html     |  |   app.py         | |
|  +--------+---------+  +--------+---------+  +--------+---------+ |
|           |                     |                     |           |
|           +---------------------+---------------------+           |
|                                 |                                 |
|                    +------------v------------+                    |
|                    |   ANALYZER ENGINE       |                    |
|                    |   analyzer_engine.py    |                    |
|                    +------------+------------+                    |
|                                 |                                 |
|           +---------------------+---------------------+           |
|           |                     |                     |           |
|  +--------v---------+  +--------v---------+  +--------v---------+ |
|  |  TAINT ENGINE    |  |  OWASP RULES     |  | EXTERNAL TOOLS   | |
|  |  taint_engine.py |  |  owasp_rules.py  |  | external_tools.py| |
|  +------------------+  +------------------+  +------------------+ |
|           |                                                       |
|  +--------v----------------+                                      |
|  |  CROSS-FILE ANALYZER    |                                      |
|  |  cross_file_taint.py    |                                      |
|  +-------------------------+                                      |
|                                 |                                 |
|                    +------------v------------+                    |
|                    |   REPORT GENERATOR      |                    |
|                    |   report_generator.py   |                    |
|                    +-------------------------+                    |
|                                                                   |
+------------------------------------------------------------------+
```

---

## Demo Flow

### Step 1: Select Analysis Mode

```
╔══════════════════════════════════════════════════════════════╗
║         Secure Code Analyzer - OWASP Top 10                  ║
║         Mode: Taint Analysis (Data Flow Tracking)            ║
╚══════════════════════════════════════════════════════════════╝
```

### Step 2: Provide Input

- Upload file via Web UI
- Enter file path in CLI
- Paste GitHub URL
- Upload ZIP archive

### Step 3: View Results

```
╭────────────────────────── Summary ──────────────────────────╮
│ Total Issues: 16                                             │
│ Security Score: 23/100                                       │
│ Critical: 3  |  High: 7  |  Medium: 6  |  Low: 0            │
╰──────────────────────────────────────────────────────────────╯
```

### Step 4: Export Report

- **PDF**: Professional document with flow diagrams
- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Browser-viewable report
- **TXT**: Plain text summary

---

## Taint Flow Visualization

The tool generates visual diagrams showing how untrusted data flows through the application:

```
+-------------------+       +--------------------+       +-------------------+
|   [!] SOURCE      | ----> |   TAINTED VARIABLE | ----> |   [X] SINK        |
+-------------------+       +--------------------+       +-------------------+
| User Input ($_GET)|       | $query = "SELECT..."       | mysql_query($sql) |
| Line 6            |       | Line 6                     | Line 7            |
+-------------------+       +--------------------+       +-------------------+

        [!] SECURITY VULNERABILITY: TAINTED DATA REACHES SINK [!]
```

---

## Sample Vulnerability Report

### Critical: SQL Injection (TAINT-SQL-INJECTION)

| Field        | Value                         |
| ------------ | ----------------------------- |
| **File**     | vulnerable.php                |
| **Line**     | 7                             |
| **Category** | Data Flow Vulnerability       |
| **Source**   | User input from `$_GET['id']` |
| **Sink**     | `mysql_query()` execution     |

**Code:**

```php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";
mysql_query($query);
```

**Remediation:** Use prepared statements with parameterized queries.

---

## Results Summary

### Vulnerabilities Detected in Test Suite

| Severity     | Count | Examples                                       |
| ------------ | ----- | ---------------------------------------------- |
| **Critical** | 3     | SQL Injection, Command Injection, Weak Hashing |
| **High**     | 7     | Path Traversal, SSRF, XSS                      |
| **Medium**   | 6     | Missing Input Validation                       |
| **Low**      | 0     | -                                              |

### Security Score: **23/100** (High Risk)

---

## Competitive Advantages

| Feature              | Our Tool | Basic Regex Scanner | Commercial SAST |
| -------------------- | -------- | ------------------- | --------------- |
| Taint Analysis       | YES      | NO                  | YES             |
| Cross-File Tracking  | YES      | NO                  | YES             |
| Visual Flow Diagrams | YES      | NO                  | LIMITED         |
| PDF Export           | YES      | NO                  | YES             |
| GitHub Integration   | YES      | NO                  | YES             |
| Open Source          | YES      | VARIES              | NO              |
| Cost                 | FREE     | FREE                | EXPENSIVE       |

---

## Future Enhancements

1. **Additional Languages**: Support for Java, Python, C#
2. **IDE Integration**: VS Code extension (in progress)
3. **CI/CD Pipeline**: GitHub Actions integration
4. **Machine Learning**: AI-powered false positive reduction
5. **Interactive Remediation**: Auto-fix suggestions

---

## Conclusion

The **Secure Code Analyzer** provides:

- Industry-standard taint analysis capabilities
- Professional-grade PDF reports with visual diagrams
- Flexible dual-mode analysis (Taint + Regex)
- Multi-source code input (File, Directory, GitHub, ZIP)
- OWASP Top 10 vulnerability coverage

**Ready for production use in security audits and CI/CD pipelines.**

---

## Contact & Resources

- **Documentation**: See `TECHNICAL_DETAILS.md` for complete API reference
- **Quick Start**: See `QUICKSTART.md` for installation guide
- **Repository**: GitHub integration available via `-g` flag

---

## Thank You!

_Building secure applications, one vulnerability at a time._
