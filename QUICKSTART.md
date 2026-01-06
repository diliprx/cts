# Quick Start Guide

## Installation

```bash
pip install -r requirements.txt
```

## Quick Test

### Test CLI with Sample Files

```bash
# Test with JavaScript file
python cli_analyzer.py -f test_samples/vulnerable.js -o test_report.html

# Test with PHP file
python cli_analyzer.py -f test_samples/vulnerable.php -o test_report.json
```

### Test Web Application

1. Start the server:
```bash
python app.py
```

2. Open browser: http://localhost:5000

3. Upload `test_samples/vulnerable.js` or `test_samples/vulnerable.php` to see vulnerabilities detected

## Expected Results

The test files contain multiple vulnerabilities that should be detected:

- SQL Injection
- XSS (Cross-Site Scripting)
- Weak Password Hashing (MD5)
- Hardcoded Secrets
- Command Injection (PHP)
- SSRF vulnerabilities

You should see a security score below 100 and multiple vulnerabilities reported.

