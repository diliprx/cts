from typing import Dict, List, Tuple, Optional
from enum import Enum
import json
import os


class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class OWASPRule:
    def __init__(self, id: str, name: str, category: str, severity: Severity,
                 patterns: List[str], description: str, remediation: str,
                 languages: List[str], multi_line_patterns: Optional[List[str]] = None):
        self.id = id
        self.name = name
        self.category = category
        self.severity = severity
        self.patterns = patterns
        self.multi_line_patterns = multi_line_patterns or []
        self.description = description
        self.remediation = remediation
        self.languages = languages


OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)"
}


def get_owasp_rules() -> List[OWASPRule]:
    rules = []

    # A01: Broken Access Control - JavaScript
    rules.append(OWASPRule(
        id="A01-JS-001",
        name="Missing Authorization Check",
        category="A01",
        severity=Severity.HIGH,
        patterns=[
            r"\.get\([^)]*\)\s*\{[^}]*\}",
            r"router\.(get|post|put|delete)\([^)]*\)\s*\{[^}]*\}",
            r"app\.(get|post|put|delete)\([^)]*\)\s*\{[^}]*\}",
            r"\.isAdmin\s*=\s*true",
            r"\.isAuthenticated\s*=\s*true",
        ],
        multi_line_patterns=[
            r"router\.(get|post|put|delete)\([^)]*\)[\s\S]*?\{[^}]*\}(?![\s\S]*?(?:auth|verify|check|validate|protect|restrict|permission|role))",
            r"app\.(get|post|put|delete)\([^)]*\)[\s\S]*?\{[^}]*\}(?![\s\S]*?(?:auth|verify|check|validate|protect|restrict|permission|role))",
        ],
        description="API endpoint lacks proper authorization checks",
        remediation="Implement role-based access control (RBAC) and verify user permissions before processing requests",
        languages=["javascript", "js"]
    ))

    # A01: Broken Access Control - PHP
    rules.append(OWASPRule(
        id="A01-PHP-001",
        name="Missing Authorization Check",
        category="A01",
        severity=Severity.HIGH,
        patterns=[
            r"if\s*\(\s*!\s*isset\s*\(\s*\$_SESSION\s*\[['\"]user['\"]\s*\]\s*\)\s*\)",
            r"if\s*\(\s*!\s*isset\s*\(\s*\$_SESSION\s*\[['\"]role['\"]\s*\]\s*\)\s*\)",
        ],
        multi_line_patterns=[
            r"\$_SESSION\s*\[['\"]role['\"]\s*\].*=[^;]*admin",
        ],
        description="Missing session-based authorization checks",
        remediation="Verify user authentication and authorization before accessing protected resources",
        languages=["php"]
    ))

    # A01: Broken Access Control - Python
    rules.append(OWASPRule(
        id="A01-PY-001",
        name="Missing Authorization Decorator",
        category="A01",
        severity=Severity.HIGH,
        patterns=[
            r"@app\.route\s*\([^)]*\)",
            r"@app\.(get|post|put|delete)\s*\([^)]*\)",
        ],
        multi_line_patterns=[
            r"@app\.(route|get|post|put|delete)\s*\([^)]*\)[\s\S]*?def\s+\w+[\s\S]*?(?!(?:@?(?:login_required|permission_required|admin_required|auth_required)))",
        ],
        description="API endpoint lacks authentication/authorization decorator",
        remediation="Add @login_required or @permission_required decorators to protected routes",
        languages=["python"]
    ))

    # A02: Cryptographic Failures - JavaScript
    rules.append(OWASPRule(
        id="A02-JS-001",
        name="Weak Password Hashing",
        category="A02",
        severity=Severity.CRITICAL,
        patterns=[
            r"md5\s*\(",
            r"sha1\s*\(",
            r"crypto\.createHash\s*\(\s*['\"]md5['\"]",
            r"crypto\.createHash\s*\(\s*['\"]sha1['\"]",
            r"\.hash\s*\(\s*['\"]md5['\"]",
            r"\.hash\s*\(\s*['\"]sha1['\"]",
        ],
        description="Use of weak cryptographic hash functions (MD5, SHA1)",
        remediation="Use strong hashing algorithms like bcrypt, argon2, or PBKDF2 with sufficient iterations",
        languages=["javascript", "js"]
    ))

    # A02: Cryptographic Failures - PHP
    rules.append(OWASPRule(
        id="A02-PHP-001",
        name="Weak Password Hashing",
        category="A02",
        severity=Severity.CRITICAL,
        patterns=[
            r"md5\s*\(",
            r"sha1\s*\(",
            r"hash\s*\(\s*['\"]md5['\"]",
            r"hash\s*\(\s*['\"]sha1['\"]",
        ],
        description="Use of weak cryptographic hash functions",
        remediation="Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID",
        languages=["php"]
    ))

    # A02: Cryptographic Failures - Python
    rules.append(OWASPRule(
        id="A02-PY-001",
        name="Weak Password Hashing",
        category="A02",
        severity=Severity.CRITICAL,
        patterns=[
            r"hashlib\.md5\s*\(",
            r"hashlib\.sha1\s*\(",
            r"bcrypt\.hashpw\s*\(\s*[^,]+,\s*[^,]*\$2[abxy]?\$",
        ],
        multi_line_patterns=[
            r"hashlib\.\w+\s*\([^)]*\)[\s\S]*?\.hexdigest\s*\(",
        ],
        description="Use of weak or incorrect cryptographic functions",
        remediation="Use hashlib.pbkdf2_hmac() or bcrypt for password hashing",
        languages=["python"]
    ))

    # A02: Cryptographic Failures - Python hardcoded key
    rules.append(OWASPRule(
        id="A02-PY-002",
        name="Hardcoded Encryption Key",
        category="A02",
        severity=Severity.HIGH,
        patterns=[
            r"Fernet\s*\(\s*['\"][^'\"]{10,}['\"]",
            r"key\s*=\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
        ],
        description="Hardcoded encryption key in source code",
        remediation="Store encryption keys in environment variables or a secure key management system",
        languages=["python"]
    ))

    # A03: Injection - SQL Injection - JavaScript
    rules.append(OWASPRule(
        id="A03-JS-001",
        name="SQL Injection Vulnerability",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"query\s*\(\s*['\"].*\+.*\+.*['\"]",
            r"\.query\s*\(\s*[`'\"].*\$.*[`'\"]",
            r"SELECT.*\+.*FROM",
            r"INSERT.*\+.*INTO",
            r"UPDATE.*\+.*SET",
            r"DELETE.*\+.*FROM",
            r"execute\s*\(\s*[`'\"].*\$.*[`'\"]",
            r"execute\s*\(\s*['\"].*\+.*\+.*['\"]",
        ],
        multi_line_patterns=[
            r"SELECT[\s\S]*?FROM[\s\S]*?\+[\s\S]*?WHERE",
            r"INSERT[\s\S]*?INTO[\s\S]*?VALUES[\s\S]*?\+",
            r"UPDATE[\s\S]*?SET[\s\S]*?(?:\+|`\$\{)",
            r"query\s*\(\s*[`'\"][\s\S]{0,200}?\$",
            r"query\s*\(\s*['\"][\s\S]{0,200}?\s*\+\s*",
            r"execute\s*\(\s*[`'\"][\s\S]{0,200}?\$",
            r"SELECT[\s\S]{0,200}?\s*\+\s*\w+[\s\S]{0,200}?query\s*\(",
            r"SELECT[\s\S]{0,200}?\s*\+\s*\w+[\s\S]{0,200}?execute\s*\(",
            r"(?:SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,200}?\+\s*\w+[\s\S]{0,200}?\.",
            r"['\"]\s*\+\s*\w+[\s\S]{0,200}?\.query\s*\(",
            r"['\"]\s*\+\s*\w+[\s\S]{0,200}?query\s*\(",
        ],
        description="SQL query constructed with string concatenation or interpolation, vulnerable to injection",
        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries",
        languages=["javascript", "js"]
    ))

    # A03: Injection - SQL Injection - JavaScript template literals
    rules.append(OWASPRule(
        id="A03-JS-004",
        name="SQL Injection via Template Literal",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"query\s*\(\s*`.*\$\{.*\}.*`",
            r"execute\s*\(\s*`.*\$\{.*\}.*`",
            r"SELECT.*\$\{.*\}.*FROM",
            r"INSERT.*\$\{.*\}.*INTO",
        ],
        description="SQL query uses template literals with interpolation, vulnerable to injection",
        remediation="Use parameterized queries with ? placeholders instead of string interpolation",
        languages=["javascript", "js"]
    ))

    # A03: Injection - SQL Injection - PHP
    rules.append(OWASPRule(
        id="A03-PHP-001",
        name="SQL Injection Vulnerability",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"mysql_query\s*\(",
            r"mysqli_query\s*\(\s*\$[^,]+,\s*['\"].*\$.*['\"]",
            r"query\s*\(\s*['\"].*\$.*['\"]",
            r"\$sql\s*=\s*['\"].*\$.*['\"]",
            r"SELECT.*\$.*FROM",
            r"INSERT.*\$.*INTO",
            r"SELECT.*\".*\$.*\".*FROM",
        ],
        multi_line_patterns=[
            r"\$sql[\s\S]{0,50}=\s*['\"][\s\S]*?\$[\s\S]*?['\"]",
            r"query\s*\(\s*\$sql",
            r"SELECT[\s\S]{0,200}?\$[\s\S]*?FROM",
            r"SELECT[\s\S]*?\.[\s\S]*?\$[\s\S]*?FROM",
        ],
        description="SQL query with direct variable interpolation, vulnerable to injection",
        remediation="Use prepared statements with mysqli_prepare() or PDO::prepare()",
        languages=["php"]
    ))

    # A03: Injection - SQL Injection - PHP heredoc/nowdoc
    rules.append(OWASPRule(
        id="A03-PHP-005",
        name="SQL Injection via Heredoc",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"<<<SQL[\s\S]*?\$[\s\S]*?SQL;",
        ],
        multi_line_patterns=[
            r"<<<SQL[\s\S]*?\$[\s\S]*?SQL;",
        ],
        description="SQL query constructed using heredoc with variable interpolation",
        remediation="Use prepared statements with PDO parameterized queries",
        languages=["php"]
    ))

    # A03: Injection - SQL Injection - Python
    rules.append(OWASPRule(
        id="A03-PY-001",
        name="SQL Injection Vulnerability",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"execute\s*\(\s*['\"].*\{.*\}.*['\"]",
            r"execute\s*\(\s*['\"].*%.*['\"]",
            r"cursor\.execute\s*\(\s*['\"].*%.*['\"]",
            r"raw_input.*SELECT",
            r"SELECT.*%.*FROM",
            r"f['\"]SELECT",
            r"f\"SELECT",
        ],
        multi_line_patterns=[
            r"execute\s*\(\s*['\"][\s\S]*?(?:\%|\{)[\s\S]*?['\"]\s*\)",
            r"SELECT[\s\S]{0,200}?\%[\s\S]*?FROM",
            r"f['\"]?[\s\S]{0,200}?SELECT[\s\S]{0,200}?FROM",
            r"cursor\.execute\s*\(\s*f['\"]",
        ],
        description="SQL query constructed with string formatting, vulnerable to injection",
        remediation="Use parameterized queries with ? or %s placeholders and pass parameters separately",
        languages=["python"]
    ))

    # A03: Injection - XSS - JavaScript
    rules.append(OWASPRule(
        id="A03-JS-002",
        name="Cross-Site Scripting (XSS)",
        category="A03",
        severity=Severity.HIGH,
        patterns=[
            r"innerHTML\s*=\s*[^;]+",
            r"\.html\s*\(\s*[^)]+\)",
            r"document\.write\s*\(",
            r"eval\s*\(",
            r"Function\s*\(",
            r"setTimeout\s*\(\s*['\"].*\$.*['\"]",
            r"setInterval\s*\(\s*['\"].*\$.*['\"]",
            r"insertAdjacentHTML\s*\(",
            r"outerHTML\s*=",
        ],
        multi_line_patterns=[
            r"innerHTML\s*=\s*['\"`][\s\S]*?['\"`]",
            r"\.html\s*\(\s*['\"`][\s\S]*?['\"`]\s*\)",
        ],
        description="Unsanitized user input rendered in HTML, vulnerable to XSS",
        remediation="Sanitize all user input, use textContent instead of innerHTML, implement Content Security Policy (CSP)",
        languages=["javascript", "js"]
    ))

    # A03: Injection - XSS - PHP
    rules.append(OWASPRule(
        id="A03-PHP-002",
        name="Cross-Site Scripting (XSS)",
        category="A03",
        severity=Severity.HIGH,
        patterns=[
            r"echo\s+\$_[A-Z]+\s*\[",
            r"print\s+\$_[A-Z]+\s*\[",
            r"<\?=\s*\$_[A-Z]+\s*\[",
            r"echo\s+\$[a-zA-Z_]+;",
            r"print\s+\$[a-zA-Z_]+;",
        ],
        description="Unsanitized output of user input, vulnerable to XSS",
        remediation="Use htmlspecialchars() or htmlentities() to escape output, implement Content Security Policy",
        languages=["php"]
    ))

    # A03: Injection - XSS - Python
    rules.append(OWASPRule(
        id="A03-PY-002",
        name="Cross-Site Scripting (XSS)",
        category="A03",
        severity=Severity.HIGH,
        patterns=[
            r"render_template_string\s*\(",
            r"Markup\s*\(\s*[^)]+\)",
            r"\.format\s*\(\s*request\.",
            r"%\s*request\.",
            r"f['\"].*\{.*request\..*\}.*['\"]",
        ],
        description="Potential XSS from unescaped template rendering",
        remediation="Use autoescaping templates (Jinja2) and avoid rendering unsanitized user input",
        languages=["python"]
    ))

    # A03: Injection - Command Injection - JavaScript
    rules.append(OWASPRule(
        id="A03-JS-003",
        name="Command Injection",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"child_process\.exec\s*\(\s*[^,]+[+$]",
            r"child_process\.spawn\s*\(\s*[^,]+[+$]",
            r"exec\s*\(\s*[^,]+[+$]",
            r"system\s*\(\s*[^,]+[+$]",
            r"execSync\s*\(\s*[^,]+[+$]",
            r"execFile\s*\(\s*[^,]+[+$]",
        ],
        multi_line_patterns=[
            r"(?:exec|execSync|execFile|spawn)\s*\(\s*['\"`][\s\S]*?(?:\+|`\$\{)",
        ],
        description="Command execution with unsanitized user input",
        remediation="Validate and sanitize all input, use whitelist approach, avoid shell execution when possible",
        languages=["javascript", "js"]
    ))

    # A03: Injection - Command Injection - PHP
    rules.append(OWASPRule(
        id="A03-PHP-003",
        name="Command Injection",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"exec\s*\(\s*\$",
            r"system\s*\(\s*\$",
            r"shell_exec\s*\(\s*\$",
            r"passthru\s*\(\s*\$",
            r"`\s*\$",
            r"popen\s*\(\s*\$",
        ],
        description="Command execution with unsanitized user input",
        remediation="Use escapeshellarg() and escapeshellcmd(), validate input against whitelist",
        languages=["php"]
    ))

    # A03: Injection - Command Injection - Python
    rules.append(OWASPRule(
        id="A03-PY-003",
        name="Command Injection",
        category="A03",
        severity=Severity.CRITICAL,
        patterns=[
            r"os\.system\s*\(\s*[^)]*request",
            r"os\.popen\s*\(\s*[^)]*request",
            r"subprocess\.(call|run|Popen|check_output)\s*\(\s*[^,]*shell\s*=\s*True",
            r"eval\s*\(\s*.*request",
            r"exec\s*\(\s*.*request",
        ],
        multi_line_patterns=[
            r"subprocess\.(call|run|Popen|check_output)\s*\([\s\S]*?shell\s*=\s*True",
            r"os\.system\s*\(\s*f['\"][\s\S]*?\{[\s\S]*?\}",
        ],
        description="Command execution with user-controlled input",
        remediation="Use subprocess.run with shell=False and pass arguments as a list, never use shell=True with user input",
        languages=["python"]
    ))

    # A04: Insecure Design - JavaScript
    rules.append(OWASPRule(
        id="A04-JS-001",
        name="Missing Rate Limiting",
        category="A04",
        severity=Severity.MEDIUM,
        patterns=[
            r"app\.post\s*\(\s*['\"]/login['\"]",
            r"app\.post\s*\(\s*['\"]/auth['\"]",
        ],
        description="Authentication endpoint lacks rate limiting",
        remediation="Implement rate limiting using express-rate-limit or similar middleware",
        languages=["javascript", "js"]
    ))

    # A04: Insecure Design - Python
    rules.append(OWASPRule(
        id="A04-PY-001",
        name="Missing Rate Limiting",
        category="A04",
        severity=Severity.MEDIUM,
        patterns=[
            r"@app\.route\s*\(\s*['\"]/login['\"]",
            r"@app\.route\s*\(\s*['\"]/auth['\"]",
        ],
        description="Authentication endpoint lacks rate limiting",
        remediation="Implement rate limiting using flask-limiter or similar extension",
        languages=["python"]
    ))

    # A05: Security Misconfiguration - JavaScript
    rules.append(OWASPRule(
        id="A05-JS-001",
        name="Hardcoded Secrets",
        category="A05",
        severity=Severity.HIGH,
        patterns=[
            r"(password|secret|api_key|apikey|token)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"process\.env\s*=\s*\{[^}]*password[^}]*:",
        ],
        multi_line_patterns=[
            r"(password|secret|api_key|apikey|token)\s*[:=]\s*['\"][\s\S]{0,200}?['\"]",
        ],
        description="Hardcoded credentials or API keys in source code",
        remediation="Store secrets in environment variables or secure secret management systems",
        languages=["javascript", "js"]
    ))

    # A05: Security Misconfiguration - PHP
    rules.append(OWASPRule(
        id="A05-PHP-001",
        name="Hardcoded Secrets",
        category="A05",
        severity=Severity.HIGH,
        patterns=[
            r"\$password\s*=\s*['\"][^'\"]+['\"]",
            r"\$secret\s*=\s*['\"][^'\"]+['\"]",
            r"\$api_key\s*=\s*['\"][^'\"]+['\"]",
            r"define\s*\(\s*['\"]PASSWORD['\"]",
        ],
        description="Hardcoded credentials or secrets in source code",
        remediation="Use environment variables or secure configuration files outside web root",
        languages=["php"]
    ))

    # A05: Security Misconfiguration - Python
    rules.append(OWASPRule(
        id="A05-PY-001",
        name="Hardcoded Secrets",
        category="A05",
        severity=Severity.HIGH,
        patterns=[
            r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
            r"PASSWORD\s*=\s*['\"][^'\"]+['\"]",
            r"API_KEY\s*=\s*['\"][^'\"]+['\"]",
            r"os\.environ\.get\s*\(\s*['\"]SECRET['\"]",
        ],
        multi_line_patterns=[
            r"SECRET_KEY\s*=\s*['\"][\s\S]{0,100}?['\"]",
        ],
        description="Hardcoded secrets or insecure secret handling",
        remediation="Use environment variables and a .env file for configuration, never hardcode secrets",
        languages=["python"]
    ))

    # A05: Security Misconfiguration - Debug Mode
    rules.append(OWASPRule(
        id="A05-JS-002",
        name="Debug Mode Enabled",
        category="A05",
        severity=Severity.MEDIUM,
        patterns=[
            r"debug\s*[:=]\s*true",
            r"DEBUG\s*[:=]\s*true",
            r"NODE_ENV\s*[:=]\s*['\"]development['\"]",
        ],
        description="Debug mode enabled in production code",
        remediation="Disable debug mode in production, use environment-based configuration",
        languages=["javascript", "js"]
    ))

    # A05 - Python Debug
    rules.append(OWASPRule(
        id="A05-PY-002",
        name="Debug Mode Enabled",
        category="A05",
        severity=Severity.MEDIUM,
        patterns=[
            r"DEBUG\s*=\s*True",
            r"app\.run\(.*debug\s*=\s*True",
            r"flask\.run\(.*debug\s*=\s*True",
        ],
        description="Debug mode enabled in production Flask/Django code",
        remediation="Set DEBUG=False in production, use environment variables for configuration",
        languages=["python"]
    ))

    # A06: Vulnerable Components - JavaScript
    rules.append(OWASPRule(
        id="A06-JS-001",
        name="Outdated or Vulnerable Package Import",
        category="A06",
        severity=Severity.MEDIUM,
        patterns=[
            r"require\s*\(\s*['\"]lodash['\"]\s*\)",
            r"from\s+['\"]jquery['\"]",
            r"import\s+\{\s*[^}]*\s*\}\s+from\s+['\"]jquery['\"]",
        ],
        description="Use of packages with known vulnerabilities",
        remediation="Use npm audit to identify and update vulnerable packages, consider using modern alternatives",
        languages=["javascript", "js"]
    ))

    # A06: Vulnerable Components - Python
    rules.append(OWASPRule(
        id="A06-PY-001",
        name="Outdated or Vulnerable Package",
        category="A06",
        severity=Severity.MEDIUM,
        patterns=[
            r"import\s+pickle",
            r"from\s+pickle\s+import",
            r"import\s+xml\.etree",
            r"from\s+xml\.etree",
        ],
        description="Use of packages with known security issues (pickle, xml.etree)",
        remediation="Avoid using pickle for untrusted data, use defusedxml instead of xml.etree",
        languages=["python"]
    ))

    # A07: Authentication Failures - JavaScript
    rules.append(OWASPRule(
        id="A07-JS-001",
        name="Weak Session Management",
        category="A07",
        severity=Severity.HIGH,
        patterns=[
            r"sessionStorage\.setItem\s*\(\s*['\"]token['\"]",
            r"localStorage\.setItem\s*\(\s*['\"]token['\"]",
            r"localStorage\.setItem\s*\(\s*['\"]password['\"]",
            r"cookie\s*=\s*[^;]+;\s*[^;]*(?:secure|httpOnly)",
        ],
        description="Sensitive data stored in browser storage or insecure cookies",
        remediation="Use httpOnly and secure cookies for session tokens, avoid storing sensitive data in localStorage",
        languages=["javascript", "js"]
    ))

    # A07: Authentication Failures - PHP
    rules.append(OWASPRule(
        id="A07-PHP-001",
        name="Weak Session Management",
        category="A07",
        severity=Severity.HIGH,
        patterns=[
            r"session_start\s*\(\s*\)",
            r"session_regenerate_id\s*\(\s*\)",
        ],
        description="Missing session security configuration",
        remediation="Configure secure session settings: httpOnly, secure flag, SameSite attribute, regenerate session ID on login",
        languages=["php"]
    ))

    # A07: Authentication Failures - Python
    rules.append(OWASPRule(
        id="A07-PY-001",
        name="Weak Session Configuration",
        category="A07",
        severity=Severity.HIGH,
        patterns=[
            r"SESSION_COOKIE_HTTPONLY\s*=\s*False",
            r"SESSION_COOKIE_SECURE\s*=\s*False",
            r"SESSION_COOKIE_SAMESITE\s*=\s*['\"]None['\"]",
        ],
        description="Insecure session cookie configuration",
        remediation="Set SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, and SESSION_COOKIE_SAMESITE='Lax'",
        languages=["python"]
    ))

    # A07: Authentication Failures - Weak Password Policy
    rules.append(OWASPRule(
        id="A07-PY-002",
        name="Weak Password Policy",
        category="A07",
        severity=Severity.MEDIUM,
        patterns=[
            r"password\s*==\s*['\"].{0,8}['\"]",
            r"len\(password\)\s*[<]\s*8",
            r"password_length\s*[<]\s*8",
        ],
        description="Weak password policy detected",
        remediation="Enforce minimum password length of 8+ characters with complexity requirements",
        languages=["python"]
    ))

    # A08: Software Integrity Failures - JavaScript
    rules.append(OWASPRule(
        id="A08-JS-001",
        name="Unsafe Deserialization",
        category="A08",
        severity=Severity.HIGH,
        patterns=[
            r"JSON\.parse\s*\(\s*[^)]+\)",
            r"eval\s*\(",
            r"Function\s*\(",
            r"new\s+Function\s*\(",
        ],
        description="Unsafe deserialization or dynamic code execution",
        remediation="Validate and sanitize data before deserialization, use safe parsing methods, avoid eval()",
        languages=["javascript", "js"]
    ))

    # A08: Software Integrity Failures - Python
    rules.append(OWASPRule(
        id="A08-PY-001",
        name="Unsafe Deserialization",
        category="A08",
        severity=Severity.HIGH,
        patterns=[
            r"pickle\.loads\s*\(",
            r"pickle\.load\s*\(",
            r"yaml\.load\s*\(\s*[^)]*\)(?!\s*,\s*Loader)",
            r"marshal\.loads\s*\(",
            r"shelve\.open\s*\(",
        ],
        multi_line_patterns=[
            r"yaml\.load\s*\([\s\S]*?\)(?![\s\S]*?Loader)",
        ],
        description="Unsafe deserialization of untrusted data",
        remediation="Use safe alternatives: json.loads() for JSON, yaml.safe_load() for YAML",
        languages=["python"]
    ))

    # A09: Logging Failures - JavaScript
    rules.append(OWASPRule(
        id="A09-JS-001",
        name="Sensitive Data in Logs",
        category="A09",
        severity=Severity.MEDIUM,
        patterns=[
            r"console\.log\s*\(\s*.*password",
            r"console\.log\s*\(\s*.*token",
            r"console\.log\s*\(\s*.*secret",
            r"console\.log\s*\(\s*.*credit",
            r"console\.log\s*\(\s*.*ssn",
        ],
        description="Potential logging of sensitive information",
        remediation="Implement proper logging practices, mask sensitive data in logs, use structured logging",
        languages=["javascript", "js"]
    ))

    # A09: Logging Failures - PHP
    rules.append(OWASPRule(
        id="A09-PHP-001",
        name="Sensitive Data in Logs",
        category="A09",
        severity=Severity.MEDIUM,
        patterns=[
            r"error_log\s*\(\s*\$",
            r"syslog\s*\(\s*[^,]+,\s*\$_",
        ],
        description="Potential logging of user input",
        remediation="Avoid logging sensitive user data, sanitize log messages",
        languages=["php"]
    ))

    # A09: Logging Failures - Python
    rules.append(OWASPRule(
        id="A09-PY-001",
        name="Sensitive Data in Logs",
        category="A09",
        severity=Severity.MEDIUM,
        patterns=[
            r"logging\.\w+\s*\(\s*.*password",
            r"logging\.\w+\s*\(\s*.*token",
            r"logging\.\w+\s*\(\s*.*secret",
            r"print\s*\(\s*.*request",
            r"logger\.\w+\s*\(\s*.*password",
        ],
        description="Potential logging of sensitive information",
        remediation="Implement proper logging practices, mask sensitive data, use structured logging",
        languages=["python"]
    ))

    # A10: SSRF - JavaScript
    rules.append(OWASPRule(
        id="A10-JS-001",
        name="Server-Side Request Forgery",
        category="A10",
        severity=Severity.HIGH,
        patterns=[
            r"fetch\s*\(\s*\$",
            r"axios\.get\s*\(\s*\$",
            r"request\s*\(\s*\$",
            r"http\.get\s*\(\s*\$",
            r"https\.get\s*\(\s*\$",
            r"got\s*\(\s*\$",
        ],
        multi_line_patterns=[
            r"fetch\s*\(\s*['\"`][\s\S]{0,100}?\$",
            r"axios\.[a-z]+\s*\(\s*['\"`][\s\S]{0,100}?\$",
        ],
        description="HTTP request with user-controlled URL, vulnerable to SSRF",
        remediation="Validate and whitelist allowed URLs, block internal IP ranges, use URL parsing libraries",
        languages=["javascript", "js"]
    ))

    # A10: SSRF - PHP
    rules.append(OWASPRule(
        id="A10-PHP-001",
        name="Server-Side Request Forgery",
        category="A10",
        severity=Severity.HIGH,
        patterns=[
            r"file_get_contents\s*\(\s*\$",
            r"curl_exec\s*\(\s*\$",
            r"fopen\s*\(\s*\$",
            r"readfile\s*\(\s*\$",
        ],
        description="File/URL access with user-controlled input, vulnerable to SSRF",
        remediation="Validate URLs, whitelist allowed domains, block internal network access",
        languages=["php"]
    ))

    # A10: SSRF - Python
    rules.append(OWASPRule(
        id="A10-PY-001",
        name="Server-Side Request Forgery",
        category="A10",
        severity=Severity.HIGH,
        patterns=[
            r"requests\.(get|post|put|delete)\s*\(\s*[^)]*request",
            r"urllib\.request\.urlopen\s*\(\s*[^)]*request",
            r"httpx\.(get|post|put|delete)\s*\(\s*[^)]*request",
        ],
        multi_line_patterns=[
            r"requests\.[a-z]+\s*\(\s*f['\"][\s\S]{0,100}?\{[\s\S]*?\}",
            r"url\s*=\s*request[\s\S]{0,20}?[\s\S]*?requests\.",
        ],
        description="HTTP request using user-controlled URL, vulnerable to SSRF",
        remediation="Validate and whitelist allowed URLs, avoid passing user input directly to request functions",
        languages=["python"]
    ))

    # Best Practices - JavaScript
    rules.append(OWASPRule(
        id="BP-JS-001",
        name="Missing Input Validation",
        category="Best Practice",
        severity=Severity.MEDIUM,
        patterns=[
            r"function\s+\w+\s*\(\s*\w+\s*\)\s*\{[^}]*\}",
        ],
        description="Function parameters may lack input validation",
        remediation="Implement input validation and sanitization for all user inputs",
        languages=["javascript", "js"]
    ))

    # Best Practices - PHP
    rules.append(OWASPRule(
        id="BP-PHP-001",
        name="Missing Input Validation",
        category="Best Practice",
        severity=Severity.MEDIUM,
        patterns=[
            r"\$_GET\s*\[",
            r"\$_POST\s*\[",
            r"\$_REQUEST\s*\[",
        ],
        description="Direct use of superglobals without validation",
        remediation="Validate and sanitize all input using filter_input() or filter_var()",
        languages=["php"]
    ))

    # Best Practices - Python
    rules.append(OWASPRule(
        id="BP-PY-001",
        name="Bare Except Clause",
        category="Best Practice",
        severity=Severity.MEDIUM,
        patterns=[
            r"except\s*:",
            r"except\s+Exception\s*:",
        ],
        description="Bare except clause catches all exceptions, potentially hiding errors",
        remediation="Catch specific exceptions instead of using bare except",
        languages=["python"]
    ))

    rules.append(OWASPRule(
        id="BP-PY-002",
        name="Missing Input Validation",
        category="Best Practice",
        severity=Severity.MEDIUM,
        patterns=[
            r"request\.args\.get\s*\(",
            r"request\.form\.get\s*\(",
            r"request\.json\.get\s*\(",
        ],
        description="Direct use of request parameters without validation",
        remediation="Validate and sanitize all input using marshmallow, pydantic, or manual validation",
        languages=["python"]
    ))

    # A04: Insecure Design - PHP
    rules.append(OWASPRule(
        id="A04-PHP-001",
        name="Insecure File Upload",
        category="A04",
        severity=Severity.HIGH,
        patterns=[
            r"\$_FILES\s*\[",
            r"move_uploaded_file\s*\(",
        ],
        description="File upload detected without proper security checks",
        remediation="Validate file type, size, and content. Store files outside web root with random names",
        languages=["php"]
    ))

    # A04: Insecure Design - JavaScript
    rules.append(OWASPRule(
        id="A04-JS-002",
        name="Insecure File Upload",
        category="A04",
        severity=Severity.HIGH,
        patterns=[
            r"multer\s*\(\s*\{[^}]*\}",
            r"\.upload\s*\(",
            r"fs\.writeFile[s]?\s*\(\s*[^)]*\.(?:originalname|filename)",
        ],
        description="File upload handling without security validation",
        remediation="Validate file types with magic bytes, limit file size, use random filenames",
        languages=["javascript", "js"]
    ))

    # A08: Software Integrity - PHP
    rules.append(OWASPRule(
        id="A08-PHP-001",
        name="Unsafe Deserialization",
        category="A08",
        severity=Severity.HIGH,
        patterns=[
            r"unserialize\s*\(",
            r"include\s*\$_",
            r"require\s*\$_",
        ],
        description="Unsafe deserialization or file inclusion",
        remediation="Avoid unserialize() on untrusted data, validate file paths for includes",
        languages=["php"]
    ))

    # ── JAVA ──────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-JAVA-001", name="SQL Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"Statement\s+\w+\s*=\s*conn\.createStatement",
            r"executeQuery\s*\(\s*\".*\+",
            r"executeUpdate\s*\(\s*\".*\+",
            r"\"SELECT.*\"\s*\+",
            r"\"INSERT.*\"\s*\+",
            r"\"UPDATE.*\"\s*\+",
            r"\"DELETE.*\"\s*\+",
        ],
        description="SQL query built via string concatenation — vulnerable to SQL Injection",
        remediation="Use PreparedStatement with parameterized queries instead of string concatenation.",
        languages=["java"]
    ))
    rules.append(OWASPRule(
        id="A03-JAVA-002", name="Command Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"Runtime\.getRuntime\(\)\.exec\s*\(",
            r"ProcessBuilder\s*\(\s*Arrays\.asList\s*\(",
            r"new\s+ProcessBuilder\s*\(",
        ],
        description="OS command execution with potentially untrusted input",
        remediation="Avoid Runtime.exec() with user input. Use ProcessBuilder with a fixed command array.",
        languages=["java"]
    ))
    rules.append(OWASPRule(
        id="A02-JAVA-001", name="Weak Cryptography (MD5/SHA1)", category="A02", severity=Severity.CRITICAL,
        patterns=[
            r"MessageDigest\.getInstance\s*\(\s*\"MD5\"",
            r"MessageDigest\.getInstance\s*\(\s*\"SHA-1\"",
            r"MessageDigest\.getInstance\s*\(\s*\"SHA1\"",
        ],
        description="Use of weak hashing algorithm (MD5 or SHA-1)",
        remediation="Use SHA-256 or stronger: MessageDigest.getInstance(\"SHA-256\")",
        languages=["java"]
    ))
    rules.append(OWASPRule(
        id="A05-JAVA-001", name="Hardcoded Secrets", category="A05", severity=Severity.HIGH,
        patterns=[
            r"(?i)(password|secret|api_key|apikey|token)\s*=\s*\"[^\"]{4,}\"",
            r"(?i)String\s+password\s*=\s*\"[^\"]+\"",
        ],
        description="Hardcoded credentials or secrets in Java source code",
        remediation="Use environment variables or a secrets manager (Vault, AWS SSM).",
        languages=["java"]
    ))
    rules.append(OWASPRule(
        id="A08-JAVA-001", name="Unsafe Deserialization", category="A08", severity=Severity.HIGH,
        patterns=[
            r"ObjectInputStream\s+\w+\s*=\s*new\s+ObjectInputStream",
            r"\.readObject\s*\(",
            r"XMLDecoder\s*\(",
        ],
        description="Java deserialization of untrusted data can lead to remote code execution",
        remediation="Avoid Java serialization for untrusted data. Use JSON/XML with schema validation instead.",
        languages=["java"]
    ))
    rules.append(OWASPRule(
        id="A03-JAVA-003", name="XXE Vulnerability", category="A03", severity=Severity.HIGH,
        patterns=[
            r"DocumentBuilderFactory\.newInstance\s*\(\s*\)",
            r"SAXParserFactory\.newInstance\s*\(\s*\)",
            r"XMLInputFactory\.newInstance\s*\(\s*\)",
            r"TransformerFactory\.newInstance\s*\(\s*\)",
        ],
        description="XML parser not configured to disable external entity processing (XXE)",
        remediation="Disable external entities: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
        languages=["java"]
    ))
    rules.append(OWASPRule(
        id="A03-JAVA-004", name="LDAP Injection", category="A03", severity=Severity.HIGH,
        patterns=[
            r"ctx\.search\s*\(\s*[^,]+,\s*\".*\+",
            r"new\s+SearchControls\s*\(",
        ],
        description="LDAP query constructed with user input — vulnerable to LDAP injection",
        remediation="Use LDAP parameterized filters and escape special characters with LdapEncoder.",
        languages=["java"]
    ))

    # ── C / C++ ───────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-C-001", name="Buffer Overflow (strcpy/gets)", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"\bstrcpy\s*\(",
            r"\bgets\s*\(",
            r"\bstrcat\s*\(",
            r"\bsprintf\s*\(",
            r"\bscanf\s*\(\s*\"[^\"]*%s",
        ],
        description="Use of unsafe C string functions that can cause buffer overflows",
        remediation="Replace with safe alternatives: strncpy, strlcpy, fgets, snprintf, strncat.",
        languages=["c", "cpp", "c++"]
    ))
    rules.append(OWASPRule(
        id="A03-C-002", name="Format String Vulnerability", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"\bprintf\s*\(\s*\w+\s*\)",
            r"\bfprintf\s*\(\s*\w+\s*,\s*\w+\s*\)",
            r"\bsyslog\s*\(\s*\w+\s*,\s*\w+\s*\)",
        ],
        description="printf/fprintf called with a user-controlled format string",
        remediation="Always use a format string literal: printf(\"%s\", user_input)",
        languages=["c", "cpp", "c++"]
    ))
    rules.append(OWASPRule(
        id="A03-C-003", name="Command Injection (system/popen)", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"\bsystem\s*\(",
            r"\bpopen\s*\(",
            r"\bexecl\s*\(",
            r"\bexeclp\s*\(",
            r"\bexecvp\s*\(",
        ],
        description="OS command execution — verify that input is sanitized",
        remediation="Avoid system() with user input. Use exec with argument arrays and validate all input.",
        languages=["c", "cpp", "c++"]
    ))
    rules.append(OWASPRule(
        id="A02-C-001", name="Weak Cryptography", category="A02", severity=Severity.HIGH,
        patterns=[
            r"\bMD5_Init\s*\(",
            r"\bSHA1_Init\s*\(",
            r"\bDES_set_key\s*\(",
            r"\bRC4\s*\(",
            r"\brand\s*\(\s*\)",
        ],
        description="Use of weak or deprecated cryptographic algorithm",
        remediation="Use SHA-256 or stronger. Replace DES with AES-256. Use /dev/urandom or RAND_bytes for randomness.",
        languages=["c", "cpp", "c++"]
    ))
    rules.append(OWASPRule(
        id="MEM-C-001", name="Memory Management Issue", category="A04", severity=Severity.HIGH,
        patterns=[
            r"\bfree\s*\(\s*\w+\s*\)\s*;[^}]*\bfree\s*\(\s*\w+\s*\)",
            r"\bmalloc\s*\(\s*[^)]+\)\s*;(?!\s*if)",
        ],
        description="Potential use-after-free or unchecked malloc return value",
        remediation="Always check malloc return for NULL. Nullify pointers after free. Use smart pointers in C++.",
        languages=["c", "cpp", "c++"]
    ))

    # ── C# ────────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-CS-001", name="SQL Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"SqlCommand\s*\(\s*\".*\+",
            r"ExecuteReader\s*\(\s*\".*\+",
            r"\"SELECT.*\"\s*\+\s*\w+",
            r"\"INSERT.*\"\s*\+\s*\w+",
        ],
        description="SQL query concatenated with user input — vulnerable to SQL Injection",
        remediation="Use parameterized queries with SqlCommand.Parameters.Add() or use an ORM (Entity Framework).",
        languages=["csharp", "c#"]
    ))
    rules.append(OWASPRule(
        id="A08-CS-001", name="Unsafe Deserialization", category="A08", severity=Severity.CRITICAL,
        patterns=[
            r"BinaryFormatter\s*\(",
            r"NetDataContractSerializer\s*\(",
            r"SoapFormatter\s*\(",
            r"JavaScriptSerializer\s*\(",
            r"TypeNameHandling\.(All|Objects|Auto)",
        ],
        description="Unsafe deserialization using BinaryFormatter or Newtonsoft with TypeNameHandling",
        remediation="Replace BinaryFormatter with System.Text.Json. Set TypeNameHandling = TypeNameHandling.None.",
        languages=["csharp", "c#"]
    ))
    rules.append(OWASPRule(
        id="A05-CS-001", name="Hardcoded Secrets", category="A05", severity=Severity.HIGH,
        patterns=[
            r"(?i)(password|secret|apikey|api_key|connectionString)\s*=\s*\"[^\"]{4,}\"",
            r"(?i)string\s+password\s*=\s*\"[^\"]+\"",
        ],
        description="Hardcoded credentials or secrets in C# source code",
        remediation="Use Secret Manager, Environment Variables, or Azure Key Vault.",
        languages=["csharp", "c#"]
    ))
    rules.append(OWASPRule(
        id="A03-CS-002", name="LDAP Injection", category="A03", severity=Severity.HIGH,
        patterns=[
            r"DirectorySearcher\s*\(",
            r"\.Filter\s*=\s*\".*\+",
        ],
        description="LDAP filter constructed with user input — vulnerable to LDAP injection",
        remediation="Escape LDAP special characters with Encoder.LdapFilterEncode().",
        languages=["csharp", "c#"]
    ))

    # ── Go ────────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-GO-001", name="SQL Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"db\.Query\s*\(\s*fmt\.Sprintf",
            r"db\.Exec\s*\(\s*fmt\.Sprintf",
            r"db\.QueryRow\s*\(\s*fmt\.Sprintf",
            r"\"SELECT.*\"\s*\+",
        ],
        description="SQL query built with fmt.Sprintf — vulnerable to SQL Injection",
        remediation="Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = ?\", id)",
        languages=["go", "golang"]
    ))
    rules.append(OWASPRule(
        id="A03-GO-002", name="Command Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"exec\.Command\s*\(\s*\"sh\"\s*,\s*\"-c\"",
            r"exec\.Command\s*\(\s*\"bash\"\s*,\s*\"-c\"",
            r"exec\.Command\s*\(\s*\"cmd\"\s*,\s*\"/c\"",
        ],
        description="Shell execution with -c flag can be vulnerable to command injection",
        remediation="Avoid shell=true patterns. Use exec.Command with individual arguments.",
        languages=["go", "golang"]
    ))
    rules.append(OWASPRule(
        id="A05-GO-001", name="Hardcoded Secrets", category="A05", severity=Severity.HIGH,
        patterns=[
            r"(?i)(password|secret|apiKey|api_key|token)\s*:?=\s*\"[^\"]{4,}\"",
        ],
        description="Hardcoded credentials in Go source code",
        remediation="Use os.Getenv() or a secrets manager to store sensitive values.",
        languages=["go", "golang"]
    ))
    rules.append(OWASPRule(
        id="A10-GO-001", name="SSRF", category="A10", severity=Severity.HIGH,
        patterns=[
            r"http\.Get\s*\(\s*\w+",
            r"http\.Post\s*\(\s*\w+",
            r"http\.NewRequest\s*\(\s*[^,]+,\s*\w+",
        ],
        description="HTTP request with potentially user-controlled URL — SSRF risk",
        remediation="Validate and whitelist URLs before making HTTP requests. Block internal IP ranges.",
        languages=["go", "golang"]
    ))

    # ── Ruby ──────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-RB-001", name="Command Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"`.*#\{",
            r"system\s*\(\s*['\"].*#\{",
            r"%x\[.*#\{",
            r"open\s*\(\s*\"\\|",
        ],
        description="Ruby code execution or command injection via eval, exec, or backticks",
        remediation="Use array form of system(). Avoid eval with user input. Sanitize shell arguments.",
        languages=["ruby", "rb"]
    ))
    rules.append(OWASPRule(
        id="A03-RB-002", name="SQL Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"where\s*\(\s*\"[^\"]*#\{",
            r"find_by_sql\s*\(\s*\"[^\"]*#\{",
            r"execute\s*\(\s*\"[^\"]*#\{",
        ],
        description="SQL query with Ruby string interpolation — SQL Injection risk",
        remediation="Use ActiveRecord parameterized queries: where('name = ?', name)",
        languages=["ruby", "rb"]
    ))
    rules.append(OWASPRule(
        id="A08-RB-001", name="Unsafe YAML Load", category="A08", severity=Severity.HIGH,
        patterns=[
            r"YAML\.load\s*\(",
            r"Psych\.load\s*\(",
        ],
        description="YAML.load() with user-supplied data can execute arbitrary Ruby code",
        remediation="Use YAML.safe_load() instead of YAML.load().",
        languages=["ruby", "rb"]
    ))

    # ── Bash / Shell ──────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-SH-001", name="Command Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"\beval\s+",
            r"\beval\s+\$",
            r"`\$[A-Za-z_]+`",
            r"sh\s+-c\s+\"\$",
            r"bash\s+-c\s+\"\$",
        ],
        description="Shell eval or dynamic command execution with user input",
        remediation="Avoid eval. Validate inputs. Use \"$variable\" with proper quoting.",
        languages=["bash", "shell", "sh"]
    ))
    rules.append(OWASPRule(
        id="A05-SH-001", name="Hardcoded Secrets in Shell Script", category="A05", severity=Severity.HIGH,
        patterns=[
            r"(?i)(PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET)\s*=\s*['\"][^'\"]{4,}['\"]",
            r"export\s+(?i)(PASSWORD|SECRET|API_KEY)\s*=\s*['\"]",
        ],
        description="Hardcoded sensitive value in shell script",
        remediation="Source secrets from a vault or environment. Never hardcode credentials in scripts.",
        languages=["bash", "shell", "sh"]
    ))
    rules.append(OWASPRule(
        id="A01-SH-001", name="Unsafe Variable Expansion", category="A01", severity=Severity.MEDIUM,
        patterns=[
            r"rm\s+-rf\s+\$",
            r"chmod\s+777\s+",
            r"curl\s+.*\|\s*(?:bash|sh)",
            r"wget\s+.*-O-\s+.*\|\s*(?:bash|sh)",
        ],
        description="Dangerous shell patterns: unsafe rm, chmod 777, or pipe to shell",
        remediation="Quote variables. Avoid chmod 777. Never pipe downloads directly to bash.",
        languages=["bash", "shell", "sh"]
    ))

    # ── PowerShell ────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-PS-001", name="Command Injection (Invoke-Expression)", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"Invoke-Expression\s+",
            r"\bIEX\s+",
            r"Invoke-Expression\s*\$",
            r"\bIEX\s*\(",
        ],
        description="Invoke-Expression (IEX) with user-controlled input — RCE risk",
        remediation="Avoid IEX/Invoke-Expression. Use specific cmdlets. Validate all inputs.",
        languages=["powershell", "ps1"]
    ))
    rules.append(OWASPRule(
        id="A05-PS-001", name="Hardcoded Credentials", category="A05", severity=Severity.HIGH,
        patterns=[
            r"(?i)(Password|SecureString|ApiKey)\s*=\s*['\"][^'\"]{4,}['\"]",
            r"ConvertTo-SecureString\s+['\"][^'\"]+['\"]",
        ],
        description="Hardcoded credentials in PowerShell script",
        remediation="Use Get-Secret (SecretManagement) or environment variables for credentials.",
        languages=["powershell", "ps1"]
    ))
    rules.append(OWASPRule(
        id="A03-PS-002", name="Download Cradle", category="A03", severity=Severity.HIGH,
        patterns=[
            r"\(New-Object\s+Net\.WebClient\)\.Download",
            r"Invoke-WebRequest.*\|\s*IEX",
            r"Invoke-RestMethod.*\|\s*IEX",
            r"DownloadString\s*\(",
        ],
        description="PowerShell download cradle — commonly used in malicious scripts and insecure automation",
        remediation="Validate downloaded content. Use HTTPS. Verify checksums. Avoid piping to IEX.",
        languages=["powershell", "ps1"]
    ))

    # ── SQL ───────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-SQL-001", name="Dynamic SQL with EXEC", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"EXEC\s*\(\s*@",
            r"EXEC\s*\(\s*N'",
            r"EXECUTE\s*\(\s*@",
            r"sp_executesql\s+@",
            r"EXEC\s+sp_executesql",
        ],
        description="Dynamic SQL execution with EXEC/sp_executesql — SQL injection risk",
        remediation="Use parameterized sp_executesql with explicit parameter declarations.",
        languages=["sql"]
    ))
    rules.append(OWASPRule(
        id="A01-SQL-001", name="Overly Permissive GRANT", category="A01", severity=Severity.HIGH,
        patterns=[
            r"GRANT\s+ALL\s+PRIVILEGES",
            r"GRANT\s+ALL\s+ON\s+\*",
            r"TO\s+'?root'?",
            r"IDENTIFIED\s+BY\s+'[^']{0,8}'",
        ],
        description="Overly permissive database privileges or weak root password",
        remediation="Follow principle of least privilege. Grant only necessary permissions.",
        languages=["sql"]
    ))

    # ── Dockerfile ────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="DOCKER-001", name="Running as Root", category="A05", severity=Severity.HIGH,
        patterns=[
            r"^USER\s+root\b",
            r"^USER\s+0\b",
        ],
        description="Container runs as root — privilege escalation risk",
        remediation="Add 'USER nonroot' or create a non-root user before the final CMD/ENTRYPOINT.",
        languages=["dockerfile"]
    ))
    rules.append(OWASPRule(
        id="DOCKER-002", name="Latest Tag Usage", category="A06", severity=Severity.MEDIUM,
        patterns=[
            r"^FROM\s+\S+:latest",
            r"^FROM\s+\S+\s*$",
        ],
        description="Using ':latest' or untagged images prevents reproducible builds",
        remediation="Pin image versions: FROM node:20.10.0-alpine3.19",
        languages=["dockerfile"]
    ))
    rules.append(OWASPRule(
        id="DOCKER-003", name="ADD Instead of COPY", category="A05", severity=Severity.LOW,
        patterns=[
            r"^ADD\s+https?://",
            r"^ADD\s+\S+\.tar",
        ],
        description="ADD with URLs or archives is unpredictable. Prefer COPY.",
        remediation="Use COPY for local files. Use RUN curl for remote files so downloads can be verified.",
        languages=["dockerfile"]
    ))
    rules.append(OWASPRule(
        id="DOCKER-004", name="Hardcoded Secrets in ENV", category="A05", severity=Severity.CRITICAL,
        patterns=[
            r"^ENV\s+(?i)(PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET)\s*=\s*\S+",
            r"^ARG\s+(?i)(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*\S+",
        ],
        description="Sensitive data hardcoded in Dockerfile ENV/ARG — visible in image layers",
        remediation="Use Docker secrets or environment injection at runtime. Never bake secrets into images.",
        languages=["dockerfile"]
    ))
    rules.append(OWASPRule(
        id="DOCKER-005", name="Privileged Container", category="A01", severity=Severity.CRITICAL,
        patterns=[
            r"--privileged",
            r"privileged:\s*true",
        ],
        description="Container runs in privileged mode — full host access",
        remediation="Remove --privileged. Use specific capabilities: --cap-add NET_ADMIN if needed.",
        languages=["dockerfile", "yaml"]
    ))

    # ── Terraform / IaC ───────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="TF-001", name="Open Security Group", category="A05", severity=Severity.CRITICAL,
        patterns=[
            r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
            r"cidr_blocks\s*=\s*\[\"::0/0\"\]",
            r'ingress\s*\{[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
        ],
        description="Security group allows inbound traffic from all IPs (0.0.0.0/0)",
        remediation="Restrict cidr_blocks to specific trusted IP ranges. Avoid open ingress rules.",
        languages=["terraform", "tf"]
    ))
    rules.append(OWASPRule(
        id="TF-002", name="Hardcoded Secrets in Terraform", category="A05", severity=Severity.CRITICAL,
        patterns=[
            r'(?i)(password|secret|access_key|private_key)\s*=\s*"[^"]{4,}"',
        ],
        description="Hardcoded sensitive value in Terraform configuration",
        remediation="Use Terraform variables, vault_generic_secret, or AWS SSM parameter store.",
        languages=["terraform", "tf"]
    ))
    rules.append(OWASPRule(
        id="TF-003", name="Unencrypted Storage", category="A02", severity=Severity.HIGH,
        patterns=[
            r"encrypted\s*=\s*false",
            r"enable_dns_hostnames\s*=\s*false",
            r"storage_encrypted\s*=\s*false",
        ],
        description="Storage resource configured without encryption",
        remediation="Set encrypted = true on all storage resources (EBS, RDS, S3).",
        languages=["terraform", "tf"]
    ))

    # ── Kubernetes YAML ───────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="K8S-001", name="Privileged Pod", category="A01", severity=Severity.CRITICAL,
        patterns=[
            r"privileged:\s*true",
            r"allowPrivilegeEscalation:\s*true",
        ],
        description="Kubernetes pod/container running in privileged mode",
        remediation="Set privileged: false and allowPrivilegeEscalation: false in securityContext.",
        languages=["yaml", "yml"]
    ))
    rules.append(OWASPRule(
        id="K8S-002", name="Missing Resource Limits", category="A04", severity=Severity.MEDIUM,
        patterns=[
            r"containers:",
            r"image:\s*\S+",
        ],
        description="Container may be missing CPU/memory resource limits — DoS risk",
        remediation="Always set resources.limits.cpu and resources.limits.memory for all containers.",
        languages=["yaml", "yml"]
    ))
    rules.append(OWASPRule(
        id="K8S-003", name="Hardcoded Secret in YAML", category="A05", severity=Severity.CRITICAL,
        patterns=[
            r"(?i)(password|secret|api_key|token):\s*\S{4,}",
        ],
        description="Potential hardcoded secret in Kubernetes manifest",
        remediation="Use Kubernetes Secrets (base64) or an external secrets operator (Vault, Sealed Secrets).",
        languages=["yaml", "yml"]
    ))

    # ── Kotlin ────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A05-KT-001", name="Hardcoded Secrets", category="A05", severity=Severity.HIGH,
        patterns=[
            r"(?i)val\s+(password|secret|apiKey|token)\s*=\s*\"[^\"]{4,}\"",
            r"(?i)const\s+val\s+(password|secret|apiKey)\s*=\s*\"[^\"]{4,}\"",
        ],
        description="Hardcoded credentials or secrets in Kotlin source code",
        remediation="Use environment variables or Android Keystore/BuildConfig for secrets.",
        languages=["kotlin", "kt"]
    ))
    rules.append(OWASPRule(
        id="A03-KT-001", name="SQL Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"rawQuery\s*\(\s*\"[^\"]*\$",
            r"execSQL\s*\(\s*\"[^\"]*\+",
        ],
        description="Raw SQL query with string interpolation — SQL Injection risk",
        remediation="Use Room with parameterized queries or ContentValues for database operations.",
        languages=["kotlin", "kt"]
    ))

    # ── Swift ─────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A05-SWIFT-001", name="Hardcoded Secrets", category="A05", severity=Severity.HIGH,
        patterns=[
            r"(?i)let\s+(password|secret|apiKey|token)\s*=\s*\"[^\"]{4,}\"",
        ],
        description="Hardcoded credentials in Swift source code",
        remediation="Use Keychain Services to store sensitive values. Never hardcode secrets.",
        languages=["swift"]
    ))
    rules.append(OWASPRule(
        id="A02-SWIFT-001", name="Insecure HTTP", category="A02", severity=Severity.HIGH,
        patterns=[
            r"http://(?!localhost|127\.0\.0\.1)",
            r"NSAllowsArbitraryLoads.*true",
        ],
        description="App uses plain HTTP or has disabled ATS (App Transport Security)",
        remediation="Use HTTPS only. Remove NSAllowsArbitraryLoads from Info.plist.",
        languages=["swift"]
    ))

    # ── Scala ─────────────────────────────────────────────────────────────────
    rules.append(OWASPRule(
        id="A03-SCALA-001", name="SQL Injection", category="A03", severity=Severity.CRITICAL,
        patterns=[
            r"SQL\s*\(\s*s\".*\$",
            r"slick.*\+\s*\w+",
            r"db\.run\s*\(\s*sql\".*\$",
        ],
        description="SQL built with string interpolation in Scala — SQL Injection risk",
        remediation="Use Slick parameterized queries or sql\"\" string interpolator with proper placeholders.",
        languages=["scala"]
    ))

    return rules


def get_rules_by_language(language: str) -> List[OWASPRule]:
    all_rules = get_owasp_rules()
    language_lower = language.lower()
    return [rule for rule in all_rules if language_lower in rule.languages]


def get_rules_by_category(category: str) -> List[OWASPRule]:
    all_rules = get_owasp_rules()
    return [rule for rule in all_rules if rule.category == category]


def load_rules_from_json(filepath: str) -> List[OWASPRule]:
    if not os.path.exists(filepath):
        return []

    custom_rules = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for rule_data in data.get('rules', []):
            severity_map = {
                'low': Severity.LOW,
                'medium': Severity.MEDIUM,
                'high': Severity.HIGH,
                'critical': Severity.CRITICAL,
            }

            rule = OWASPRule(
                id=rule_data.get('id', 'CUSTOM-000'),
                name=rule_data.get('name', 'Custom Rule'),
                category=rule_data.get('category', 'Custom'),
                severity=severity_map.get(rule_data.get('severity', 'medium').lower(), Severity.MEDIUM),
                patterns=rule_data.get('patterns', []),
                multi_line_patterns=rule_data.get('multi_line_patterns', []),
                description=rule_data.get('description', ''),
                remediation=rule_data.get('remediation', ''),
                languages=rule_data.get('languages', [])
            )
            custom_rules.append(rule)
    except (json.JSONDecodeError, IOError) as e:
        raise ValueError(f"Error loading rules from {filepath}: {str(e)}")

    return custom_rules


def merge_rules(builtin_rules: List[OWASPRule], custom_rules: List[OWASPRule]) -> List[OWASPRule]:
    existing_ids = {rule.id for rule in builtin_rules}
    merged = list(builtin_rules)
    for rule in custom_rules:
        if rule.id in existing_ids:
            idx = next(i for i, r in enumerate(merged) if r.id == rule.id)
            merged[idx] = rule
        else:
            merged.append(rule)
    return merged
