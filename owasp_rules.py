"""
OWASP Top 10 Vulnerability Rules and Patterns
Defines detection patterns for JavaScript and PHP security vulnerabilities
"""

from typing import Dict, List, Tuple
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class OWASPRule:
    """Represents an OWASP vulnerability rule"""
    def __init__(self, id: str, name: str, category: str, severity: Severity, 
                 patterns: List[str], description: str, remediation: str, 
                 languages: List[str]):
        self.id = id
        self.name = name
        self.category = category
        self.severity = severity
        self.patterns = patterns
        self.description = description
        self.remediation = remediation
        self.languages = languages


# OWASP Top 10 2021 Categories
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
    """Returns all OWASP Top 10 vulnerability detection rules"""
    
    rules = []
    
    # A01: Broken Access Control - JavaScript
    rules.append(OWASPRule(
        id="A01-JS-001",
        name="Missing Authorization Check",
        category="A01",
        severity=Severity.HIGH,
        patterns=[
            r"\.get\([^)]*\)\s*\{[^}]*\}",  # Express route without auth
            r"router\.(get|post|put|delete)\([^)]*\)\s*\{[^}]*\}",
            r"app\.(get|post|put|delete)\([^)]*\)\s*\{[^}]*\}",
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
        description="Missing session-based authorization checks",
        remediation="Verify user authentication and authorization before accessing protected resources",
        languages=["php"]
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
        ],
        description="SQL query constructed with string concatenation, vulnerable to injection",
        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries",
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
        ],
        description="SQL query with direct variable interpolation, vulnerable to injection",
        remediation="Use prepared statements with mysqli_prepare() or PDO::prepare()",
        languages=["php"]
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
        ],
        description="Command execution with unsanitized user input",
        remediation="Use escapeshellarg() and escapeshellcmd(), validate input against whitelist",
        languages=["php"]
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
        ],
        description="Sensitive data stored in browser storage",
        remediation="Use httpOnly cookies for session tokens, avoid storing sensitive data in localStorage",
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
        ],
        description="Unsafe deserialization of untrusted data",
        remediation="Validate and sanitize data before deserialization, use safe parsing methods",
        languages=["javascript", "js"]
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
        ],
        description="File/URL access with user-controlled input, vulnerable to SSRF",
        remediation="Validate URLs, whitelist allowed domains, block internal network access",
        languages=["php"]
    ))
    
    # Additional Best Practices - JavaScript
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
    
    # Additional Best Practices - PHP
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
    
    return rules


def get_rules_by_language(language: str) -> List[OWASPRule]:
    """Get all rules applicable to a specific language"""
    all_rules = get_owasp_rules()
    language_lower = language.lower()
    return [rule for rule in all_rules if language_lower in rule.languages]


def get_rules_by_category(category: str) -> List[OWASPRule]:
    """Get all rules for a specific OWASP category"""
    all_rules = get_owasp_rules()
    return [rule for rule in all_rules if rule.category == category]

