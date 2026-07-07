"""
Secret Detector Module
Detects hardcoded secrets, credentials, API keys, and sensitive data
across all supported file types using pattern-based analysis.
"""
import re
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class SecretFinding:
    secret_type: str
    file_path: str
    line_number: int
    line_content: str
    masked_value: str
    severity: str
    description: str
    remediation: str
    rule_id: str


# ── Secret patterns ────────────────────────────────────────────────────────────
SECRET_PATTERNS: List[Dict] = [
    # AWS
    {
        "id": "SEC-AWS-001",
        "type": "AWS Access Key ID",
        "severity": "Critical",
        "pattern": r"(?<![A-Z0-9])(AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "description": "AWS Access Key ID found in source code",
        "remediation": "Rotate this AWS key immediately. Use IAM roles or AWS Secrets Manager. Never commit credentials.",
    },
    {
        "id": "SEC-AWS-002",
        "type": "AWS Secret Access Key",
        "severity": "Critical",
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]",
        "description": "AWS Secret Access Key found in source code",
        "remediation": "Rotate this AWS key immediately and remove from source code. Store in environment variables or AWS Secrets Manager.",
    },
    # GitHub / GitLab / Bitbucket
    {
        "id": "SEC-GIT-001",
        "type": "GitHub Personal Access Token",
        "severity": "Critical",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "description": "GitHub Personal Access Token (classic) detected",
        "remediation": "Revoke this token at github.com/settings/tokens. Use GitHub Actions secrets or environment variables.",
    },
    {
        "id": "SEC-GIT-002",
        "type": "GitHub OAuth Token",
        "severity": "Critical",
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "description": "GitHub OAuth Token detected",
        "remediation": "Revoke token immediately. Use environment variables for token storage.",
    },
    {
        "id": "SEC-GIT-003",
        "type": "GitHub Fine-Grained Token",
        "severity": "Critical",
        "pattern": r"github_pat_[A-Za-z0-9_]{82}",
        "description": "GitHub fine-grained personal access token detected",
        "remediation": "Revoke at github.com/settings/tokens and use GitHub secrets instead.",
    },
    {
        "id": "SEC-GIT-004",
        "type": "GitLab Personal Access Token",
        "severity": "Critical",
        "pattern": r"glpat-[A-Za-z0-9\-_]{20}",
        "description": "GitLab Personal Access Token detected",
        "remediation": "Revoke token in GitLab settings. Use CI/CD variables for automation.",
    },
    # Google / GCP
    {
        "id": "SEC-GCP-001",
        "type": "Google API Key",
        "severity": "High",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "description": "Google API Key detected in source code",
        "remediation": "Restrict the API key in Google Cloud Console and rotate it. Store in environment variables.",
    },
    {
        "id": "SEC-GCP-002",
        "type": "GCP Service Account Key",
        "severity": "Critical",
        "pattern": r'"type":\s*"service_account"',
        "description": "GCP Service Account JSON key file detected",
        "remediation": "Remove from source code immediately. Use Workload Identity Federation or Secret Manager.",
    },
    # Azure
    {
        "id": "SEC-AZR-001",
        "type": "Azure Storage Account Key",
        "severity": "Critical",
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        "description": "Azure Storage Account connection string with key detected",
        "remediation": "Rotate the storage account key and use Managed Identity or Azure Key Vault.",
    },
    {
        "id": "SEC-AZR-002",
        "type": "Azure Client Secret",
        "severity": "Critical",
        "pattern": r"(?i)azure.{0,30}(secret|password|key).{0,10}['\"]([A-Za-z0-9~._\-]{34,})['\"]",
        "description": "Azure client secret or password detected",
        "remediation": "Rotate the secret in Azure AD. Use Azure Key Vault for storage.",
    },
    # Slack
    {
        "id": "SEC-SLK-001",
        "type": "Slack Bot Token",
        "severity": "High",
        "pattern": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{23,25}",
        "description": "Slack Bot Token detected",
        "remediation": "Revoke at api.slack.com/apps. Store in environment variables.",
    },
    {
        "id": "SEC-SLK-002",
        "type": "Slack Webhook URL",
        "severity": "High",
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}",
        "description": "Slack Webhook URL detected in source code",
        "remediation": "Regenerate the webhook URL and store it in environment variables or secrets manager.",
    },
    # SSH / Private Keys
    {
        "id": "SEC-KEY-001",
        "type": "RSA Private Key",
        "severity": "Critical",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "description": "RSA Private Key embedded in source code",
        "remediation": "Remove key from source code immediately. Store private keys in secure key vaults or HSMs.",
    },
    {
        "id": "SEC-KEY-002",
        "type": "EC Private Key",
        "severity": "Critical",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "description": "EC Private Key embedded in source code",
        "remediation": "Remove key immediately. Use a key management service (KMS) for private key storage.",
    },
    {
        "id": "SEC-KEY-003",
        "type": "OpenSSH Private Key",
        "severity": "Critical",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "description": "OpenSSH Private Key embedded in source code",
        "remediation": "Remove from source code. Store SSH keys in ~/.ssh and reference via SSH agent.",
    },
    {
        "id": "SEC-KEY-004",
        "type": "Generic Private Key",
        "severity": "Critical",
        "pattern": r"-----BEGIN (DSA|PGP|PRIVATE) (PRIVATE )?KEY-----",
        "description": "Private cryptographic key embedded in source code",
        "remediation": "Remove key from source. Store in a KMS, HashiCorp Vault, or HSM.",
    },
    # JWT
    {
        "id": "SEC-JWT-001",
        "type": "Hardcoded JWT Secret",
        "severity": "Critical",
        "pattern": r"(?i)(jwt|json.web.token).{0,30}(secret|key|password)\s*[=:]\s*['\"][^'\"]{10,}['\"]",
        "description": "Hardcoded JWT signing secret detected",
        "remediation": "Generate a strong random secret and store in environment variables. Rotate all existing tokens.",
    },
    {
        "id": "SEC-JWT-002",
        "type": "JWT Bearer Token",
        "severity": "High",
        "pattern": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "description": "JWT token literal found in source code",
        "remediation": "Never hardcode JWT tokens. Obtain tokens at runtime via authentication.",
    },
    # Database credentials
    {
        "id": "SEC-DB-001",
        "type": "Database Connection String",
        "severity": "Critical",
        "pattern": r"(?i)(postgresql|mysql|mongodb|mssql|sqlite|oracle|redis)://[^:]+:[^@]+@[^/\s]+",
        "description": "Database connection string with credentials detected",
        "remediation": "Use environment variables or a secrets manager. Never hardcode DB credentials.",
    },
    {
        "id": "SEC-DB-002",
        "type": "Hardcoded Database Password",
        "severity": "Critical",
        "pattern": r"(?i)(db_pass|database_password|db_password|mysql_password|postgres_password)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        "description": "Hardcoded database password found",
        "remediation": "Use environment variables (os.environ, process.env) and a .env file excluded from version control.",
    },
    # SMTP credentials
    {
        "id": "SEC-SMTP-001",
        "type": "SMTP Credentials",
        "severity": "High",
        "pattern": r"(?i)(smtp_password|smtp_pass|email_password|mail_password)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        "description": "SMTP password hardcoded in source code",
        "remediation": "Store email credentials in environment variables. Use OAuth2 / App Passwords where supported.",
    },
    # Stripe / Payment
    {
        "id": "SEC-PAY-001",
        "type": "Stripe Secret Key",
        "severity": "Critical",
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{24,}",
        "description": "Stripe Secret API Key detected in source code",
        "remediation": "Rotate the key at dashboard.stripe.com/apikeys. Use environment variables.",
    },
    {
        "id": "SEC-PAY-002",
        "type": "Stripe Publishable Key",
        "severity": "Medium",
        "pattern": r"pk_(live|test)_[A-Za-z0-9]{24,}",
        "description": "Stripe Publishable Key in source code (lower risk but should be managed)",
        "remediation": "While publishable keys are safe client-side, restrict them via Stripe dashboard settings.",
    },
    # SendGrid / Twilio
    {
        "id": "SEC-API-001",
        "type": "SendGrid API Key",
        "severity": "High",
        "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "description": "SendGrid API Key detected",
        "remediation": "Revoke key at app.sendgrid.com/settings/api_keys. Use environment variables.",
    },
    {
        "id": "SEC-API-002",
        "type": "Twilio Account SID",
        "severity": "High",
        "pattern": r"AC[a-z0-9]{32}",
        "description": "Twilio Account SID detected",
        "remediation": "Pair with Auth Token check. Store in environment variables.",
    },
    # Generic secrets and passwords
    {
        "id": "SEC-GEN-001",
        "type": "Hardcoded Secret/Password",
        "severity": "High",
        "pattern": r"(?i)(?:password|passwd|secret|api_key|apikey|access_token|auth_token)\s*[=:]\s*['\"][A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]{8,}['\"]",
        "description": "Potential hardcoded password or secret value detected",
        "remediation": "Store all secrets in environment variables or a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.).",
    },
    {
        "id": "SEC-GEN-002",
        "type": "Hardcoded IP Address",
        "severity": "Low",
        "pattern": r"(?<![.\d])((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(?![.\d])",
        "description": "Hardcoded IP address detected — may expose internal infrastructure",
        "remediation": "Use DNS names and configuration files instead of hardcoded IPs.",
    },
    # Encryption keys
    {
        "id": "SEC-ENC-001",
        "type": "Hardcoded Encryption Key",
        "severity": "Critical",
        "pattern": r"(?i)(encryption_key|encrypt_key|aes_key|cipher_key)\s*[=:]\s*['\"][A-Fa-f0-9]{32,}['\"]",
        "description": "Hardcoded AES or encryption key detected",
        "remediation": "Use a KMS to manage encryption keys. Never hardcode cryptographic material.",
    },
]

# Extensions that should not be scanned for secrets (binary/generated)
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2',
    '.ttf', '.eot', '.mp4', '.mp3', '.zip', '.tar', '.gz', '.min.js',
    '.lock', '.sum', '.pdf', '.pyc', '.class',
}


def _mask_value(line: str, match_start: int, match_end: int) -> str:
    """Replace the matched secret value with masked asterisks."""
    val = line[match_start:match_end]
    visible = min(4, len(val) // 4)
    return line[:match_start] + val[:visible] + '*' * (len(val) - visible) + line[match_end:]


def scan_content_for_secrets(content: str, file_path: str) -> List[SecretFinding]:
    """Scan file content for secret patterns."""
    import os
    ext = os.path.splitext(file_path)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return []

    findings: List[SecretFinding] = []
    lines = content.split('\n')

    for rule in SECRET_PATTERNS:
        try:
            compiled = re.compile(rule["pattern"], re.IGNORECASE)
            for line_num, line in enumerate(lines, 1):
                # Skip comment-only lines that are obvious examples
                stripped = line.strip()
                if stripped.startswith(('#', '//', '/*', '*', '<!--', '--')):
                    # Still check — devs sometimes put real secrets in comments
                    pass

                match = compiled.search(line)
                if match:
                    masked = _mask_value(line.rstrip(), match.start(), match.end())
                    findings.append(SecretFinding(
                        secret_type=rule["type"],
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.rstrip(),
                        masked_value=masked,
                        severity=rule["severity"],
                        description=rule["description"],
                        remediation=rule["remediation"],
                        rule_id=rule["id"],
                    ))
                    break  # One finding per rule per file
        except re.error:
            continue

    return findings


def scan_file_for_secrets(file_path: str) -> List[SecretFinding]:
    """Read a file from disk and scan it for secrets."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return scan_content_for_secrets(content, file_path)
    except Exception:
        return []


def secret_findings_to_vulnerabilities(findings: List[SecretFinding]):
    """Convert SecretFindings to Vulnerability-compatible dicts for the API."""
    results = []
    for f in findings:
        results.append({
            'rule_id': f.rule_id,
            'rule_name': f.secret_type,
            'category': 'Secret Detection',
            'severity': f.severity,
            'file_path': f.file_path,
            'line_number': f.line_number,
            'line_end': None,
            'code_snippet': f.masked_value,
            'description': f.description,
            'remediation': f.remediation,
            'match_type': 'secret',
            'cwe': 'CWE-798',
            'owasp': 'A05:2021 – Security Misconfiguration',
        })
    return results
