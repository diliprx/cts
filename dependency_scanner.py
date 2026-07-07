"""
Dependency Scanner Module
Scans package manifest files for vulnerable, outdated, or insecure dependencies.
Maps findings to CWE-1104 and OWASP A06:2021.
"""
import re
import json
import os
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class DependencyFinding:
    rule_id: str
    package_name: str
    current_version: Optional[str]
    issue_type: str  # "known_vulnerable", "unpinned", "dangerous_package"
    severity: str
    file_path: str
    line_number: int
    description: str
    remediation: str
    cwe: str
    owasp: str


# ── Known vulnerable / dangerous packages ─────────────────────────────────────
# Format: package_name -> {severity, reason, safe_version}
DANGEROUS_NPM_PACKAGES: Dict[str, Dict] = {
    "lodash": {"severity": "High", "reason": "Prototype pollution (CVE-2019-10744, CVE-2020-8203). Use lodash >= 4.17.21 or alternatives.", "safe_version": ">=4.17.21"},
    "jquery": {"severity": "Medium", "reason": "Multiple XSS vulnerabilities in versions < 3.5.0 (CVE-2019-11358, CVE-2020-11022).", "safe_version": ">=3.5.0"},
    "minimist": {"severity": "High", "reason": "Prototype pollution (CVE-2020-7598, CVE-2021-44906).", "safe_version": ">=1.2.6"},
    "node-fetch": {"severity": "High", "reason": "Exposure of sensitive information (CVE-2022-0235) in versions < 2.6.7.", "safe_version": ">=2.6.7"},
    "axios": {"severity": "Medium", "reason": "CSRF vulnerability (CVE-2023-45857) in versions < 1.6.0.", "safe_version": ">=1.6.0"},
    "express": {"severity": "Medium", "reason": "Open redirect and ReDoS issues in older versions. Keep updated.", "safe_version": ">=4.18.2"},
    "jsonwebtoken": {"severity": "High", "reason": "Authentication bypass (CVE-2022-23529, CVE-2022-23539) in versions < 9.0.0.", "safe_version": ">=9.0.0"},
    "moment": {"severity": "Medium", "reason": "Path traversal (CVE-2022-24785) and ReDoS. Consider using date-fns or dayjs.", "safe_version": ">=2.29.4"},
    "set-value": {"severity": "High", "reason": "Prototype pollution (CVE-2019-10747).", "safe_version": ">=4.0.1"},
    "tar": {"severity": "High", "reason": "Path traversal (CVE-2021-32803, CVE-2021-37701) in versions < 6.1.9.", "safe_version": ">=6.1.9"},
    "semver": {"severity": "Medium", "reason": "ReDoS vulnerability (CVE-2022-25883) in versions < 7.5.2.", "safe_version": ">=7.5.2"},
    "word-wrap": {"severity": "Medium", "reason": "ReDoS vulnerability (CVE-2023-26115).", "safe_version": ">=1.2.4"},
    "tough-cookie": {"severity": "High", "reason": "Prototype pollution (CVE-2023-26136) in versions < 4.1.3.", "safe_version": ">=4.1.3"},
    "yaml": {"severity": "Medium", "reason": "Arbitrary code execution risk with untrusted YAML in older versions.", "safe_version": ">=2.2.2"},
    "ws": {"severity": "High", "reason": "DoS vulnerability (CVE-2024-37890) in versions < 8.17.1.", "safe_version": ">=8.17.1"},
    "ejs": {"severity": "Critical", "reason": "Server-side template injection (CVE-2022-29078) in versions < 3.1.7.", "safe_version": ">=3.1.7"},
    "vm2": {"severity": "Critical", "reason": "Sandbox escape (CVE-2023-29017, CVE-2023-30547). Package is unmaintained — do not use.", "safe_version": "ABANDON"},
    "node-ipc": {"severity": "Critical", "reason": "Malicious code injection by maintainer (supply chain attack).", "safe_version": "ABANDON"},
    "colors": {"severity": "High", "reason": "Maintainer deliberately introduced infinite loop (supply chain attack).", "safe_version": "<=1.4.0"},
    "chalk": {"severity": "Low", "reason": "ESM-only from v5. Ensure your project supports ESM or pin to v4.x.", "safe_version": ">=4.0.0"},
    "multer": {"severity": "Medium", "reason": "Older versions have path traversal risks. Keep updated.", "safe_version": ">=1.4.5-lts.1"},
    "helmet": {"severity": "Low", "reason": "Older versions missing Content-Security-Policy defaults.", "safe_version": ">=7.0.0"},
    "passport": {"severity": "Medium", "reason": "Session fixation (CVE-2022-25896) in versions < 0.6.0.", "safe_version": ">=0.6.0"},
    "xml2js": {"severity": "High", "reason": "Prototype pollution (CVE-2023-0842).", "safe_version": ">=0.5.0"},
    "crossws": {"severity": "Medium", "reason": "Prototype pollution in versions < 0.3.4.", "safe_version": ">=0.3.4"},
}

DANGEROUS_PY_PACKAGES: Dict[str, Dict] = {
    "pickle": {"severity": "High", "reason": "Unsafe deserialization of untrusted data. Use json or marshmallow instead.", "safe_version": "N/A"},
    "pyyaml": {"severity": "High", "reason": "yaml.load() without Loader= is unsafe (CVE-2017-18342). Use yaml.safe_load().", "safe_version": ">=6.0"},
    "pillow": {"severity": "High", "reason": "Multiple RCE and DoS CVEs in older versions. Update to latest.", "safe_version": ">=10.0.0"},
    "requests": {"severity": "Medium", "reason": "CVE-2023-32681 (Proxy-Authorization leak) in versions < 2.31.0.", "safe_version": ">=2.31.0"},
    "cryptography": {"severity": "Medium", "reason": "Several CVEs in older versions. Use latest version.", "safe_version": ">=41.0.0"},
    "paramiko": {"severity": "High", "reason": "Authentication bypass (CVE-2023-48795) in versions < 3.4.0.", "safe_version": ">=3.4.0"},
    "werkzeug": {"severity": "High", "reason": "Path traversal (CVE-2023-46136, CVE-2024-34069) in older versions.", "safe_version": ">=3.0.3"},
    "flask": {"severity": "Medium", "reason": "Keep updated. Pin to secure versions.", "safe_version": ">=3.0.3"},
    "django": {"severity": "High", "reason": "Multiple CVEs in older versions. Use latest LTS (4.2.x or 5.0.x).", "safe_version": ">=4.2.0"},
    "jinja2": {"severity": "High", "reason": "SSTI in older versions (CVE-2024-34064).", "safe_version": ">=3.1.4"},
    "sqlalchemy": {"severity": "Medium", "reason": "SQL injection risks in raw query usage. Keep updated.", "safe_version": ">=2.0.0"},
    "aiohttp": {"severity": "High", "reason": "Request smuggling (CVE-2024-23334, CVE-2024-30251).", "safe_version": ">=3.9.4"},
    "lxml": {"severity": "High", "reason": "XXE vulnerability via older libxml2 bindings.", "safe_version": ">=5.0.0"},
    "pyarrow": {"severity": "Critical", "reason": "Arbitrary code execution (CVE-2023-47248) in versions < 14.0.1.", "safe_version": ">=14.0.1"},
    "setuptools": {"severity": "High", "reason": "Remote code execution via package URL (CVE-2024-6345).", "safe_version": ">=70.0.0"},
    "urllib3": {"severity": "High", "reason": "Header injection (CVE-2023-45803) and SSRF risks in older versions.", "safe_version": ">=2.0.7"},
    "certifi": {"severity": "Medium", "reason": "Outdated CA bundle may include revoked certificates.", "safe_version": ">=2023.7.22"},
    "httpx": {"severity": "Low", "reason": "Keep updated for security patches.", "safe_version": ">=0.27.0"},
    "uvicorn": {"severity": "Medium", "reason": "Keep updated. Older versions have DoS risks.", "safe_version": ">=0.29.0"},
    "starlette": {"severity": "High", "reason": "Path traversal (CVE-2023-29159) in versions < 0.28.0.", "safe_version": ">=0.28.0"},
}


def _extract_version(version_str: str) -> Optional[str]:
    """Extract a clean version string."""
    if not version_str:
        return None
    version_str = version_str.strip().lstrip('^~>=<!')
    if version_str in ('*', '', 'latest', 'next', 'canary'):
        return version_str
    return version_str


def _is_unpinned(version_str: str) -> bool:
    """Check if a version is unpinned (wildcard, range, or 'latest')."""
    if not version_str:
        return True
    v = version_str.strip()
    return v in ('*', 'latest', 'next', 'canary', '') or v.startswith('^') or v.startswith('~') or v == 'x'


def scan_package_json(file_path: str) -> List[DependencyFinding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return findings

    all_deps = {}
    all_deps.update(data.get('dependencies', {}))
    all_deps.update(data.get('devDependencies', {}))

    for pkg, version in all_deps.items():
        ver_clean = _extract_version(str(version))
        line_num = 1
        # Unpinned versions
        if _is_unpinned(str(version)):
            findings.append(DependencyFinding(
                rule_id="DEP-NPM-UNPIN",
                package_name=pkg,
                current_version=str(version),
                issue_type="unpinned",
                severity="Low",
                file_path=file_path,
                line_number=line_num,
                description=f"Package '{pkg}' has unpinned version '{version}'. Unpinned deps may pull in vulnerable versions.",
                remediation=f"Pin '{pkg}' to a specific version in package.json and use package-lock.json.",
                cwe="CWE-1104",
                owasp="A06:2021 – Vulnerable and Outdated Components",
            ))

        # Known vulnerable packages
        pkg_lower = pkg.lower()
        if pkg_lower in DANGEROUS_NPM_PACKAGES:
            info = DANGEROUS_NPM_PACKAGES[pkg_lower]
            findings.append(DependencyFinding(
                rule_id=f"DEP-NPM-{pkg_lower.upper()[:8]}",
                package_name=pkg,
                current_version=ver_clean,
                issue_type="known_vulnerable",
                severity=info["severity"],
                file_path=file_path,
                line_number=line_num,
                description=f"Package '{pkg}' has known security issues: {info['reason']}",
                remediation=f"Update to safe version: {info['safe_version']}. Run 'npm audit fix'.",
                cwe="CWE-1104",
                owasp="A06:2021 – Vulnerable and Outdated Components",
            ))

    return findings


def scan_requirements_txt(file_path: str) -> List[DependencyFinding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue

        # Parse: package==version or package>=version or just package
        match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]{0,2})\s*([A-Za-z0-9\._\-\*]*)', line)
        if not match:
            continue

        pkg_name = match.group(1).lower().replace('-', '_')
        operator = match.group(2)
        version = match.group(3)

        if not operator or not version:
            findings.append(DependencyFinding(
                rule_id="DEP-PY-UNPIN",
                package_name=match.group(1),
                current_version=None,
                issue_type="unpinned",
                severity="Low",
                file_path=file_path,
                line_number=line_num,
                description=f"Package '{match.group(1)}' has no version pin in requirements.txt.",
                remediation="Pin exact versions (e.g., requests==2.31.0) and use pip freeze for reproducible installs.",
                cwe="CWE-1104",
                owasp="A06:2021 – Vulnerable and Outdated Components",
            ))

        if pkg_name in DANGEROUS_PY_PACKAGES:
            info = DANGEROUS_PY_PACKAGES[pkg_name]
            findings.append(DependencyFinding(
                rule_id=f"DEP-PY-{pkg_name.upper()[:8]}",
                package_name=match.group(1),
                current_version=version or None,
                issue_type="known_vulnerable",
                severity=info["severity"],
                file_path=file_path,
                line_number=line_num,
                description=f"Package '{match.group(1)}' has known security issues: {info['reason']}",
                remediation=f"Update to safe version: {info['safe_version']}. Run 'pip install --upgrade {match.group(1)}'.",
                cwe="CWE-1104",
                owasp="A06:2021 – Vulnerable and Outdated Components",
            ))

    return findings


def scan_go_mod(file_path: str) -> List[DependencyFinding]:
    findings = []
    DANGEROUS_GO = {
        "golang.org/x/crypto": {"severity": "Medium", "reason": "Multiple CVEs. Always use latest."},
        "golang.org/x/net": {"severity": "Medium", "reason": "HTTP/2 DoS (CVE-2023-44487) in older versions."},
        "github.com/dgrijalva/jwt-go": {"severity": "Critical", "reason": "Abandoned. Use golang-jwt/jwt instead (CVE-2020-26160)."},
        "github.com/form3tech-oss/jwt-go": {"severity": "High", "reason": "Use golang-jwt/jwt (actively maintained)."},
    }
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('//') or not line.startswith('require') and '\t' not in line:
            continue
        for pkg, info in DANGEROUS_GO.items():
            if pkg in line:
                findings.append(DependencyFinding(
                    rule_id=f"DEP-GO-{pkg.split('/')[-1].upper()[:8]}",
                    package_name=pkg,
                    current_version=None,
                    issue_type="known_vulnerable",
                    severity=info["severity"],
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Go dependency '{pkg}' has known security issues: {info['reason']}",
                    remediation=f"Update or replace '{pkg}'. Run 'go get -u {pkg}'.",
                    cwe="CWE-1104",
                    owasp="A06:2021 – Vulnerable and Outdated Components",
                ))
    return findings


def scan_cargo_toml(file_path: str) -> List[DependencyFinding]:
    findings = []
    DANGEROUS_RUST = {
        "openssl": {"severity": "Medium", "reason": "Ensure openssl crate is up to date (wraps libssl CVEs)."},
        "hyper": {"severity": "Medium", "reason": "HTTP/2 DoS in older versions. Use >=1.0.0."},
        "actix-web": {"severity": "Low", "reason": "Use latest stable version for security patches."},
    }
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, 1):
        for pkg, info in DANGEROUS_RUST.items():
            if line.strip().startswith(pkg):
                findings.append(DependencyFinding(
                    rule_id=f"DEP-RUST-{pkg.upper()[:8]}",
                    package_name=pkg,
                    current_version=None,
                    issue_type="known_vulnerable",
                    severity=info["severity"],
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Rust dependency '{pkg}': {info['reason']}",
                    remediation=f"Run 'cargo audit' for full vulnerability report. Update '{pkg}' to latest.",
                    cwe="CWE-1104",
                    owasp="A06:2021 – Vulnerable and Outdated Components",
                ))
    return findings


def scan_manifest_file(file_path: str) -> List[DependencyFinding]:
    """Auto-detect manifest type and scan appropriately."""
    basename = os.path.basename(file_path).lower()
    if basename == 'package.json':
        return scan_package_json(file_path)
    elif basename in ('requirements.txt', 'requirements-dev.txt', 'requirements-test.txt'):
        return scan_requirements_txt(file_path)
    elif basename == 'go.mod':
        return scan_go_mod(file_path)
    elif basename == 'cargo.toml':
        return scan_cargo_toml(file_path)
    return []


MANIFEST_FILES = {'package.json', 'requirements.txt', 'requirements-dev.txt', 'go.mod', 'cargo.toml', 'composer.json', 'pom.xml', 'build.gradle'}


def is_manifest_file(filename: str) -> bool:
    return os.path.basename(filename).lower() in MANIFEST_FILES


def dependency_findings_to_dicts(findings: List[DependencyFinding]) -> List[dict]:
    return [
        {
            'rule_id': f.rule_id,
            'rule_name': f"Dependency: {f.package_name} ({f.issue_type.replace('_', ' ').title()})",
            'category': 'Dependency Analysis',
            'severity': f.severity,
            'file_path': f.file_path,
            'line_number': f.line_number,
            'line_end': None,
            'code_snippet': f"Package: {f.package_name}  Version: {f.current_version or 'unspecified'}",
            'description': f.description,
            'remediation': f.remediation,
            'match_type': 'dependency',
            'cwe': f.cwe,
            'owasp': f.owasp,
        }
        for f in findings
    ]
