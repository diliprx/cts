import re
import os
import zipfile
import tarfile
import tempfile
import shutil
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

from owasp_rules import OWASPRule, get_owasp_rules, Severity, load_rules_from_json, merge_rules


@dataclass
class Vulnerability:
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    remediation: str
    matched_pattern: str
    line_end: Optional[int] = None
    match_type: str = "single-line"
    cwe: str = ""
    owasp: str = ""


class Language(Enum):
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    GO = "go"
    RUBY = "ruby"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    SCALA = "scala"
    RUST = "rust"
    BASH = "bash"
    POWERSHELL = "powershell"
    SQL = "sql"
    HTML = "html"
    CSS = "css"
    XML = "xml"
    YAML = "yaml"
    JSON = "json"
    DOCKERFILE = "dockerfile"
    TERRAFORM = "terraform"
    DART = "dart"
    UNKNOWN = "unknown"


# Extension to language mapping
EXT_MAP = {
    '.js': Language.JAVASCRIPT, '.jsx': Language.JAVASCRIPT, '.mjs': Language.JAVASCRIPT,
    '.ts': Language.TYPESCRIPT, '.tsx': Language.TYPESCRIPT,
    '.php': Language.PHP, '.phtml': Language.PHP, '.php3': Language.PHP, '.php4': Language.PHP, '.php5': Language.PHP,
    '.py': Language.PYTHON, '.pyw': Language.PYTHON,
    '.java': Language.JAVA,
    '.c': Language.C, '.h': Language.C,
    '.cpp': Language.CPP, '.cc': Language.CPP, '.cxx': Language.CPP, '.hpp': Language.CPP,
    '.cs': Language.CSHARP,
    '.go': Language.GO,
    '.rb': Language.RUBY,
    '.kt': Language.KOTLIN, '.kts': Language.KOTLIN,
    '.swift': Language.SWIFT,
    '.scala': Language.SCALA,
    '.rs': Language.RUST,
    '.sh': Language.BASH, '.bash': Language.BASH,
    '.ps1': Language.POWERSHELL, '.psm1': Language.POWERSHELL,
    '.sql': Language.SQL,
    '.html': Language.HTML, '.htm': Language.HTML,
    '.css': Language.CSS,
    '.xml': Language.XML,
    '.yaml': Language.YAML, '.yml': Language.YAML,
    '.json': Language.JSON,
    '.tf': Language.TERRAFORM, '.tfvars': Language.TERRAFORM,
    '.dart': Language.DART,
}

# Language name used for rule lookup
LANG_KEY_MAP = {
    Language.JAVASCRIPT: ['javascript', 'js'],
    Language.TYPESCRIPT: ['javascript', 'js', 'typescript', 'ts'],
    Language.PHP: ['php'],
    Language.PYTHON: ['python'],
    Language.JAVA: ['java'],
    Language.C: ['c'],
    Language.CPP: ['cpp', 'c++'],
    Language.CSHARP: ['csharp', 'c#'],
    Language.GO: ['go', 'golang'],
    Language.RUBY: ['ruby', 'rb'],
    Language.KOTLIN: ['kotlin', 'kt'],
    Language.SWIFT: ['swift'],
    Language.SCALA: ['scala'],
    Language.RUST: ['rust'],
    Language.BASH: ['bash', 'shell', 'sh'],
    Language.POWERSHELL: ['powershell', 'ps1'],
    Language.SQL: ['sql'],
    Language.HTML: ['html'],
    Language.CSS: ['css'],
    Language.XML: ['xml'],
    Language.YAML: ['yaml', 'yml'],
    Language.JSON: ['json'],
    Language.DOCKERFILE: ['dockerfile'],
    Language.TERRAFORM: ['terraform', 'tf'],
    Language.DART: ['dart'],
}

# All supported extensions for directory scanning
ALL_SUPPORTED_EXTENSIONS = set(EXT_MAP.keys())
# Add dockerfile (no extension matching)
DOCKERFILE_NAMES = {'dockerfile', 'dockerfile.dev', 'dockerfile.prod', 'containerfile'}

# Directories to skip during scanning
SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'venv',
    'env', '.env', 'dist', 'build', '.next', 'target', 'bin', 'obj',
    '.gradle', '.idea', '.vscode', 'coverage', '.pytest_cache',
}


class CodeAnalyzer:
    def __init__(self, custom_rules_file: Optional[str] = None, enable_multi_line: bool = True):
        builtin_rules = get_owasp_rules()
        custom_rules = []
        if custom_rules_file and os.path.exists(custom_rules_file):
            custom_rules = load_rules_from_json(custom_rules_file)
        self.rules = merge_rules(builtin_rules, custom_rules)
        self.vulnerabilities: List[Vulnerability] = []
        self.enable_multi_line = enable_multi_line

    def detect_language(self, file_path: str, content: Optional[str] = None) -> Language:
        basename = os.path.basename(file_path).lower()
        if basename in DOCKERFILE_NAMES:
            return Language.DOCKERFILE

        ext = os.path.splitext(file_path)[1].lower()
        if ext in EXT_MAP:
            return EXT_MAP[ext]

        # Fallback: content-based detection
        if content:
            if re.search(r'<\?php', content, re.IGNORECASE):
                return Language.PHP
            if re.search(r'^FROM\s+\S+', content, re.MULTILINE):
                return Language.DOCKERFILE
            if re.search(r'(import\s+\w+|from\s+\w+|def\s+\w+|class\s+\w+:)', content):
                return Language.PYTHON
            if re.search(r'(function|const|let|var|export|import)', content):
                return Language.JAVASCRIPT

        return Language.UNKNOWN

    def get_applicable_rules(self, language: Language) -> List[OWASPRule]:
        keys = LANG_KEY_MAP.get(language, [])
        return [rule for rule in self.rules if any(k in rule.languages for k in keys)]

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            raise Exception(f"Error reading file {file_path}: {str(e)}")

        language = self.detect_language(file_path, content)
        if language == Language.UNKNOWN:
            return []

        return self._analyze_content(content, file_path, language)

    def analyze_directory(self, directory_path: str, extensions: List[str] = None) -> List[Vulnerability]:
        if extensions is None:
            extensions = list(ALL_SUPPORTED_EXTENSIONS)

        all_vulnerabilities = []

        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]

            for file in files:
                file_path = os.path.join(root, file)
                basename = os.path.basename(file_path).lower()
                ext = os.path.splitext(file)[1].lower()

                if ext in extensions or basename in DOCKERFILE_NAMES:
                    try:
                        vulns = self.analyze_file(file_path)
                        all_vulnerabilities.extend(vulns)
                    except Exception as e:
                        print(f"Warning: Could not analyze {file_path}: {str(e)}")

        return all_vulnerabilities

    def analyze_zip(self, zip_path: str) -> tuple:
        """Extract ZIP/TAR and analyze all files inside. Returns (vulnerabilities, file_list, extract_dir)."""
        extract_dir = tempfile.mkdtemp(prefix='cts_scan_')
        file_list = []

        try:
            if zipfile.is_zipfile(zip_path):
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(extract_dir)
            elif tarfile.is_tarfile(zip_path):
                with tarfile.open(zip_path, 'r:*') as tf:
                    tf.extractall(extract_dir)
            else:
                raise ValueError("Unsupported archive format. Use ZIP or TAR.")

            # Collect file paths
            for root, dirs, files in os.walk(extract_dir):
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
                for f in files:
                    fpath = os.path.join(root, f)
                    rel_path = os.path.relpath(fpath, extract_dir)
                    file_list.append(rel_path)

            vulns = self.analyze_directory(extract_dir)

            # Rewrite paths to be relative
            for v in vulns:
                try:
                    v.file_path = os.path.relpath(v.file_path, extract_dir)
                except Exception:
                    pass

            return vulns, file_list, extract_dir

        except Exception:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise

    def analyze_repo(self, repo_url: str) -> tuple:
        """Clone a git repository and analyze it. Returns (vulnerabilities, file_list, clone_dir)."""
        import subprocess
        clone_dir = tempfile.mkdtemp(prefix='cts_repo_')
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, clone_dir],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr[:500]}")

            file_list = []
            for root, dirs, files in os.walk(clone_dir):
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
                for f in files:
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, clone_dir)
                    file_list.append(rel)

            vulns = self.analyze_directory(clone_dir)
            for v in vulns:
                try:
                    v.file_path = os.path.relpath(v.file_path, clone_dir)
                except Exception:
                    pass

            return vulns, file_list, clone_dir

        except Exception:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise

    def analyze_code_string(self, code: str, language_str: str, file_path: str = "input") -> List[Vulnerability]:
        # Map string to Language enum
        lang_str_lower = language_str.lower()
        lang = Language.UNKNOWN
        for lang_enum, keys in LANG_KEY_MAP.items():
            if lang_str_lower in keys or lang_str_lower == lang_enum.value:
                lang = lang_enum
                break
        if lang == Language.UNKNOWN:
            # Try extension-based
            lang = self.detect_language(f"file.{language_str}", code)
        return self._analyze_content(code, file_path, lang)

    def _analyze_content(self, content: str, file_path: str, language: Language) -> List[Vulnerability]:
        vulnerabilities = []
        lines = content.split('\n')
        applicable_rules = self.get_applicable_rules(language)

        # Single-line analysis
        for line_num, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, line_num - 3)
                            end = min(len(lines), line_num + 2)
                            snippet = '\n'.join(lines[start:end])
                            vuln = Vulnerability(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                category=rule.category,
                                severity=rule.severity,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=snippet,
                                description=rule.description,
                                remediation=rule.remediation,
                                matched_pattern=pattern,
                                match_type="single-line"
                            )
                            vulnerabilities.append(vuln)
                            break
                    except re.error:
                        continue

        # Multi-line analysis (if enabled)
        if self.enable_multi_line:
            multi_vulns = self._analyze_multi_line(content, lines, file_path, applicable_rules)
            existing_ranges = {}
            for v in vulnerabilities:
                end = v.line_number if v.line_end is None else v.line_end
                existing_ranges[(v.rule_id, v.matched_pattern)] = (v.line_number, end)

            for mv in multi_vulns:
                rule_key = (mv.rule_id, mv.matched_pattern)
                if rule_key in existing_ranges:
                    ex_start, ex_end = existing_ranges[rule_key]
                    if ex_start <= mv.line_number <= ex_end:
                        continue
                vulnerabilities.append(mv)

        return vulnerabilities

    def _analyze_multi_line(self, content: str, lines: List[str], file_path: str,
                            applicable_rules: List[OWASPRule]) -> List[Vulnerability]:
        vulnerabilities = []
        total_lines = len(lines)

        for rule in applicable_rules:
            if not rule.multi_line_patterns:
                continue
            for ml_pattern in rule.multi_line_patterns:
                try:
                    compiled = re.compile(ml_pattern, re.IGNORECASE | re.DOTALL)
                    for match in compiled.finditer(content):
                        matched_text = match.group(0)
                        if not matched_text.strip():
                            continue
                        start_pos = match.start()
                        end_pos = match.end()
                        start_line = content[:start_pos].count('\n') + 1
                        end_line = content[:end_pos].count('\n') + 1
                        context_start = max(0, start_line - 2)
                        context_end = min(total_lines, end_line + 1)
                        snippet = '\n'.join(lines[context_start:context_end])
                        vuln = Vulnerability(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            file_path=file_path,
                            line_number=start_line,
                            line_end=end_line,
                            code_snippet=snippet,
                            description=rule.description,
                            remediation=rule.remediation,
                            matched_pattern=ml_pattern,
                            match_type="multi-line"
                        )
                        vulnerabilities.append(vuln)
                except re.error:
                    continue

        # Deduplicate
        if vulnerabilities:
            vulnerabilities.sort(key=lambda v: (v.rule_id, v.line_number))
            deduped = []
            for v in vulnerabilities:
                if deduped and deduped[-1].rule_id == v.rule_id:
                    prev = deduped[-1]
                    prev_end = prev.line_end or prev.line_number
                    if v.line_number - prev_end <= 3:
                        continue
                deduped.append(v)
            vulnerabilities = deduped

        return vulnerabilities

    def get_statistics(self, vulnerabilities: List[Vulnerability], extra: dict = None) -> Dict:
        stats = {
            'total': len(vulnerabilities),
            'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'by_category': {},
            'by_file': {},
            'by_match_type': {'single-line': 0, 'multi-line': 0, 'secret': 0, 'dependency': 0},
            'languages_detected': [],
            'files_scanned': 0,
        }
        if extra:
            stats.update(extra)

        for vuln in vulnerabilities:
            sev = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev in stats['by_severity']:
                stats['by_severity'][sev] += 1

            category = vuln.category
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1

            fp = vuln.file_path
            stats['by_file'][fp] = stats['by_file'].get(fp, 0) + 1

            mt = vuln.match_type
            if mt in stats['by_match_type']:
                stats['by_match_type'][mt] += 1

        return stats

    def calculate_security_score(self, vulnerabilities: List[Vulnerability]) -> float:
        if not vulnerabilities:
            return 100.0
        weights = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 2, Severity.LOW: 1}
        total_penalty = sum(weights.get(vuln.severity, 0) for vuln in vulnerabilities)
        score = max(0, 100 - min(total_penalty, 100))
        return round(score, 2)

    def get_security_grade(self, score: float) -> str:
        if score >= 95: return 'A+'
        if score >= 85: return 'A'
        if score >= 75: return 'B'
        if score >= 60: return 'C'
        if score >= 40: return 'D'
        return 'F'
