"""
Core Analysis Engine
Implements taint-based static code analysis for OWASP Top 10 vulnerabilities
Now uses data flow analysis instead of regex patterns
Supports both TAINT and REGEX modes
Supports directory and GitHub repository analysis
"""

import re
import os
import subprocess
import tempfile
import shutil
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from owasp_rules import OWASPRule, get_owasp_rules, get_rules_by_language, Severity
from external_tools import ExternalToolRunner
from taint_engine import TaintAnalyzer, TaintType


__all__ = ['CodeAnalyzer', 'Vulnerability', 'Language', 'AnalysisMode', 'Severity']


# Supported file extensions for analysis
SUPPORTED_EXTENSIONS = {'.php', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.phtml'}

# Directories to skip during scanning
SKIP_DIRECTORIES = {'node_modules', 'vendor', '.git', '__pycache__', 'dist', 'build', 
                    '.venv', 'venv', 'env', '.idea', '.vscode', 'coverage', 'test_output'}


@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
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


class Language(Enum):
    """Supported programming languages"""
    JAVASCRIPT = "javascript"
    PHP = "php"
    UNKNOWN = "unknown"


class AnalysisMode(Enum):
    """Analysis modes"""
    TAINT = "taint"  # Data flow / taint analysis
    REGEX = "regex"  # Pattern-based regex matching
    HYBRID = "hybrid"  # Both approaches combined


class CodeAnalyzer:
    """Main code analysis engine - supports taint and regex modes"""
    
    def __init__(self, mode: AnalysisMode = AnalysisMode.TAINT):
        self.rules = get_owasp_rules()
        self.vulnerabilities: List[Vulnerability] = []
        self.tool_runner = ExternalToolRunner()
        self.taint_analyzer = TaintAnalyzer()
        self.analysis_mode = mode
        self._temp_dirs = []  # Track temp directories for cleanup
    
    def clone_github_repo(self, repo_url: str) -> str:
        """
        Clone a GitHub repository for analysis.
        Returns the path to the cloned repository.
        """
        # Clean up URL
        repo_url = repo_url.strip()
        if repo_url.endswith('/'):
            repo_url = repo_url[:-1]
        if not repo_url.endswith('.git') and 'github.com' in repo_url:
            repo_url = repo_url + '.git'
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix='code_analysis_')
        self._temp_dirs.append(temp_dir)
        
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, temp_dir],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large repos
            )
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
            return temp_dir
        except FileNotFoundError:
            raise Exception("Git is not installed or not in PATH")
        except subprocess.TimeoutExpired:
            raise Exception("Git clone timed out (repository too large?)")
    
    def analyze_directory(self, directory: str, recursive: bool = True, 
                         mode: Optional[AnalysisMode] = None) -> List[Vulnerability]:
        """
        Analyze all supported files in a directory.
        Supports cross-file taint tracking.
        """
        all_vulnerabilities = []
        files_to_analyze = self._collect_files(directory, recursive)
        
        # Use provided mode or instance mode
        analysis_mode = mode if mode else self.analysis_mode
        
        # For cross-file taint analysis, use the advanced engine
        if analysis_mode == AnalysisMode.TAINT:
            try:
                from cross_file_taint import CrossFileTaintAnalyzer
                cross_analyzer = CrossFileTaintAnalyzer()
                taint_flows = cross_analyzer.analyze_directory(directory, recursive)
                
                # Convert TaintFlow objects to Vulnerability objects
                for flow in taint_flows:
                    severity_map = {
                        'CRITICAL': Severity.CRITICAL,
                        'HIGH': Severity.HIGH,
                        'MEDIUM': Severity.MEDIUM,
                        'LOW': Severity.LOW
                    }
                    
                    # Build description with full path info
                    source_info = f"{flow.source.description} (line {flow.source.location.line_number})"
                    sink_info = f"{flow.sink.description}"
                    
                    if flow.cross_file:
                        desc = f"CROSS-FILE VULNERABILITY: Tainted data from {source_info} in {os.path.basename(flow.source.location.file_path)} " \
                               f"flows through variable '{flow.source.variable_name}' to {sink_info} in {os.path.basename(flow.sink.location.file_path)}"
                    else:
                        desc = f"Tainted data from {source_info} flows through variable '{flow.source.variable_name}' to {sink_info}"
                    
                    vuln = Vulnerability(
                        rule_id=f"TAINT-{flow.vulnerability_type.replace(' ', '-').upper()}",
                        rule_name=f"Taint Analysis: {flow.vulnerability_type}",
                        category="Data Flow Vulnerability" + (" (Cross-File)" if flow.cross_file else ""),
                        severity=severity_map.get(flow.severity, Severity.HIGH),
                        file_path=flow.sink.location.file_path,
                        line_number=flow.sink.location.line_number,
                        code_snippet=flow.sink.code_snippet,
                        description=desc,
                        remediation=f"Sanitize data from '{flow.source.description}' before using in '{flow.sink.description}'. "
                                   f"Files involved: {', '.join(os.path.basename(f) for f in flow.files_involved)}",
                        matched_pattern=f"Taint Flow: {flow.source.variable_name}"
                    )
                    all_vulnerabilities.append(vuln)
            except ImportError:
                pass  # Fall back to per-file analysis
        
        # Fall back or complement with per-file analysis
        for file_path in files_to_analyze:
            try:
                file_vulns = self.analyze_file(file_path, mode=analysis_mode)
                all_vulnerabilities.extend(file_vulns)
            except Exception as e:
                # Continue with other files even if one fails
                print(f"Warning: Failed to analyze {file_path}: {e}")
        
        # Deduplicate vulnerabilities
        all_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
        
        return all_vulnerabilities
    
    def analyze_github_repo(self, repo_url: str, mode: Optional[AnalysisMode] = None) -> Tuple[List[Vulnerability], str]:
        """
        Analyze a GitHub repository.
        Returns tuple of (vulnerabilities, repo_path)
        """
        repo_path = self.clone_github_repo(repo_url)
        vulnerabilities = self.analyze_directory(repo_path, recursive=True, mode=mode)
        return vulnerabilities, repo_path
    
    def _collect_files(self, directory: str, recursive: bool) -> List[str]:
        """Collect all supported files in directory"""
        files = []
        directory = Path(directory)
        
        if not directory.exists():
            raise Exception(f"Directory does not exist: {directory}")
        
        if recursive:
            for file_path in directory.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    # Skip files in excluded directories
                    if not any(skip_dir in str(file_path) for skip_dir in SKIP_DIRECTORIES):
                        files.append(str(file_path))
        else:
            for file_path in directory.glob('*'):
                if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files.append(str(file_path))
        
        return files
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities based on key attributes"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create a key from unique identifying attributes
            key = (vuln.rule_id, vuln.file_path, vuln.line_number, vuln.description[:100])
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def cleanup(self):
        """Clean up temporary directories"""
        for temp_dir in self._temp_dirs:
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
        self._temp_dirs = []
    
    def __del__(self):
        """Cleanup on destruction"""
        self.cleanup()
    
    def detect_language(self, file_path: str, content: Optional[str] = None) -> Language:
        """Detect programming language from file extension or content"""
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext in ['.js', '.jsx', '.mjs', '.ts', '.tsx']:
            return Language.JAVASCRIPT
        elif ext in ['.php', '.phtml', '.php3', '.php4', '.php5']:
            return Language.PHP
        
        # Try content-based detection if extension is unknown
        if content:
            if re.search(r'<\?php', content, re.IGNORECASE):
                return Language.PHP
            if re.search(r'(function|const|let|var|export|import)', content):
                return Language.JAVASCRIPT
        
        return Language.UNKNOWN
    
    def analyze_file(self, file_path: str, mode: Optional[AnalysisMode] = None) -> List[Vulnerability]:
        """Analyze a single file for vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            raise Exception(f"Error reading file {file_path}: {str(e)}")
        
        language = self.detect_language(file_path, content)
        
        if language == Language.UNKNOWN:
            return []
        
        # Use provided mode or instance mode
        analysis_mode = mode if mode else self.analysis_mode
        
        if analysis_mode == AnalysisMode.TAINT:
            return self._analyze_file_taint(file_path, content, language)
        elif analysis_mode == AnalysisMode.REGEX:
            return self._analyze_file_regex(file_path, content, language)
        else:  # HYBRID
            return self._analyze_file_hybrid(file_path, content, language)
    
    def _analyze_file_taint(self, file_path: str, content: str, language: Language) -> List[Vulnerability]:
        """Analyze using TAINT ANALYSIS (data flow tracking)"""
        
        all_vulnerabilities = []
        
        # ========================================
        # PRIMARY: TAINT ANALYSIS (Data Flow Tracking)
        # ========================================
        taint_vulnerabilities = []
        
        if language == Language.PHP:
            taint_results = self.taint_analyzer.analyze_php_code(content, file_path)
        elif language == Language.JAVASCRIPT:
            taint_results = self.taint_analyzer.analyze_javascript_code(content, file_path)
        else:
            taint_results = []
        
        # Convert taint results to Vulnerability objects
        for taint_vuln in taint_results:
            severity_map = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.HIGH,
                'MEDIUM': Severity.MEDIUM,
                'LOW': Severity.LOW
            }
            
            vuln = Vulnerability(
                rule_id=f"TAINT-{taint_vuln['type'].replace(' ', '-').upper()}",
                rule_name=f"Taint Analysis: {taint_vuln['type']}",
                category="Data Flow Vulnerability",
                severity=severity_map.get(taint_vuln['severity'], Severity.HIGH),
                file_path=file_path,
                line_number=taint_vuln['line'],
                code_snippet=taint_vuln['snippet'],
                description=taint_vuln['description'],
                remediation=f"Sanitize data from '{taint_vuln['source']}' before using in '{taint_vuln['sink']}'. "
                           f"Data flow: {taint_vuln['propagation']}",
                matched_pattern=f"Taint Flow: {taint_vuln['variable']}"
            )
            taint_vulnerabilities.append(vuln)
        
        # ========================================
        # SECONDARY: External AST Tools (complementary)
        # ========================================
        ast_vulnerabilities = []
        
        if language == Language.PHP and self.tool_runner.tools_available['psalm']:
            result = self.tool_runner.run_psalm(file_path)
            for v_dict in result.vulnerabilities:
                vuln = Vulnerability(
                    rule_id=f"AST-{v_dict['rule_id']}",
                    rule_name=f"Psalm: {v_dict['rule_id']}",
                    category="AST Analysis",
                    severity=getattr(Severity, v_dict['severity'], Severity.MEDIUM),
                    file_path=file_path,
                    line_number=v_dict['line'],
                    code_snippet=v_dict['snippet'],
                    description=v_dict['message'],
                    remediation="Fix the data flow or sanitize input/output.",
                    matched_pattern="AST Analysis"
                )
                ast_vulnerabilities.append(vuln)

        elif language == Language.JAVASCRIPT:
            if self.tool_runner.tools_available['semgrep']:
                result = self.tool_runner.run_semgrep(file_path)
                for v_dict in result.vulnerabilities:
                    severity_enum = Severity.MEDIUM
                    if v_dict['severity'] == 'ERROR' or v_dict['severity'] == 'CRITICAL':
                        severity_enum = Severity.CRITICAL
                    elif v_dict['severity'] == 'WARNING':
                        severity_enum = Severity.HIGH
                        
                    vuln = Vulnerability(
                        rule_id=f"AST-{v_dict['rule_id']}",
                        rule_name=f"Semgrep: {v_dict['rule_id']}",
                        category="AST Analysis",
                        severity=severity_enum,
                        file_path=file_path,
                        line_number=v_dict['line'],
                        code_snippet=v_dict['snippet'],
                        description=v_dict['message'],
                        remediation="Check Semgrep verification guidance.",
                        matched_pattern="AST Analysis"
                    )
                    ast_vulnerabilities.append(vuln)
        
        # ========================================
        # TERTIARY: Pattern-based rules (secrets, config issues)
        # Only for non-dataflow issues like hardcoded secrets
        # ========================================
        pattern_vulnerabilities = []
        lines = content.split('\n')
        language_str = language.value
        
        # Get only non-injection rules (secrets, auth, config)
        applicable_rules = self._get_supplementary_rules(language_str)
        
        for line_num, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, line_num - 2)
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
                                matched_pattern=pattern
                            )
                            pattern_vulnerabilities.append(vuln)
                            break
                    except re.error:
                        continue
        
        # Merge results: Taint analysis first (highest priority), then AST, then patterns
        all_vulnerabilities = taint_vulnerabilities + ast_vulnerabilities + pattern_vulnerabilities
        return all_vulnerabilities
    
    def _analyze_file_regex(self, file_path: str, content: str, language: Language) -> List[Vulnerability]:
        """Analyze using REGEX PATTERNS (traditional pattern matching)"""
        all_vulnerabilities = []
        
        # Run External AST Tools
        if language == Language.PHP and self.tool_runner.tools_available['psalm']:
            result = self.tool_runner.run_psalm(file_path)
            for v_dict in result.vulnerabilities:
                vuln = Vulnerability(
                    rule_id=f"AST-{v_dict['rule_id']}",
                    rule_name=f"Psalm: {v_dict['rule_id']}",
                    category="AST Analysis",
                    severity=getattr(Severity, v_dict['severity'], Severity.MEDIUM),
                    file_path=file_path,
                    line_number=v_dict['line'],
                    code_snippet=v_dict['snippet'],
                    description=v_dict['message'],
                    remediation="Fix the data flow or sanitize input/output.",
                    matched_pattern="AST Analysis"
                )
                all_vulnerabilities.append(vuln)
        elif language == Language.JAVASCRIPT and self.tool_runner.tools_available['semgrep']:
            result = self.tool_runner.run_semgrep(file_path)
            for v_dict in result.vulnerabilities:
                severity_enum = Severity.MEDIUM
                if v_dict['severity'] in ['ERROR', 'CRITICAL']:
                    severity_enum = Severity.CRITICAL
                elif v_dict['severity'] == 'WARNING':
                    severity_enum = Severity.HIGH
                    
                vuln = Vulnerability(
                    rule_id=f"AST-{v_dict['rule_id']}",
                    rule_name=f"Semgrep: {v_dict['rule_id']}",
                    category="AST Analysis",
                    severity=severity_enum,
                    file_path=file_path,
                    line_number=v_dict['line'],
                    code_snippet=v_dict['snippet'],
                    description=v_dict['message'],
                    remediation="Check Semgrep verification guidance.",
                    matched_pattern="AST Analysis"
                )
                all_vulnerabilities.append(vuln)
        
        # Run ALL Regex Rules (including injection patterns)
        lines = content.split('\n')
        language_str = language.value
        applicable_rules = get_rules_by_language(language_str)
        
        for line_num, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, line_num - 2)
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
                                matched_pattern=pattern
                            )
                            all_vulnerabilities.append(vuln)
                            break
                    except re.error:
                        continue
        
        return all_vulnerabilities
    
    def _analyze_file_hybrid(self, file_path: str, content: str, language: Language) -> List[Vulnerability]:
        """Analyze using HYBRID approach (both taint and regex)"""
        taint_vulnerabilities = self._analyze_file_taint(file_path, content, language)
        regex_vulnerabilities = self._analyze_file_regex(file_path, content, language)
        
        # Merge and deduplicate
        all_vulnerabilities = taint_vulnerabilities + regex_vulnerabilities
        return all_vulnerabilities
    
    def _get_supplementary_rules(self, language: str) -> List[OWASPRule]:
        """Get rules for non-dataflow issues (secrets, config, etc.)"""
        all_rules = get_rules_by_language(language)
        # Filter out injection-related rules (A03) as they're handled by taint analysis
        supplementary = [rule for rule in all_rules 
                        if not any(keyword in rule.name.lower() 
                                 for keyword in ['injection', 'xss', 'sql', 'command', 'ssrf'])]
        return supplementary
    
    def analyze_code_string(self, code: str, language: str, file_path: str = "input", mode: Optional[AnalysisMode] = None) -> List[Vulnerability]:
        """Analyze code provided as a string"""
        # Use provided mode or instance mode
        analysis_mode = mode if mode else self.analysis_mode
        
        if analysis_mode == AnalysisMode.REGEX:
            return self._analyze_string_regex(code, language, file_path)
        elif analysis_mode == AnalysisMode.TAINT:
            return self._analyze_string_taint(code, language, file_path)
        else:  # HYBRID
            taint_vulns = self._analyze_string_taint(code, language, file_path)
            regex_vulns = self._analyze_string_regex(code, language, file_path)
            return taint_vulns + regex_vulns
    
    def _analyze_string_taint(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze string using taint analysis"""
        vulnerabilities = []
        
        # Run taint analysis
        if language == "php":
            taint_results = self.taint_analyzer.analyze_php_code(code, file_path)
        elif language in ["javascript", "js"]:
            taint_results = self.taint_analyzer.analyze_javascript_code(code, file_path)
        else:
            taint_results = []
        
        # Convert taint results to Vulnerability objects
        for taint_vuln in taint_results:
            severity_map = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.HIGH,
                'MEDIUM': Severity.MEDIUM,
                'LOW': Severity.LOW
            }
            
            vuln = Vulnerability(
                rule_id=f"TAINT-{taint_vuln['type'].replace(' ', '-').upper()}",
                rule_name=f"Taint Analysis: {taint_vuln['type']}",
                category="Data Flow Vulnerability",
                severity=severity_map.get(taint_vuln['severity'], Severity.HIGH),
                file_path=file_path,
                line_number=taint_vuln['line'],
                code_snippet=taint_vuln['snippet'],
                description=taint_vuln['description'],
                remediation=f"Sanitize data from '{taint_vuln['source']}' before using in '{taint_vuln['sink']}'. "
                           f"Data flow: {taint_vuln['propagation']}",
                matched_pattern=f"Taint Flow: {taint_vuln['variable']}"
            )
            vulnerabilities.append(vuln)
        
        # Also run supplementary pattern-based rules for non-dataflow issues
        lines = code.split('\n')
        applicable_rules = self._get_supplementary_rules(language)
        
        for line_num, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, line_num - 2)
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
                                matched_pattern=pattern
                            )
                            vulnerabilities.append(vuln)
                            break
                    except re.error:
                        continue
        
        return vulnerabilities
    
    def _analyze_string_regex(self, code: str, language: str, file_path: str) -> List[Vulnerability]:
        """Analyze string using regex patterns"""
        vulnerabilities = []
        lines = code.split('\n')
        applicable_rules = get_rules_by_language(language)
        
        for line_num, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, line_num - 2)
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
                                matched_pattern=pattern
                            )
                            vulnerabilities.append(vuln)
                            break
                    except re.error:
                        continue
        
        return vulnerabilities
    
    def get_statistics(self, vulnerabilities: List[Vulnerability]) -> Dict:
        """Calculate statistics from vulnerabilities"""
        stats = {
            'total': len(vulnerabilities),
            'by_severity': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            },
            'by_category': {},
            'by_file': {}
        }
        
        for vuln in vulnerabilities:
            # Count by severity
            stats['by_severity'][vuln.severity.value] += 1
            
            # Count by category
            category = vuln.category
            if category not in stats['by_category']:
                stats['by_category'][category] = 0
            stats['by_category'][category] += 1
            
            # Count by file
            file_path = vuln.file_path
            if file_path not in stats['by_file']:
                stats['by_file'][file_path] = 0
            stats['by_file'][file_path] += 1
        
        return stats
    
    def calculate_security_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate security score (0-100, higher is better)"""
        if not vulnerabilities:
            return 100.0
        
        # Weighted penalty system
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1
        }
        
        total_penalty = sum(weights.get(vuln.severity, 0) for vuln in vulnerabilities)
        
        # Normalize to 0-100 scale (max penalty = 100 points)
        max_penalty = 100
        score = max(0, 100 - min(total_penalty, max_penalty))
        
        return round(score, 2)

