"""
Core Analysis Engine
Implements static code analysis for OWASP Top 10 vulnerabilities
"""

import re
import os
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from owasp_rules import OWASPRule, get_owasp_rules, get_rules_by_language, Severity


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


class CodeAnalyzer:
    """Main code analysis engine"""
    
    def __init__(self):
        self.rules = get_owasp_rules()
        self.vulnerabilities: List[Vulnerability] = []
    
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
    
    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Analyze a single file for vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            raise Exception(f"Error reading file {file_path}: {str(e)}")
        
        language = self.detect_language(file_path, content)
        
        if language == Language.UNKNOWN:
            return []
        
        vulnerabilities = []
        lines = content.split('\n')
        
        # Get rules applicable to this language
        language_str = language.value
        applicable_rules = get_rules_by_language(language_str)
        
        # Analyze each line with each rule
        for line_num, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Extract code snippet (context around the line)
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
                                matched_pattern=pattern
                            )
                            vulnerabilities.append(vuln)
                            break  # Only report once per line per rule
                    except re.error:
                        # Skip invalid regex patterns
                        continue
        
        return vulnerabilities
    
    def analyze_directory(self, directory_path: str, extensions: List[str] = None) -> List[Vulnerability]:
        """Analyze all files in a directory"""
        if extensions is None:
            extensions = ['.js', '.jsx', '.mjs', '.ts', '.tsx', '.php', '.phtml']
        
        all_vulnerabilities = []
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor', '__pycache__']]
            
            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                if ext in extensions:
                    try:
                        vulns = self.analyze_file(file_path)
                        all_vulnerabilities.extend(vulns)
                    except Exception as e:
                        print(f"Warning: Could not analyze {file_path}: {str(e)}")
        
        return all_vulnerabilities
    
    def analyze_code_string(self, code: str, language: str, file_path: str = "input") -> List[Vulnerability]:
        """Analyze code provided as a string"""
        vulnerabilities = []
        lines = code.split('\n')
        
        applicable_rules = get_rules_by_language(language)
        
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

