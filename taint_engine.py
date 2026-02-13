"""
Taint Analysis Engine
Implements data flow tracking for security vulnerabilities
"""

import ast
import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class TaintType(Enum):
    """Types of taint"""
    SQL = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND = "Command Injection"
    PATH = "Path Traversal"
    SSRF = "Server-Side Request Forgery"
    CODE = "Code Injection"
    LDAP = "LDAP Injection"
    XML = "XML Injection"
    GENERIC = "Untrusted Data"


@dataclass
class TaintSource:
    """Defines a source of untrusted data"""
    pattern: str
    taint_types: List[TaintType]
    language: str
    description: str


@dataclass
class TaintSink:
    """Defines a dangerous operation that should not receive tainted data"""
    pattern: str
    taint_types: List[TaintType]
    language: str
    description: str
    severity: str = "CRITICAL"


@dataclass
class Sanitizer:
    """Defines a function that removes or neutralizes taint"""
    pattern: str
    removes_taints: List[TaintType]
    language: str
    description: str


@dataclass
class TaintedVariable:
    """Represents a tainted variable in the program"""
    name: str
    taint_types: Set[TaintType]
    source_line: int
    source_function: str = ""
    sanitized: bool = False
    propagation_path: List[str] = field(default_factory=list)


class TaintAnalyzer:
    """Core taint analysis engine"""
    
    def __init__(self):
        self.sources = self._initialize_sources()
        self.sinks = self._initialize_sinks()
        self.sanitizers = self._initialize_sanitizers()
        self.tainted_vars: Dict[str, TaintedVariable] = {}
        self.vulnerabilities = []
    
    def _initialize_sources(self) -> List[TaintSource]:
        """Initialize taint sources for different languages"""
        sources = []
        
        # PHP Sources
        sources.extend([
            TaintSource(
                pattern=r'\$_GET\s*\[\s*["\']([^"\']+)["\']\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, 
                           TaintType.PATH, TaintType.SSRF, TaintType.CODE],
                language="php",
                description="User input from URL parameters"
            ),
            TaintSource(
                pattern=r'\$_POST\s*\[\s*["\']([^"\']+)["\']\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, 
                           TaintType.PATH, TaintType.CODE],
                language="php",
                description="User input from POST data"
            ),
            TaintSource(
                pattern=r'\$_REQUEST\s*\[\s*["\']([^"\']+)["\']\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, 
                           TaintType.PATH, TaintType.SSRF, TaintType.CODE],
                language="php",
                description="User input from request"
            ),
            TaintSource(
                pattern=r'\$_COOKIE\s*\[\s*["\']([^"\']+)["\']\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.CODE],
                language="php",
                description="User input from cookies"
            ),
            TaintSource(
                pattern=r'\$_SERVER\s*\[\s*["\'](?:HTTP_|REQUEST_)[^"\']+["\']\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                language="php",
                description="User-controllable server variables"
            ),
            TaintSource(
                pattern=r'file_get_contents\s*\(\s*["\']php://input["\']\s*\)',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.CODE],
                language="php",
                description="Raw POST data"
            ),
        ])
        
        # JavaScript/Node.js Sources
        sources.extend([
            TaintSource(
                pattern=r'req\.query\.',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, 
                           TaintType.PATH, TaintType.SSRF],
                language="javascript",
                description="URL query parameters"
            ),
            TaintSource(
                pattern=r'req\.params\.',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, 
                           TaintType.PATH],
                language="javascript",
                description="URL route parameters"
            ),
            TaintSource(
                pattern=r'req\.body\.',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, 
                           TaintType.CODE],
                language="javascript",
                description="POST request body"
            ),
            TaintSource(
                pattern=r'req\.cookies\.',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.CODE],
                language="javascript",
                description="Cookie data"
            ),
            TaintSource(
                pattern=r'req\.headers\.',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                language="javascript",
                description="HTTP headers"
            ),
            TaintSource(
                pattern=r'location\.(?:search|hash|href)',
                taint_types=[TaintType.XSS, TaintType.CODE],
                language="javascript",
                description="Browser location data"
            ),
            TaintSource(
                pattern=r'window\.location',
                taint_types=[TaintType.XSS, TaintType.CODE],
                language="javascript",
                description="Window location"
            ),
        ])
        
        return sources
    
    def _initialize_sinks(self) -> List[TaintSink]:
        """Initialize taint sinks (dangerous operations)"""
        sinks = []
        
        # PHP Sinks
        sinks.extend([
            # SQL Injection Sinks
            TaintSink(
                pattern=r'mysqli_query\s*\([^,]+,\s*([^)]+)\)',
                taint_types=[TaintType.SQL],
                language="php",
                description="MySQL query execution",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'mysql_query\s*\(([^)]+)\)',
                taint_types=[TaintType.SQL],
                language="php",
                description="Legacy MySQL query",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'->query\s*\(([^)]+)\)',
                taint_types=[TaintType.SQL],
                language="php",
                description="PDO/MySQLi query",
                severity="CRITICAL"
            ),
            
            # XSS Sinks
            TaintSink(
                pattern=r'echo\s+([^;]+)',
                taint_types=[TaintType.XSS],
                language="php",
                description="Output to HTML",
                severity="HIGH"
            ),
            TaintSink(
                pattern=r'print\s+([^;]+)',
                taint_types=[TaintType.XSS],
                language="php",
                description="Output to HTML",
                severity="HIGH"
            ),
            TaintSink(
                pattern=r'printf?\s*\([^,]*,?\s*([^)]+)\)',
                taint_types=[TaintType.XSS],
                language="php",
                description="Formatted output",
                severity="HIGH"
            ),
            
            # Command Injection Sinks
            TaintSink(
                pattern=r'(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(([^)]+)\)',
                taint_types=[TaintType.COMMAND],
                language="php",
                description="Shell command execution",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'`([^`]+)`',
                taint_types=[TaintType.COMMAND],
                language="php",
                description="Backtick shell execution",
                severity="CRITICAL"
            ),
            
            # Code Injection Sinks
            TaintSink(
                pattern=r'eval\s*\(([^)]+)\)',
                taint_types=[TaintType.CODE],
                language="php",
                description="Dynamic code evaluation",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'assert\s*\(([^)]+)\)',
                taint_types=[TaintType.CODE],
                language="php",
                description="Assertion with code execution",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'(?:require|include)(?:_once)?\s*\(([^)]+)\)',
                taint_types=[TaintType.PATH, TaintType.CODE],
                language="php",
                description="File inclusion",
                severity="CRITICAL"
            ),
            
            # Path Traversal Sinks
            TaintSink(
                pattern=r'(?:fopen|file_get_contents|readfile|file|unlink)\s*\(([^)]+)\)',
                taint_types=[TaintType.PATH],
                language="php",
                description="File system operation",
                severity="HIGH"
            ),
            
            # SSRF Sinks
            TaintSink(
                pattern=r'file_get_contents\s*\(([^)]+)\)',
                taint_types=[TaintType.SSRF, TaintType.PATH],
                language="php",
                description="Remote file access",
                severity="HIGH"
            ),
            TaintSink(
                pattern=r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*([^)]+)\)',
                taint_types=[TaintType.SSRF],
                language="php",
                description="cURL URL setting",
                severity="HIGH"
            ),
        ])
        
        # JavaScript/Node.js Sinks
        sinks.extend([
            # SQL Injection Sinks
            TaintSink(
                pattern=r'\.query\s*\(([^)]+)\)',
                taint_types=[TaintType.SQL],
                language="javascript",
                description="Database query",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'\.execute\s*\(([^)]+)\)',
                taint_types=[TaintType.SQL],
                language="javascript",
                description="Database query execution",
                severity="CRITICAL"
            ),
            
            # XSS Sinks
            TaintSink(
                pattern=r'\.innerHTML\s*=\s*([^;]+)',
                taint_types=[TaintType.XSS],
                language="javascript",
                description="DOM manipulation",
                severity="HIGH"
            ),
            TaintSink(
                pattern=r'\.outerHTML\s*=\s*([^;]+)',
                taint_types=[TaintType.XSS],
                language="javascript",
                description="DOM manipulation",
                severity="HIGH"
            ),
            TaintSink(
                pattern=r'document\.write\s*\(([^)]+)\)',
                taint_types=[TaintType.XSS],
                language="javascript",
                description="Document write",
                severity="HIGH"
            ),
            TaintSink(
                pattern=r'\.insertAdjacentHTML\s*\([^,]+,\s*([^)]+)\)',
                taint_types=[TaintType.XSS],
                language="javascript",
                description="HTML insertion",
                severity="HIGH"
            ),
            
            # Command Injection Sinks
            TaintSink(
                pattern=r'(?:exec|execSync|spawn|spawnSync)\s*\(([^)]+)\)',
                taint_types=[TaintType.COMMAND],
                language="javascript",
                description="Command execution",
                severity="CRITICAL"
            ),
            
            # Code Injection Sinks
            TaintSink(
                pattern=r'eval\s*\(([^)]+)\)',
                taint_types=[TaintType.CODE],
                language="javascript",
                description="Code evaluation",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'Function\s*\(([^)]+)\)',
                taint_types=[TaintType.CODE],
                language="javascript",
                description="Dynamic function creation",
                severity="CRITICAL"
            ),
            TaintSink(
                pattern=r'setTimeout\s*\(([^,]+),',
                taint_types=[TaintType.CODE],
                language="javascript",
                description="Timer with code string",
                severity="HIGH"
            ),
            TaintSink(
                pattern=r'setInterval\s*\(([^,]+),',
                taint_types=[TaintType.CODE],
                language="javascript",
                description="Interval with code string",
                severity="HIGH"
            ),
            
            # SSRF Sinks
            TaintSink(
                pattern=r'(?:fetch|axios|request)\s*\(([^)]+)\)',
                taint_types=[TaintType.SSRF],
                language="javascript",
                description="HTTP request",
                severity="HIGH"
            ),
        ])
        
        return sinks
    
    def _initialize_sanitizers(self) -> List[Sanitizer]:
        """Initialize sanitization functions"""
        sanitizers = []
        
        # PHP Sanitizers
        sanitizers.extend([
            Sanitizer(
                pattern=r'htmlspecialchars\s*\(',
                removes_taints=[TaintType.XSS],
                language="php",
                description="HTML entity encoding"
            ),
            Sanitizer(
                pattern=r'htmlentities\s*\(',
                removes_taints=[TaintType.XSS],
                language="php",
                description="HTML entity encoding"
            ),
            Sanitizer(
                pattern=r'mysqli_real_escape_string\s*\(',
                removes_taints=[TaintType.SQL],
                language="php",
                description="SQL escaping (partial)"
            ),
            Sanitizer(
                pattern=r'escapeshellarg\s*\(',
                removes_taints=[TaintType.COMMAND],
                language="php",
                description="Shell argument escaping"
            ),
            Sanitizer(
                pattern=r'escapeshellcmd\s*\(',
                removes_taints=[TaintType.COMMAND],
                language="php",
                description="Shell command escaping"
            ),
            Sanitizer(
                pattern=r'filter_input\s*\(',
                removes_taints=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                language="php",
                description="Input filtering"
            ),
            Sanitizer(
                pattern=r'filter_var\s*\(',
                removes_taints=[TaintType.SQL, TaintType.XSS],
                language="php",
                description="Variable filtering"
            ),
            Sanitizer(
                pattern=r'intval\s*\(',
                removes_taints=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                language="php",
                description="Integer conversion"
            ),
            Sanitizer(
                pattern=r'->prepare\s*\(',
                removes_taints=[TaintType.SQL],
                language="php",
                description="Prepared statement"
            ),
        ])
        
        # JavaScript Sanitizers
        sanitizers.extend([
            Sanitizer(
                pattern=r'escape\s*\(',
                removes_taints=[TaintType.XSS],
                language="javascript",
                description="HTML escaping"
            ),
            Sanitizer(
                pattern=r'encodeURIComponent\s*\(',
                removes_taints=[TaintType.XSS, TaintType.SSRF],
                language="javascript",
                description="URL encoding"
            ),
            Sanitizer(
                pattern=r'encodeURI\s*\(',
                removes_taints=[TaintType.SSRF],
                language="javascript",
                description="URI encoding"
            ),
            Sanitizer(
                pattern=r'textContent\s*=',
                removes_taints=[TaintType.XSS],
                language="javascript",
                description="Safe text content"
            ),
            Sanitizer(
                pattern=r'innerText\s*=',
                removes_taints=[TaintType.XSS],
                language="javascript",
                description="Safe inner text"
            ),
            Sanitizer(
                pattern=r'parseInt\s*\(',
                removes_taints=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                language="javascript",
                description="Integer parsing"
            ),
            Sanitizer(
                pattern=r'Number\s*\(',
                removes_taints=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                language="javascript",
                description="Number conversion"
            ),
        ])
        
        return sanitizers
    
    def track_variable_assignment(self, var_name: str, value_expr: str, 
                                  line_num: int, language: str) -> None:
        """Track a variable assignment and determine if it's tainted"""
        # Check if value comes from a taint source
        for source in self.sources:
            if source.language != language:
                continue
            
            if re.search(source.pattern, value_expr):
                # Variable is tainted
                self.tainted_vars[var_name] = TaintedVariable(
                    name=var_name,
                    taint_types=set(source.taint_types),
                    source_line=line_num,
                    source_function=source.description,
                    propagation_path=[f"Source: {source.description}"]
                )
                return
        
        # Check if value comes from another tainted variable
        for tainted_var_name, tainted_var in self.tainted_vars.items():
            if re.search(rf'\${tainted_var_name}|\b{tainted_var_name}\b', value_expr):
                # Propagate taint
                if var_name in self.tainted_vars:
                    self.tainted_vars[var_name].taint_types.update(tainted_var.taint_types)
                else:
                    self.tainted_vars[var_name] = TaintedVariable(
                        name=var_name,
                        taint_types=set(tainted_var.taint_types),
                        source_line=line_num,
                        source_function=tainted_var.source_function,
                        propagation_path=tainted_var.propagation_path + [f"Propagated to {var_name}"]
                    )
                return
        
        # Check if value is sanitized
        for sanitizer in self.sanitizers:
            if sanitizer.language != language:
                continue
            
            if re.search(sanitizer.pattern, value_expr):
                # If variable was tainted, mark as sanitized
                if var_name in self.tainted_vars:
                    for taint_type in sanitizer.removes_taints:
                        if taint_type in self.tainted_vars[var_name].taint_types:
                            self.tainted_vars[var_name].taint_types.discard(taint_type)
                    
                    # If all taints removed, mark as sanitized
                    if not self.tainted_vars[var_name].taint_types:
                        self.tainted_vars[var_name].sanitized = True
                return
    
    def check_sink_usage(self, line: str, line_num: int, language: str, 
                        file_path: str, code_snippet: str) -> List[Dict]:
        """Check if tainted data reaches a sink"""
        vulnerabilities = []
        
        for sink in self.sinks:
            if sink.language != language:
                continue
            
            match = re.search(sink.pattern, line)
            if not match:
                continue
            
            # Extract the argument/value being passed to the sink
            sink_arg = match.group(1) if match.groups() else match.group(0)
            
            # Check if any tainted variable is used in the sink
            for var_name, tainted_var in self.tainted_vars.items():
                if tainted_var.sanitized:
                    continue
                
                var_pattern = rf'\${var_name}|\b{var_name}\b'
                if re.search(var_pattern, sink_arg):
                    # Check if taint type matches sink
                    matching_taints = set(sink.taint_types) & tainted_var.taint_types
                    if matching_taints:
                        for taint_type in matching_taints:
                            vulnerabilities.append({
                                'type': taint_type.value,
                                'severity': sink.severity,
                                'line': line_num,
                                'file': file_path,
                                'sink': sink.description,
                                'source': tainted_var.source_function,
                                'source_line': tainted_var.source_line,
                                'variable': var_name,
                                'snippet': code_snippet,
                                'propagation': ' -> '.join(tainted_var.propagation_path),
                                'description': f"Tainted data from {tainted_var.source_function} (line {tainted_var.source_line}) "
                                             f"flows through variable '{var_name}' to {sink.description}"
                            })
        
        return vulnerabilities
    
    def analyze_php_code(self, code: str, file_path: str) -> List[Dict]:
        """Analyze PHP code for taint vulnerabilities"""
        self.tainted_vars = {}
        self.vulnerabilities = []
        
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            
            # Track variable assignments
            # Pattern: $var = <expression>
            assignment_match = re.match(r'\$(\w+)\s*=\s*(.+)', line)
            if assignment_match:
                var_name = assignment_match.group(1)
                value_expr = assignment_match.group(2)
                self.track_variable_assignment(var_name, value_expr, line_num, "php")
            
            # Check for sinks
            start = max(0, line_num - 2)
            end = min(len(lines), line_num + 2)
            snippet = '\n'.join(lines[start:end])
            
            vulns = self.check_sink_usage(line, line_num, "php", file_path, snippet)
            self.vulnerabilities.extend(vulns)
        
        return self.vulnerabilities
    
    def analyze_javascript_code(self, code: str, file_path: str) -> List[Dict]:
        """Analyze JavaScript code for taint vulnerabilities"""
        self.tainted_vars = {}
        self.vulnerabilities = []
        
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            
            # Track variable assignments
            # Pattern: var/let/const name = <expression>
            assignment_match = re.match(r'(?:var|let|const)\s+(\w+)\s*=\s*(.+)', line)
            if assignment_match:
                var_name = assignment_match.group(1)
                value_expr = assignment_match.group(2)
                self.track_variable_assignment(var_name, value_expr, line_num, "javascript")
            
            # Also track simple reassignments
            reassignment_match = re.match(r'(\w+)\s*=\s*(.+)', line)
            if reassignment_match and not line.startswith('//'):
                var_name = reassignment_match.group(1)
                value_expr = reassignment_match.group(2)
                self.track_variable_assignment(var_name, value_expr, line_num, "javascript")
            
            # Check for sinks
            start = max(0, line_num - 2)
            end = min(len(lines), line_num + 2)
            snippet = '\n'.join(lines[start:end])
            
            vulns = self.check_sink_usage(line, line_num, "javascript", file_path, snippet)
            self.vulnerabilities.extend(vulns)
        
        return self.vulnerabilities
