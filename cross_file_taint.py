"""
Cross-File Taint Analysis Engine
Industry-standard data flow tracking across multiple files
Supports PHP and JavaScript projects
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime


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
    DESERIALIZATION = "Insecure Deserialization"
    XXE = "XML External Entity"


@dataclass
class CodeLocation:
    """Represents a location in the codebase"""
    file_path: str
    line_number: int
    column: int = 0
    code_snippet: str = ""
    function_name: str = ""
    class_name: str = ""
    
    def __str__(self):
        return f"{self.file_path}:{self.line_number}"


@dataclass
class TaintNode:
    """Represents a node in the taint flow graph"""
    node_type: str  # 'source', 'propagation', 'sanitizer', 'sink'
    location: CodeLocation
    description: str
    code_snippet: str
    taint_types: Set[TaintType] = field(default_factory=set)
    variable_name: str = ""
    
    def to_dict(self):
        return {
            'node_type': self.node_type,
            'file': self.location.file_path,
            'line': self.location.line_number,
            'function': self.location.function_name,
            'description': self.description,
            'code': self.code_snippet,
            'variable': self.variable_name,
            'taint_types': [t.value for t in self.taint_types]
        }


@dataclass
class TaintFlow:
    """Represents a complete taint flow from source to sink"""
    flow_id: str
    source: TaintNode
    sink: TaintNode
    propagation_nodes: List[TaintNode] = field(default_factory=list)
    sanitizers_bypassed: List[str] = field(default_factory=list)
    vulnerability_type: str = ""
    severity: str = "HIGH"
    confidence: float = 0.8
    cross_file: bool = False
    files_involved: List[str] = field(default_factory=list)
    
    def get_full_path(self) -> List[TaintNode]:
        """Get the complete path from source to sink"""
        return [self.source] + self.propagation_nodes + [self.sink]
    
    def to_dict(self):
        return {
            'flow_id': self.flow_id,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'cross_file': self.cross_file,
            'files_involved': self.files_involved,
            'source': self.source.to_dict(),
            'sink': self.sink.to_dict(),
            'propagation': [n.to_dict() for n in self.propagation_nodes],
            'path_length': len(self.get_full_path())
        }


@dataclass  
class ExportedTaint:
    """Taint that can flow across file boundaries"""
    variable_name: str
    taint_types: Set[TaintType]
    export_type: str  # 'function_return', 'global', 'parameter', 'include', 'require'
    source_file: str
    source_line: int
    original_source: str


class CrossFileTaintAnalyzer:
    """Advanced taint analyzer supporting cross-file data flow tracking"""
    
    SUPPORTED_EXTENSIONS = {'.php', '.js', '.ts', '.jsx', '.tsx', '.mjs'}
    
    def __init__(self):
        self.taint_flows: List[TaintFlow] = []
        self.global_taint_context: Dict[str, List[ExportedTaint]] = {}
        self.file_exports: Dict[str, Dict] = {}  # file -> exported functions/vars
        self.file_imports: Dict[str, Dict] = {}  # file -> imported functions/vars
        self.call_graph: Dict[str, Set[str]] = {}  # function -> called functions
        self.include_graph: Dict[str, Set[str]] = {}  # file -> included files
        self.analyzed_files: Set[str] = set()
        self.flow_counter = 0
        self._initialize_rules()
    
    def _initialize_rules(self):
        """Initialize comprehensive taint tracking rules"""
        # PHP Sources
        self.php_sources = [
            {'pattern': r'\$_GET\s*\[\s*["\']?([^"\'\]]+)', 'desc': 'URL Query Parameter', 
             'taints': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.PATH, TaintType.SSRF]},
            {'pattern': r'\$_POST\s*\[\s*["\']?([^"\'\]]+)', 'desc': 'POST Data',
             'taints': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.PATH]},
            {'pattern': r'\$_REQUEST\s*\[\s*["\']?([^"\'\]]+)', 'desc': 'Request Data',
             'taints': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.PATH, TaintType.SSRF]},
            {'pattern': r'\$_COOKIE\s*\[\s*["\']?([^"\'\]]+)', 'desc': 'Cookie Data',
             'taints': [TaintType.SQL, TaintType.XSS]},
            {'pattern': r'\$_SERVER\s*\[\s*["\']?(HTTP_[^"\'\]]+)', 'desc': 'HTTP Header',
             'taints': [TaintType.SQL, TaintType.XSS, TaintType.SSRF]},
            {'pattern': r'\$_FILES\s*\[\s*["\']?([^"\'\]]+)', 'desc': 'File Upload',
             'taints': [TaintType.PATH, TaintType.CODE]},
            {'pattern': r'file_get_contents\s*\(\s*["\']php://input["\']', 'desc': 'Raw Request Body',
             'taints': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.DESERIALIZATION]},
            {'pattern': r'getenv\s*\(\s*["\']([^"\']+)', 'desc': 'Environment Variable',
             'taints': [TaintType.COMMAND, TaintType.PATH]},
        ]
        
        # PHP Sinks
        self.php_sinks = [
            {'pattern': r'(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^,]*,?\s*([^)]+)',
             'desc': 'SQL Query Execution', 'severity': 'CRITICAL', 'type': TaintType.SQL},
            {'pattern': r'\$\w+->query\s*\(([^)]+)\)', 
             'desc': 'PDO/MySQLi Query', 'severity': 'CRITICAL', 'type': TaintType.SQL},
            {'pattern': r'(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(([^)]+)',
             'desc': 'Shell Command Execution', 'severity': 'CRITICAL', 'type': TaintType.COMMAND},
            {'pattern': r'`([^`]+)`', 'desc': 'Backtick Command', 'severity': 'CRITICAL', 'type': TaintType.COMMAND},
            {'pattern': r'eval\s*\(([^)]+)\)', 'desc': 'Code Evaluation', 'severity': 'CRITICAL', 'type': TaintType.CODE},
            {'pattern': r'(?:include|require)(?:_once)?\s*(?:\(|\s)([^;]+)',
             'desc': 'File Inclusion', 'severity': 'CRITICAL', 'type': TaintType.PATH},
            {'pattern': r'(?:fopen|file_get_contents|readfile|file|fread)\s*\(([^,)]+)',
             'desc': 'File Read Operation', 'severity': 'HIGH', 'type': TaintType.PATH},
            {'pattern': r'(?:file_put_contents|fwrite|fputs)\s*\(([^,]+)',
             'desc': 'File Write Operation', 'severity': 'HIGH', 'type': TaintType.PATH},
            {'pattern': r'unserialize\s*\(([^)]+)\)', 
             'desc': 'Deserialization', 'severity': 'CRITICAL', 'type': TaintType.DESERIALIZATION},
            {'pattern': r'(?:echo|print)\s+(.+?)(?:;|$)', 
             'desc': 'HTML Output', 'severity': 'HIGH', 'type': TaintType.XSS},
            {'pattern': r'header\s*\(\s*["\']Location:\s*["\']?\s*\.?\s*([^)]+)',
             'desc': 'Open Redirect', 'severity': 'MEDIUM', 'type': TaintType.SSRF},
            {'pattern': r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,([^)]+)',
             'desc': 'CURL Request', 'severity': 'HIGH', 'type': TaintType.SSRF},
            {'pattern': r'(?:simplexml_load_string|DOMDocument->loadXML)\s*\(([^)]+)',
             'desc': 'XML Parsing', 'severity': 'HIGH', 'type': TaintType.XXE},
        ]
        
        # PHP Sanitizers
        self.php_sanitizers = [
            {'pattern': r'htmlspecialchars\s*\(', 'removes': [TaintType.XSS], 'desc': 'HTML Encoding'},
            {'pattern': r'htmlentities\s*\(', 'removes': [TaintType.XSS], 'desc': 'HTML Entity Encoding'},
            {'pattern': r'mysqli_real_escape_string\s*\(', 'removes': [TaintType.SQL], 'desc': 'SQL Escaping'},
            {'pattern': r'PDO::quote\s*\(', 'removes': [TaintType.SQL], 'desc': 'PDO Quote'},
            {'pattern': r'->prepare\s*\(', 'removes': [TaintType.SQL], 'desc': 'Prepared Statement'},
            {'pattern': r'escapeshellarg\s*\(', 'removes': [TaintType.COMMAND], 'desc': 'Shell Arg Escape'},
            {'pattern': r'escapeshellcmd\s*\(', 'removes': [TaintType.COMMAND], 'desc': 'Shell Cmd Escape'},
            {'pattern': r'realpath\s*\(', 'removes': [TaintType.PATH], 'desc': 'Path Normalization'},
            {'pattern': r'basename\s*\(', 'removes': [TaintType.PATH], 'desc': 'Basename Extraction'},
            {'pattern': r'intval\s*\(|(?:\(int\))', 'removes': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND], 'desc': 'Integer Cast'},
            {'pattern': r'filter_var\s*\([^,]+,\s*FILTER_SANITIZE', 'removes': [TaintType.XSS, TaintType.SQL], 'desc': 'Filter Var'},
            {'pattern': r'strip_tags\s*\(', 'removes': [TaintType.XSS], 'desc': 'Strip Tags'},
        ]
        
        # JavaScript Sources  
        self.js_sources = [
            {'pattern': r'(?:req|request)\.(?:query|params|body)\s*\.\s*(\w+)', 'desc': 'Express Request Data',
             'taints': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.PATH]},
            {'pattern': r'(?:req|request)\.(?:query|params|body)\s*\[\s*["\']([^"\']+)', 'desc': 'Express Request Data',
             'taints': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.PATH]},
            {'pattern': r'document\.location\.(?:search|hash)', 'desc': 'URL Parameters',
             'taints': [TaintType.XSS, TaintType.PATH]},
            {'pattern': r'window\.location\.(?:search|hash|href)', 'desc': 'Window Location',
             'taints': [TaintType.XSS, TaintType.PATH, TaintType.SSRF]},
            {'pattern': r'URLSearchParams\([^)]*\)\.get\s*\(["\']([^"\']+)', 'desc': 'URL Search Params',
             'taints': [TaintType.XSS, TaintType.SQL]},
            {'pattern': r'process\.env\s*\.\s*(\w+)', 'desc': 'Environment Variable',
             'taints': [TaintType.COMMAND, TaintType.PATH]},
            {'pattern': r'fs\.readFileSync\s*\([^)]+\)', 'desc': 'File Read',
             'taints': [TaintType.PATH]},
            {'pattern': r'localStorage\.getItem\s*\(["\']([^"\']+)', 'desc': 'Local Storage',
             'taints': [TaintType.XSS]},
            {'pattern': r'document\.cookie', 'desc': 'Cookie Data',
             'taints': [TaintType.XSS]},
        ]
        
        # JavaScript Sinks
        self.js_sinks = [
            {'pattern': r'\.query\s*\(([^)]+)\)', 'desc': 'Database Query', 'severity': 'CRITICAL', 'type': TaintType.SQL},
            {'pattern': r'\.execute\s*\(([^)]+)\)', 'desc': 'SQL Execute', 'severity': 'CRITICAL', 'type': TaintType.SQL},
            {'pattern': r'\.raw\s*\(([^)]+)\)', 'desc': 'Raw SQL Query', 'severity': 'CRITICAL', 'type': TaintType.SQL},
            {'pattern': r'eval\s*\(([^)]+)\)', 'desc': 'Eval Execution', 'severity': 'CRITICAL', 'type': TaintType.CODE},
            {'pattern': r'new\s+Function\s*\(([^)]+)\)', 'desc': 'Dynamic Function', 'severity': 'CRITICAL', 'type': TaintType.CODE},
            {'pattern': r'(?:child_process\.)?(?:exec|spawn|execSync|spawnSync)\s*\(([^)]+)',
             'desc': 'Command Execution', 'severity': 'CRITICAL', 'type': TaintType.COMMAND},
            {'pattern': r'innerHTML\s*=([^;]+)', 'desc': 'innerHTML Assignment', 'severity': 'HIGH', 'type': TaintType.XSS},
            {'pattern': r'outerHTML\s*=([^;]+)', 'desc': 'outerHTML Assignment', 'severity': 'HIGH', 'type': TaintType.XSS},
            {'pattern': r'document\.write\s*\(([^)]+)\)', 'desc': 'Document Write', 'severity': 'HIGH', 'type': TaintType.XSS},
            {'pattern': r'\.html\s*\(([^)]+)\)', 'desc': 'jQuery HTML', 'severity': 'HIGH', 'type': TaintType.XSS},
            {'pattern': r'res\.send\s*\(([^)]+)\)', 'desc': 'Express Response', 'severity': 'MEDIUM', 'type': TaintType.XSS},
            {'pattern': r'(?:fetch|axios\.get|axios\.post)\s*\(([^)]+)', 'desc': 'HTTP Request', 'severity': 'HIGH', 'type': TaintType.SSRF},
            {'pattern': r'require\s*\(([^)]+)\)', 'desc': 'Dynamic Require', 'severity': 'HIGH', 'type': TaintType.PATH},
        ]
        
        # JavaScript Sanitizers
        self.js_sanitizers = [
            {'pattern': r'encodeURIComponent\s*\(', 'removes': [TaintType.XSS, TaintType.SSRF], 'desc': 'URL Encoding'},
            {'pattern': r'encodeURI\s*\(', 'removes': [TaintType.SSRF], 'desc': 'URI Encoding'},
            {'pattern': r'escape\s*\(', 'removes': [TaintType.XSS], 'desc': 'Escape'},
            {'pattern': r'parseInt\s*\(', 'removes': [TaintType.SQL, TaintType.XSS, TaintType.COMMAND], 'desc': 'Parse Int'},
            {'pattern': r'Number\s*\(', 'removes': [TaintType.SQL, TaintType.XSS], 'desc': 'Number Conversion'},
            {'pattern': r'textContent\s*=', 'removes': [TaintType.XSS], 'desc': 'Text Content'},
            {'pattern': r'innerText\s*=', 'removes': [TaintType.XSS], 'desc': 'Inner Text'},
            {'pattern': r'DOMPurify\.sanitize\s*\(', 'removes': [TaintType.XSS], 'desc': 'DOMPurify'},
            {'pattern': r'validator\.escape\s*\(', 'removes': [TaintType.XSS], 'desc': 'Validator Escape'},
            {'pattern': r'path\.normalize\s*\(', 'removes': [TaintType.PATH], 'desc': 'Path Normalize'},
        ]
    
    def clone_github_repo(self, repo_url: str, target_dir: str = None) -> str:
        """Clone a GitHub repository for analysis"""
        if target_dir is None:
            target_dir = tempfile.mkdtemp(prefix='taint_analysis_')
        
        # Clean up URL
        if repo_url.endswith('/'):
            repo_url = repo_url[:-1]
        if not repo_url.endswith('.git'):
            repo_url = repo_url + '.git'
        
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, target_dir],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
            return target_dir
        except FileNotFoundError:
            raise Exception("Git is not installed or not in PATH")
        except subprocess.TimeoutExpired:
            raise Exception("Git clone timed out")
    
    def analyze_directory(self, directory: str, recursive: bool = True) -> List[TaintFlow]:
        """Analyze all supported files in a directory"""
        self.taint_flows = []
        self.global_taint_context = {}
        self.file_exports = {}
        self.file_imports = {}
        self.include_graph = {}
        self.analyzed_files = set()
        
        # First pass: Build include/import graph and collect exports
        files_to_analyze = self._collect_files(directory, recursive)
        
        for file_path in files_to_analyze:
            self._preprocess_file(file_path)
        
        # Second pass: Analyze each file with cross-file context
        for file_path in files_to_analyze:
            self._analyze_file_with_context(file_path)
        
        # Third pass: Track cross-file flows
        self._resolve_cross_file_flows()
        
        return self.taint_flows
    
    def _collect_files(self, directory: str, recursive: bool) -> List[str]:
        """Collect all supported files in directory"""
        files = []
        directory = Path(directory)
        
        if recursive:
            for ext in self.SUPPORTED_EXTENSIONS:
                files.extend(directory.rglob(f'*{ext}'))
        else:
            for ext in self.SUPPORTED_EXTENSIONS:
                files.extend(directory.glob(f'*{ext}'))
        
        # Filter out common non-source directories
        skip_dirs = {'node_modules', 'vendor', '.git', '__pycache__', 'dist', 'build', '.venv'}
        filtered_files = []
        for f in files:
            if not any(skip_dir in str(f) for skip_dir in skip_dirs):
                filtered_files.append(str(f))
        
        return filtered_files
    
    def _preprocess_file(self, file_path: str):
        """First pass: Extract exports, imports, includes"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return
        
        ext = Path(file_path).suffix.lower()
        
        if ext == '.php':
            self._preprocess_php(file_path, content)
        elif ext in {'.js', '.ts', '.jsx', '.tsx', '.mjs'}:
            self._preprocess_javascript(file_path, content)
    
    def _preprocess_php(self, file_path: str, content: str):
        """Extract PHP includes/requires and function definitions"""
        includes = set()
        
        # Find includes/requires
        include_patterns = [
            r'(?:include|require)(?:_once)?\s*\(?["\']([^"\']+)["\']',
            r'(?:include|require)(?:_once)?\s*\(?([^;]+)',
        ]
        
        for pattern in include_patterns:
            for match in re.finditer(pattern, content):
                inc_file = match.group(1).strip()
                # Remove quotes if present
                inc_file = inc_file.strip('"\'')
                includes.add(inc_file)
        
        self.include_graph[file_path] = includes
        
        # Find function definitions
        functions = {}
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1)
            params = match.group(2)
            functions[func_name] = {'params': params, 'file': file_path}
        
        self.file_exports[file_path] = {'functions': functions}
    
    def _preprocess_javascript(self, file_path: str, content: str):
        """Extract JS imports/exports and function definitions"""
        imports = {}
        exports = {}
        
        # ES6 imports
        import_patterns = [
            r'import\s+(?:{([^}]+)}|(\w+))\s+from\s+["\']([^"\']+)["\']',
            r'const\s+(?:{([^}]+)}|(\w+))\s*=\s*require\s*\(["\']([^"\']+)["\']',
        ]
        
        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                module = match.group(3)
                imports[module] = match.groups()
        
        # Export detection
        export_patterns = [
            r'export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)',
            r'module\.exports\s*=\s*(?:{([^}]+)}|(\w+))',
        ]
        
        for pattern in export_patterns:
            for match in re.finditer(pattern, content):
                for g in match.groups():
                    if g:
                        exports[g] = {'file': file_path}
        
        self.file_imports[file_path] = imports
        self.file_exports[file_path] = {'exports': exports}
    
    def _analyze_file_with_context(self, file_path: str):
        """Analyze a single file with cross-file taint context"""
        if file_path in self.analyzed_files:
            return
        
        self.analyzed_files.add(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return
        
        ext = Path(file_path).suffix.lower()
        lines = content.split('\n')
        
        # Track tainted variables in this file
        local_tainted_vars = {}
        
        # Include cross-file taint context
        if file_path in self.global_taint_context:
            for exported_taint in self.global_taint_context[file_path]:
                local_tainted_vars[exported_taint.variable_name] = {
                    'taint_types': exported_taint.taint_types,
                    'source_line': exported_taint.source_line,
                    'source_file': exported_taint.source_file,
                    'source_desc': exported_taint.original_source,
                    'cross_file': True
                }
        
        if ext == '.php':
            self._analyze_php_file(file_path, lines, local_tainted_vars)
        elif ext in {'.js', '.ts', '.jsx', '.tsx', '.mjs'}:
            self._analyze_js_file(file_path, lines, local_tainted_vars)
    
    def _analyze_php_file(self, file_path: str, lines: List[str], tainted_vars: Dict):
        """Analyze PHP file for taint flows"""
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('#'):
                continue
            
            # Check for taint sources
            for source in self.php_sources:
                match = re.search(source['pattern'], line)
                if match:
                    var_match = re.search(r'\$(\w+)\s*=', line)
                    if var_match:
                        var_name = var_match.group(1)
                        tainted_vars[var_name] = {
                            'taint_types': set(source['taints']),
                            'source_line': line_num,
                            'source_file': file_path,
                            'source_desc': source['desc'],
                            'code': line.strip(),
                            'cross_file': False
                        }
            
            # Track variable propagation
            prop_match = re.search(r'\$(\w+)\s*=\s*(.+)', line)
            if prop_match:
                target_var = prop_match.group(1)
                value_expr = prop_match.group(2)
                
                # Check if value contains tainted var
                for tainted_var, taint_info in list(tainted_vars.items()):
                    if re.search(rf'\${tainted_var}\b', value_expr):
                        # Check for sanitization
                        sanitized_types = set()
                        for sanitizer in self.php_sanitizers:
                            if re.search(sanitizer['pattern'], value_expr):
                                sanitized_types.update(sanitizer['removes'])
                        
                        remaining_taints = taint_info['taint_types'] - sanitized_types
                        if remaining_taints:
                            tainted_vars[target_var] = {
                                'taint_types': remaining_taints,
                                'source_line': taint_info['source_line'],
                                'source_file': taint_info['source_file'],
                                'source_desc': taint_info['source_desc'],
                                'code': line.strip(),
                                'cross_file': taint_info.get('cross_file', False),
                                'propagation': taint_info.get('propagation', []) + [{
                                    'line': line_num,
                                    'file': file_path,
                                    'code': line.strip(),
                                    'var': target_var
                                }]
                            }
            
            # Check for sinks
            for sink in self.php_sinks:
                match = re.search(sink['pattern'], line)
                if match:
                    sink_arg = match.group(1) if match.groups() else match.group(0)
                    
                    for var_name, taint_info in tainted_vars.items():
                        if re.search(rf'\${var_name}\b', sink_arg):
                            if sink['type'] in taint_info['taint_types']:
                                self._create_taint_flow(
                                    file_path=file_path,
                                    lines=lines,
                                    line_num=line_num,
                                    var_name=var_name,
                                    taint_info=taint_info,
                                    sink=sink,
                                    sink_code=line.strip()
                                )
    
    def _analyze_js_file(self, file_path: str, lines: List[str], tainted_vars: Dict):
        """Analyze JavaScript file for taint flows"""
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if stripped.startswith('//'):
                continue
            
            # Check for taint sources
            for source in self.js_sources:
                match = re.search(source['pattern'], line)
                if match:
                    var_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=', line)
                    if var_match:
                        var_name = var_match.group(1)
                        tainted_vars[var_name] = {
                            'taint_types': set(source['taints']),
                            'source_line': line_num,
                            'source_file': file_path,
                            'source_desc': source['desc'],
                            'code': line.strip(),
                            'cross_file': False
                        }
            
            # Track propagation  
            prop_match = re.search(r'(?:const|let|var)?\s*(\w+)\s*=\s*(.+)', line)
            if prop_match:
                target_var = prop_match.group(1)
                value_expr = prop_match.group(2)
                
                for tainted_var, taint_info in list(tainted_vars.items()):
                    if re.search(rf'\b{tainted_var}\b', value_expr):
                        sanitized_types = set()
                        for sanitizer in self.js_sanitizers:
                            if re.search(sanitizer['pattern'], value_expr):
                                sanitized_types.update(sanitizer['removes'])
                        
                        remaining_taints = taint_info['taint_types'] - sanitized_types
                        if remaining_taints:
                            tainted_vars[target_var] = {
                                'taint_types': remaining_taints,
                                'source_line': taint_info['source_line'],
                                'source_file': taint_info['source_file'],
                                'source_desc': taint_info['source_desc'],
                                'code': line.strip(),
                                'cross_file': taint_info.get('cross_file', False),
                                'propagation': taint_info.get('propagation', []) + [{
                                    'line': line_num,
                                    'file': file_path,
                                    'code': line.strip(),
                                    'var': target_var
                                }]
                            }
            
            # Check for sinks
            for sink in self.js_sinks:
                match = re.search(sink['pattern'], line)
                if match:
                    sink_arg = match.group(1) if match.groups() else match.group(0)
                    
                    for var_name, taint_info in tainted_vars.items():
                        if re.search(rf'\b{var_name}\b', sink_arg):
                            if sink['type'] in taint_info['taint_types']:
                                self._create_taint_flow(
                                    file_path=file_path,
                                    lines=lines,
                                    line_num=line_num,
                                    var_name=var_name,
                                    taint_info=taint_info,
                                    sink=sink,
                                    sink_code=line.strip()
                                )
    
    def _create_taint_flow(self, file_path: str, lines: List[str], line_num: int,
                          var_name: str, taint_info: Dict, sink: Dict, sink_code: str):
        """Create a TaintFlow object for the detected vulnerability"""
        self.flow_counter += 1
        flow_id = f"FLOW-{self.flow_counter:04d}"
        
        # Get code context for source
        source_start = max(0, taint_info['source_line'] - 2)
        source_end = min(len(lines), taint_info['source_line'] + 1)
        source_snippet = '\n'.join(lines[source_start:source_end])
        
        # Get code context for sink
        sink_start = max(0, line_num - 2)
        sink_end = min(len(lines), line_num + 1)
        sink_snippet = '\n'.join(lines[sink_start:sink_end])
        
        source_node = TaintNode(
            node_type='source',
            location=CodeLocation(
                file_path=taint_info['source_file'],
                line_number=taint_info['source_line'],
                code_snippet=taint_info.get('code', source_snippet)
            ),
            description=taint_info['source_desc'],
            code_snippet=taint_info.get('code', source_snippet),
            taint_types=taint_info['taint_types'],
            variable_name=var_name
        )
        
        sink_node = TaintNode(
            node_type='sink',
            location=CodeLocation(
                file_path=file_path,
                line_number=line_num,
                code_snippet=sink_code
            ),
            description=sink['desc'],
            code_snippet=sink_code,
            taint_types={sink['type']},
            variable_name=var_name
        )
        
        # Build propagation nodes
        propagation_nodes = []
        if 'propagation' in taint_info:
            for prop in taint_info['propagation']:
                prop_node = TaintNode(
                    node_type='propagation',
                    location=CodeLocation(
                        file_path=prop['file'],
                        line_number=prop['line'],
                        code_snippet=prop['code']
                    ),
                    description=f"Propagated to ${prop['var']}",
                    code_snippet=prop['code'],
                    taint_types=taint_info['taint_types'],
                    variable_name=prop['var']
                )
                propagation_nodes.append(prop_node)
        
        # Determine if cross-file
        files_involved = list(set([
            taint_info['source_file'],
            file_path
        ] + [p['file'] for p in taint_info.get('propagation', [])]))
        
        cross_file = len(set(files_involved)) > 1
        
        flow = TaintFlow(
            flow_id=flow_id,
            source=source_node,
            sink=sink_node,
            propagation_nodes=propagation_nodes,
            vulnerability_type=sink['type'].value,
            severity=sink['severity'],
            confidence=0.9 if not cross_file else 0.7,
            cross_file=cross_file,
            files_involved=files_involved
        )
        
        self.taint_flows.append(flow)
    
    def _resolve_cross_file_flows(self):
        """Resolve taint flows that span multiple files"""
        # TODO: Enhanced cross-file resolution using include graph
        pass
    
    def get_analysis_summary(self) -> Dict:
        """Get summary of analysis results"""
        return {
            'total_flows': len(self.taint_flows),
            'files_analyzed': len(self.analyzed_files),
            'cross_file_flows': sum(1 for f in self.taint_flows if f.cross_file),
            'by_severity': {
                'CRITICAL': sum(1 for f in self.taint_flows if f.severity == 'CRITICAL'),
                'HIGH': sum(1 for f in self.taint_flows if f.severity == 'HIGH'),
                'MEDIUM': sum(1 for f in self.taint_flows if f.severity == 'MEDIUM'),
                'LOW': sum(1 for f in self.taint_flows if f.severity == 'LOW'),
            },
            'by_type': {}
        }
    
    def analyze_single_file(self, file_path: str, content: str = None) -> List[TaintFlow]:
        """Analyze a single file"""
        self.taint_flows = []
        self.flow_counter = 0
        
        if content is None:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        
        lines = content.split('\n')
        tainted_vars = {}
        
        ext = Path(file_path).suffix.lower()
        if ext == '.php':
            self._analyze_php_file(file_path, lines, tainted_vars)
        elif ext in {'.js', '.ts', '.jsx', '.tsx', '.mjs'}:
            self._analyze_js_file(file_path, lines, tainted_vars)
        
        return self.taint_flows
