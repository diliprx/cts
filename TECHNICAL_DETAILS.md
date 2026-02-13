# Technical Documentation - Secure Code Analyzer

## Table of Contents

1. [System Overview](#system-overview)
2. [Module Architecture](#module-architecture)
3. [Package Dependencies](#package-dependencies)
4. [Module Details](#module-details)
5. [Data Flow Architecture](#data-flow-architecture)
6. [API Reference](#api-reference)
7. [Configuration](#configuration)
8. [Flowcharts](#flowcharts)

---

## System Overview

The Secure Code Analyzer is a modular static analysis tool built with Python 3.13. It employs two primary analysis strategies:

1. **Taint Analysis**: Tracks data flow from untrusted sources to dangerous sinks
2. **Regex Pattern Matching**: Uses predefined vulnerability patterns

```
System Architecture:
====================

    User Interface Layer
    +------------------+------------------+------------------+
    |   index.html     |  cli_analyzer.py |     app.py       |
    |   (Web Frontend) |  (CLI Interface) |   (REST API)     |
    +--------+---------+--------+---------+--------+---------+
             |                  |                  |
             +------------------+------------------+
                               |
                    Core Analysis Layer
                    +------------------+
                    | analyzer_engine  |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
    +----v-----+       +-----v----+       +-----v------+
    |  taint   |       |  owasp   |       | external   |
    |  engine  |       |  rules   |       |   tools    |
    +----+-----+       +----------+       +------------+
         |
    +----v--------------+
    | cross_file_taint  |
    +-------------------+
                             |
                    Output Generation Layer
                    +------------------+
                    | report_generator |
                    +------------------+
```

---

## Module Architecture

### File Structure

```
c:\projects\cts\
├── analyzer_engine.py      # Core orchestration engine
├── taint_engine.py         # Single-file taint analysis
├── cross_file_taint.py     # Multi-file taint tracking
├── owasp_rules.py          # Vulnerability rule definitions
├── external_tools.py       # External tool integration
├── report_generator.py     # Multi-format report generation
├── cli_analyzer.py         # Command-line interface
├── app.py                  # Flask web server
├── index.html              # Web UI frontend
├── app.js                  # Frontend JavaScript
├── style.css               # Frontend styles
├── requirements.txt        # Python dependencies
├── test_samples/           # Sample vulnerable code
└── vscode-extension/       # VS Code extension (future)
```

---

## Package Dependencies

### requirements.txt

```
Flask==3.0.0              # Web framework
flask-cors==4.0.0         # Cross-origin resource sharing
Werkzeug==3.0.1           # WSGI utilities
rich==13.7.0              # Terminal formatting
google-generativeai==0.3.2 # AI code analysis (optional)
requests==2.31.0          # HTTP client
reportlab==4.0.7          # PDF generation (primary)
weasyprint==60.2          # PDF generation (fallback)
```

### Package Details

| Package                 | Version | Purpose                                    | Used In               |
| ----------------------- | ------- | ------------------------------------------ | --------------------- |
| **Flask**               | 3.0.0   | REST API server, routing, request handling | `app.py`              |
| **flask-cors**          | 4.0.0   | Enable CORS for browser requests           | `app.py`              |
| **Werkzeug**            | 3.0.1   | File uploads, secure filename handling     | `app.py`              |
| **rich**                | 13.7.0  | Terminal tables, progress bars, colors     | `cli_analyzer.py`     |
| **reportlab**           | 4.0.7   | PDF generation, custom flowables, canvas   | `report_generator.py` |
| **weasyprint**          | 60.2    | HTML-to-PDF conversion (fallback)          | `report_generator.py` |
| **requests**            | 2.31.0  | HTTP client for external APIs              | `app.py`              |
| **google-generativeai** | 0.3.2   | Gemini AI for code explanations (optional) | `app.py`              |

---

## Module Details

### 1. analyzer_engine.py (665 lines)

**Purpose**: Core orchestration engine that coordinates all analysis operations.

#### Classes

##### `Vulnerability` (dataclass)

```python
@dataclass
class Vulnerability:
    rule_id: str           # e.g., "TAINT-SQL-INJECTION"
    rule_name: str         # e.g., "SQL Injection"
    category: str          # OWASP category or custom
    severity: Severity     # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str         # Absolute path to file
    line_number: int       # Line where vulnerability found
    code_snippet: str      # Vulnerable code excerpt
    description: str       # Detailed explanation
    remediation: str       # How to fix
    matched_pattern: str   # What triggered detection
```

##### `Language` (Enum)

```python
class Language(Enum):
    JAVASCRIPT = "javascript"
    PHP = "php"
    UNKNOWN = "unknown"
```

##### `AnalysisMode` (Enum)

```python
class AnalysisMode(Enum):
    TAINT = "taint"    # Data flow tracking
    REGEX = "regex"    # Pattern matching
    HYBRID = "hybrid"  # Both combined
```

##### `CodeAnalyzer`

Main analysis class with the following methods:

| Method                     | Parameters                                            | Returns                           | Description                          |
| -------------------------- | ----------------------------------------------------- | --------------------------------- | ------------------------------------ |
| `__init__`                 | `mode: AnalysisMode`                                  | `None`                            | Initialize analyzer with mode        |
| `clone_github_repo`        | `repo_url: str`                                       | `str`                             | Clone repo, return temp path         |
| `analyze_directory`        | `directory: str, recursive: bool, mode: AnalysisMode` | `List[Vulnerability]`             | Analyze all files in directory       |
| `analyze_github_repo`      | `repo_url: str, mode: AnalysisMode`                   | `Tuple[List[Vulnerability], str]` | Clone and analyze GitHub repo        |
| `analyze_file`             | `file_path: str, mode: AnalysisMode`                  | `List[Vulnerability]`             | Analyze single file                  |
| `_analyze_with_taint`      | `content: str, file_path: str, language: Language`    | `List[Vulnerability]`             | Run taint analysis                   |
| `_analyze_with_regex`      | `content: str, file_path: str, language: Language`    | `List[Vulnerability]`             | Run regex analysis                   |
| `get_statistics`           | `vulnerabilities: List`                               | `Dict`                            | Calculate stats by severity/category |
| `calculate_security_score` | `vulnerabilities: List`                               | `int`                             | Compute 0-100 score                  |
| `cleanup`                  | `None`                                                | `None`                            | Remove temp directories              |

#### Constants

```python
SUPPORTED_EXTENSIONS = {'.php', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.phtml'}

SKIP_DIRECTORIES = {'node_modules', 'vendor', '.git', '__pycache__',
                    'dist', 'build', '.venv', 'venv', 'env', '.idea',
                    '.vscode', 'coverage', 'test_output'}
```

---

### 2. taint_engine.py (657 lines)

**Purpose**: Core taint analysis engine for single-file data flow tracking.

#### Classes

##### `TaintType` (Enum)

```python
class TaintType(Enum):
    SQL = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND = "Command Injection"
    PATH = "Path Traversal"
    SSRF = "Server-Side Request Forgery"
    CODE = "Code Injection"
    LDAP = "LDAP Injection"
    XML = "XML Injection"
    GENERIC = "Untrusted Data"
```

##### `TaintSource` (dataclass)

```python
@dataclass
class TaintSource:
    pattern: str              # Regex to match source
    taint_types: List[TaintType]  # Types of taint introduced
    language: str             # "php" or "javascript"
    description: str          # Human-readable description
```

##### `TaintSink` (dataclass)

```python
@dataclass
class TaintSink:
    pattern: str              # Regex to match sink
    taint_types: List[TaintType]  # Vulnerable to these taints
    language: str
    description: str
    severity: str = "CRITICAL"
```

##### `Sanitizer` (dataclass)

```python
@dataclass
class Sanitizer:
    pattern: str              # Regex to match sanitizer
    removes_taints: List[TaintType]  # Taints neutralized
    language: str
    description: str
```

##### `TaintedVariable` (dataclass)

```python
@dataclass
class TaintedVariable:
    name: str                 # Variable name
    taint_types: Set[TaintType]  # Active taints
    source_line: int          # Where taint originated
    source_function: str      # Enclosing function
    sanitized: bool = False   # True if sanitized
    propagation_path: List[str] = []  # Path through code
```

##### `TaintAnalyzer`

Main taint analysis class:

| Method                        | Parameters                               | Returns             | Description                           |
| ----------------------------- | ---------------------------------------- | ------------------- | ------------------------------------- |
| `__init__`                    | `None`                                   | `None`              | Initialize sources, sinks, sanitizers |
| `_initialize_sources`         | `None`                                   | `List[TaintSource]` | Define all taint sources              |
| `_initialize_sinks`           | `None`                                   | `List[TaintSink]`   | Define all dangerous sinks            |
| `_initialize_sanitizers`      | `None`                                   | `List[Sanitizer]`   | Define all sanitizers                 |
| `analyze_php_code`            | `content: str, file_path: str`           | `List[Dict]`        | Analyze PHP code                      |
| `analyze_javascript_code`     | `content: str, file_path: str`           | `List[Dict]`        | Analyze JavaScript code               |
| `_track_taint_propagation`    | `line: str, line_number: int, lang: str` | `None`              | Track taint through assignments       |
| `_check_sink_vulnerabilities` | `line: str, line_number: int, lang: str` | `List[Dict]`        | Check if taint reaches sink           |

#### Taint Sources by Language

**PHP Sources:**

- `$_GET[]`, `$_POST[]`, `$_REQUEST[]`
- `$_COOKIE[]`, `$_SERVER[]`, `$_FILES[]`
- `file_get_contents('php://input')`
- `getenv()`, `$_ENV[]`

**JavaScript Sources:**

- `req.query`, `req.body`, `req.params`
- `document.location`, `window.location`
- `document.cookie`, `localStorage`, `sessionStorage`

#### Taint Sinks by Type

| Sink Type         | PHP Examples                                | JS Examples                           |
| ----------------- | ------------------------------------------- | ------------------------------------- |
| SQL Injection     | `mysql_query`, `mysqli_query`, `PDO::query` | `sequelize.query`, `connection.query` |
| Command Injection | `exec`, `shell_exec`, `system`, `passthru`  | `child_process.exec`, `eval`          |
| XSS               | `echo`, `print`                             | `innerHTML`, `document.write`         |
| Path Traversal    | `file_get_contents`, `fopen`, `include`     | `fs.readFile`, `require`              |
| SSRF              | `curl_exec`, `file_get_contents`            | `fetch`, `axios.get`                  |

---

### 3. cross_file_taint.py (703 lines)

**Purpose**: Advanced taint tracking across multiple files in a project.

#### Classes

##### `CodeLocation` (dataclass)

```python
@dataclass
class CodeLocation:
    file_path: str
    line_number: int
    column: int = 0
    code_snippet: str = ""
    function_name: str = ""
    class_name: str = ""
```

##### `TaintNode` (dataclass)

```python
@dataclass
class TaintNode:
    node_type: str            # 'source', 'propagation', 'sanitizer', 'sink'
    location: CodeLocation
    description: str
    code_snippet: str
    taint_types: Set[TaintType]
    variable_name: str = ""
```

##### `TaintFlow` (dataclass)

```python
@dataclass
class TaintFlow:
    flow_id: str
    source: TaintNode
    sink: TaintNode
    propagation_nodes: List[TaintNode]
    sanitizers_bypassed: List[str]
    vulnerability_type: str
    severity: str = "HIGH"
    confidence: float = 0.8
    cross_file: bool = False
    files_involved: List[str]
```

##### `ExportedTaint` (dataclass)

```python
@dataclass
class ExportedTaint:
    variable_name: str
    taint_types: Set[TaintType]
    export_type: str      # 'function_return', 'global', 'parameter', etc.
    source_file: str
    source_line: int
    original_source: str
```

##### `CrossFileTaintAnalyzer`

| Method                    | Parameters                        | Returns           | Description                     |
| ------------------------- | --------------------------------- | ----------------- | ------------------------------- |
| `__init__`                | `None`                            | `None`            | Initialize rules and context    |
| `analyze_directory`       | `directory: str, recursive: bool` | `List[TaintFlow]` | Analyze entire directory        |
| `_build_file_graph`       | `directory: str`                  | `None`            | Build include/import graph      |
| `_analyze_file`           | `file_path: str`                  | `List[TaintFlow]` | Single file analysis            |
| `_track_cross_file_taint` | `None`                            | `List[TaintFlow]` | Find cross-file vulnerabilities |
| `_php_track_taint_flow`   | `content: str, file_path: str`    | `List[TaintFlow]` | PHP-specific tracking           |
| `_js_track_taint_flow`    | `content: str, file_path: str`    | `List[TaintFlow]` | JavaScript-specific tracking    |

---

### 4. owasp_rules.py (405 lines)

**Purpose**: Define vulnerability detection rules based on OWASP Top 10.

#### Classes

##### `Severity` (Enum)

```python
class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
```

##### `OWASPRule`

```python
class OWASPRule:
    id: str              # e.g., "A03-PHP-001"
    name: str            # Human-readable name
    category: str        # OWASP category (A01-A10)
    severity: Severity
    patterns: List[str]  # Regex patterns
    description: str
    remediation: str
    languages: List[str] # ["php", "javascript"]
```

#### Rule Categories

| Category | ID                        | Description                  |
| -------- | ------------------------- | ---------------------------- |
| A01      | Broken Access Control     | Missing authorization checks |
| A02      | Cryptographic Failures    | Weak hashing (MD5, SHA1)     |
| A03      | Injection                 | SQL, Command, XSS injection  |
| A05      | Security Misconfiguration | Debug mode, error display    |
| A07      | Authentication Failures   | Weak password handling       |
| A10      | SSRF                      | Server-side request forgery  |

#### Functions

| Function                | Parameters      | Returns           | Description        |
| ----------------------- | --------------- | ----------------- | ------------------ |
| `get_owasp_rules`       | `None`          | `List[OWASPRule]` | Get all rules      |
| `get_rules_by_language` | `language: str` | `List[OWASPRule]` | Filter by language |

---

### 5. report_generator.py (1008 lines)

**Purpose**: Generate security reports in multiple formats with visual diagrams.

#### Classes

##### `TaintFlowDiagram` (Flowable)

Custom ReportLab flowable for rendering taint flow diagrams.

```python
class TaintFlowDiagram(Flowable):
    def __init__(self, taint_data: Dict, width=520, height=200):
        self.taint_data = taint_data
        self.width = width
        self.height = height

    def draw(self):
        # Draws: SOURCE BOX --> TAINTED VARIABLE --> SINK BOX
        # With arrows, color coding, and code snippets
```

**Visual Output:**

```
+─────────────────────────────────────────────────────────────────+
│                  TAINT DATA FLOW ANALYSIS                       │
+─────────────────────────────────────────────────────────────────+
│                                                                 │
│  +──────────────+     +──────────────+     +──────────────+    │
│  │[!] SOURCE    │────>│ TAINTED VAR  │────>│[X] SINK      │    │
│  │ User Input   │     │ $query       │     │ mysql_query  │    │
│  │ Line 6       │     │ Line 6       │     │ Line 7       │    │
│  │ $_GET['id']  │     │ "SELECT..."  │     │ $query       │    │
│  +──────────────+     +──────────────+     +──────────────+    │
│                                                                 │
│      [!] SECURITY VULNERABILITY: TAINTED DATA REACHES SINK     │
+─────────────────────────────────────────────────────────────────+
```

##### `ReportGenerator`

| Method                     | Parameters                     | Returns | Description              |
| -------------------------- | ------------------------------ | ------- | ------------------------ |
| `__init__`                 | `analyzer: CodeAnalyzer`       | `None`  | Initialize with analyzer |
| `generate_json`            | `vulnerabilities, output_path` | `str`   | JSON report              |
| `generate_html`            | `vulnerabilities, output_path` | `str`   | HTML report              |
| `generate_text`            | `vulnerabilities, output_path` | `str`   | Plain text report        |
| `generate_pdf`             | `vulnerabilities, output_path` | `str`   | PDF with diagrams        |
| `_generate_pdf_reportlab`  | `vulnerabilities, output_path` | `str`   | ReportLab PDF            |
| `_generate_pdf_weasyprint` | `vulnerabilities, output_path` | `str`   | WeasyPrint PDF           |
| `_parse_taint_info`        | `vulnerability: Vulnerability` | `Dict`  | Extract taint data       |

#### PDF Generation Flow

```
generate_pdf()
     │
     ├──[ReportLab Available?]──> _generate_pdf_reportlab()
     │                                  │
     │                                  ├── Create SimpleDocTemplate
     │                                  ├── Add title, summary table
     │                                  ├── For each vulnerability:
     │                                  │       ├── Add details table
     │                                  │       ├── Add code snippet
     │                                  │       ├── Add TaintFlowDiagram
     │                                  │       └── Add page break
     │                                  └── doc.build(story)
     │
     └──[Fallback]──> _generate_pdf_weasyprint()
                              │
                              └── HTML --> PDF conversion
```

---

### 6. cli_analyzer.py (466 lines)

**Purpose**: Interactive command-line interface with rich formatting.

#### Classes

##### `CLIAnalyzer`

| Method                          | Parameters                                     | Returns | Description              |
| ------------------------------- | ---------------------------------------------- | ------- | ------------------------ |
| `__init__`                      | `mode: AnalysisMode`                           | `None`  | Initialize CLI           |
| `print_banner`                  | `None`                                         | `None`  | Display app banner       |
| `analyze_file_interactive`      | `None`                                         | `None`  | Prompt for file, analyze |
| `analyze_directory_interactive` | `None`                                         | `None`  | Prompt for directory     |
| `analyze_github_interactive`    | `repo_url: str`                                | `None`  | Analyze GitHub repo      |
| `display_results`               | `vulnerabilities, source`                      | `None`  | Show results table       |
| `export_options`                | `vulnerabilities`                              | `None`  | Prompt for export format |
| `run`                           | `file_path, dir_path, output_path, github_url` | `None`  | Main entry point         |

#### CLI Arguments

| Argument        | Short | Description                        |
| --------------- | ----- | ---------------------------------- |
| `--file`        | `-f`  | Single file to analyze             |
| `--directory`   | `-d`  | Directory to analyze               |
| `--github`      | `-g`  | GitHub repository URL              |
| `--output`      | `-o`  | Output report path                 |
| `--mode`        | `-m`  | Analysis mode (taint/regex/hybrid) |
| `--interactive` | `-i`  | Interactive mode                   |

#### Usage Examples

```bash
# Analyze single file with taint mode
python cli_analyzer.py -f vulnerable.php -m taint

# Analyze directory with hybrid mode
python cli_analyzer.py -d ./src -m hybrid -o report.pdf

# Analyze GitHub repository
python cli_analyzer.py -g https://github.com/user/repo -m taint

# Interactive mode
python cli_analyzer.py -i
```

---

### 7. app.py (742 lines)

**Purpose**: Flask REST API server for web-based analysis.

#### Endpoints

| Endpoint                 | Method | Description           |
| ------------------------ | ------ | --------------------- |
| `/`                      | GET    | Serve index.html      |
| `/style.css`             | GET    | Serve CSS             |
| `/app.js`                | GET    | Serve JavaScript      |
| `/api/analyze`           | POST   | Analyze uploaded file |
| `/api/analyze-code`      | POST   | Analyze code snippet  |
| `/api/analyze-github`    | POST   | Analyze GitHub repo   |
| `/api/analyze-directory` | POST   | Analyze uploaded ZIP  |
| `/api/export/json`       | POST   | Export JSON report    |
| `/api/export/html`       | POST   | Export HTML report    |
| `/api/export/pdf`        | POST   | Export PDF report     |
| `/api/explain`           | POST   | AI code explanation   |

#### Request/Response Formats

**POST /api/analyze**

```json
// Request (multipart/form-data)
{
    "file": "<binary file data>",
    "mode": "taint"  // or "regex", "hybrid"
}

// Response
{
    "success": true,
    "vulnerabilities": [...],
    "statistics": {
        "total": 16,
        "by_severity": {"Critical": 3, "High": 7, ...},
        "by_category": {...}
    },
    "security_score": 23
}
```

**POST /api/analyze-github**

```json
// Request
{
    "repo_url": "https://github.com/user/repo",
    "mode": "taint"
}

// Response
{
    "success": true,
    "repo_path": "/tmp/code_analysis_...",
    "files_analyzed": 15,
    "vulnerabilities": [...]
}
```

---

### 8. external_tools.py (149 lines)

**Purpose**: Integration with external static analysis tools.

#### Classes

##### `ToolResult` (dataclass)

```python
@dataclass
class ToolResult:
    tool_name: str
    vulnerabilities: List[Dict]
    raw_output: str
    error: Optional[str] = None
```

##### `ExternalToolRunner`

| Method        | Parameters       | Returns      | Description             |
| ------------- | ---------------- | ------------ | ----------------------- |
| `__init__`    | `None`           | `None`       | Check tool availability |
| `run_semgrep` | `file_path: str` | `ToolResult` | Run Semgrep scanner     |
| `run_psalm`   | `file_path: str` | `ToolResult` | Run Psalm (PHP)         |
| `run_eslint`  | `file_path: str` | `ToolResult` | Run ESLint (JS)         |

#### Supported External Tools

| Tool        | Language   | Purpose                    |
| ----------- | ---------- | -------------------------- |
| **Semgrep** | Multi      | Pattern-based scanner      |
| **Psalm**   | PHP        | Type-safe static analysis  |
| **ESLint**  | JavaScript | Linting and security rules |

---

## Data Flow Architecture

### Analysis Flow

```
                    Input (File/Directory/GitHub/ZIP)
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │       analyzer_engine.py      │
                    │    analyze_file() or          │
                    │    analyze_directory()        │
                    └───────────────┬───────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
            ▼                       ▼                       ▼
    ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
    │  TAINT MODE   │     │  REGEX MODE   │     │  HYBRID MODE  │
    │               │     │               │     │   (Both)      │
    └───────┬───────┘     └───────┬───────┘     └───────┬───────┘
            │                     │                     │
            ▼                     ▼                     │
    ┌───────────────┐     ┌───────────────┐            │
    │ taint_engine  │     │ owasp_rules   │            │
    │    +          │     │   regex       │◄───────────┘
    │ cross_file    │     │   matching    │
    └───────┬───────┘     └───────┬───────┘
            │                     │
            └──────────┬──────────┘
                       │
                       ▼
              ┌───────────────────┐
              │  Vulnerability    │
              │     List          │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ report_generator  │
              │  PDF/JSON/HTML    │
              └───────────────────┘
```

### Taint Analysis Flow

```
    Source Code
         │
         ▼
┌─────────────────────┐
│  Find SOURCES       │ ◄── $_GET, $_POST, req.query, etc.
│  (Untrusted Input)  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Track PROPAGATION  │ ◄── Variable assignments, concatenations
│  (Taint Spreads)    │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Check SANITIZERS   │ ◄── htmlspecialchars, prepared statements
│  (Remove Taint?)    │
└─────────┬───────────┘
          │
          ├── Sanitized ──────> Safe (No vulnerability)
          │
          ▼
┌─────────────────────┐
│  Reaches SINK?      │ ◄── mysql_query, exec, echo
│  (Dangerous Op)     │
└─────────┬───────────┘
          │
          ▼
   ┌──────────────┐
   │ VULNERABILITY │
   │   DETECTED!   │
   └──────────────┘
```

---

## API Reference

### Python API Usage

```python
from analyzer_engine import CodeAnalyzer, AnalysisMode
from report_generator import ReportGenerator

# Initialize analyzer
analyzer = CodeAnalyzer(mode=AnalysisMode.TAINT)

# Analyze single file
vulnerabilities = analyzer.analyze_file("path/to/file.php")

# Analyze directory
vulnerabilities = analyzer.analyze_directory("path/to/project/", recursive=True)

# Analyze GitHub repository
vulnerabilities, repo_path = analyzer.analyze_github_repo(
    "https://github.com/user/repo"
)

# Get statistics
stats = analyzer.get_statistics(vulnerabilities)
score = analyzer.calculate_security_score(vulnerabilities)

# Generate reports
report_gen = ReportGenerator(analyzer)
report_gen.generate_pdf(vulnerabilities, "report.pdf")
report_gen.generate_json(vulnerabilities, "report.json")
report_gen.generate_html(vulnerabilities, "report.html")

# Cleanup
analyzer.cleanup()
```

---

## Configuration

### Environment Variables

```bash
# Optional: Gemini AI API key for code explanations
GEMINI_API_KEY=your_api_key_here

# Flask configuration
FLASK_ENV=development
FLASK_DEBUG=1
```

### File Size Limits

```python
# app.py
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
```

### Supported File Extensions

```python
ALLOWED_EXTENSIONS = {'js', 'jsx', 'mjs', 'ts', 'tsx', 'php', 'phtml', 'txt'}
```

---

## Flowcharts

### Complete System Flowchart

```
                              START
                                │
                                ▼
                    ┌───────────────────────┐
                    │  Select Input Source  │
                    └───────────┬───────────┘
                                │
        ┌───────────┬───────────┼───────────┬───────────┐
        │           │           │           │           │
        ▼           ▼           ▼           ▼           ▼
    ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐
    │ File  │   │  Dir  │   │GitHub │   │  ZIP  │   │ Code  │
    └───┬───┘   └───┬───┘   └───┬───┘   └───┬───┘   └───┬───┘
        │           │           │           │           │
        │           │           ▼           │           │
        │           │    ┌───────────┐      │           │
        │           │    │git clone  │      │           │
        │           │    └─────┬─────┘      │           │
        │           │          │            │           │
        │           └──────────┴────────────┘           │
        │                      │                        │
        └──────────────────────┴────────────────────────┘
                               │
                               ▼
                    ┌───────────────────────┐
                    │  Select Analysis Mode │
                    └───────────┬───────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
            ▼                   ▼                   ▼
        ┌───────┐           ┌───────┐           ┌───────┐
        │ TAINT │           │ REGEX │           │HYBRID │
        └───┬───┘           └───┬───┘           └───┬───┘
            │                   │                   │
            ▼                   ▼                   ▼
    ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
    │ Data Flow     │   │ Pattern       │   │ Combined      │
    │ Tracking      │   │ Matching      │   │ Analysis      │
    └───────┬───────┘   └───────┬───────┘   └───────┬───────┘
            │                   │                   │
            └───────────────────┴───────────────────┘
                               │
                               ▼
                    ┌───────────────────────┐
                    │  Vulnerability List   │
                    └───────────┬───────────┘
                                │
                               ▼
                    ┌───────────────────────┐
                    │  Generate Report      │
                    └───────────┬───────────┘
                                │
            ┌───────────┬───────┼───────┬───────────┐
            │           │       │       │           │
            ▼           ▼       ▼       ▼           ▼
        ┌───────┐   ┌───────┐ ┌───┐ ┌──────┐   ┌───────┐
        │  PDF  │   │  JSON │ │TXT│ │ HTML │   │Display│
        └───────┘   └───────┘ └───┘ └──────┘   └───────┘
                                │
                               ▼
                              END
```

### PDF Generation Flowchart

```
             generate_pdf(vulnerabilities, output_path)
                               │
                               ▼
                    ┌───────────────────────┐
                    │ Normalize output_path │
                    │ Create directories    │
                    │ Add .pdf extension    │
                    └───────────┬───────────┘
                                │
                               ▼
                    ┌───────────────────────┐
              ┌────►│ ReportLab Available?  │
              │     └───────────┬───────────┘
              │                 │
              │        YES      │       NO
              │        ┌────────┴────────┐
              │        ▼                 ▼
              │  ┌───────────┐    ┌───────────┐
              │  │ ReportLab │    │WeasyPrint │
              │  │   PDF     │    │   PDF     │
              │  └─────┬─────┘    └─────┬─────┘
              │        │                │
              │        ▼                │
              │  ┌───────────┐          │
              │  │ For each  │          │
              │  │   vuln:   │          │
              │  └─────┬─────┘          │
              │        │                │
              │        ▼                │
              │  ┌───────────┐          │
              │  │Add table, │          │
              │  │code, flow │          │
              │  │ diagram   │          │
              │  └─────┬─────┘          │
              │        │                │
              │        ▼                │
              │  ┌───────────┐          │
              │  │doc.build()│          │
              │  └─────┬─────┘          │
              │        │                │
              │  ERROR │                │
              │────────┤                │
              │        │                │
              │        ▼                │
              │  ┌───────────┐          │
              │  │  Success  │◄─────────┘
              │  └─────┬─────┘
              │        │
              │        ▼
              │  ┌───────────┐
              │  │ Return    │
              │  │ file path │
              │  └───────────┘
```

---

## Error Handling

### Common Errors and Solutions

| Error                    | Cause             | Solution                              |
| ------------------------ | ----------------- | ------------------------------------- |
| `Git is not installed`   | Git not in PATH   | Install Git and add to PATH           |
| `File not found`         | Invalid file path | Verify path exists                    |
| `ModuleNotFoundError`    | Missing package   | Run `pip install -r requirements.txt` |
| `WeasyPrint OSError`     | Missing GTK libs  | ReportLab used as fallback            |
| `Max file size exceeded` | File > 10MB       | Use smaller file or increase limit    |

---

## Security Considerations

1. **Temp File Cleanup**: All cloned repos cleaned up after analysis
2. **File Validation**: Only allowed extensions processed
3. **Path Sanitization**: `secure_filename()` for uploads
4. **Input Size Limits**: 10MB max file size
5. **CORS Enabled**: Controlled cross-origin access

---

## Performance

- **Single File**: ~100ms average
- **Directory (100 files)**: ~5s average
- **Cross-File Analysis**: ~10s for small projects
- **PDF Generation**: ~500ms per report

---

_Document Version: 2.0 | Last Updated: February 2026_
