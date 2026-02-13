import subprocess
import json
import os
import shutil
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

@dataclass
class ToolResult:
    tool_name: str
    vulnerabilities: List[Dict]
    raw_output: str
    error: Optional[str] = None

class ExternalToolRunner:
    """Runs external static analysis tools (Semgrep, Psalm, ESLint)"""

    def __init__(self):
        self.tools_available = {
            'semgrep': shutil.which('semgrep') is not None,
            'psalm': shutil.which('psalm') is not None or os.path.exists('vendor/bin/psalm'),
            'eslint': shutil.which('eslint') is not None or os.path.exists('node_modules/.bin/eslint') or shutil.which('npm') is not None
        }

    def _run_command(self, command: List[str], cwd: str = '.') -> Tuple[str, str, int]:
        """Execute a shell command and return output"""
        try:
            # shell=True is needed for some windows commands to resolve correctly, 
            # but usually list config is safer. On windows, shell=True might be needed for .cmd/.bat files
            use_shell = os.name == 'nt'
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                shell=use_shell,
                universal_newlines=True,
                encoding='utf-8',
                errors='ignore'
            )
            stdout, stderr = process.communicate()
            return stdout, stderr, process.returncode
        except Exception as e:
            return "", str(e), -1

    def run_semgrep(self, file_path: str) -> ToolResult:
        """Run Semgrep on a file"""
        if not self.tools_available['semgrep']:
            return ToolResult('semgrep', [], "", "Semgrep not found")

        # semgrep --json --quiet <file>
        cmd = ['semgrep', '--json', '--quiet', file_path]
        stdout, stderr, code = self._run_command(cmd)

        if code != 0 and not stdout:
            return ToolResult('semgrep', [], stdout, f"Semgrep failed: {stderr}")

        try:
            data = json.loads(stdout)
            vulns = []
            for result in data.get('results', []):
                vulns.append({
                    'rule_id': result.get('check_id'),
                    'message': result.get('extra', {}).get('message', ''),
                    'line': result.get('start', {}).get('line'),
                    'severity': result.get('extra', {}).get('severity', 'medium').upper(),
                    'snippet': result.get('extra', {}).get('lines', '')
                })
            return ToolResult('semgrep', vulns, stdout)
        except json.JSONDecodeError:
            return ToolResult('semgrep', [], stdout, "Failed to parse Semgrep JSON output")

    def run_psalm(self, file_path: str) -> ToolResult:
        """Run Psalm on a PHP file"""
        # Determine psalm executable path
        if os.path.exists('vendor/bin/psalm'):
            psalm_exec = 'vendor\\bin\\psalm' if os.name == 'nt' else 'vendor/bin/psalm'
        elif self.tools_available['psalm']:
            psalm_exec = 'psalm'
        else:
            return ToolResult('psalm', [], "", "Psalm not found")

        # psalm --output-format=json <file>
        cmd = [psalm_exec, '--output-format=json', file_path]
        stdout, stderr, code = self._run_command(cmd)
        
        # Psalm returns exit code 1 or 2 if issues found, so we check stdout length
        if not stdout and code != 0:
             return ToolResult('psalm', [], stdout, f"Psalm error: {stderr}")

        try:
            if not stdout.strip():
                return ToolResult('psalm', [], stdout) # No issues found

            data = json.loads(stdout)
            vulns = []
            for issue in data:
                vulns.append({
                    'rule_id': issue.get('type'),
                    'message': issue.get('message'),
                    'line': issue.get('line_from'),
                    'severity': issue.get('severity', 'error').upper(),
                    'snippet': issue.get('snippet', '')
                })
            return ToolResult('psalm', vulns, stdout)
        except json.JSONDecodeError:
             return ToolResult('psalm', [], stdout, f"Failed to parse Psalm JSON output. Raw: {stdout[:100]}")

    def run_eslint(self, file_path: str) -> ToolResult:
        """Run ESLint on a JS/TS file"""
        # Determine eslint executable
        if os.path.exists('node_modules/.bin/eslint'):
            eslint_exec = 'node_modules\\.bin\\eslint' if os.name == 'nt' else './node_modules/.bin/eslint'
            cmd = [eslint_exec]
        elif shutil.which('eslint'):
            eslint_exec = 'eslint'
            cmd = [eslint_exec]
        elif shutil.which('npm'):
            # Fallback to npx if straight eslint not found but npm is there
            cmd = ['npx', 'eslint']
        else:
             return ToolResult('eslint', [], "", "ESLint not found")

        # eslint -f json <file>
        cmd.extend(['-f', 'json', file_path])
        
        stdout, stderr, code = self._run_command(cmd)

        try:
            if not stdout.strip():
                 return ToolResult('eslint', [], stdout, f"ESLint produced no output. Stderr: {stderr}")

            data = json.loads(stdout)
            vulns = []
            if isinstance(data, list) and len(data) > 0:
                # ESLint returns an array of file results
                file_result = data[0]
                for msg in file_result.get('messages', []):
                    vulns.append({
                        'rule_id': msg.get('ruleId'),
                        'message': msg.get('message'),
                        'line': msg.get('line'),
                        'severity': 'HIGH' if msg.get('severity') == 2 else 'MEDIUM', # 2=Error, 1=Warning
                        'snippet': msg.get('source', '') # 'source' might be missing in some eslint versions/formatters
                    })
            return ToolResult('eslint', vulns, stdout)
        except json.JSONDecodeError:
             return ToolResult('eslint', [], stdout, f"Failed to parse ESLint JSON output. Raw: {stdout[:100]}")
