import os
import sys
import argparse
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich import box
    from rich.columns import Columns
except ImportError:
    print("Error: 'rich' library is required. Install it with: pip install rich")
    sys.exit(1)

from analyzer_engine import CodeAnalyzer
from report_generator import ReportGenerator


class CLIAnalyzer:
    def __init__(self, custom_rules_file: Optional[str] = None, enable_multi_line: bool = True):
        self.console = Console()
        self.analyzer = CodeAnalyzer(
            custom_rules_file=custom_rules_file,
            enable_multi_line=enable_multi_line
        )
        self.report_generator = ReportGenerator(self.analyzer)
        self.custom_rules_file = custom_rules_file

    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║         🔒 Secure Code Analyzer - OWASP Top 10              ║
║         Static Security Analysis for JS, PHP, & Python      ║
║         Multi-line Pattern Detection Enabled                ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")

        if self.custom_rules_file and os.path.exists(self.custom_rules_file):
            self.console.print(f"[dim]Custom rules loaded from: {self.custom_rules_file}[/dim]")

    def analyze_file_interactive(self):
        self.print_banner()

        self.console.print("\n[bold]File Analysis Mode[/bold]\n")

        file_path = self.console.input("[cyan]Enter file path to analyze: [/cyan]")

        if not os.path.exists(file_path):
            self.console.print(f"[red]Error: File not found: {file_path}[/red]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Analyzing code...", total=None)
            try:
                vulnerabilities = self.analyzer.analyze_file(file_path)
                progress.update(task, completed=True)
            except Exception as e:
                self.console.print(f"[red]Error analyzing file: {str(e)}[/red]")
                return

        self.display_results(vulnerabilities, file_path)
        self.export_options(vulnerabilities)

    def analyze_directory_interactive(self):
        self.print_banner()

        self.console.print("\n[bold]Directory Analysis Mode[/bold]\n")

        dir_path = self.console.input("[cyan]Enter directory path to analyze: [/cyan]")

        if not os.path.isdir(dir_path):
            self.console.print(f"[red]Error: Directory not found: {dir_path}[/red]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Scanning directory...", total=None)
            try:
                vulnerabilities = self.analyzer.analyze_directory(dir_path)
                progress.update(task, completed=True)
            except Exception as e:
                self.console.print(f"[red]Error analyzing directory: {str(e)}[/red]")
                return

        self.display_results(vulnerabilities, dir_path)
        self.export_options(vulnerabilities)

    def analyze_text_interactive(self):
        self.print_banner()
        self.console.print("\n[bold]Text Analysis Mode[/bold]\n")

        self.console.print("[dim]Enter/paste your code (press Enter then Ctrl+Z then Enter to finish):[/dim]")
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass

        code = '\n'.join(lines)
        if not code.strip():
            self.console.print("[red]No code provided[/red]")
            return

        language = self.console.input("[cyan]Enter language (javascript/php/python): [/cyan]").lower()
        if language not in ['javascript', 'js', 'php', 'python', 'py']:
            language = 'javascript'

        if language in ['js', 'javascript']:
            lang = 'javascript'
        elif language in ['py', 'python']:
            lang = 'python'
        else:
            lang = 'php'

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Analyzing code...", total=None)
            try:
                vulnerabilities = self.analyzer.analyze_code_string(code, lang, "pasted_input")
                progress.update(task, completed=True)
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")
                return

        self.display_results(vulnerabilities, "Pasted Code")
        self.export_options(vulnerabilities)

    def display_results(self, vulnerabilities, source_path):
        stats = self.analyzer.get_statistics(vulnerabilities)
        score = self.analyzer.calculate_security_score(vulnerabilities)

        summary_text = f"""
[bold]Source:[/bold] {source_path}
[bold]Total Issues:[/bold] {len(vulnerabilities)}
[bold]Security Score:[/bold] {self._get_score_color(score)}{score}/100[/]
        """
        self.console.print(Panel(summary_text, title="Summary", border_style="cyan"))

        severity_table = Table(title="Issues by Severity", box=box.ROUNDED)
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")

        for severity in ["Critical", "High", "Medium", "Low"]:
            count = stats['by_severity'][severity]
            color = self._get_severity_color(severity)
            severity_table.add_row(
                f"[{color}]{severity}[/{color}]",
                str(count)
            )

        self.console.print("\n")
        self.console.print(severity_table)

        match_type_table = Table(title="Issues by Match Type", box=box.ROUNDED)
        match_type_table.add_column("Match Type", style="bold")
        match_type_table.add_column("Count", justify="right")

        for mtype in ['single-line', 'multi-line']:
            count = stats['by_match_type'].get(mtype, 0)
            match_type_table.add_row(mtype, str(count))

        self.console.print("\n")
        self.console.print(match_type_table)

        if stats['by_category']:
            category_table = Table(title="Issues by Category", box=box.ROUNDED)
            category_table.add_column("Category", style="bold")
            category_table.add_column("Count", justify="right")

            for category, count in sorted(stats['by_category'].items()):
                category_table.add_row(category, str(count))

            self.console.print("\n")
            self.console.print(category_table)

        if vulnerabilities:
            self.console.print("\n")
            self.console.print(Panel("[bold]Vulnerabilities Detected[/bold]", border_style="yellow"))

            for i, vuln in enumerate(vulnerabilities[:20], 1):
                severity_color = self._get_severity_color(vuln.severity.value)
                match_tag = "[dim]ML[/dim]" if vuln.match_type == "multi-line" else ""
                self.console.print(f"\n[bold][{i}][/bold] [{severity_color}]{vuln.severity.value}[/{severity_color}] {vuln.rule_name} {match_tag}")
                self.console.print(f"    File: {vuln.file_path}:{vuln.line_number}" +
                                   (f"-{vuln.line_end}" if vuln.line_end else ""))
                self.console.print(f"    Category: {vuln.category} | Rule: {vuln.rule_id} | Type: {vuln.match_type}")
                self.console.print(f"    [dim]{vuln.description}[/dim]")

            if len(vulnerabilities) > 20:
                self.console.print(f"\n[dim]... and {len(vulnerabilities) - 20} more (see full report)[/dim]")
        else:
            self.console.print("\n")
            self.console.print(Panel("[bold green]✅ No vulnerabilities detected![/bold green]", border_style="green"))

    def export_options(self, vulnerabilities):
        self.console.print("\n")
        export_choice = self.console.input(
            "[cyan]Export report? (json/html/txt/n): [/cyan]"
        ).lower()

        if export_choice in ['json', 'html', 'txt']:
            output_path = self.console.input("[cyan]Enter output file path: [/cyan]")

            try:
                if export_choice == 'json':
                    self.report_generator.generate_json(vulnerabilities, output_path)
                elif export_choice == 'html':
                    self.report_generator.generate_html(vulnerabilities, output_path)
                elif export_choice == 'txt':
                    self.report_generator.generate_txt(vulnerabilities, output_path)

                self.console.print(f"[green]✓ Report saved to: {output_path}[/green]")
            except Exception as e:
                self.console.print(f"[red]Error saving report: {str(e)}[/red]")

    def _get_severity_color(self, severity: str) -> str:
        colors = {
            'Critical': 'red',
            'High': 'bright_red',
            'Medium': 'yellow',
            'Low': 'blue'
        }
        return colors.get(severity, 'white')

    def _get_score_color(self, score: float) -> str:
        if score >= 80:
            return '[green]'
        elif score >= 60:
            return '[yellow]'
        else:
            return '[red]'

    def run_cli(self, args):
        if args.file:
            file_path = args.file
            if not os.path.exists(file_path):
                self.console.print(f"[red]Error: File not found: {file_path}[/red]")
                return

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Analyzing...", total=None)
                vulnerabilities = self.analyzer.analyze_file(file_path)
                progress.update(task, completed=True)

            self.display_results(vulnerabilities, file_path)

            if args.output:
                ext = os.path.splitext(args.output)[1].lower()
                if ext == '.json':
                    self.report_generator.generate_json(vulnerabilities, args.output)
                elif ext == '.html':
                    self.report_generator.generate_html(vulnerabilities, args.output)
                elif ext == '.txt':
                    self.report_generator.generate_txt(vulnerabilities, args.output)
                else:
                    self.console.print(f"[yellow]Unknown format, defaulting to JSON[/yellow]")
                    self.report_generator.generate_json(vulnerabilities, args.output)

                self.console.print(f"[green]✓ Report saved to: {args.output}[/green]")

        elif args.directory:
            dir_path = args.directory
            if not os.path.isdir(dir_path):
                self.console.print(f"[red]Error: Directory not found: {dir_path}[/red]")
                return

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Scanning...", total=None)
                vulnerabilities = self.analyzer.analyze_directory(dir_path)
                progress.update(task, completed=True)

            self.display_results(vulnerabilities, dir_path)

            if args.output:
                ext = os.path.splitext(args.output)[1].lower()
                if ext == '.json':
                    self.report_generator.generate_json(vulnerabilities, args.output)
                elif ext == '.html':
                    self.report_generator.generate_html(vulnerabilities, args.output)
                elif ext == '.txt':
                    self.report_generator.generate_txt(vulnerabilities, args.output)
                else:
                    self.console.print(f"[yellow]Unknown format, defaulting to JSON[/yellow]")
                    self.report_generator.generate_json(vulnerabilities, args.output)

                self.console.print(f"[green]✓ Report saved to: {args.output}[/green]")

        elif args.text:
            code = args.text
            language = args.language or 'javascript'
            if language in ['js', 'javascript']:
                lang = 'javascript'
            elif language in ['py', 'python']:
                lang = 'python'
            else:
                lang = 'php'

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                task = progress.add_task("Analyzing...", total=None)
                vulnerabilities = self.analyzer.analyze_code_string(code, lang, "cli_input")
                progress.update(task, completed=True)

            self.display_results(vulnerabilities, "CLI Input")
        else:
            self.print_banner()
            self.console.print("\n[bold]Select Analysis Mode:[/bold]\n")
            self.console.print("1. Analyze single file")
            self.console.print("2. Analyze directory")
            self.console.print("3. Analyze pasted code (text)")
            self.console.print("4. Exit\n")

            choice = self.console.input("[cyan]Enter choice (1-4): [/cyan]")

            if choice == '1':
                self.analyze_file_interactive()
            elif choice == '2':
                self.analyze_directory_interactive()
            elif choice == '3':
                self.analyze_text_interactive()
            elif choice == '4':
                self.console.print("[green]Goodbye![/green]")
                return
            else:
                self.console.print("[red]Invalid choice[/red]")


def main():
    parser = argparse.ArgumentParser(
        description='Secure Code Analyzer - OWASP Top 10 Security Analysis with Multi-line Detection'
    )
    parser.add_argument(
        '-f', '--file',
        help='File to analyze'
    )
    parser.add_argument(
        '-d', '--directory',
        help='Directory to analyze'
    )
    parser.add_argument(
        '-t', '--text',
        help='Code text to analyze'
    )
    parser.add_argument(
        '-l', '--language',
        choices=['javascript', 'php', 'python', 'js', 'py'],
        help='Language for --text mode (default: javascript)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path for report'
    )
    parser.add_argument(
        '-r', '--rules',
        help='Path to custom rules JSON file'
    )
    parser.add_argument(
        '--no-multi-line',
        action='store_true',
        help='Disable multi-line pattern detection'
    )

    args = parser.parse_args()

    cli = CLIAnalyzer(
        custom_rules_file=args.rules,
        enable_multi_line=not args.no_multi_line
    )
    cli.run_cli(args)


if __name__ == '__main__':
    main()
