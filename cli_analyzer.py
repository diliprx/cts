"""
CLI Application for Secure Code Analyzer
Interactive command-line interface with rich terminal formatting
"""

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
except ImportError:
    print("Error: 'rich' library is required. Install it with: pip install rich")
    sys.exit(1)

from analyzer_engine import CodeAnalyzer
from report_generator import ReportGenerator


class CLIAnalyzer:
    """Command-line interface for code analysis"""
    
    def __init__(self):
        self.console = Console()
        self.analyzer = CodeAnalyzer()
        self.report_generator = ReportGenerator(self.analyzer)
    
    def print_banner(self):
        """Print application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║         🔒 Secure Code Analyzer - OWASP Top 10              ║
║         Static Security Analysis for JS & PHP                ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")
    
    def analyze_file_interactive(self):
        """Interactive file analysis"""
        self.print_banner()
        
        self.console.print("\n[bold]File Analysis Mode[/bold]\n")
        
        # Get file path
        file_path = self.console.input("[cyan]Enter file path to analyze: [/cyan]")
        
        if not os.path.exists(file_path):
            self.console.print(f"[red]Error: File not found: {file_path}[/red]")
            return
        
        # Analyze file
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
        """Interactive directory analysis"""
        self.print_banner()
        
        self.console.print("\n[bold]Directory Analysis Mode[/bold]\n")
        
        # Get directory path
        dir_path = self.console.input("[cyan]Enter directory path to analyze: [/cyan]")
        
        if not os.path.isdir(dir_path):
            self.console.print(f"[red]Error: Directory not found: {dir_path}[/red]")
            return
        
        # Analyze directory
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
    
    def display_results(self, vulnerabilities, source_path):
        """Display analysis results in terminal"""
        stats = self.analyzer.get_statistics(vulnerabilities)
        score = self.analyzer.calculate_security_score(vulnerabilities)
        
        # Summary panel
        summary_text = f"""
[bold]Source:[/bold] {source_path}
[bold]Total Issues:[/bold] {len(vulnerabilities)}
[bold]Security Score:[/bold] {self._get_score_color(score)}{score}/100[/]
        """
        self.console.print(Panel(summary_text, title="Summary", border_style="cyan"))
        
        # Severity breakdown
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
        
        # Category breakdown
        if stats['by_category']:
            category_table = Table(title="Issues by Category", box=box.ROUNDED)
            category_table.add_column("Category", style="bold")
            category_table.add_column("Count", justify="right")
            
            for category, count in sorted(stats['by_category'].items()):
                category_table.add_row(category, str(count))
            
            self.console.print("\n")
            self.console.print(category_table)
        
        # Vulnerabilities list
        if vulnerabilities:
            self.console.print("\n")
            self.console.print(Panel("[bold]Vulnerabilities Detected[/bold]", border_style="yellow"))
            
            for i, vuln in enumerate(vulnerabilities[:10], 1):  # Show first 10
                severity_color = self._get_severity_color(vuln.severity.value)
                self.console.print(f"\n[bold][{i}][/bold] [{severity_color}]{vuln.severity.value}[/{severity_color}] {vuln.rule_name}")
                self.console.print(f"    File: {vuln.file_path}:{vuln.line_number}")
                self.console.print(f"    Category: {vuln.category} | Rule: {vuln.rule_id}")
                self.console.print(f"    [dim]{vuln.description}[/dim]")
            
            if len(vulnerabilities) > 10:
                self.console.print(f"\n[dim]... and {len(vulnerabilities) - 10} more (see full report)[/dim]")
        else:
            self.console.print("\n")
            self.console.print(Panel("[bold green]✅ No vulnerabilities detected![/bold green]", border_style="green"))
    
    def export_options(self, vulnerabilities):
        """Prompt user for export options"""
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
        """Get color for severity level"""
        colors = {
            'Critical': 'red',
            'High': 'bright_red',
            'Medium': 'yellow',
            'Low': 'blue'
        }
        return colors.get(severity, 'white')
    
    def _get_score_color(self, score: float) -> str:
        """Get color for security score"""
        if score >= 80:
            return '[green]'
        elif score >= 60:
            return '[yellow]'
        else:
            return '[red]'
    
    def run_cli(self, args):
        """Run CLI with command-line arguments"""
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
                    self.report_generator.generate_json(vulnerabilities, args.output)
                
                self.console.print(f"[green]✓ Report saved to: {args.output}[/green]")
        
        else:
            # Interactive mode
            self.print_banner()
            self.console.print("\n[bold]Select Analysis Mode:[/bold]\n")
            self.console.print("1. Analyze single file")
            self.console.print("2. Analyze directory")
            self.console.print("3. Exit\n")
            
            choice = self.console.input("[cyan]Enter choice (1-3): [/cyan]")
            
            if choice == '1':
                self.analyze_file_interactive()
            elif choice == '2':
                self.analyze_directory_interactive()
            elif choice == '3':
                self.console.print("[green]Goodbye![/green]")
                return
            else:
                self.console.print("[red]Invalid choice[/red]")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Secure Code Analyzer - OWASP Top 10 Security Analysis'
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
        '-o', '--output',
        help='Output file path for report'
    )
    
    args = parser.parse_args()
    
    cli = CLIAnalyzer()
    cli.run_cli(args)


if __name__ == '__main__':
    main()

