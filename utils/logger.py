"""
ScriptX Logger - Rich console logging with colors and formatting
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.text import Text
from rich import box
from datetime import datetime
import sys


class Logger:
    """Rich-based logger for ScriptX"""
    
    def __init__(self, verbose: bool = False):
        self.console = Console()
        self.verbose = verbose
        self._progress = None
        self._live = None
        
    def banner(self):
        """Display ScriptX banner"""
        banner_text = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗ ██████╗██████╗ ██╗██████╗ ████████╗██╗  ██╗        ║
║   ██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗██╔╝        ║
║   ███████╗██║     ██████╔╝██║██████╔╝   ██║    ╚███╔╝         ║
║   ╚════██║██║     ██╔══██╗██║██╔═══╝    ██║    ██╔██╗         ║
║   ███████║╚██████╗██║  ██║██║██║        ██║   ██╔╝ ██╗        ║
║   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝        ║
║                                                               ║
║       Advanced XSS Detection with Browser Control             ║
║                        v1.0.0                                 ║
╚═══════════════════════════════════════════════════════════════╝
"""
        self.console.print(banner_text, style="bold cyan")
    
    def info(self, message: str):
        """Log info message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [bold blue][INFO][/bold blue] {message}")
    
    def success(self, message: str):
        """Log success message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [bold green][SUCCESS][/bold green] {message}")
    
    def warning(self, message: str):
        """Log warning message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [bold yellow][WARNING][/bold yellow] {message}")
    
    def error(self, message: str):
        """Log error message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[dim]{timestamp}[/dim] [bold red][ERROR][/bold red] {message}")
    
    def debug(self, message: str):
        """Log debug message (only in verbose mode)"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.console.print(f"[dim]{timestamp}[/dim] [dim][DEBUG][/dim] {message}")
    
    def vuln_found(self, vuln_type: str, url: str, param: str, payload: str):
        """Log vulnerability found"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        vuln_panel = Panel(
            f"[bold]Type:[/bold] {vuln_type}\n"
            f"[bold]URL:[/bold] {url}\n"
            f"[bold]Parameter:[/bold] {param}\n"
            f"[bold]Payload:[/bold] [red]{payload}[/red]",
            title="🔴 XSS VULNERABILITY FOUND",
            title_align="left",
            border_style="red",
            box=box.DOUBLE
        )
        self.console.print(vuln_panel)
    
    def scan_summary(self, total_urls: int, total_forms: int, total_params: int, 
                     vulns_found: int, duration: float):
        """Display scan summary"""
        table = Table(title="Scan Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("URLs Scanned", str(total_urls))
        table.add_row("Forms Found", str(total_forms))
        table.add_row("Parameters Tested", str(total_params))
        table.add_row("Vulnerabilities Found", f"[bold red]{vulns_found}[/bold red]" if vulns_found > 0 else "0")
        table.add_row("Duration", f"{duration:.2f}s")
        
        self.console.print(table)
    
    def target_info(self, url: str, browser: str, mode: str):
        """Display target information"""
        panel = Panel(
            f"[bold]Target:[/bold] {url}\n"
            f"[bold]Browser:[/bold] {browser}\n"
            f"[bold]Mode:[/bold] {mode}",
            title="🎯 Scan Configuration",
            title_align="left",
            border_style="cyan"
        )
        self.console.print(panel)
    
    def create_progress(self):
        """Create a progress bar"""
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        )
        return self._progress
    
    def status(self, message: str):
        """Show status spinner"""
        return self.console.status(message, spinner="dots")


# Global logger instance
logger = Logger()
