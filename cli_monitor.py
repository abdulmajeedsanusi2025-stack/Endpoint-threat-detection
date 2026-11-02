"""
Command Line Real-Time Threat Monitor.
Renders real-time endpoint telemetry and AI risk assessment using Rich console tables.
Operates completely offline.
"""

import time
import sys
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

from telemetry.telemetry_manager import TelemetryManager
from engine.risk_engine import RiskEngine
from config import TELEMETRY_CONFIG


class CLIMonitor:
    """
    Renders live threat detection telemetry in terminal.
    """
    def __init__(self):
        self.console = Console()
        self.telemetry = TelemetryManager()
        self.engine = RiskEngine()

    def _format_age(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"

    def _get_tier_style(self, tier: str) -> str:
        styles = {
            "Critical": "bold white on red",
            "High": "bold red",
            "Medium": "bold yellow",
            "Low": "bold green"
        }
        return styles.get(tier, "white")

    def generate_view(self, top_n: int = 15) -> Panel:
        snapshots = self.telemetry.get_unified_snapshots(max_processes=top_n * 2)
        evaluated = []

        for snap in snapshots:
            assessment = self.engine.assess_telemetry(snap)
            evaluated.append(assessment)

        # Sort so highest risk processes appear first
        evaluated.sort(key=lambda x: x["composite_risk_percent"], reverse=True)
        top_procs = evaluated[:top_n]

        table = Table(title="[bold cyan]Endpoint Threat Telemetry & AI Risk Engine[/bold cyan]", expand=True)
        table.add_column("PID", justify="right", style="cyan", no_wrap=True)
        table.add_column("Process Name", style="white", min_width=18)
        table.add_column("CPU %", justify="right")
        table.add_column("Memory (MB)", justify="right")
        table.add_column("Net Sockets", justify="right")
        table.add_column("File Mods (60s)", justify="right")
        table.add_column("Process Age", justify="right")
        table.add_column("Risk Tier", justify="center")
        table.add_column("Risk Score %", justify="right")
        table.add_column("AI Class Probabilities (L / M / H / C)", justify="left")

        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0

        for item in evaluated:
            t = item["tier"]
            if t == "Critical":
                crit_count += 1
            elif t == "High":
                high_count += 1
            elif t == "Medium":
                med_count += 1
            else:
                low_count += 1

        for item in top_procs:
            tel = item["telemetry"]
            tier = item["tier"]
            tier_style = self._get_tier_style(tier)
            pcts = item["tier_percentages"]
            risk_pct = item["composite_risk_percent"]

            # Probability breakdown string
            prob_str = f"[green]{pcts['Low']:.0f}%[/green] / [yellow]{pcts['Medium']:.0f}%[/yellow] / [red]{pcts['High']:.0f}%[/red] / [bold red]{pcts['Critical']:.0f}%[/bold red]"

            # Format fields
            cpu_val = f"{tel.get('cpu_percent', 0.0):.1f}%"
            if tel.get('cpu_percent', 0.0) >= 70:
                cpu_val = f"[bold red]{cpu_val}[/bold red]"

            net_conn = str(tel.get("connection_count", 0))
            if tel.get("has_suspicious_port", False):
                net_conn = f"[bold red]{net_conn} (ALERT)[/bold red]"

            file_churn = str(tel.get("file_modifications_window", 0))
            if tel.get("file_modifications_window", 0) >= 25:
                file_churn = f"[bold red]{file_churn}[/bold red]"

            table.add_row(
                str(item["pid"]),
                item["name"],
                cpu_val,
                f"{tel.get('memory_mb', 0.0):.1f}",
                net_conn,
                file_churn,
                self._format_age(tel.get("process_age_seconds", 0.0)),
                f"[{tier_style}] {tier} [/{tier_style}]",
                f"[bold]{risk_pct:.1f}%[/bold]",
                prob_str
            )

        header_text = Text()
        header_text.append("STATUS: ", style="bold")
        header_text.append("Threat Protection Active | ", style="bold green")
        header_text.append(f"Threat Breakdown: ", style="bold")
        header_text.append(f"Critical: {crit_count}  ", style="bold red")
        header_text.append(f"High: {high_count}  ", style="red")
        header_text.append(f"Medium: {med_count}  ", style="yellow")
        header_text.append(f"Low: {low_count}", style="green")

        return Panel(table, title=str(header_text), border_style="blue")

    def run(self, interval: float = 2.0, max_iterations: Optional[int] = None):
        """Runs the live terminal monitoring loop."""
        self.telemetry.start()
        self.console.print("[bold green]Starting Endpoint Threat Detection System (Offline AI Engine)...[/bold green]")
        iterations = 0

        try:
            with Live(self.generate_view(), refresh_per_second=2, console=self.console) as live:
                while True:
                    time.sleep(interval)
                    live.update(self.generate_view())
                    iterations += 1
                    if max_iterations and iterations >= max_iterations:
                        break
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow]Stopping monitor...[/bold yellow]")
        finally:
            self.telemetry.stop()
