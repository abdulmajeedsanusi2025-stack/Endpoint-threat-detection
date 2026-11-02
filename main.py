"""
AI-Powered Endpoint Threat Detection System.
Operates completely offline.

Monitored events:
1. Process Name
2. CPU Usage
3. Memory Usage
4. Active Network Connection
5. File Modification in a Time Window (60s rolling)
6. Process Age

Risk assessment engine:
- Low (%)
- Medium (%)
- High (%)
- Critical (%)
"""

import argparse
import sys
import time
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table

from engine.model import ThreatModel
from engine.risk_engine import RiskEngine
from simulator.threat_simulator import ThreatSimulator
from cli_monitor import CLIMonitor


def run_training():
    """Trains the offline AI model and displays metrics."""
    console = Console()
    console.print("\n[bold cyan]=== Training Offline Endpoint Threat AI Model ===[/bold cyan]")
    model = ThreatModel()
    metrics = model.train(n_samples_per_class=1200, save=True)
    
    console.print(f"[bold green]✓ Model trained and persisted to data/threat_model.joblib[/bold green]")
    console.print(f"Test Accuracy: [bold]{metrics['accuracy'] * 100:.2f}%[/bold]\n")

    table = Table(title="Feature Importances")
    table.add_column("Feature", style="cyan")
    table.add_column("Importance Weight", justify="right", style="green")

    for f_name, imp in sorted(metrics["feature_importances"].items(), key=lambda x: x[1], reverse=True):
        table.add_row(f_name, f"{imp:.4f}")
    console.print(table)


def run_simulation_benchmark():
    """Executes automated benchmark across threat scenarios."""
    console = Console()
    console.print("\n[bold cyan]=== Running Automated Threat Detection Benchmark ===[/bold cyan]")
    engine = RiskEngine()
    scenarios = ThreatSimulator.get_simulation_scenarios()

    table = Table(title="Offline AI Threat Detection Evaluation Results", expand=True)
    table.add_column("Scenario Name", style="bold white", min_width=25)
    table.add_column("Target Proc", style="cyan")
    table.add_column("Assessed Tier", justify="center")
    table.add_column("Composite Risk %", justify="right", style="bold")
    table.add_column("Low %", justify="right")
    table.add_column("Medium %", justify="right")
    table.add_column("High %", justify="right")
    table.add_column("Critical %", justify="right")

    for sc_name, sc_data in scenarios.items():
        assessment = engine.assess_telemetry(sc_data)
        tier = assessment["tier"]
        tier_style = "bold white on red" if tier == "Critical" else "bold red" if tier == "High" else "bold yellow" if tier == "Medium" else "bold green"
        pcts = assessment["tier_percentages"]

        table.add_row(
            sc_name,
            sc_data["name"],
            f"[{tier_style}] {tier} [/{tier_style}]",
            f"{assessment['composite_risk_percent']:.1f}%",
            f"{pcts['Low']:.1f}%",
            f"{pcts['Medium']:.1f}%",
            f"{pcts['High']:.1f}%",
            f"{pcts['Critical']:.1f}%",
        )

    console.print(table)


def run_dashboard():
    """Launches the Streamlit Web Dashboard."""
    console = Console()
    dashboard_path = Path(__file__).resolve().parent / "dashboard" / "app.py"
    console.print(f"[bold green]Launching Streamlit Dashboard at http://localhost:8501 ...[/bold green]")
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(dashboard_path)])


def run_web_app(port: int = 5000):
    """Launches the Professional Flask Backend and React Frontend."""
    import webbrowser
    from backend.app import create_app
    console = Console()
    console.print(f"\n[bold cyan]=== AI Endpoint Threat Detection System ===[/bold cyan]")
    console.print(f"[bold green]Starting Professional Flask Backend + React Frontend...[/bold green]")
    console.print(f"URL: [bold underline cyan]http://localhost:{port}[/bold underline cyan]")
    console.print(f"Mode: [bold green]Local Threat Protection Active[/bold green]\n")

    app = create_app()
    # Open browser after 1 second
    import threading
    def open_browser():
        time.sleep(1.2)
        webbrowser.open(f"http://localhost:{port}")
    threading.Thread(target=open_browser, daemon=True).start()

    app.run(host="127.0.0.1", port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(description="AI-Powered Offline Endpoint Threat Detection System")
    parser.add_argument(
        "--mode",
        choices=["web", "monitor", "dashboard", "train", "simulate"],
        default="web",
        help="Operating mode: web (Professional React+Flask UI), monitor (CLI table), dashboard (Streamlit UI), train (ML model), simulate (benchmark)"
    )
    parser.add_argument("--port", type=int, default=5000, help="Port for web server (default: 5000)")
    args = parser.parse_args()

    if args.mode == "web":
        run_web_app(port=args.port)
    elif args.mode == "train":
        run_training()
    elif args.mode == "simulate":
        run_simulation_benchmark()
    elif args.mode == "dashboard":
        run_dashboard()
    else:
        monitor = CLIMonitor()
        monitor.run(interval=2.0)


if __name__ == "__main__":
    main()
