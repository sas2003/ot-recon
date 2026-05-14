# ot_recon/core/reporter.py

from rich.console import Console
from rich.table import Table

console = Console()


def generate_report(data):

    console.print("\n[bold cyan]=== OT Recon Report ===[/bold cyan]\n")

    if not data:
        console.print("[red]No devices found.[/red]")
        return

    table = Table(show_header=True, header_style="bold magenta")

    table.add_column("IP", style="cyan")
    table.add_column("Type")
    table.add_column("Protocols")
    table.add_column("Confidence")
    table.add_column("Risks")

    for host in data:

        host_type = host.get("type", "Unknown")

        protocols = ", ".join(
            [p["protocol"] for p in host.get("ot_ports", [])]
        ) or "-"

        confidence = ", ".join(
            [p["confidence"] for p in host.get("ot_ports", [])]
        ) or "-"

        risks = host.get("risks", [])

        risk_text = (
            "\n".join([f"[red]{r}[/red]" for r in risks])
            if risks
            else "[green]None[/green]"
        )

        table.add_row(
            host["ip"],
            host_type,
            protocols,
            confidence,
            risk_text
        )

    console.print(table)