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
    table.add_column("Notes")

    for host in data:
        protocols = ", ".join([p["protocol"] for p in host.get("ot_ports", [])]) or "-"
        host_type = host.get("type", "Unknown")
        notes = host.get("notes", "-")

        table.add_row(
            host["ip"],
            host_type,
            protocols,
            notes
        )

    console.print(table)