from rich.console import Console
from rich.table import Table

console = Console()


def generate_report(data):

    console.print("\n[bold cyan]=== OT Recon Report ===[/bold cyan]\n")

    table = Table(show_header=True)

    table.add_column("IP")
    table.add_column("Type")
    table.add_column("Vendor")
    table.add_column("Model")
    table.add_column("Firmware")
    table.add_column("Confidence")
    table.add_column("Protocols")
    table.add_column("Risks")

    ot_assets = 0

    for host in data:

        if host.get("type") != "Unknown":
            ot_assets += 1

        protocols = ", ".join(
            [
                p["protocol"]
                for p in host.get("ot_ports", [])
            ]
        ) or "-"

        risks = "\n".join(
            host.get("risks", [])
        ) or "None"

        table.add_row(
            host["ip"],
            host.get("type", "-"),
            str(host.get("vendor", "-") or "-"),
            str(host.get("model", "-") or "-"),
            str(host.get("firmware", "-") or "-"),
            host.get("confidence", "-"),
            protocols,
            risks
        )

    console.print(table)

    console.print("\n[bold]Scan Summary[/bold]")

    console.print(
        f"Hosts discovered : {len(data)}"
    )

    console.print(
        f"OT Assets found  : {ot_assets}"
    )

    if ot_assets == 0:

        console.print(
            "[yellow]No OT-specific assets identified.[/yellow]"
        )