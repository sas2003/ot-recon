# main.py

import argparse
from pathlib import Path
from ot_recon.core.scanner import discover_hosts, scan_live_hosts
from ot_recon.core.parser import parse_results
from ot_recon.core.enricher import enrich
from ot_recon.core.reporter import generate_report, generate_diff_report
from ot_recon.core.classifier import classify
from ot_recon.core.risk import assess_risk
from ot_recon.core.fingerprinter import fingerprint
from ot_recon.core.exporter import export_json, export_csv
from ot_recon.core.paths import OUTPUT_DIR
from ot_recon.core.config import load_config
from ot_recon.core import history


def banner():
    print(r"""
          
  /$$$$$$  /$$$$$$$$       /$$$$$$$  /$$$$$$$$  /$$$$$$   /$$$$$$  /$$   /$$
 /$$__  $$|__  $$__/      | $$__  $$| $$_____/ /$$__  $$ /$$__  $$| $$$ | $$
| $$  \ $$   | $$         | $$  \ $$| $$      | $$  \__/| $$  \ $$| $$$$| $$
| $$  | $$   | $$         | $$$$$$$/| $$$$$   | $$      | $$  | $$| $$ $$ $$
| $$  | $$   | $$         | $$__  $$| $$__/   | $$      | $$  | $$| $$  $$$$
| $$  | $$   | $$         | $$  \ $$| $$      | $$    $$| $$  | $$| $$\  $$$
|  $$$$$$/   | $$         | $$  | $$| $$$$$$$$|  $$$$$$/|  $$$$$$/| $$ \  $$
 \______/    |__/         |__/  |__/|________/ \______/  \______/ |__/  \__/
                                                 
                OT RECON TOOL
""")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ot-recon",
        description="OT Network Recon Tool (Safe & OT-aware)",
        epilog="Author: Abhinav | Version: v1.0"
    )
    parser.add_argument("--version", action="version", version="ot-recon v0.1")

    subparsers = parser.add_subparsers(dest="command")

    # --- scan ---
    scan_p = subparsers.add_parser("scan", help="Discover and fingerprint OT assets on a subnet")
    scan_p.add_argument("target", help="Target subnet (e.g. 192.168.1.0/24)")
    scan_p.add_argument("--verbose", action="store_true", help="Show detailed scan output")
    scan_p.add_argument(
        "--udp", action="store_true",
        help="Also scan UDP OT ports (EtherNet/IP I/O, SNMP). Requires root/sudo."
    )
    scan_p.add_argument(
        "--workers", type=int, default=None,
        help="Number of concurrent workers for fingerprinting (default: from config, normally 10)"
    )
    scan_p.add_argument(
        "--format", choices=["table", "json", "csv", "all"], default=None,
        help="Output format(s). 'table' prints to console; 'json'/'csv'/'all' "
             "also write report file(s) to the output dir. (default: from config)"
    )
    scan_p.add_argument(
        "--outfile", type=str, default=None,
        help="Base path/name for exported report file(s) (extension is added "
             "automatically). Defaults to output/report.<ext>."
    )
    scan_p.add_argument(
        "--config", type=str, default=None,
        help="Path to a site-specific config YAML, layered on top of "
             "data/config.yaml (only needs to contain the keys you want to override)."
    )
    scan_p.add_argument(
        "--no-history", action="store_true",
        help="Don't save this run as a history snapshot (skips output/history/*.json)."
    )

    # --- diff ---
    diff_p = subparsers.add_parser("diff", help="Compare two saved scan snapshots")
    diff_p.add_argument(
        "--from", dest="from_snapshot", type=str, default=None,
        help="Path to the older snapshot (default: second-most-recent in output/history/)"
    )
    diff_p.add_argument(
        "--to", dest="to_snapshot", type=str, default=None,
        help="Path to the newer snapshot (default: most recent in output/history/)"
    )

    # --- history ---
    history_p = subparsers.add_parser("history", help="List saved scan snapshots")
    history_p.add_argument(
        "--limit", type=int, default=20,
        help="Max number of snapshots to list, most recent first (default: 20)"
    )

    return parser


def run_scan(args):
    config = load_config(args.config)

    # CLI flags win over config file, which wins over built-in defaults.
    workers = args.workers if args.workers is not None else config["fingerprint"]["workers"]
    out_format = args.format or config["output"]["format"]
    outfile = args.outfile or config["output"]["outfile"]

    hosts = discover_hosts(args.target, args.verbose)
    scan_live_hosts(
        hosts, args.verbose, udp=args.udp,
        tcp_ports=config["scan"]["tcp_ports"],
        udp_ports=config["scan"]["udp_ports"],
        tcp_timing=config["scan"]["tcp_timing"],
        udp_timing=config["scan"]["udp_timing"],
    )

    data = parse_results()
    data = enrich(data)
    data = fingerprint(
        data, args.verbose, workers=workers,
        script_timeout=config["fingerprint"]["nmap_script_timeout"],
        
    )
    data = classify(data)
    data = assess_risk(data)

    # Console table is always shown, regardless of --format, so the
    # operator always gets immediate feedback even when exporting.
    generate_report(data)

    base = Path(outfile) if outfile else OUTPUT_DIR / "report"
    base.parent.mkdir(parents=True, exist_ok=True)

    if out_format in ("json", "all"):
        export_json(data, base.with_suffix(".json"))

    if out_format in ("csv", "all"):
        export_csv(data, base.with_suffix(".csv"))

    if not args.no_history:
        history.save_snapshot(data)


def run_diff(args):
    if args.from_snapshot and args.to_snapshot:
        old_path, new_path = Path(args.from_snapshot), Path(args.to_snapshot)
    else:
        snapshots = history.list_snapshots()

        if len(snapshots) < 2:
            print(
                "[-] Need at least 2 saved snapshots to diff "
                f"(found {len(snapshots)} in output/history/). Run 'ot-recon scan' at least twice first."
            )
            return

        old_path, new_path = snapshots[-2], snapshots[-1]

    try:
        old_snap = history.load_snapshot(old_path)
        new_snap = history.load_snapshot(new_path)
    except FileNotFoundError as e:
        print(f"[-] Snapshot file not found: {e}")
        return

    diff = history.diff_snapshots(old_snap["hosts"], new_snap["hosts"])
    generate_diff_report(diff, old_snap.get("timestamp"), new_snap.get("timestamp"))


def run_history(args):
    snapshots = history.list_snapshots()

    if not snapshots:
        print("[-] No saved snapshots yet. Run 'ot-recon scan <target>' first.")
        return

    print(f"[+] {len(snapshots)} snapshot(s) found (showing up to {args.limit}, most recent first):\n")

    for path in list(reversed(snapshots))[:args.limit]:
        snap = history.load_snapshot(path)
        ts = snap.get("timestamp", path.stem)
        count = snap.get("host_count", len(snap.get("hosts", [])))
        high_sev_hosts = sum(
            1 for h in snap.get("hosts", [])
            if h.get("risk_severity") in ("Critical", "High")
        )
        print(f"  {ts}  |  {count} host(s)  |  {high_sev_hosts} Critical/High  |  {path}")


def main():
    banner()

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    elif args.command == "diff":
        run_diff(args)
    elif args.command == "history":
        run_history(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
