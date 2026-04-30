# main.py

import argparse
from ot_recon.core.scanner import discover_hosts, scan_live_hosts
from ot_recon.core.parser import parse_results
from ot_recon.core.enricher import enrich
from ot_recon.core.reporter import generate_report
from ot_recon.core.classifier import classify

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

def main():
    banner()

    parser = argparse.ArgumentParser(
        prog="ot-recon",
        description="OT Network Recon Tool (Safe & OT-aware)",
        epilog="Author: Abhinav | Version: v0.1"
    )

    parser.add_argument("command", help="scan")
    parser.add_argument("target", nargs="?", help="Target subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed scan output")
    parser.add_argument("--version", action="version", version="ot-recon v0.1")

    args = parser.parse_args()

    if args.command == "scan":
        if not args.target:
            print("[-] Please provide target (e.g. 192.168.1.0/24)")
            return

        hosts = discover_hosts(args.target, args.verbose)
        scan_live_hosts(hosts, args.verbose)

        data = parse_results()
        data = enrich(data)
        data = classify(data)   # Newly added
        generate_report(data)

    else:
        print("[-] Unknown command")


if __name__ == "__main__":
    main()