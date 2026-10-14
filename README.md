# OT Recon Tool

A safety-first OT (Operational Technology) network reconnaissance and vulnerability
assessment tool for Siemens, Rockwell/Allen-Bradley and B&R Automation environments.
Nmap does the scanning; OT-Recon adds OT-aware identification, evidence-based
classification, risk scoring, CVE correlation, and an honest report of what it could
**not** assess.

## Features

* Network discovery and OT service enumeration (Nmap-based)
* Read-only vendor fingerprinting (Siemens S7, Rockwell EtherNet/IP, B&R web endpoints)
* Evidence-based device classification (PLC, Safety PLC, HMI, ...)
* Risk scoring with CVE correlation (local database; optional live NVD lookup)
* Detailed self-contained HTML assessment report, with raw probe evidence and a coverage section
* History snapshots and scan-to-scan diffs
* CLI and optional GUI

## Usage

```bash
ot-recon scan 192.168.1.0/24                    # gentle "safe" profile by default
ot-recon scan 192.168.1.0/24 --dry-run          # show exactly what would run; sends nothing
ot-recon scan 192.168.1.0/24 --format html      # also write output/report.html
ot-recon report                                 # re-render the latest scan as HTML (no rescan)
ot-recon history | diff | report                # snapshots, comparisons, reports
```

## Safety guardrails

OT devices can be fragile, so the tool is gentle by default and refuses risky scans.

| Feature | What it does |
|---|---|
| **Scan profiles** `--profile safe\|standard\|fast` | `safe` (default): polite timing (T2), 200 ms between probes, 1 retry, minimal service-detection probing, 2 workers. `fast` is the original aggressive T5 behaviour - lab/IT networks only. Tunable under `profiles:` in config. |
| **Scope policy** `scope.allowed` | Allowlist of networks. A target outside it is **always refused** - `--force` cannot override it. |
| **Sanity checks** | Refuses non-private target space, targets over `scope.max_addresses` (default 1024), unverifiable hostnames, and option-like targets (`-sS`). `--force` overrides these (and the override is recorded). |
| **Typo guard** `--scope CIDR` | Refuse unless the target is inside these networks for this run. |
| **Do-not-scan list** `--exclude` / `scope.exclude` | Addresses never touched (fragile or safety-critical devices). This machine is excluded automatically (`--include-self` to include it). |
| **`--dry-run`** | Prints every command that would run. No packets sent, no files written. |
| **Audit log** | Every command (exact arguments, timing, outcome), plus refused scans, is written to `output/audit/scan_<timestamp>.jsonl`. If the log can't be written the scan is refused rather than run unaudited. |
| **Clean slate** | Previous scan output is deleted before each run, and only hosts discovered *this run* are ever probed. |

Fingerprint probes also skip redundant host discovery (`-Pn`) since discovery already
proved the host is alive.

## The assessment report

`--format html` (or `ot-recon report`) writes one self-contained HTML file - no scripts, no
external assets - safe to email or open air-gapped:

1. Executive summary  2. Scope & methodology (profile, scope, versions, audit log)
3. Asset inventory  4. Remediation plan (grouped, prioritised)  5. **Coverage & limitations**
6. Detailed findings per host, with raw probe evidence  7. Changes since the previous scan

Every finding states **how it was established**: `observed`, `product_matched`,
`version_matched`, `inconclusive` (firmware unreadable - verify manually) or
`external_unverified` (live NVD match). The coverage section lists what could *not* be
assessed (UDP not scanned, protocols with no probe, unreadable firmware, failed probes) so
"no findings" is never mistaken for "safe". Anything a device sends back is HTML-escaped.

## Optional: live CVE lookup

```bash
pip install -e ".[cve-live]"
export NVD_API_KEY=your-key-here      # optional; raises the NVD rate limit
ot-recon scan 192.168.1.0/24 --cve-live
```

The local curated database (`data/cve_db.yaml`) always runs and is the offline fallback.
Live results are cached in `output/cve_cache.json` (7-day TTL).

## Optional: GUI

```bash
sudo apt install python3-wxgtk4.0     # Debian/Ubuntu: don't let pip build wxPython
pip install -e ".[gui]"
ot-recon-gui
```

## Requirements

* Python 3.x
* Nmap (UDP scanning needs root)

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## Author

Abhinav
