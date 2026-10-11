from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

OUTPUT_DIR = PROJECT_ROOT / "output"
DATA_DIR = PROJECT_ROOT / "data"

DISCOVERY_XML = OUTPUT_DIR / "discovery.xml"
SCAN_XML = OUTPUT_DIR / "scan.xml"
UDP_SCAN_XML = OUTPUT_DIR / "scan_udp.xml"
PORTS_YAML = DATA_DIR / "ports.yaml"
CVE_DB_YAML = DATA_DIR / "cve_db.yaml"
HISTORY_DIR = OUTPUT_DIR / "history"

# Auto-populated by live NVD lookups (see core/nvd_client.py). Separate
# from the hand-curated CVE_DB_YAML on purpose: the curated file is a
# trusted, version-controlled seed; this is a generated, growing cache.
CVE_CACHE_JSON = OUTPUT_DIR / "cve_cache.json"

# One JSON-Lines file per scan recording every command the tool ran.
AUDIT_DIR = OUTPUT_DIR / "audit"