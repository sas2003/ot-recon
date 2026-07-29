from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

OUTPUT_DIR = PROJECT_ROOT / "output"
DATA_DIR = PROJECT_ROOT / "data"

DISCOVERY_XML = OUTPUT_DIR / "discovery.xml"
SCAN_XML = OUTPUT_DIR / "scan.xml"
PORTS_YAML = DATA_DIR / "ports.yaml"