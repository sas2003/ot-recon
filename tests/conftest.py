import sys
from pathlib import Path

# Ensure the project root is importable as `ot_recon` regardless of where
# pytest is invoked from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


import pytest


@pytest.fixture(autouse=True)
def _isolate_output_paths(tmp_path, monkeypatch):
    """Redirect every on-disk location the tool reads or writes into a
    per-test temp dir.

    A scan DELETES the previous run's nmap XML (scanner.clear_artifacts),
    writes audit logs, history snapshots and the CVE cache. Without this,
    any test that reaches those code paths would wipe or pollute the real
    project's output/ directory. Tests that need specific paths still
    monkeypatch their own - theirs are applied after this and win."""

    out = tmp_path / "_output"
    out.mkdir()

    targets = {
        "ot_recon.core.scanner": {
            "DISCOVERY_XML": out / "discovery.xml",
            "SCAN_XML": out / "scan.xml",
            "UDP_SCAN_XML": out / "scan_udp.xml",
        },
        "ot_recon.core.parser": {
            "SCAN_XML": out / "scan.xml",
            "UDP_SCAN_XML": out / "scan_udp.xml",
        },
        "ot_recon.core.history": {"HISTORY_DIR": out / "history"},
        "ot_recon.core.cve_cache": {"CVE_CACHE_JSON": out / "cve_cache.json"},
        "ot_recon.main": {"OUTPUT_DIR": out, "AUDIT_DIR": out / "audit"},
    }

    import importlib
    for module_name, attrs in targets.items():
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        for attr, value in attrs.items():
            monkeypatch.setattr(module, attr, value, raising=False)

    # Never leave auditing switched on between tests.
    from ot_recon.core import runner
    runner.reset()
    yield
    runner.reset()
