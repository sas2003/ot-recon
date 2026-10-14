# ot_recon/core/config.py
#
# Layered config: built-in defaults -> data/config.yaml (shipped, user-
# editable) -> an optional --config file for per-site overrides. Any layer
# can be partial; missing keys fall through to the layer below. This keeps
# the tool zero-config out of the box while letting port lists, nmap
# timing, script timeouts, and worker counts be tuned without touching
# code.

import copy
import os
import yaml

from ot_recon.core.paths import DATA_DIR
from ot_recon.core.profiles import PROFILES, DEFAULT_PROFILE

DEFAULT_CONFIG_PATH = DATA_DIR / "config.yaml"

_DEFAULTS = {
    "scan": {
        "tcp_ports": (
            "21,22,80,81,102,161,443,502,2222,4840,5900,"
            "8084,11159,11160,11169,20000,44818,50000,51000"
        ),
        "udp_ports": "161,2222",
        # Which pacing profile to use (safe | standard | fast, see
        # core/profiles.py). The explicit timing keys below are None by
        # default so the profile decides; set one to override just that
        # value regardless of profile.
        "profile": DEFAULT_PROFILE,
        "tcp_timing": None,
        "udp_timing": None,
        # Auto-exclude the scanning machine's own IP(s) from discovery.
        # Overridable per-run with --include-self.
        "exclude_self": True,
    },
    "fingerprint": {
        # None -> taken from the scan profile (see core/profiles.py).
        "workers": None,
        "nmap_script_timeout": None,
    },
    # Built-in profiles; a site can override any single value, e.g.
    #   profiles: {safe: {workers: 1}}
    "profiles": copy.deepcopy(PROFILES),
    "scope": {
        # POLICY allowlist: scans of anything outside these networks are
        # refused and --force cannot override it. Empty = no allowlist.
        "allowed": [],
        # Never scanned (fragile devices etc.), in addition to this machine.
        "exclude": [],
        # Sanity limit on target size; --force overrides it.
        "max_addresses": 1024,
    },
    "audit": {
        # Write every command the tool runs to output/audit/*.jsonl.
        "enabled": True,
    },
    "output": {
        "format": "table",
        "outfile": None,
    },
    "cve": {
        # Off by default - local_db correlation always runs regardless;
        # this only controls the supplementary live NVD lookup.
        "live_lookup": False,
        # Prefer the NVD_API_KEY env var over committing a key to a config
        # file; this stays None here on purpose (see load_config()).
        "api_key": None,
        "cache_ttl_days": 7,
        "request_timeout": 30,
    },
}


def _deep_merge(base, override):
    result = copy.deepcopy(base)

    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value

    return result


def load_config(extra_path=None):
    """Return the effective config dict.

    Layering order (later overrides earlier): built-in defaults ->
    data/config.yaml (if present) -> extra_path (if given, e.g. from
    --config). A missing file at any layer is silently skipped so the tool
    still runs with sane defaults.
    """

    config = copy.deepcopy(_DEFAULTS)

    for candidate in [DEFAULT_CONFIG_PATH, extra_path]:
        if not candidate:
            continue

        try:
            with open(candidate, "r") as f:
                user_cfg = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_cfg)
        except FileNotFoundError:
            continue
        except yaml.YAMLError as e:
            print(f"[-] Could not parse config file {candidate}: {e}")
            continue

    # Env var takes priority over a config file for the API key - keeps
    # credentials out of anything that might get committed to version
    # control. A key in a config file still works if that's preferred.
    env_key = os.environ.get("NVD_API_KEY")
    if env_key:
        config["cve"]["api_key"] = env_key

    return config
