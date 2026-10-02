# ot_recon/core/config.py
#
# Layered config: built-in defaults -> data/config.yaml (shipped, user-
# editable) -> an optional --config file for per-site overrides. Any layer
# can be partial; missing keys fall through to the layer below. This keeps
# the tool zero-config out of the box while letting port lists, nmap
# timing, script timeouts, and worker counts be tuned without touching
# code.

import copy
import yaml

from ot_recon.core.paths import DATA_DIR

DEFAULT_CONFIG_PATH = DATA_DIR / "config.yaml"

_DEFAULTS = {
    "scan": {
        "tcp_ports": (
            "21,22,80,81,102,161,443,502,2222,4840,5900,"
            "8084,11159,11160,11169,20000,44818,50000,51000"
        ),
        "udp_ports": "161,2222",
        "tcp_timing": "T5",
        "udp_timing": "T4",
    },
    "fingerprint": {
        "workers": 10,
        "nmap_script_timeout": 30,
        
    },
    "output": {
        "format": "table",
        "outfile": None,
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

    return config
