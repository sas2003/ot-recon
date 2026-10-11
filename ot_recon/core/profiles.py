# ot_recon/core/profiles.py
#
# Scan profiles: named bundles of pacing/probing settings so the operator
# chooses how hard the tool leans on the network with one word, instead
# of tuning five flags. OT devices vary enormously - a modern controller
# shrugs off an aggressive scan, a 15-year-old one with a handful of
# connection slots may not - so the DEFAULT is the gentle one.
#
#   safe      polite timing, a delay between probes, one retry, minimal
#             service-detection probing, few concurrent fingerprinters.
#   standard  nmap's default timing; ordinary service detection.
#   fast      the tool's original behaviour (T5 TCP / T4 UDP). Fine on
#             lab and IT-side networks; think twice on live control networks.
#
# Profiles live in the config's `profiles:` section (built-ins below are
# the defaults), so a site can retune one without editing code.

DEFAULT_PROFILE = "safe"

PROFILES = {
    "safe": {
        "description": "Gentle: polite timing, 200ms between probes, minimal version probing.",
        "tcp_timing": "T2",
        "udp_timing": "T2",
        "scan_delay": "200ms",
        "max_retries": 1,
        "version_intensity": 0,
        "workers": 2,
        "nmap_script_timeout": 60,
    },
    "standard": {
        "description": "Balanced: nmap default timing and service detection.",
        "tcp_timing": "T3",
        "udp_timing": "T3",
        "scan_delay": None,
        "max_retries": None,
        "version_intensity": None,
        "workers": 5,
        "nmap_script_timeout": 30,
    },
    "fast": {
        "description": "Aggressive (T5 TCP / T4 UDP). Only for lab or IT-side networks.",
        "tcp_timing": "T5",
        "udp_timing": "T4",
        "scan_delay": None,
        "max_retries": None,
        "version_intensity": None,
        "workers": 10,
        "nmap_script_timeout": 30,
    },
}


def resolve(config, cli_profile=None, cli_workers=None):
    """Compute the effective scan settings.

    Precedence (highest first): CLI flag > explicit value in config
    (scan.tcp_timing, fingerprint.workers, ...) > the chosen profile.
    Raises ValueError for an unknown profile name.
    """

    profiles = config.get("profiles") or PROFILES
    name = cli_profile or config["scan"].get("profile") or DEFAULT_PROFILE

    if name not in profiles:
        raise ValueError(
            f"Unknown scan profile {name!r}. Available: {', '.join(sorted(profiles))}"
        )

    settings = dict(profiles[name])
    settings["name"] = name

    scan_cfg = config["scan"]
    fp_cfg = config["fingerprint"]

    overrides = {
        "tcp_timing": scan_cfg.get("tcp_timing"),
        "udp_timing": scan_cfg.get("udp_timing"),
        "workers": fp_cfg.get("workers"),
        "nmap_script_timeout": fp_cfg.get("nmap_script_timeout"),
    }
    for key, value in overrides.items():
        if value is not None:
            settings[key] = value

    if cli_workers is not None:
        settings["workers"] = cli_workers

    return settings


def pacing_args(settings, proto="tcp"):
    """nmap flags implementing a profile's pacing, e.g.
    ['-T2', '--scan-delay', '200ms', '--max-retries', '1']."""

    timing = settings.get("udp_timing" if proto == "udp" else "tcp_timing")
    args = [f"-{timing}"] if timing else []

    if settings.get("scan_delay"):
        args += ["--scan-delay", str(settings["scan_delay"])]
    if settings.get("max_retries") is not None:
        args += ["--max-retries", str(settings["max_retries"])]

    return args
