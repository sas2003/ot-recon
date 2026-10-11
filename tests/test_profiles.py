import pytest

from ot_recon.core import profiles
from ot_recon.core.config import load_config


def _cfg(**scan_overrides):
    cfg = load_config()
    cfg["scan"].update(scan_overrides)
    return cfg


def test_default_profile_is_the_gentle_one():
    s = profiles.resolve(_cfg())
    assert s["name"] == "safe"
    assert s["tcp_timing"] == "T2" and s["scan_delay"] == "200ms"


def test_fast_profile_preserves_original_aggressive_behaviour():
    s = profiles.resolve(_cfg(), cli_profile="fast")
    assert (s["tcp_timing"], s["udp_timing"], s["workers"]) == ("T5", "T4", 10)
    assert profiles.pacing_args(s) == ["-T5"]   # no extra delay/retry flags


def test_safe_is_strictly_gentler_than_fast():
    safe = profiles.resolve(_cfg(), cli_profile="safe")
    fast = profiles.resolve(_cfg(), cli_profile="fast")
    assert safe["workers"] < fast["workers"]
    assert safe["version_intensity"] == 0 and fast["version_intensity"] is None
    assert safe["nmap_script_timeout"] >= fast["nmap_script_timeout"]


def test_cli_profile_beats_config_profile():
    s = profiles.resolve(_cfg(profile="fast"), cli_profile="standard")
    assert s["name"] == "standard"


def test_config_profile_used_when_no_cli():
    assert profiles.resolve(_cfg(profile="standard"))["name"] == "standard"


def test_explicit_config_value_overrides_profile():
    s = profiles.resolve(_cfg(tcp_timing="T4"))
    assert s["tcp_timing"] == "T4"     # explicit config wins over 'safe' T2
    assert s["udp_timing"] == "T2"     # untouched keys still come from profile


def test_cli_workers_beats_everything():
    assert profiles.resolve(_cfg(), cli_workers=7)["workers"] == 7


def test_unknown_profile_is_a_clear_error():
    with pytest.raises(ValueError, match="Unknown scan profile.*Available"):
        profiles.resolve(_cfg(), cli_profile="turbo")


def test_site_can_retune_a_profile_via_config_without_code():
    cfg = load_config()
    cfg["profiles"]["safe"]["workers"] = 1
    assert profiles.resolve(cfg)["workers"] == 1


def test_pacing_args_safe_profile():
    s = profiles.resolve(_cfg(), cli_profile="safe")
    assert profiles.pacing_args(s) == ["-T2", "--scan-delay", "200ms", "--max-retries", "1"]
    assert profiles.pacing_args(s, "udp")[0] == "-T2"


def test_max_retries_zero_is_emitted_not_dropped():
    assert "--max-retries" in profiles.pacing_args({"tcp_timing": "T3", "max_retries": 0})
