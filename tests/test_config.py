import yaml
from ot_recon.core.config import load_config, _deep_merge, _DEFAULTS


def test_defaults_loaded_when_no_override():
    cfg = load_config()

    assert cfg["scan"]["tcp_timing"] == "T5"
    assert cfg["fingerprint"]["workers"] == 10
    assert "11169" in cfg["scan"]["tcp_ports"]  # B&R port present


def test_site_override_merges_without_clobbering_other_keys(tmp_path):
    site_cfg = {"fingerprint": {"workers": 25}}
    site_path = tmp_path / "site.yaml"

    with open(site_path, "w") as f:
        yaml.safe_dump(site_cfg, f)

    cfg = load_config(str(site_path))

    assert cfg["fingerprint"]["workers"] == 25
    # untouched sibling key should still be the default
    assert cfg["fingerprint"]["nmap_script_timeout"] == 30
    # untouched top-level section should still be the default
    assert cfg["scan"]["tcp_timing"] == "T5"


def test_missing_override_file_falls_back_silently(tmp_path):
    nonexistent = tmp_path / "does_not_exist.yaml"
    cfg = load_config(str(nonexistent))

    assert cfg == load_config()  # identical to defaults-only


def test_deep_merge_nested_dicts():
    base = {"a": {"x": 1, "y": 2}, "b": 3}
    override = {"a": {"y": 99}}

    result = _deep_merge(base, override)

    assert result == {"a": {"x": 1, "y": 99}, "b": 3}
    # base must not be mutated
    assert base == {"a": {"x": 1, "y": 2}, "b": 3}


def test_deep_merge_with_empty_override():
    base = {"a": 1}
    assert _deep_merge(base, {}) == base
    assert _deep_merge(base, None) == base


def test_defaults_are_not_mutated_by_load_config(tmp_path):
    """load_config must not mutate the module-level _DEFAULTS dict, or
    repeated calls with different overrides would leak state."""

    site_cfg = {"fingerprint": {"workers": 999}}
    site_path = tmp_path / "site.yaml"
    with open(site_path, "w") as f:
        yaml.safe_dump(site_cfg, f)

    load_config(str(site_path))

    assert _DEFAULTS["fingerprint"]["workers"] == 10
