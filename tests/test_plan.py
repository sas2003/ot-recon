from ot_recon.core import plan, profiles
from ot_recon.core.config import load_config


def _build(**kw):
    cfg = load_config()
    settings = profiles.resolve(cfg, cli_profile=kw.pop("profile", "safe"))
    args = dict(target="10.0.0.0/24", settings=settings, config=cfg, exclude=[], udp=False,
                local_ips=set(), cve_live=False)
    args.update(kw)
    return args, plan.build_plan(**args)


def _text(args, steps, scope=None):
    scope = scope or {"target": args["target"], "address_count": 256, "allowed": [], "overridden": []}
    return plan.format_plan(steps, args["settings"], scope, args["exclude"], args["local_ips"])


def test_plan_lists_discovery_scan_and_every_probe():
    _args, steps = _build()
    names = [s["step"] for s in steps]
    assert names[0].startswith("Host discovery") and names[1].startswith("TCP port scan")
    assert {"Fingerprint probe: s7-info", "Fingerprint probe: http-title",
            "Fingerprint probe: enip-info", "Fingerprint probe: br-info"} <= set(names)


def test_plan_commands_are_the_same_ones_the_real_scan_builds():
    """The plan must be built from the real builders, never hand-copied."""
    from ot_recon.core import scanner, fingerprinter
    args, steps = _build()
    pacing = profiles.pacing_args(args["settings"])
    assert steps[0]["command"] == scanner.build_discovery_cmd("10.0.0.0/24", [], pacing)
    s7 = next(s for s in steps if s["step"].endswith("s7-info"))
    assert s7["command"] == fingerprinter.build_probe_cmd("s7-info", "<ip>", pacing=pacing, version_intensity=0)


def test_plan_udp_and_cve_steps_are_conditional():
    _a, plain = _build()
    assert not any("UDP" in s["step"] or "CVE" in s["step"] for s in plain)
    _a, full = _build(udp=True, cve_live=True)
    assert any("UDP" in s["step"] for s in full) and any("CVE" in s["step"] for s in full)
    assert next(s for s in full if "CVE" in s["step"])["command"] is None   # not an nmap command


def test_plan_excludes_include_this_machine_and_user_list():
    _a, steps = _build(exclude=["10.0.0.9"], local_ips={"10.0.0.99"})
    cmd = steps[0]["command"]
    assert cmd[cmd.index("--exclude") + 1] == "10.0.0.99,10.0.0.9"


def test_format_plan_shows_policy_overrides_and_exclusions():
    args, steps = _build(exclude=["10.0.0.9"], local_ips={"10.0.0.99"})
    scope = {"target": "10.0.0.0/24", "address_count": 256, "allowed": ["10.0.0.0/16"],
             "overridden": ["target size 4096 > 1024"]}
    text = _text(args, steps, scope)
    assert "Allowed scope : 10.0.0.0/16" in text
    assert "Overridden    : target size 4096 > 1024  (via --force)" in text
    assert "this machine (10.0.0.99)" in text and "Do-not-scan   : 10.0.0.9" in text
    assert "Nothing will be sent" in text


def test_format_plan_omits_optional_lines_when_unused():
    args, steps = _build()
    text = _text(args, steps)
    for absent in ("Allowed scope", "Overridden", "Do-not-scan", "Excluded"):
        assert absent not in text


def test_fast_profile_plan_has_no_extra_pacing_flags():
    _a, steps = _build(profile="fast")
    cmd = steps[0]["command"]
    assert "-T5" in cmd and "--scan-delay" not in cmd
