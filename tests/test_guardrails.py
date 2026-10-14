import pytest

from ot_recon.core import guardrails
from ot_recon.core.guardrails import ScopeError, check_target, parse_target


# --- parse_target ---

def test_parse_cidr():
    t = parse_target("192.168.1.0/24")
    assert t.kind == "network" and t.count == 256


def test_parse_single_ip_is_one_address():
    t = parse_target("10.0.0.5")
    assert t.count == 1 and t.low == t.high


def test_parse_octet_range_counts_and_bounds():
    t = parse_target("10.0.0.1-50")
    assert t.kind == "ranges" and t.count == 50
    assert t.low < t.high


def test_parse_octet_list_and_wildcard():
    assert parse_target("10.0.0.1,5,9").count == 3
    assert parse_target("10.0.0.*").count == 256


@pytest.mark.parametrize("bad", [
    "", "   ", "-sS", "--script=evil", "-iL /etc/passwd",
    "10.0.0.0/24 192.168.0.0/24",   # whitespace -> would smuggle a 2nd target
    "10.0.0.256", "10.0.0.5-2", "10.0.0.0/33", "not a target!",
])
def test_parse_rejects_malformed_or_option_like_targets(bad):
    with pytest.raises(ScopeError):
        parse_target(bad)


def test_parse_rejects_ipv6():
    with pytest.raises(ScopeError):
        parse_target("2001:db8::/32")


def test_parse_hostname():
    assert parse_target("plc1.plant.local").kind == "hostname"


# --- check_target: sanity rules ---

def test_private_target_passes_with_no_config():
    info = check_target("192.168.1.0/24")
    assert info["address_count"] == 256 and info["overridden"] == []


@pytest.mark.parametrize("target", ["8.8.8.0/24", "101.1.1.0/24", "0.0.0.0/0", "1.2.3.4"])
def test_public_space_refused_by_default(target):
    with pytest.raises(ScopeError):
        check_target(target, max_addresses=10**12)


def test_range_straddling_into_public_space_is_refused():
    """172.0.0.0/8 looks 'almost private' but includes public space - a
    containment check must catch it, not a prefix-string guess."""
    with pytest.raises(ScopeError):
        check_target("172.0.0.0/8", max_addresses=10**12)


def test_octet_range_spanning_private_and_public_is_refused():
    with pytest.raises(ScopeError):
        check_target("10-200.0.0.1")


def test_force_overrides_public_check_and_records_it():
    info = check_target("8.8.8.8", force=True)
    assert "non-private target space" in info["overridden"]


def test_oversized_target_refused_unless_forced():
    with pytest.raises(ScopeError):
        check_target("10.0.0.0/16", max_addresses=1024)

    info = check_target("10.0.0.0/16", max_addresses=1024, force=True)
    assert any("target size" in o for o in info["overridden"])


def test_size_limit_is_configurable():
    assert check_target("10.0.0.0/16", max_addresses=70000)["address_count"] == 65536


def test_hostname_refused_unless_forced():
    with pytest.raises(ScopeError):
        check_target("plc1.plant.local")
    assert check_target("plc1.plant.local", force=True)["overridden"]


# --- check_target: policy rules ---

def test_target_inside_allowlist_passes():
    info = check_target("192.168.10.0/25", allowed=["192.168.10.0/24"])
    assert info["allowed"] == ["192.168.10.0/24"]


def test_target_outside_allowlist_refused():
    with pytest.raises(ScopeError, match="outside the allowed scope"):
        check_target("192.168.20.0/24", allowed=["192.168.10.0/24"])


def test_force_can_not_override_allowlist_policy():
    """The central design rule: --force relaxes SANITY checks, never POLICY."""
    with pytest.raises(ScopeError, match="outside the allowed scope"):
        check_target("192.168.20.0/24", allowed=["192.168.10.0/24"], force=True)


def test_target_larger_than_allowlist_entry_refused():
    with pytest.raises(ScopeError):
        check_target("192.168.0.0/16", allowed=["192.168.10.0/24"], max_addresses=10**9)


def test_allowlist_authorises_non_private_space():
    """An org whose OT DMZ uses its own public block can allow-list it."""
    info = check_target("203.0.114.0/24", allowed=["203.0.114.0/24"])
    assert info["overridden"] == []


def test_hostname_refused_even_when_forced_if_allowlist_active():
    with pytest.raises(ScopeError):
        check_target("plc1.plant.local", allowed=["10.0.0.0/8"], force=True)


def test_cli_scope_restricts_the_run():
    check_target("192.168.10.5", cli_scope="192.168.10.0/24")
    with pytest.raises(ScopeError, match="--scope"):
        check_target("192.168.11.5", cli_scope="192.168.10.0/24")


def test_both_config_and_cli_scope_must_be_satisfied():
    with pytest.raises(ScopeError):
        check_target("192.168.10.5", allowed=["192.168.10.0/24"], cli_scope="192.168.10.128/25")


def test_invalid_allowlist_entry_is_an_error_not_silently_ignored():
    with pytest.raises(ScopeError, match="scope.allowed"):
        check_target("10.0.0.1", allowed=["not-a-network"])


def test_range_target_checked_against_allowlist_by_bounds():
    check_target("10.0.0.1-50", allowed=["10.0.0.0/24"])
    with pytest.raises(ScopeError):
        check_target("10.0.0.200-300", allowed=["10.0.0.0/24"])  # invalid octet


def test_parse_exclusions():
    nets = guardrails.parse_exclusions("10.0.0.1, 10.0.1.0/24")
    assert len(nets) == 2
    with pytest.raises(ScopeError):
        guardrails.parse_exclusions(["junk"])


@pytest.mark.parametrize("bad", ["-sS", "--script=evil", "-iL", "-oN /tmp/x"])
def test_option_like_targets_get_an_explicit_explanation(bad):
    """Other parse rules also reject these, but the dedicated check gives the
    operator a clear reason - and is the last line of defence if those
    rules are ever loosened (a leading '-' would be read by nmap as a flag)."""
    with pytest.raises(ScopeError, match="must not start with '-'"):
        parse_target(bad)
