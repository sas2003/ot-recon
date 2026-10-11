# ot_recon/core/guardrails.py
#
# Pre-flight safety checks on a scan target, run BEFORE any packet is sent.
# Two deliberately different kinds of rule:
#
#   POLICY  - an allowlist (config `scope.allowed`, or the per-run --scope
#             flag). A target outside it is always refused. --force can
#             NOT override policy; changing policy means editing config.
#
#   SANITY  - catches honest mistakes: a target that isn't private address
#             space (a typo turning 10.1.1.0/24 into 101.1.1.0/24), or is
#             far larger than an OT segment, or can't be verified (a
#             hostname). These refuse by default but --force overrides
#             them, and the override is recorded in the audit log/report.
#
# Python's ip_network.is_private is deliberately NOT used for the public-
# space check: which ranges it covers has changed between Python releases,
# so the same target could be accepted on one machine and refused on
# another. Containment in the explicit APPROVED_NETWORKS list below gives
# the same answer everywhere.

import ipaddress
import re

DEFAULT_MAX_ADDRESSES = 1024


class ScopeError(Exception):
    """A target (or exclusion) was refused or could not be verified."""


# Address space it is reasonable to scan without extra confirmation.
APPROVED_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",      # RFC 1918
    "169.254.0.0/16",                                      # link-local
    "127.0.0.0/8",                                         # loopback
    "100.64.0.0/10",                                       # shared / CGNAT space
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # documentation ranges
)]

_OCTET_RE = re.compile(r"^(\*|\d{1,3}(-\d{1,3})?(,\d{1,3}(-\d{1,3})?)*)$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


class ParsedTarget:
    """A target reduced to what scope checks need: the lowest and highest
    address it can touch (every address in between is >= low and <= high,
    so containment of both ends in one contiguous network proves
    containment of all of it) and how many addresses it expands to."""

    def __init__(self, kind, low=None, high=None, count=None):
        self.kind = kind          # "network" | "ranges" | "hostname"
        self.low = low
        self.high = high
        self.count = count


def parse_target(text):
    t = (text or "").strip()

    if not t:
        raise ScopeError("empty scan target")
    if t.startswith("-"):
        # Would be parsed by nmap as an option - never pass this through.
        raise ScopeError(f"invalid target {text!r}: must not start with '-'")
    if any(c.isspace() for c in t):
        raise ScopeError(f"invalid target {text!r}: whitespace is not allowed")

    # CIDR / single IP with prefix
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise ScopeError(f"invalid CIDR target {text!r}")
        if net.version != 4:
            raise ScopeError("IPv6 targets are not supported yet")
        return ParsedTarget("network", int(net.network_address),
                            int(net.broadcast_address), net.num_addresses)

    # Plain IPv4 or nmap octet-range syntax (10.0.0.1-50, 10.0.*.1, 10.0.0.1,5)
    parts = t.split(".")
    if len(parts) == 4 and all(_OCTET_RE.match(p) for p in parts):
        lows, highs, count = [], [], 1
        for p in parts:
            values = set()
            if p == "*":
                values = set(range(256))
            else:
                for chunk in p.split(","):
                    a, _, b = chunk.partition("-")
                    lo, hi = int(a), int(b or a)
                    if not (0 <= lo <= hi <= 255):
                        raise ScopeError(f"invalid octet range {chunk!r} in target {text!r}")
                    values.update(range(lo, hi + 1))
            lows.append(min(values))
            highs.append(max(values))
            count *= len(values)
        to_int = lambda octets: int.from_bytes(bytes(octets), "big")
        return ParsedTarget("ranges", to_int(lows), to_int(highs), count)

    if _HOSTNAME_RE.match(t):
        return ParsedTarget("hostname")

    raise ScopeError(f"unrecognised target {text!r}")


def _parse_networks(items, label):
    nets = []
    for item in items or []:
        try:
            net = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            raise ScopeError(f"{label}: invalid network {item!r}")
        if net.version != 4:
            raise ScopeError(f"{label}: IPv6 is not supported yet ({item!r})")
        nets.append(net)
    return nets


def _split(value):
    """Accept a list, or a comma-separated string (CLI convenience)."""
    if not value:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return list(value)


split_list = _split   # public alias for callers (CLI/config list handling)


def _contained(parsed, nets):
    return any(
        int(n.network_address) <= parsed.low and parsed.high <= int(n.broadcast_address)
        for n in nets
    )


def check_target(target, allowed=None, cli_scope=None,
                 max_addresses=DEFAULT_MAX_ADDRESSES, force=False):
    """Validate `target`. Returns a dict describing the check (recorded in
    the audit log and report); raises ScopeError if the scan must not run."""

    parsed = parse_target(target)
    allowed_nets = _parse_networks(_split(allowed), "scope.allowed")
    cli_nets = _parse_networks(_split(cli_scope), "--scope")
    overridden = []

    if parsed.kind == "hostname":
        if allowed_nets or cli_nets:
            raise ScopeError(
                f"{target!r} is a hostname and cannot be verified against the scope "
                f"allowlist - use an IP address or CIDR"
            )
        if not force:
            raise ScopeError(
                f"{target!r} is a hostname, so it can't be checked for private address "
                f"space - use an IP/CIDR, or pass --force to scan it anyway"
            )
        overridden.append("hostname target not verified")
    else:
        # POLICY - not overridable by --force
        if allowed_nets and not _contained(parsed, allowed_nets):
            raise ScopeError(
                f"{target} is outside the allowed scope "
                f"({', '.join(str(n) for n in allowed_nets)}) set in config scope.allowed"
            )
        if cli_nets and not _contained(parsed, cli_nets):
            raise ScopeError(
                f"{target} is outside --scope ({', '.join(str(n) for n in cli_nets)})"
            )

        # SANITY - overridable with --force (and recorded when overridden).
        # Only a config allowlist counts as authorisation for non-private space.
        policy_authorised = bool(allowed_nets)

        if not policy_authorised and not _contained(parsed, APPROVED_NETWORKS):
            msg = (f"{target} includes address space outside private/link-local ranges "
                   f"(10/8, 172.16/12, 192.168/16, ...) - is that a typo?")
            if not force:
                raise ScopeError(msg + " Pass --force to scan it anyway.")
            overridden.append("non-private target space")

        if parsed.count > max_addresses:
            msg = (f"{target} expands to {parsed.count} addresses, over the "
                   f"{max_addresses} limit (scope.max_addresses)")
            if not force:
                raise ScopeError(msg + ". Pass --force to scan it anyway.")
            overridden.append(f"target size {parsed.count} > {max_addresses}")

    return {
        "target": target,
        "kind": parsed.kind,
        "address_count": parsed.count,
        "allowed": [str(n) for n in allowed_nets],
        "cli_scope": [str(n) for n in cli_nets],
        "max_addresses": max_addresses,
        "overridden": overridden,
    }


def parse_exclusions(items):
    """Validate a do-not-scan list (IPs/CIDRs). Returns the networks."""
    return _parse_networks(_split(items), "exclude")
