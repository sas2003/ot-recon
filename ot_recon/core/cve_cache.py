# ot_recon/core/cve_cache.py
#
# Persists live NVD lookup results to output/cve_cache.json, keyed by
# "vendor|model", so a scan across many hosts of the same product family
# (e.g. 40x Siemens S7-1500 on a /24) queries NVD once, not 40 times - and
# so previously-fetched results remain usable on a later offline run.

import json
import time

from ot_recon.core.paths import CVE_CACHE_JSON

DEFAULT_TTL_DAYS = 7


def _cache_key(vendor, model):
    return f"{(vendor or '').strip().lower()}|{(model or '').strip().lower()}"


def load_cache():
    try:
        with open(CVE_CACHE_JSON, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache):
    CVE_CACHE_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(CVE_CACHE_JSON, "w") as f:
        json.dump(cache, f, indent=2)


def get_cached(vendor, model, ttl_days=DEFAULT_TTL_DAYS, cache=None):
    """Return cached NVD results for (vendor, model) if present and not
    expired, else None. Pass an already-loaded `cache` dict to avoid
    re-reading the file per host during a scan."""

    cache = cache if cache is not None else load_cache()
    entry = cache.get(_cache_key(vendor, model))

    if entry is None:
        return None

    age_seconds = time.time() - entry.get("fetched_at", 0)
    if age_seconds > ttl_days * 86400:
        return None

    return entry.get("results", [])


def set_cached(vendor, model, results, cache=None):
    """Store results for (vendor, model). Pass an already-loaded `cache`
    dict to batch multiple updates before a single save_cache() call."""

    owns_cache = cache is None
    cache = cache if cache is not None else load_cache()

    cache[_cache_key(vendor, model)] = {
        "vendor": vendor,
        "model": model,
        "fetched_at": time.time(),
        "results": results,
    }

    if owns_cache:
        save_cache(cache)

    return cache
