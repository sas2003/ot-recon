import time
from unittest.mock import patch

from ot_recon.core import cve_cache


def test_cache_key_is_case_and_whitespace_insensitive():
    k1 = cve_cache._cache_key("Siemens", " SIMATIC S7-1500 ")
    k2 = cve_cache._cache_key("siemens", "simatic s7-1500")
    assert k1 == k2


def test_set_and_get_cached_round_trip(tmp_path):
    cache_file = tmp_path / "cve_cache.json"

    with patch.object(cve_cache, "CVE_CACHE_JSON", cache_file):
        results = [{"id": "CVE-2024-0001", "severity": "High"}]
        cve_cache.set_cached("Siemens", "S7-1500", results)

        got = cve_cache.get_cached("Siemens", "S7-1500")
        assert got == results

        # File actually persisted to disk, not just held in memory.
        assert cache_file.exists()


def test_get_cached_returns_none_for_missing_key(tmp_path):
    cache_file = tmp_path / "cve_cache.json"
    with patch.object(cve_cache, "CVE_CACHE_JSON", cache_file):
        assert cve_cache.get_cached("Rockwell", "CompactLogix 5370") is None


def test_get_cached_returns_none_when_expired(tmp_path):
    cache_file = tmp_path / "cve_cache.json"

    with patch.object(cve_cache, "CVE_CACHE_JSON", cache_file):
        cve_cache.set_cached("B&R", "X20", [{"id": "CVE-2024-9999"}])

        # Manually backdate the fetched_at timestamp to simulate an
        # expired entry rather than sleeping in a test.
        cache = cve_cache.load_cache()
        key = cve_cache._cache_key("B&R", "X20")
        cache[key]["fetched_at"] = time.time() - (8 * 86400)  # 8 days old
        cve_cache.save_cache(cache)

        assert cve_cache.get_cached("B&R", "X20", ttl_days=7) is None
        # But a longer TTL should still accept it.
        assert cve_cache.get_cached("B&R", "X20", ttl_days=30) is not None


def test_load_cache_missing_file_returns_empty_dict(tmp_path):
    cache_file = tmp_path / "does_not_exist.json"
    with patch.object(cve_cache, "CVE_CACHE_JSON", cache_file):
        assert cve_cache.load_cache() == {}


def test_load_cache_corrupt_json_returns_empty_dict(tmp_path):
    cache_file = tmp_path / "cve_cache.json"
    cache_file.write_text("{not valid json")
    with patch.object(cve_cache, "CVE_CACHE_JSON", cache_file):
        assert cve_cache.load_cache() == {}


def test_set_cached_can_batch_with_shared_cache_dict(tmp_path):
    """Passing an already-loaded cache dict should let callers batch
    multiple updates before a single save, rather than hitting disk once
    per host during a scan."""

    cache_file = tmp_path / "cve_cache.json"
    with patch.object(cve_cache, "CVE_CACHE_JSON", cache_file):
        shared = {}
        shared = cve_cache.set_cached("Siemens", "S7-1200", [{"id": "CVE-A"}], cache=shared)
        shared = cve_cache.set_cached("Rockwell", "5370", [{"id": "CVE-B"}], cache=shared)

        # Nothing written to disk yet - caller owns the save.
        assert not cache_file.exists()

        cve_cache.save_cache(shared)
        assert cache_file.exists()

        reloaded = cve_cache.load_cache()
        assert len(reloaded) == 2
