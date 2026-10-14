import time
from unittest.mock import patch, MagicMock

import pytest

from ot_recon.core import nvd_client


# --- _model_tokens ---

def test_model_tokens_splits_and_filters_stopwords():
    tokens = nvd_client._model_tokens("CompactLogix 5370 CPU PN")
    assert "5370" in tokens
    assert "CompactLogix" in tokens
    assert "CPU" not in tokens  # stopword
    assert "PN" not in tokens   # stopword (and too short-ish/generic)


def test_model_tokens_empty_for_none():
    assert nvd_client._model_tokens(None) == []
    assert nvd_client._model_tokens("") == []


def test_model_tokens_drops_very_short_tokens():
    tokens = nvd_client._model_tokens("X 5370 A")
    assert "5370" in tokens
    assert "X" not in tokens
    assert "A" not in tokens


# --- _severity_from_cvss ---

def test_severity_prefers_v31_over_v30_and_v2():
    cve_obj = {
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
        }
    }
    severity, score = nvd_client._severity_from_cvss(cve_obj)
    assert severity == "Critical"
    assert score == 9.8


def test_severity_falls_back_to_score_derived_when_no_base_severity():
    cve_obj = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}}
    severity, score = nvd_client._severity_from_cvss(cve_obj)
    assert severity == "High"
    assert score == 7.5


def test_severity_defaults_to_medium_when_no_metrics_present():
    severity, score = nvd_client._severity_from_cvss({"metrics": {}})
    assert severity == "Medium"
    assert score is None


@pytest.mark.parametrize("cvss_score,expected", [
    (9.5, "Critical"),
    (7.2, "High"),
    (5.0, "Medium"),
    (1.0, "Low"),
])
def test_severity_score_thresholds(cvss_score, expected):
    cve_obj = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": cvss_score}}]}}
    severity, _ = nvd_client._severity_from_cvss(cve_obj)
    assert severity == expected


# --- _vendor_model_match_cpe (the correctness-critical cross-validation) ---

def test_cpe_cross_validation_matches_vendor_and_model():
    criteria_list = [
        ("cpe:2.3:o:siemens:simatic_s7-1500_cpu_1511-1_pn_firmware:*:*:*:*:*:*:*:*", {}),
    ]
    assert nvd_client._vendor_model_match_cpe(criteria_list, "Siemens", ["1511-1"])


def test_cpe_cross_validation_rejects_wrong_vendor():
    criteria_list = [
        ("cpe:2.3:o:rockwellautomation:compactlogix_5370_firmware:*:*:*:*:*:*:*:*", {}),
    ]
    # Wrong vendor token entirely - even though this is a real industrial
    # CPE, it must not match a Siemens host.
    assert not nvd_client._vendor_model_match_cpe(criteria_list, "Siemens", ["5370"])


def test_cpe_cross_validation_rejects_right_vendor_wrong_model():
    criteria_list = [
        ("cpe:2.3:o:siemens:simatic_s7-1200_firmware:*:*:*:*:*:*:*:*", {}),
    ]
    # Same vendor, but none of these model tokens appear in the CPE -
    # must not silently match an unrelated Siemens product line.
    assert not nvd_client._vendor_model_match_cpe(criteria_list, "Siemens", ["S7-1500", "1500"])


def test_cpe_cross_validation_with_no_model_tokens_matches_on_vendor_alone():
    """When we genuinely have no usable model tokens (e.g. fingerprinting
    only confirmed the vendor), fall back to vendor-only matching rather
    than rejecting everything."""

    criteria_list = [("cpe:2.3:o:siemens:simatic_s7-1500_firmware:*:*:*:*:*:*:*:*", {})]
    assert nvd_client._vendor_model_match_cpe(criteria_list, "Siemens", [])


# --- query_nvd (mocked HTTP, using the real documented NVD response shape) ---

def _fake_nvd_response(vulnerabilities):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"vulnerabilities": vulnerabilities, "totalResults": len(vulnerabilities)}
    return resp


def test_query_nvd_filters_out_unrelated_cves_via_cpe_cross_validation():
    vulnerabilities = [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "A vulnerability in Siemens SIMATIC S7-1500."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
                "references": [{"url": "https://example.com/advisory1"}],
                "configurations": [{"nodes": [{"cpeMatch": [
                    {"criteria": "cpe:2.3:o:siemens:simatic_s7-1500_firmware:*:*:*:*:*:*:*:*"}
                ]}]}],
            }
        },
        {
            # Same keyword search could surface something unrelated that
            # merely mentions "1500" in its description - must be filtered
            # out because its own CPE data points to a different vendor.
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en", "value": "Unrelated product, port 1500 misconfiguration."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
                "references": [],
                "configurations": [{"nodes": [{"cpeMatch": [
                    {"criteria": "cpe:2.3:a:somecompany:unrelated_product:*:*:*:*:*:*:*:*"}
                ]}]}],
            }
        },
    ]

    with patch.object(nvd_client, "requests") as mock_requests, \
         patch.object(nvd_client, "_pace"):
        mock_requests.get.return_value = _fake_nvd_response(vulnerabilities)
        results = nvd_client.query_nvd("Siemens", "SIMATIC S7-1500")

    ids = [r["id"] for r in results]
    assert "CVE-2024-0001" in ids
    assert "CVE-2024-9999" not in ids
    assert results[0]["severity"] == "Critical"
    assert results[0]["advisory"] == "https://example.com/advisory1"


def test_query_nvd_falls_back_to_description_match_when_no_cpe_data():
    """Recent CVEs sometimes ship with no CPE configuration data at all -
    should fall back to checking the model token in the description
    rather than discarding every such CVE."""

    vulnerabilities = [{
        "cve": {
            "id": "CVE-2026-0001",
            "descriptions": [{"lang": "en", "value": "Vulnerability in B&R X20 series controllers."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"}}]},
            "references": [{"url": "https://example.com/br-advisory"}],
            "configurations": [],
        }
    }]

    with patch.object(nvd_client, "requests") as mock_requests, \
         patch.object(nvd_client, "_pace"):
        mock_requests.get.return_value = _fake_nvd_response(vulnerabilities)
        results = nvd_client.query_nvd("B&R", "X20")

    assert len(results) == 1
    assert results[0]["id"] == "CVE-2026-0001"


def test_query_nvd_raises_without_requests_installed():
    with patch.object(nvd_client, "requests", None):
        with pytest.raises(RuntimeError):
            nvd_client.query_nvd("Siemens", "S7-1500")


def test_query_nvd_propagates_http_errors_for_caller_to_handle():
    """query_nvd itself doesn't swallow errors - cve.py's _correlate_live
    is responsible for catching these and falling back gracefully."""

    with patch.object(nvd_client, "requests") as mock_requests, \
         patch.object(nvd_client, "_pace"):
        mock_requests.get.side_effect = ConnectionError("no route to host")
        with pytest.raises(ConnectionError):
            nvd_client.query_nvd("Siemens", "S7-1500")


def test_query_nvd_sends_api_key_header_when_provided():
    with patch.object(nvd_client, "requests") as mock_requests, \
         patch.object(nvd_client, "_pace"):
        mock_requests.get.return_value = _fake_nvd_response([])
        nvd_client.query_nvd("Siemens", "S7-1500", api_key="my-test-key")

        _, kwargs = mock_requests.get.call_args
        assert kwargs["headers"]["apiKey"] == "my-test-key"


# --- _pace (rate limiting) ---

def test_pace_sleeps_longer_without_api_key_than_with_one():
    # Simulate "the last request was 0.1s ago" (less than either pacing
    # interval, so both branches actually take the sleep path) by mocking
    # time.time() to a fixed "now" just after the recorded last-request time.
    nvd_client._last_request_at["t"] = 999.9

    with patch.object(nvd_client.time, "sleep") as mock_sleep, \
         patch.object(nvd_client.time, "time", return_value=1000.0):
        nvd_client._pace(has_api_key=False)
        no_key_sleep = mock_sleep.call_args[0][0]

    nvd_client._last_request_at["t"] = 999.9

    with patch.object(nvd_client.time, "sleep") as mock_sleep, \
         patch.object(nvd_client.time, "time", return_value=1000.0):
        nvd_client._pace(has_api_key=True)
        with_key_sleep = mock_sleep.call_args[0][0]

    assert no_key_sleep > with_key_sleep


def test_cpe_cross_validation_matches_rockwell_vendor_alias():
    criteria_list = [
        ("cpe:2.3:o:rockwellautomation:compactlogix_5370_firmware:*:*:*:*:*:*:*:*", {}),
    ]
    assert nvd_client._vendor_model_match_cpe(
        criteria_list, "Rockwell Automation/Allen-Bradley", ["5370"]
    )
