"""Unit tests for intel_server.py — mock all outbound HTTP calls."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import mcp_servers.intel_server as intel


def _mock_get(return_value: dict):
    return patch("mcp_servers.intel_server._get", return_value=return_value)


def test_shodan_missing_key(monkeypatch):
    monkeypatch.setattr(intel, "_SHODAN_KEY", "")
    result = intel._shodan_host("1.2.3.4")
    assert "[error:no_api_key]" in result


def test_nvd_lookup_by_cve_id():
    mock_data = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Test vulnerability description"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            }
        }]
    }
    with _mock_get(mock_data):
        result = intel._nvd_lookup("CVE-2024-1234")
    assert "CVE-2024-1234" in result
    assert "9.8" in result


def test_nvd_no_results():
    with _mock_get({"vulnerabilities": []}):
        result = intel._nvd_lookup("nonexistent keyword xyz")
    assert "No CVEs found" in result


def test_vt_missing_key(monkeypatch):
    monkeypatch.setattr(intel, "_VT_KEY", "")
    result = intel._vt_lookup("abc123", "file")
    assert "[error:no_api_key]" in result


@pytest.mark.asyncio
async def test_call_tool_cve():
    mock_data = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                "metrics": {},
            }
        }]
    }
    with _mock_get(mock_data):
        results = await intel.call_tool("cve_lookup", {"query": "CVE-2021-44228"})
    assert results
    assert "CVE-2021-44228" in results[0].text
