"""Unit tests for spiderfoot_server.py — mock all outbound HTTP to SpiderFoot."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import mcp_servers.spiderfoot_server as sf


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(json_data=None, text="", status_code=200):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"content-type": "application/json"}
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


def _patch_get(return_value):
    return patch("mcp_servers.spiderfoot_server.requests.get", return_value=_mock_response(json_data=return_value))


def _patch_post(return_value=None, text="abc123"):
    resp = _mock_response(json_data=return_value, text=text)
    if return_value is None:
        resp.headers = {"content-type": "text/plain"}
        resp.json.side_effect = ValueError("not json")
    return patch("mcp_servers.spiderfoot_server.requests.post", return_value=resp)


# ---------------------------------------------------------------------------
# _start_scan
# ---------------------------------------------------------------------------

def test_start_scan_plain_text_id():
    """SpiderFoot returns the scan ID as a plain text string on some versions."""
    with _patch_post(return_value=None, text="SCAN-ID-XYZ\n"):
        result = sf._start_scan("example.com", "test", "passive")
    assert result == {"scan_id": "SCAN-ID-XYZ"}


def test_start_scan_json_id():
    """Some SpiderFoot builds return {"id": "..."}."""
    with patch("mcp_servers.spiderfoot_server.requests.post",
               return_value=_mock_response(json_data={"id": "SCAN-JSON-001"})):
        result = sf._start_scan("10.0.0.1", "test", "passive")
    assert result["scan_id"] == "SCAN-JSON-001"


def test_start_scan_connection_error():
    with patch("mcp_servers.spiderfoot_server.requests.post", side_effect=requests.ConnectionError()):
        result = sf._start_scan("example.com", "test", "passive")
    assert "error" in result
    assert "odysseus-spiderfoot" in result["error"]


def test_start_scan_falls_back_to_scanlist_lookup_when_response_is_html():
    """Regression: SpiderFoot v2.12's /startscan renders the scan-list HTML
    page directly as its response body on success (confirmed live) --
    carries no scan ID at all. _start_scan must fall back to looking the
    new scan up by name via /scanlist rather than returning the raw HTML
    as if it were the ID."""
    html_resp = _mock_response(text="<!DOCTYPE html><html>...</html>")
    html_resp.headers = {"content-type": "text/html;charset=utf-8"}
    html_resp.json.side_effect = ValueError("not json")
    scanlist_rows = [
        ["NEWEST01", "quick: example.com", "example.com", "t", "t", "t", "FINISHED", 3],
        ["OLDER02", "some other scan", "example.com", "t", "t", "t", "FINISHED", 1],
    ]
    with patch("mcp_servers.spiderfoot_server.requests.post", return_value=html_resp), \
         patch("mcp_servers.spiderfoot_server.requests.get",
               return_value=_mock_response(json_data=scanlist_rows)):
        result = sf._start_scan("example.com", "quick: example.com", "passive")
    assert result == {"scan_id": "NEWEST01"}


def test_start_scan_html_response_and_no_scanlist_match_is_reported_as_error():
    html_resp = _mock_response(text="<!DOCTYPE html><html>...</html>")
    html_resp.headers = {"content-type": "text/html;charset=utf-8"}
    html_resp.json.side_effect = ValueError("not json")
    with patch("mcp_servers.spiderfoot_server.requests.post", return_value=html_resp), \
         patch("mcp_servers.spiderfoot_server.requests.get", return_value=_mock_response(json_data=[])):
        result = sf._start_scan("example.com", "quick: example.com", "passive")
    assert "error" in result


def test_start_scan_posts_typelist_and_modulelist():
    """Regression: SpiderFoot's /startscan 404s with "Missing parameters:
    typelist,modulelist" unless both are present in the POST body, even
    when empty -- usecase alone is not enough."""
    with _patch_post(return_value=None, text="SCAN-ID-XYZ\n") as mock_post:
        sf._start_scan("example.com", "test", "passive")
    posted = mock_post.call_args.kwargs["data"]
    assert posted["typelist"] == ""
    assert posted["modulelist"] == ""
    assert posted["usecase"] == "passive"


# ---------------------------------------------------------------------------
# _get_status
# ---------------------------------------------------------------------------

def test_get_status_flat_row_format():
    """/scanstatus/<id> returns ONE flat row directly (confirmed live):
    [name, target, created, started, ended, status] -- NOT a list of rows
    like /scanlist. Regression: treating it as a list-of-rows picked off
    the scan's *name string* as the "row" and indexed into its
    characters, so status could never equal "FINISHED" and polling in
    _wait_for_scan never terminated."""
    row = ["my scan", "example.com", "2026-06-20", "2026-06-20", "", "RUNNING"]
    with _patch_get(row):
        status = sf._get_status("SCAN-001")
    assert status["status"] == "RUNNING"
    assert status["scan_id"] == "SCAN-001"
    assert status["name"] == "my scan"
    assert status["target"] == "example.com"


def test_get_status_unknown_on_empty():
    with _patch_get([]):
        status = sf._get_status("SCAN-002")
    assert status.get("status") == "UNKNOWN"


def test_wait_for_scan_terminates_on_finished_status():
    """End-to-end regression for the _get_status flat-row bug: a scan that
    is already FINISHED on the very first poll must return immediately,
    not loop until timeout."""
    row = ["my scan", "example.com", "2026-06-20", "2026-06-20", "2026-06-20", "FINISHED"]
    with _patch_get(row), patch("mcp_servers.spiderfoot_server.time.sleep") as mock_sleep:
        status = sf._wait_for_scan("SCAN-001", timeout=30)
    assert status["status"] == "FINISHED"
    mock_sleep.assert_not_called()


# ---------------------------------------------------------------------------
# _get_results
# ---------------------------------------------------------------------------

def test_get_results_parses_rows():
    # Real shape (confirmed against SpiderFoot's own sfwebui.py and live):
    # [lastseen, data, source, module, confidence, visibility, risk, hash, ?, ?, type]
    rows = [
        ["2026-06-20", "admin@example.com", "example.com", "sfp_hunter", 100, 5, 0, "hash1", 0, 0, "EMAILADDR"],
        ["2026-06-20", "93.184.216.34", "example.com", "sfp_dns", 100, 5, 0, "hash2", 0, 0, "IP_ADDRESS"],
    ]
    with _patch_get(rows):
        results = sf._get_results("SCAN-001")
    assert len(results) == 2
    assert results[0]["type"] == "EMAILADDR"
    assert results[0]["module"] == "sfp_hunter"
    assert results[0]["source"] == "example.com"
    assert results[0]["data"] == "admin@example.com"
    assert results[1]["type"] == "IP_ADDRESS"


def test_get_results_limit():
    rows = [
        ["2026-06-20", f"sub{i}.example.com", "example.com", "sfp_dns", 100, 5, 0, "h", 0, 0, "DOMAIN_NAME"]
        for i in range(50)
    ]
    with _patch_get(rows):
        results = sf._get_results("SCAN-001", limit=10)
    assert len(results) == 10


def test_get_results_uses_id_and_eventtype_query_params():
    """Regression: /scaneventresults takes id/eventType as query params,
    not path segments -- the old `/scaneventresults/{scan_id}` path
    404'd every time."""
    with _patch_get([]) as mock_get:
        sf._get_results("SCAN-001", event_type="EMAILADDR")
    assert mock_get.call_args.kwargs["params"] == {"id": "SCAN-001", "eventType": "EMAILADDR"}


def test_get_results_defaults_eventtype_to_all():
    with _patch_get([]) as mock_get:
        sf._get_results("SCAN-001")
    assert mock_get.call_args.kwargs["params"] == {"id": "SCAN-001", "eventType": "ALL"}


def test_get_results_empty():
    with _patch_get([]):
        results = sf._get_results("SCAN-001")
    assert results == []


# ---------------------------------------------------------------------------
# _format_results
# ---------------------------------------------------------------------------

def test_format_results_groups_by_type():
    results = [
        {"type": "EMAILADDR", "module": "sfp_hunter", "source": "", "data": "a@example.com"},
        {"type": "EMAILADDR", "module": "sfp_hunter", "source": "", "data": "b@example.com"},
        {"type": "IP_ADDRESS", "module": "sfp_dns", "source": "", "data": "1.2.3.4"},
    ]
    text = sf._format_results(results)
    assert "EMAILADDR" in text
    assert "IP_ADDRESS" in text
    assert "a@example.com" in text
    assert "Total findings: 3" in text


def test_format_results_empty():
    assert sf._format_results([]) == "No results found."


# ---------------------------------------------------------------------------
# _list_scans
# ---------------------------------------------------------------------------

def test_list_scans():
    rows = [
        ["SCAN-001", "test", "example.com", "2026-06-20", "2026-06-20", "FINISHED", 150],
        ["SCAN-002", "recon", "10.0.0.1", "2026-06-20", "", "RUNNING", 0],
    ]
    with _patch_get(rows):
        scans = sf._list_scans()
    assert len(scans) == 2
    assert scans[0]["status"] == "FINISHED"
    assert scans[1]["status"] == "RUNNING"


# ---------------------------------------------------------------------------
# call_tool (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_tool_sf_list_scans_empty():
    with _patch_get([]):
        results = await sf.call_tool("sf_list_scans", {})
    assert results[0].text == "No scans found."


@pytest.mark.asyncio
async def test_call_tool_sf_scan_start_returns_id():
    with _patch_post(return_value=None, text="SCAN-XYZ"):
        results = await sf.call_tool("sf_scan_start", {"target": "example.com", "usecase": "passive"})
    text = results[0].text
    assert "SCAN-XYZ" in text
    assert "sf_scan_status" in text


@pytest.mark.asyncio
async def test_call_tool_unknown():
    results = await sf.call_tool("does_not_exist", {})
    assert "Unknown tool" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_sf_scan_status():
    row = ["SCAN-001", "test", "example.com", "2026-06-20", "2026-06-20", "FINISHED", 99]
    with _patch_get([row]):
        results = await sf.call_tool("sf_scan_status", {"scan_id": "SCAN-001"})
    assert "FINISHED" in results[0].text
    assert "example.com" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_sf_scan_results():
    rows = [
        ["2026-06-20", "ceo@example.com", "example.com", "sfp_hunter", 100, 5, 0, "h1", 0, 0, "EMAILADDR"],
    ]
    with _patch_get(rows):
        results = await sf.call_tool("sf_scan_results", {"scan_id": "SCAN-001"})
    assert "EMAILADDR" in results[0].text
    assert "ceo@example.com" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_connection_error_propagates():
    with patch("mcp_servers.spiderfoot_server.requests.post", side_effect=requests.ConnectionError()):
        results = await sf.call_tool("sf_scan_start", {"target": "example.com"})
    assert "error" in results[0].text.lower()
