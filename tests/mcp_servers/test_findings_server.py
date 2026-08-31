"""Unit tests for findings_server.py's _req/_ensure_index — mocks the raw
requests.request call (not a higher-level wrapper) because the bug this
guards against is specifically in how _req() parses the raw HTTP response.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import mcp_servers.findings_server as findings_mod


def _fake_response(status_code=200, content=b"", json_data=None):
    """A minimal stand-in for requests.Response. content=b"" (the real
    shape of a real HEAD response) makes .json() raise JSONDecodeError if
    _req() ever calls it unconditionally again."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    if status_code >= 400:
        resp.raise_for_status.side_effect = findings_mod.requests.HTTPError(response=resp)
    else:
        resp.raise_for_status.side_effect = None
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        # Real behavior: parsing empty content raises, matching requests'
        # own json.JSONDecodeError on an empty body.
        resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
    return resp


def test_req_head_with_empty_body_does_not_raise():
    """The regression this guards: a HEAD response never carries a body,
    so _req() must not unconditionally call .json() on it."""
    with patch.object(findings_mod.requests, "request", return_value=_fake_response(200, b"")):
        result = findings_mod._req("HEAD", "/odysseus-findings")
    assert result == {}


def test_req_post_with_real_body_still_parses_json():
    body = {"hits": {"total": {"value": 3}}}
    with patch.object(findings_mod.requests, "request", return_value=_fake_response(200, b"{}", json_data=body)):
        result = findings_mod._req("POST", "/odysseus-findings/_search", {"size": 0})
    assert result == body


def test_ensure_index_head_200_does_not_crash():
    """Steady-state case: the index already exists. Before the fix, this
    path raised json.JSONDecodeError uncaught (not a requests.HTTPError,
    so _ensure_index's own except clause never caught it) on every single
    call after the index's first creation."""
    with patch.object(findings_mod.requests, "request", return_value=_fake_response(200, b"")):
        err = findings_mod._ensure_index()
    assert err is None


def test_ensure_index_head_404_creates_index():
    calls = []

    def _fake_request(method, url, **kwargs):
        calls.append(method)
        if method == "HEAD":
            return _fake_response(404, b"")
        return _fake_response(200, b"{}", json_data={"acknowledged": True})

    with patch.object(findings_mod.requests, "request", side_effect=_fake_request):
        err = findings_mod._ensure_index()
    assert err is None
    assert calls == ["HEAD", "PUT"]


def test_ensure_index_head_real_error_is_reported():
    with patch.object(findings_mod.requests, "request", return_value=_fake_response(500, b"")):
        err = findings_mod._ensure_index()
    assert err is not None


@pytest.mark.asyncio
async def test_finding_index_omits_ip_when_not_provided():
    """Regression: `ip` is mapped as OpenSearch type "ip", which rejects
    "" outright. finding_index must omit the field entirely when the
    caller doesn't provide one, not default it to an empty string."""
    captured = {}

    def _fake_req(method, path, body=None):
        captured["doc"] = body
        return {"_id": "1", "result": "created"}

    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", side_effect=_fake_req):
        await findings_mod.call_tool("finding_index", {"title": "t", "severity": "low"})

    assert "ip" not in captured["doc"]


@pytest.mark.asyncio
async def test_finding_index_includes_ip_when_provided():
    captured = {}

    def _fake_req(method, path, body=None):
        captured["doc"] = body
        return {"_id": "1", "result": "created"}

    with patch.object(findings_mod, "_ensure_index", return_value=None), \
         patch.object(findings_mod, "_req", side_effect=_fake_req):
        await findings_mod.call_tool(
            "finding_index", {"title": "t", "severity": "low", "ip": "10.0.0.5"}
        )

    assert captured["doc"]["ip"] == "10.0.0.5"
