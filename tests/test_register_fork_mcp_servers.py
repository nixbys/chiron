"""Unit tests for scripts/register_fork_mcp_servers.py's pure logic --
_existing_script_paths' parsing (no live server needed) and the LABELS/
FORK_SECURITY_SERVERS consistency the module docstring promises."""

from unittest.mock import MagicMock

from scripts.mcp_health_check import FORK_SECURITY_SERVERS
from scripts.register_fork_mcp_servers import LABELS, _existing_script_paths


def _fake_session(servers_json):
    session = MagicMock()
    resp = MagicMock()
    resp.json.return_value = servers_json
    resp.raise_for_status.return_value = None
    session.get.return_value = resp
    return session


def test_existing_script_paths_extracts_script_names():
    servers = [
        {"args": ["/app/mcp_servers/recon_server.py"]},
        {"args": ["/app/mcp_servers/intel_server.py"]},
    ]
    paths = _existing_script_paths(_fake_session(servers), "http://x")
    assert paths == {"recon_server.py", "intel_server.py"}


def test_existing_script_paths_ignores_non_fork_servers():
    """A user's own remote/SSE MCP server, or a stdio server pointed at a
    script outside mcp_servers/, must never register as "already present"
    for one of this fork's own servers it has nothing to do with."""
    servers = [
        {"args": ["/app/mcp_servers/recon_server.py"]},
        {"args": []},
        {"url": "https://example.com/mcp", "args": None},
        {"args": ["/some/other/path/not_a_fork_server.py"]},
    ]
    paths = _existing_script_paths(_fake_session(servers), "http://x")
    assert paths == {"recon_server.py"}


def test_existing_script_paths_empty_when_nothing_registered():
    assert _existing_script_paths(_fake_session([]), "http://x") == set()


def test_every_fork_security_server_has_a_label():
    """LABELS is keyed by the same names FORK_SECURITY_SERVERS lists -- a
    server present in one but missing from the other means either a label
    typo or a forgotten registration, both silent otherwise."""
    missing = set(FORK_SECURITY_SERVERS) - set(LABELS)
    assert not missing, f"no LABELS entry for: {missing}"


def test_no_stale_labels_for_removed_servers():
    extra = set(LABELS) - set(FORK_SECURITY_SERVERS)
    assert not extra, f"LABELS has entries not in FORK_SECURITY_SERVERS: {extra}"


def test_labels_are_unique():
    """Two servers sharing a display name would be indistinguishable in
    Settings -> Integrations -> MCP."""
    values = list(LABELS.values())
    assert len(values) == len(set(values))
