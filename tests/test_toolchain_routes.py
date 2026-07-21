"""Tests for GET /api/toolchain/exec-modes (routes/toolchain_routes.py)."""

from fastapi import Request

import routes.toolchain_routes as toolchain_routes
from routes.toolchain_routes import setup_toolchain_routes


def _get_handler():
    router = setup_toolchain_routes()
    route = next(r for r in router.routes if r.path == "/api/toolchain/exec-modes")
    return route.endpoint


def test_exec_modes_defaults_all_container(monkeypatch):
    monkeypatch.setattr(toolchain_routes, "require_admin", lambda r: None)
    monkeypatch.setattr("mcp_servers.common._EXEC_MODE_DEFAULT", "container")
    for binary in toolchain_routes._KNOWN_BINARIES:
        monkeypatch.delenv(f"TOOLCHAIN_EXEC_MODE_{binary.upper()}", raising=False)

    handler = _get_handler()
    result = handler(request=Request(scope={"type": "http"}))

    assert len(result["binaries"]) == len(toolchain_routes._KNOWN_BINARIES)
    assert all(entry["mode"] == "container" for entry in result["binaries"])
    assert all("installed" not in entry for entry in result["binaries"])


def test_exec_modes_reports_local_and_installed_status(monkeypatch):
    monkeypatch.setattr(toolchain_routes, "require_admin", lambda r: None)
    monkeypatch.setattr("mcp_servers.common._EXEC_MODE_DEFAULT", "container")
    monkeypatch.setenv("TOOLCHAIN_EXEC_MODE_NMAP", "local")
    monkeypatch.setattr(
        toolchain_routes.shutil, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None
    )

    handler = _get_handler()
    result = handler(request=Request(scope={"type": "http"}))

    by_binary = {entry["binary"]: entry for entry in result["binaries"]}
    assert by_binary["nmap"]["mode"] == "local"
    assert by_binary["nmap"]["installed"] is True
    assert by_binary["nmap"]["path"] == "/usr/bin/nmap"
    assert by_binary["gobuster"]["mode"] == "container"
