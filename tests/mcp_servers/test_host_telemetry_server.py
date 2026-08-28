"""Unit tests for host_telemetry_server.py -- mocks psutil and subprocess,
never touches the real host."""

import sys
from collections import namedtuple
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import mcp_servers.host_telemetry_server as hts


class _FakeProc:
    def __init__(self, info):
        self.info = info


@pytest.mark.asyncio
async def test_host_processes_lists_and_formats():
    procs = [
        _FakeProc({"pid": 1, "name": "systemd", "username": "root", "cmdline": ["/sbin/init"]}),
        _FakeProc({"pid": 42, "name": "sshd", "username": "root", "cmdline": ["/usr/sbin/sshd", "-D"]}),
    ]
    with patch.object(hts.psutil, "process_iter", return_value=procs):
        results = await hts.call_tool("host_processes", {})
    text = results[0].text
    assert "sshd" in text
    assert "systemd" in text
    assert "[error:" not in text


@pytest.mark.asyncio
async def test_host_processes_limit_applied():
    # pids start at 1, not 0 -- _processes_format's `p['pid'] or ''` (same
    # falsy-default idiom used elsewhere in this codebase, e.g.
    # monitor_server's row formatting) would blank out a pid of 0.
    procs = [_FakeProc({"pid": i, "name": f"proc{i}", "username": "root", "cmdline": [f"proc{i}"]}) for i in range(1, 6)]
    with patch.object(hts.psutil, "process_iter", return_value=procs):
        results = await hts.call_tool("host_processes", {"limit": 2})
    data_rows = [ln for ln in results[0].text.splitlines() if ln.strip().startswith(("1", "2", "3", "4", "5"))]
    assert len(data_rows) == 2


@pytest.mark.asyncio
async def test_host_listening_ports_filters_to_listen_state():
    Addr = namedtuple("Addr", ["ip", "port"])
    Conn = namedtuple("Conn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
    conns = [
        Conn(1, 2, 1, Addr("0.0.0.0", 22), None, "LISTEN", 100),
        Conn(2, 2, 1, Addr("127.0.0.1", 5000), Addr("127.0.0.1", 6000), "ESTABLISHED", 200),
    ]
    with patch.object(hts.psutil, "net_connections", return_value=conns), \
         patch.object(hts.psutil, "CONN_LISTEN", "LISTEN"):
        results = await hts.call_tool("host_listening_ports", {})
    text = results[0].text
    assert "22" in text
    assert "5000" not in text


@pytest.mark.asyncio
async def test_host_listening_ports_access_denied_reports_error_not_crash():
    with patch.object(hts.psutil, "net_connections", side_effect=hts.psutil.AccessDenied()):
        results = await hts.call_tool("host_listening_ports", {})
    assert "[error:" in results[0].text


@pytest.mark.asyncio
async def test_host_users_lists_logged_in_users():
    User = namedtuple("User", ["name", "terminal", "host", "started", "pid"])
    with patch.object(hts.psutil, "users", return_value=[User("alice", "pts/0", "10.0.0.1", 1700000000.0, 123)]):
        results = await hts.call_tool("host_users", {})
    assert "alice" in results[0].text


@pytest.mark.asyncio
async def test_host_cron_jobs_unsupported_on_non_linux():
    with patch.object(hts, "_IS_LINUX", False):
        results = await hts.call_tool("host_cron_jobs", {})
    assert "[error:unsupported_platform]" in results[0].text


@pytest.mark.asyncio
async def test_host_cron_jobs_reads_crontab():
    fake_result = MagicMock(returncode=0, stdout="0 3 * * * /usr/bin/backup.sh\n")
    with patch.object(hts, "_IS_LINUX", True), \
         patch.object(hts.subprocess, "run", return_value=fake_result), \
         patch.object(hts.Path, "is_file", return_value=False), \
         patch.object(hts.Path, "is_dir", return_value=False):
        results = await hts.call_tool("host_cron_jobs", {})
    assert "backup.sh" in results[0].text


@pytest.mark.asyncio
async def test_host_packages_unsupported_on_non_linux():
    with patch.object(hts, "_IS_LINUX", False):
        results = await hts.call_tool("host_packages", {})
    assert "[error:unsupported_platform]" in results[0].text


@pytest.mark.asyncio
async def test_host_packages_reads_dpkg():
    fake_result = MagicMock(returncode=0, stdout="curl\t7.88.1-1\nbash\t5.2.15-2\n")
    with patch.object(hts, "_IS_LINUX", True), \
         patch.object(hts.subprocess, "run", return_value=fake_result):
        results = await hts.call_tool("host_packages", {})
    text = results[0].text
    assert "curl" in text
    assert "bash" in text


@pytest.mark.asyncio
async def test_host_packages_no_package_manager_reports_error_not_crash():
    with patch.object(hts, "_IS_LINUX", True), \
         patch.object(hts.subprocess, "run", side_effect=FileNotFoundError()):
        results = await hts.call_tool("host_packages", {})
    assert "[error:not_found]" in results[0].text


@pytest.mark.asyncio
async def test_unknown_tool_reports_error_not_crash():
    results = await hts.call_tool("not_a_real_tool", {})
    assert "[error:unknown_tool]" in results[0].text


@pytest.mark.asyncio
async def test_fetch_exception_reports_error_not_crash():
    with patch.object(hts.psutil, "process_iter", side_effect=RuntimeError("boom")):
        results = await hts.call_tool("host_processes", {})
    assert "[error:" in results[0].text
    assert "boom" in results[0].text


def test_subprocess_calls_never_use_shell():
    # host_telemetry_server must never shell out with untrusted formatting --
    # regression guard for the cron/packages subprocess calls.
    import inspect
    src = inspect.getsource(hts)
    assert "shell=True" not in src
