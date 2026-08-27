"""Tests for src/host_capabilities.py — the scan-then-verify-then-ask host
tool/service detection used by setup.py's host capability scan."""

import os
import stat
import sys

import pytest

import src.host_capabilities as hc


# ---------------------------------------------------------------------------
# running_in_container()
# ---------------------------------------------------------------------------

def test_running_in_container_true_via_dockerenv(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/.dockerenv")
    assert hc.running_in_container() is True


def test_running_in_container_true_via_cgroup(monkeypatch, tmp_path):
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    cgroup = tmp_path / "cgroup"
    cgroup.write_text("12:pids:/docker/abc123\n")
    real_open = open

    def _fake_open(path, *a, **k):
        return real_open(str(cgroup), *a, **k) if path == "/proc/1/cgroup" else real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _fake_open)
    assert hc.running_in_container() is True


def test_running_in_container_false_natively(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    real_open = open

    def _fake_open(path, *a, **k):
        if path == "/proc/1/cgroup":
            raise OSError("no such file")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _fake_open)
    assert hc.running_in_container() is False


# ---------------------------------------------------------------------------
# check_binary() / scan_toolchain_binaries() — hermetic via a fake PATH
# ---------------------------------------------------------------------------

def _make_fake_binary(tmp_path, name, script_body):
    """Write an executable script named `name` into a fresh PATH dir, return
    that dir. Isolates the test from whatever's actually installed on the
    machine running it."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    script = bindir / name
    script.write_text(script_body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(bindir)


def test_check_binary_found_and_verified(tmp_path, monkeypatch):
    bindir = _make_fake_binary(
        tmp_path, "nmap",
        "#!/bin/sh\necho 'Nmap version 7.94'\n",
    )
    monkeypatch.setenv("PATH", bindir)
    cap = hc.BinaryCapability("nmap", "TOOLCHAIN_EXEC_MODE_NMAP", ("--version",))

    result = hc.check_binary(cap)

    assert result.found is True
    assert result.verified is True
    assert "7.94" in result.detail


def test_check_binary_found_but_silent_on_every_flag(tmp_path, monkeypatch):
    # Exists, executable, but produces no output for any of its flags -- must
    # not be treated as usable (a stale/broken tool is not "verified").
    bindir = _make_fake_binary(tmp_path, "sqlmap", "#!/bin/sh\nexit 0\n")
    monkeypatch.setenv("PATH", bindir)
    cap = hc.BinaryCapability("sqlmap", "TOOLCHAIN_EXEC_MODE_SQLMAP", ("--version",))

    result = hc.check_binary(cap)

    assert result.found is True
    assert result.verified is False


def test_check_binary_not_on_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # empty dir, nothing on PATH
    cap = hc.BinaryCapability("nuclei", "TOOLCHAIN_EXEC_MODE_NUCLEI", ("-version",))

    result = hc.check_binary(cap)

    assert result.found is False
    assert result.verified is False


def test_check_binary_tries_aliases(tmp_path, monkeypatch):
    # theHarvester is invoked with capital H; ALLOWED_BINARIES also lists the
    # lowercase spelling as an alias some installs use.
    bindir = _make_fake_binary(
        tmp_path, "theharvester",
        "#!/bin/sh\necho 'theHarvester 4.0'\n",
    )
    monkeypatch.setenv("PATH", bindir)
    cap = hc.BinaryCapability(
        "theHarvester", "TOOLCHAIN_EXEC_MODE_THEHARVESTER", ("--version",),
        aliases=("theharvester",),
    )

    result = hc.check_binary(cap)

    assert result.found is True
    assert result.found_as == "theharvester"
    assert result.verified is True


def test_check_binary_exhausts_version_flags_in_order(tmp_path, monkeypatch):
    # Only responds to the second flag -- nikto-shaped case (-Version fails,
    # -version works, or vice versa depending on build).
    bindir = _make_fake_binary(
        tmp_path, "nikto",
        "#!/bin/sh\n"
        'if [ "$1" = "-version" ]; then echo "Nikto 2.5.0"; fi\n',
    )
    monkeypatch.setenv("PATH", bindir)
    cap = hc.BinaryCapability("nikto", "TOOLCHAIN_EXEC_MODE_NIKTO", ("-Version", "-version"))

    result = hc.check_binary(cap)

    assert result.verified is True
    assert "2.5.0" in result.detail


def test_scan_toolchain_binaries_covers_every_declared_capability(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # nothing found
    results = hc.scan_toolchain_binaries()
    assert len(results) == len(hc.TOOLCHAIN_BINARIES)
    assert all(not r.found for r in results)


# ---------------------------------------------------------------------------
# Service verify_* functions — string-matching logic against mocked bodies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("verify_fn, good_body, bad_body", [
    (hc._verify_ollama, '{"version":"0.3.1"}', "<html>not ollama</html>"),
    (hc._verify_chromadb, '{"nanosecond heartbeat": 123456}', "<html>nope</html>"),
    (hc._verify_searxng, '{"instance_name": "SearXNG"}', "not json at all"),
    (hc._verify_spiderfoot, "<title>SpiderFoot</title>", "<title>Grafana</title>"),
    (hc._verify_opensearch, '{"tagline": "The OpenSearch Project"}', '{"tagline": "elastic"}'),
])
def test_service_verify_functions_distinguish_real_from_unrelated(monkeypatch, verify_fn, good_body, bad_body):
    monkeypatch.setattr(hc, "_http_get", lambda url, timeout=3.0: good_body)
    ok, detail = verify_fn("localhost", 1234)
    assert ok is True, detail

    monkeypatch.setattr(hc, "_http_get", lambda url, timeout=3.0: bad_body)
    ok, detail = verify_fn("localhost", 1234)
    assert ok is False, detail


def test_verify_functions_handle_no_response(monkeypatch):
    monkeypatch.setattr(hc, "_http_get", lambda url, timeout=3.0: None)
    for fn in (hc._verify_ollama, hc._verify_chromadb, hc._verify_searxng,
               hc._verify_spiderfoot, hc._verify_opensearch):
        ok, detail = fn("localhost", 1234)
        assert ok is False


def test_verify_bentopdf_accepts_any_response_weakest_signal(monkeypatch):
    # BentoPDF has no distinctive API to check against -- documented as the
    # weakest of the six verifications. Any response at all is accepted;
    # None (no response) is not.
    monkeypatch.setattr(hc, "_http_get", lambda url, timeout=3.0: "<html>anything</html>")
    assert hc._verify_bentopdf("localhost", 1234)[0] is True

    monkeypatch.setattr(hc, "_http_get", lambda url, timeout=3.0: None)
    assert hc._verify_bentopdf("localhost", 1234)[0] is False


# ---------------------------------------------------------------------------
# check_service() — host fallback order (localhost, then extra_hosts)
# ---------------------------------------------------------------------------

def test_check_service_finds_on_localhost_first(monkeypatch):
    cap = hc.ServiceCapability(
        "Fake", 9999, ("FAKE_URL",), "fake",
        verify=lambda host, port: (True, f"verified on {host}"),
    )
    monkeypatch.setattr(hc, "_port_open", lambda host, port, timeout=1.5: host == "localhost")

    result = hc.check_service(cap, extra_hosts=("host.docker.internal",))

    assert result.verified is True
    assert result.found_at == "localhost:9999"


def test_check_service_falls_back_to_extra_host(monkeypatch):
    cap = hc.ServiceCapability(
        "Fake", 9999, ("FAKE_URL",), "fake",
        verify=lambda host, port: (True, f"verified on {host}"),
    )
    # Only reachable via the container's host-gateway alias, not localhost --
    # the containerized-setup.py scenario this fork-back exists for.
    monkeypatch.setattr(hc, "_port_open", lambda host, port, timeout=1.5: host == "host.docker.internal")

    result = hc.check_service(cap, extra_hosts=("host.docker.internal",))

    assert result.verified is True
    assert result.found_at == "host.docker.internal:9999"


def test_check_service_not_found_anywhere(monkeypatch):
    cap = hc.ServiceCapability(
        "Fake", 9999, ("FAKE_URL",), "fake",
        verify=lambda host, port: (True, "should never be called"),
    )
    monkeypatch.setattr(hc, "_port_open", lambda host, port, timeout=1.5: False)

    result = hc.check_service(cap)

    assert result.verified is False
    assert result.found_at is None


def test_scan_services_adds_docker_internal_only_when_containerized(monkeypatch):
    seen_hosts = []

    def _fake_port_open(host, port, timeout=1.5):
        seen_hosts.append(host)
        return False

    monkeypatch.setattr(hc, "_port_open", _fake_port_open)

    monkeypatch.setattr(hc, "running_in_container", lambda: False)
    seen_hosts.clear()
    hc.scan_services()
    assert "host.docker.internal" not in seen_hosts

    monkeypatch.setattr(hc, "running_in_container", lambda: True)
    seen_hosts.clear()
    hc.scan_services()
    assert "host.docker.internal" in seen_hosts


# ---------------------------------------------------------------------------
# format_env_suggestion()
# ---------------------------------------------------------------------------

def test_format_env_suggestion_binary():
    cap = hc.BinaryCapability("nmap", "TOOLCHAIN_EXEC_MODE_NMAP", ("--version",))
    check = hc.BinaryCheck(capability=cap, found=True, verified=True)
    assert hc.format_env_suggestion(check) == "TOOLCHAIN_EXEC_MODE_NMAP=local"


def test_format_env_suggestion_service_single_url_var():
    cap = hc.ServiceCapability("Ollama", 11434, ("OLLAMA_BASE_URL",), "ollama", verify=None)
    check = hc.ServiceCheck(capability=cap, found_at="localhost:11434", verified=True)
    assert hc.format_env_suggestion(check) == "OLLAMA_BASE_URL=http://localhost:11434"


def test_format_env_suggestion_service_host_and_port_vars():
    cap = hc.ServiceCapability("ChromaDB", 8000, ("CHROMADB_HOST", "CHROMADB_PORT"), "chromadb", verify=None)
    check = hc.ServiceCheck(capability=cap, found_at="localhost:8000", verified=True)
    lines = hc.format_env_suggestion(check).splitlines()
    assert "CHROMADB_HOST=localhost" in lines
    assert "CHROMADB_PORT=8000" in lines


def test_format_env_suggestion_rejects_unknown_type():
    with pytest.raises(TypeError):
        hc.format_env_suggestion(object())


# ---------------------------------------------------------------------------
# ScanResult properties
# ---------------------------------------------------------------------------

def test_scan_result_reusable_properties():
    cap_b = hc.BinaryCapability("nmap", "TOOLCHAIN_EXEC_MODE_NMAP", ("--version",))
    cap_s = hc.ServiceCapability("Ollama", 11434, ("OLLAMA_BASE_URL",), "ollama", verify=None)

    result = hc.ScanResult(
        in_container=False,
        binaries=[
            hc.BinaryCheck(capability=cap_b, found=True, verified=True),
            hc.BinaryCheck(capability=cap_b, found=False, verified=False),
        ],
        services=[
            hc.ServiceCheck(capability=cap_s, verified=False),
        ],
    )

    assert len(result.reusable_binaries) == 1
    assert result.reusable_services == []
    assert result.has_anything_reusable is True

    empty = hc.ScanResult(in_container=False)
    assert empty.has_anything_reusable is False


def test_isolation_tradeoff_warning_mentions_isolation():
    assert "isolation" in hc.isolation_tradeoff_warning().lower()
