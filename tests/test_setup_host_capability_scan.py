"""Tests for setup.py's host_capability_scan() step — the interactive
scan-then-verify-then-ask flow wired around src/host_capabilities.py."""

import importlib.util
from pathlib import Path

import pytest


def _load_setup_module():
    spec = importlib.util.spec_from_file_location("odysseus_setup_under_test_hcs", Path("setup.py"))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _fake_result(binaries=(), services=(), in_container=False):
    import src.host_capabilities as hc
    return hc.ScanResult(in_container=in_container, binaries=list(binaries), services=list(services))


def _binary_check(name="nmap", env_var="TOOLCHAIN_EXEC_MODE_NMAP", verified=True, detail="Nmap 7.94"):
    import src.host_capabilities as hc
    cap = hc.BinaryCapability(name, env_var, ("--version",))
    return hc.BinaryCheck(capability=cap, found=True, verified=verified, path=f"/usr/bin/{name}", detail=detail)


def _service_check(name="Ollama", env_vars=("OLLAMA_BASE_URL",), profile="ollama", found_at="localhost:11434", verified=True):
    import src.host_capabilities as hc
    cap = hc.ServiceCapability(name, 11434, env_vars, profile, verify=None)
    return hc.ServiceCheck(capability=cap, found_at=found_at, verified=verified, detail="verified")


def test_nothing_found_prints_ok_and_writes_nothing(tmp_path, monkeypatch, capsys):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "BASE_DIR", str(tmp_path))
    (tmp_path / ".env").write_text("EXISTING=1\n")

    import src.host_capabilities as hc
    monkeypatch.setattr(hc, "run_scan", lambda: _fake_result())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    setup_module.host_capability_scan()

    assert "nothing already on this host" in capsys.readouterr().out.lower()
    assert (tmp_path / ".env").read_text() == "EXISTING=1\n"


def test_interactive_accept_writes_env_and_logs(tmp_path, monkeypatch, capsys):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "BASE_DIR", str(tmp_path))
    (tmp_path / ".env").write_text("EXISTING=1\n")

    import src.host_capabilities as hc
    result = _fake_result(binaries=[_binary_check()])
    monkeypatch.setattr(hc, "run_scan", lambda: result)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    setup_module.host_capability_scan()

    env_text = (tmp_path / ".env").read_text()
    assert "TOOLCHAIN_EXEC_MODE_NMAP=local" in env_text
    assert "EXISTING=1" in env_text  # original content preserved

    out = capsys.readouterr().out
    assert "isolation" in out.lower()  # trade-off warning shown

    log_path = tmp_path / "logs" / "host_capability_scan.log"
    assert log_path.exists()
    log_text = log_path.read_text()
    assert "accepted=true" in log_text


def test_interactive_decline_writes_nothing(tmp_path, monkeypatch, capsys):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "BASE_DIR", str(tmp_path))
    (tmp_path / ".env").write_text("EXISTING=1\n")

    import src.host_capabilities as hc
    result = _fake_result(binaries=[_binary_check()])
    monkeypatch.setattr(hc, "run_scan", lambda: result)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    setup_module.host_capability_scan()

    assert (tmp_path / ".env").read_text() == "EXISTING=1\n"
    log_text = (tmp_path / "logs" / "host_capability_scan.log").read_text()
    assert "accepted=false" in log_text
    assert "accepted=true" not in log_text


def test_non_interactive_never_prompts_or_writes(tmp_path, monkeypatch, capsys):
    """ODYSSEUS_SKIP_HOST_SCAN or a non-tty stdin (Docker entrypoint, CI) must
    report findings without ever blocking on input or silently accepting a
    reuse suggestion — a default of "no reuse" is always the safe one when
    nobody is present to answer."""
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "BASE_DIR", str(tmp_path))
    (tmp_path / ".env").write_text("EXISTING=1\n")

    import src.host_capabilities as hc
    result = _fake_result(binaries=[_binary_check()], services=[_service_check()])
    monkeypatch.setattr(hc, "run_scan", lambda: result)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    def _fail_if_called(prompt):
        raise AssertionError("must not prompt when non-interactive")
    monkeypatch.setattr("builtins.input", _fail_if_called)

    setup_module.host_capability_scan()

    assert (tmp_path / ".env").read_text() == "EXISTING=1\n"
    out = capsys.readouterr().out
    assert "not interactive" in out.lower()


def test_already_configured_binary_is_skipped_without_prompting(tmp_path, monkeypatch, capsys):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "BASE_DIR", str(tmp_path))
    (tmp_path / ".env").write_text("TOOLCHAIN_EXEC_MODE_NMAP=local\n")

    import src.host_capabilities as hc
    result = _fake_result(binaries=[_binary_check()])
    monkeypatch.setattr(hc, "run_scan", lambda: result)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def _fail_if_called(prompt):
        raise AssertionError("must not re-prompt for an already-configured var")
    monkeypatch.setattr("builtins.input", _fail_if_called)

    setup_module.host_capability_scan()

    # .env content unchanged -- no duplicate line appended.
    assert (tmp_path / ".env").read_text() == "TOOLCHAIN_EXEC_MODE_NMAP=local\n"


def test_service_accept_prints_compose_profile_guidance(tmp_path, monkeypatch, capsys):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "BASE_DIR", str(tmp_path))
    (tmp_path / ".env").write_text("")

    import src.host_capabilities as hc
    result = _fake_result(services=[_service_check(profile="ollama")])
    monkeypatch.setattr(hc, "run_scan", lambda: result)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    setup_module.host_capability_scan()

    out = capsys.readouterr().out
    assert "OLLAMA_BASE_URL=http://localhost:11434" in (tmp_path / ".env").read_text()
    assert "ollama" in out  # compose-profile-to-omit guidance mentions it


def test_in_container_prints_binary_scan_skip_notice(tmp_path, monkeypatch, capsys):
    setup_module = _load_setup_module()
    monkeypatch.setattr(setup_module, "BASE_DIR", str(tmp_path))
    (tmp_path / ".env").write_text("")

    import src.host_capabilities as hc
    result = _fake_result(services=[_service_check()], in_container=True)
    monkeypatch.setattr(hc, "run_scan", lambda: result)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    setup_module.host_capability_scan()

    out = capsys.readouterr().out
    assert "container" in out.lower()
    assert "host.docker.internal" in out
