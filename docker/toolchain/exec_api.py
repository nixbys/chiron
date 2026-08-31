#!/usr/bin/env python3
"""
Minimal HTTP exec API for the odysseus-toolchain sidecar.

POST /exec  { "args": ["nmap", "-sV", "target"], "timeout": 300 }
  → { "returncode": 0, "stdout": "...", "stderr": "..." }

Listens on 0.0.0.0:8088. Accessible only on the internal compose network —
the port is never published to the host.

Security:
  Set EXEC_API_TOKEN in environment to require Bearer auth on every request.
  All invocations are logged as JSON lines to EXEC_LOG_FILE (default
  /var/log/exec_api.jsonl) — mountable as a shared volume for audit purposes.
  args[0] (the binary) is checked against ALLOWED_BINARIES below — only the
  tools this image actually installs (see docker/toolchain/Dockerfile) may
  be invoked. The MCP servers that call this API always choose args[0]
  themselves (mcp_servers/common.py); an agent/user only ever influences the
  trailing arguments, never which program runs. The allowlist makes that
  assumption a hard server-side boundary instead of an implicit one.
"""
import json
import logging
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_TOKEN = os.environ.get("EXEC_API_TOKEN", "")

# Keep in sync with the tools installed by docker/toolchain/Dockerfile.
ALLOWED_BINARIES = frozenset({
    # Network recon
    "nmap", "masscan", "nc", "nc.traditional", "dig", "whois", "curl", "wget",
    # Web assessment / fuzzing
    "nikto", "gobuster", "sqlmap", "ffuf",
    # OSINT
    "theharvester", "theHarvester", "recon-ng", "sherlock",
    # Password / hash
    "john", "hydra", "hashid",
    # Exploitation
    "searchsploit", "msfconsole", "msfvenom",
    # Forensics & analysis
    "binwalk", "exiftool", "yara",
    # Go-based recon suite
    "nuclei", "httpx", "subfinder", "amass",
    # Misc utilities the sidecar exposes
    "trivy", "jq", "git", "unzip", "7z", "gitleaks",
    # Base coreutils/grep the MCP servers shell out to directly (yara_server's
    # rule-file writes/reads/listing, exploit_server's local Metasploit
    # module grep, osint_server's secrets_scan clearing its own fixed
    # scratch checkout dir before each clone) — always present on the base
    # image, not separately apt-installed. No general-purpose shell (sh/
    # bash) is ever allowed here — MCP servers must call one of these
    # directly, not chain commands.
    "ls", "mkdir", "tee", "grep", "cat", "rm",
})

_log_path = Path(os.environ.get("EXEC_LOG_FILE", "/var/log/exec_api.jsonl"))
_log_path.parent.mkdir(parents=True, exist_ok=True)

_logger = logging.getLogger("exec_api")
_handler = logging.FileHandler(str(_log_path))
_handler.setFormatter(logging.Formatter("%(message)s"))
_logger.addHandler(_handler)
_logger.setLevel(logging.INFO)


def _log(record: dict) -> None:
    _logger.info(json.dumps(record, default=str))


class ExecHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # HTTP noise suppressed; we emit structured JSON logs instead

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not _TOKEN:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {_TOKEN}"

    def do_POST(self):
        if self.path != "/exec":
            self.send_error(404)
            return

        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        args = body.get("args", [])
        timeout = int(body.get("timeout", 120))
        stdin_data = body.get("stdin")

        binary = Path(args[0]).name if args else ""
        if binary not in ALLOWED_BINARIES:
            _log({"ts": time.time(), "cmd": [binary], "exit": -1,
                  "error": "binary_not_allowed"})
            self._send_json(400, {
                "error": "binary_not_allowed",
                "detail": f"{binary!r} is not in ALLOWED_BINARIES",
            })
            return

        t0 = time.time()
        try:
            r = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_data,
            )
            out = {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
            _log({
                "ts": t0, "cmd": args[:1], "args_count": len(args),
                "exit": r.returncode, "duration": round(time.time() - t0, 2),
            })
        except subprocess.TimeoutExpired:
            out = {"returncode": -1, "stdout": "", "stderr": f"[timeout after {timeout}s]"}
            _log({"ts": t0, "cmd": args[:1], "exit": -1, "error": "timeout", "duration": timeout})
        except Exception as e:  # noqa: BLE001
            out = {"returncode": -1, "stdout": "", "stderr": str(e)}
            _log({"ts": t0, "cmd": args[:1], "exit": -1, "error": str(e),
                  "duration": round(time.time() - t0, 2)})

        self._send_json(200, out)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        else:
            self.send_error(404)


if __name__ == "__main__":
    mode = "authenticated" if _TOKEN else "unauthenticated"
    print(f"toolchain exec API listening on :8088 ({mode})", flush=True)
    HTTPServer(("0.0.0.0", 8088), ExecHandler).serve_forever()
