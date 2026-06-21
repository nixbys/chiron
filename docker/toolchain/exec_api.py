#!/usr/bin/env python3
"""
Minimal HTTP exec API for the odysseus-toolchain sidecar.

POST /exec  { "args": ["nmap", "-sV", "target"], "timeout": 300 }
  → { "returncode": 0, "stdout": "...", "stderr": "..." }

Listens on 0.0.0.0:8088. Accessible only on the internal compose network —
the port is never published to the host.
"""
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


class ExecHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # keep logs quiet; errors are returned in JSON

    def do_POST(self):
        if self.path != "/exec":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        args = body.get("args", [])
        timeout = int(body.get("timeout", 120))
        stdin_data = body.get("stdin")

        try:
            r = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_data,
            )
            out = {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
        except subprocess.TimeoutExpired:
            out = {"returncode": -1, "stdout": "", "stderr": f"[timeout after {timeout}s]"}
        except Exception as e:  # noqa: BLE001
            out = {"returncode": -1, "stdout": "", "stderr": str(e)}

        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print("toolchain exec API listening on :8088", flush=True)
    HTTPServer(("0.0.0.0", 8088), ExecHandler).serve_forever()
