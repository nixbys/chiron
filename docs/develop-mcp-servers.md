# Developing MCP Servers for Chiron

This guide explains how to add a new MCP server to the Chiron security toolchain.

## Architecture overview

```
Odysseus agent (main container)
  └─ MCP server (Python, stdio transport)
       └─ exec_in_toolchain() ──HTTP POST──▶ Kali sidecar exec API (:8088)
                                                  └─ subprocess (nmap, nuclei, ...)
```

MCP servers run inside the Odysseus container as Python processes communicating over stdio. When a tool needs to run a Kali binary, it calls `exec_in_toolchain()` from `mcp_servers/common.py` instead of running subprocesses directly. This keeps security tool execution isolated in the hardened Kali container.

---

## Minimal template

```python
"""
my_server.py — MCP server for <purpose>
"""

import asyncio
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import exec_in_toolchain, mcp_error, validate_ip

server = Server("my_server")

TOOLS = [
    Tool(
        name="my_tool",
        description="One clear sentence describing what this does and what it returns.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname to scan"},
            },
            "required": ["target"],
        },
    ),
]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "my_tool":
        target = arguments["target"]

        # Always validate external inputs at the boundary
        validated = validate_ip(target)
        if validated is None:
            return [TextContent(type="text", text=mcp_error("invalid_input", f"Not a valid IP: {target}"))]

        # Run the binary in the Kali sidecar
        result = exec_in_toolchain(["mytool", "--flag", validated], timeout=120)
    else:
        result = mcp_error("unknown_tool", name)

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Shared utilities (`mcp_servers/common.py`)

Import these instead of reimplementing them:

| Function | Purpose |
|---|---|
| `exec_in_toolchain(cmd, timeout, stdin)` | POST to the Kali exec API; returns combined stdout+stderr or an `[error:...]` string |
| `mcp_error(code, message)` | Returns a standardized `[error:code] message` string |
| `validate_ip(value)` | Validates an IPv4/IPv6 address or CIDR. Returns the input on success, `None` on failure |
| `validate_url(url)` | Validates an http/https URL. Returns the input on success, `None` on failure |
| `validate_domain(domain)` | Validates a hostname. Returns the input on success, `None` on failure |

---

## Error format

All tools must return errors in this exact format so the agent can detect and handle them:

```
[error:code] Human-readable message
```

Use `mcp_error(code, message)` from `common.py`. Never raise exceptions out of `call_tool()` — catch them and return an error string.

Common codes:

| Code | Meaning |
|---|---|
| `invalid_input` | Input validation failed |
| `not_found` | Resource/record doesn't exist |
| `toolchain_error` | exec API unreachable or binary failed |
| `auth_error` | Missing or invalid credentials |
| `timeout` | Tool execution exceeded timeout |
| `unknown_tool` | Tool name not recognized |

---

## Input validation rules

**Always validate at the boundary — never pass raw user input to subprocess args.**

- IP addresses: use `validate_ip()`. Returns `None` for invalid inputs.
- URLs: use `validate_url()`. Only allows `http`/`https` scheme.
- Domains: use `validate_domain()`. Rejects anything with special chars.
- File paths: reject `..` and absolute `/` paths. Use an allowlist if possible.
- Hash values: validate with a regex, e.g. `re.match(r"^[a-fA-F0-9]{32,128}$", value)`
- CVE IDs: validate with `re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE)`

---

## Registering the new server

1. Add the server script to `mcp_servers/my_server.py`
2. Register it as a stdio MCP server pointing at `python mcp_servers/my_server.py` — Odysseus has no static config file for this; servers are registered as rows in the app's own `McpServer` table, either through **Settings → Integrations → MCP** in the UI, or by an admin-authenticated `POST /api/mcp/servers` call (see `routes/mcp/mcp_routes.py`). There's no separate seed step for a fresh install: the built-in fork servers aren't auto-registered by default, so exercising a new one locally means adding it the same way an operator would. `scripts/register_fork_mcp_servers.py` does this for every server in `FORK_SECURITY_SERVERS` (step 5 below) in one shot and is idempotent, so re-running it after adding yours is the fastest way to pick it up on an existing instance instead of clicking through Settings by hand — add its `LABELS` entry there too.
3. Add the file path to the CI `paths:` trigger in `.github/workflows/ci-security.yml`
4. Add the file to the bandit scan list in the same workflow
5. Also add it to `scripts/mcp_health_check.py`'s `FORK_SECURITY_SERVERS` list and `.pre-commit-config.yaml`'s file alternation, and give it a `### my_server` section in `README.md` (tool table + repo-layout tree) — easy to miss since none of these three are enforced by CI.

If the server needs a heavyweight or niche Python package that most installs won't use (e.g. `sigma_server.py`'s `pysigma`), add it to `requirements-optional.txt` instead of `requirements.txt`, and gate the import:

```python
try:
    import pysigma
    _PYSIGMA_AVAILABLE = True
except ImportError:
    _PYSIGMA_AVAILABLE = False
```

Two variants exist depending on how central the dependency is:
- If it's required by *every* tool in the server (`pdf_server.py`'s `pypdf`), have `list_tools()` swap the whole `TOOLS` list for a single placeholder tool explaining what to install, and `call_tool()` short-circuit the same way — see `pdf_server.py`'s `_PYPDF_AVAILABLE` checks in both.
- If only *some* tools need it (`sigma_server.py`'s `pysigma` — `sigma_rule_write`/`list`/`delete` work without it, only `convert`/`test` don't), keep `list_tools()` returning the full `TOOLS` list unconditionally, and have just the handlers that need the package check the flag and return `mcp_error("not_installed", ...)`. Shrinking the list here would make a client unable to tell "not installed" from "tool doesn't exist."

---

## Security checklist

Before submitting a new MCP server:

- [ ] All external inputs are validated before use
- [ ] No raw user input is passed directly as a shell argument without validation
- [ ] File path operations reject `..` and absolute paths
- [ ] Errors are caught and returned as `mcp_error()` strings — no unhandled exceptions
- [ ] Secrets (API keys, tokens) come from environment variables, never hardcoded
- [ ] Added to bandit scan list in CI
- [ ] Added to `paths:` trigger in CI workflow
- [ ] `exec_in_toolchain()` is used for all subprocess execution

---

## Testing

Place unit tests in `tests/mcp_servers/test_my_server.py`. Test:
- Valid inputs return expected output shape
- Invalid inputs return `[error:...]` strings, not exceptions
- Path traversal attempts are rejected

```python
import pytest
from mcp_servers.my_server import call_tool

@pytest.mark.asyncio
async def test_invalid_ip_rejected():
    result = await call_tool("my_tool", {"target": "../../etc/passwd"})
    assert result[0].text.startswith("[error:")
```
