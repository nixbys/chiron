# Developing MCP Servers for Odysseus-red

This guide explains how to add a new MCP server to the odysseus-red security toolchain.

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
2. Add an MCP server entry in the upstream Odysseus `config.json` (or equivalent config) pointing to `python mcp_servers/my_server.py`
3. Add the file path to the CI `paths:` trigger in `.github/workflows/ci-security.yml`
4. Add the file to the bandit scan list in the same workflow

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
