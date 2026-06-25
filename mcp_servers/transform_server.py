"""
transform_server.py

MCP server for data encoding, decoding, hashing, and transformation operations.
Replaces the need for a CyberChef sidecar for common operations.
All processing happens in-process — no toolchain sidecar required.
"""

import asyncio
import base64
import gzip
import hashlib
import html
import json
import re
import struct
import sys
import urllib.parse
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_servers.common import mcp_error

server = Server("transform")

TOOLS = [
    Tool(
        name="encode",
        description="Encode data using a specified scheme (base64, hex, url, html, rot13).",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Input data to encode"},
                "scheme": {
                    "type": "string",
                    "enum": ["base64", "base64url", "hex", "url", "html", "rot13", "binary"],
                    "description": "Encoding scheme",
                },
            },
            "required": ["data", "scheme"],
        },
    ),
    Tool(
        name="decode",
        description="Decode data from a specified scheme (base64, hex, url, html, rot13).",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Input data to decode"},
                "scheme": {
                    "type": "string",
                    "enum": ["base64", "base64url", "hex", "url", "html", "rot13", "binary"],
                    "description": "Decoding scheme",
                },
            },
            "required": ["data", "scheme"],
        },
    ),
    Tool(
        name="hash_data",
        description="Compute one or more cryptographic hashes of a string.",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "String to hash"},
                "algorithms": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["md5", "sha1", "sha256", "sha512", "sha3_256"]},
                    "description": "Hash algorithms to compute",
                    "default": ["md5", "sha1", "sha256"],
                },
            },
            "required": ["data"],
        },
    ),
    Tool(
        name="gzip_compress",
        description="Gzip-compress a string and return the result as base64.",
        inputSchema={
            "type": "object",
            "properties": {"data": {"type": "string"}},
            "required": ["data"],
        },
    ),
    Tool(
        name="gzip_decompress",
        description="Decompress a base64-encoded gzip payload and return the plaintext.",
        inputSchema={
            "type": "object",
            "properties": {"data": {"type": "string", "description": "Base64-encoded gzip data"}},
            "required": ["data"],
        },
    ),
    Tool(
        name="regex_extract",
        description=(
            "Extract all matches of a regex pattern from text. "
            "Useful for extracting IPs, emails, URLs, hashes from raw tool output."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "pattern": {"type": "string", "description": "Python regex pattern"},
                "preset": {
                    "type": "string",
                    "enum": ["ip", "ipv6", "domain", "email", "url", "md5", "sha256", "cve", "mac"],
                    "description": "Use a built-in pattern preset instead of a custom one",
                },
            },
            "required": ["text"],
        },
    ),
    Tool(
        name="jwt_decode",
        description=(
            "Decode a JWT without verifying the signature. "
            "Returns header and payload as formatted JSON."
        ),
        inputSchema={
            "type": "object",
            "properties": {"token": {"type": "string", "description": "JWT string"}},
            "required": ["token"],
        },
    ),
    Tool(
        name="xor",
        description="XOR a hex-encoded payload with a key (hex or text). Returns hex and ASCII output.",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Hex-encoded input"},
                "key": {"type": "string", "description": "XOR key — hex (0x prefix) or plain text"},
            },
            "required": ["data", "key"],
        },
    ),
]

_PRESETS = {
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "ipv6": r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "url": r"https?://[^\s\"'>]+",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,}",
    "mac": r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()  # noqa: C901
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "encode":
            data = arguments["data"]
            scheme = arguments["scheme"]
            b = data.encode()
            if scheme == "base64":
                result = base64.b64encode(b).decode()
            elif scheme == "base64url":
                result = base64.urlsafe_b64encode(b).decode()
            elif scheme == "hex":
                result = b.hex()
            elif scheme == "url":
                result = urllib.parse.quote(data, safe="")
            elif scheme == "html":
                result = html.escape(data)
            elif scheme == "rot13":
                result = data.translate(str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                ))
            elif scheme == "binary":
                result = " ".join(f"{byte:08b}" for byte in b)
            else:
                return [TextContent(type="text", text=mcp_error("unknown_scheme", scheme))]

        elif name == "decode":
            data = arguments["data"]
            scheme = arguments["scheme"]
            if scheme == "base64":
                result = base64.b64decode(data + "==").decode(errors="replace")
            elif scheme == "base64url":
                result = base64.urlsafe_b64decode(data + "==").decode(errors="replace")
            elif scheme == "hex":
                result = bytes.fromhex(data.replace(" ", "")).decode(errors="replace")
            elif scheme == "url":
                result = urllib.parse.unquote(data)
            elif scheme == "html":
                result = html.unescape(data)
            elif scheme == "rot13":
                result = data.translate(str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                ))
            elif scheme == "binary":
                parts = data.split()
                result = "".join(chr(int(p, 2)) for p in parts if p)
            else:
                return [TextContent(type="text", text=mcp_error("unknown_scheme", scheme))]

        elif name == "hash_data":
            data = arguments["data"].encode()
            algos = arguments.get("algorithms", ["md5", "sha1", "sha256"])
            lines = []
            for algo in algos:
                h = hashlib.new(algo, data)
                lines.append(f"{algo.upper()}: {h.hexdigest()}")
            result = "\n".join(lines)

        elif name == "gzip_compress":
            compressed = gzip.compress(arguments["data"].encode())
            result = base64.b64encode(compressed).decode()

        elif name == "gzip_decompress":
            raw = base64.b64decode(arguments["data"] + "==")
            result = gzip.decompress(raw).decode(errors="replace")

        elif name == "regex_extract":
            text = arguments["text"]
            preset = arguments.get("preset")
            pattern = _PRESETS.get(preset, "") if preset else arguments.get("pattern", "")
            if not pattern:
                return [TextContent(type="text", text=mcp_error("missing_param", "Provide either 'pattern' or 'preset'"))]
            matches = re.findall(pattern, text)
            unique = sorted(set(matches))
            result = f"Found {len(unique)} unique match(es):\n" + "\n".join(unique) if unique else "No matches found."

        elif name == "jwt_decode":
            token = arguments["token"].strip()
            parts = token.split(".")
            if len(parts) < 2:
                return [TextContent(type="text", text=mcp_error("invalid_jwt", "Token must have at least 2 parts"))]
            header_raw = base64.urlsafe_b64decode(parts[0] + "==")
            payload_raw = base64.urlsafe_b64decode(parts[1] + "==")
            header = json.loads(header_raw)
            payload = json.loads(payload_raw)
            result = (
                f"[Header]\n{json.dumps(header, indent=2)}\n\n"
                f"[Payload]\n{json.dumps(payload, indent=2)}\n\n"
                f"[Signature present]: {'yes' if len(parts) == 3 else 'no'}"
            )

        elif name == "xor":
            raw_data = bytes.fromhex(arguments["data"].replace(" ", "").replace("0x", ""))
            key_str = arguments["key"]
            if key_str.startswith("0x"):
                key_bytes = bytes.fromhex(key_str[2:])
            else:
                key_bytes = key_str.encode()
            if not key_bytes:
                return [TextContent(type="text", text=mcp_error("invalid_key", "XOR key must not be empty"))]
            xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw_data))
            hex_out = xored.hex()
            ascii_out = "".join(chr(b) if 32 <= b < 127 else "." for b in xored)
            result = f"Hex: {hex_out}\nASCII: {ascii_out}"

        else:
            result = mcp_error("unknown_tool", name)

    except Exception as exc:  # noqa: BLE001
        result = mcp_error("transform_error", str(exc))

    return [TextContent(type="text", text=result)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
