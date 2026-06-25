"""Unit tests for transform_server.py — all operations run in-process, no mocking needed."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import mcp_servers.transform_server as ts


async def _call(name: str, **kwargs) -> str:
    results = await ts.call_tool(name, kwargs)
    assert results
    return results[0].text


@pytest.mark.asyncio
async def test_encode_base64():
    result = await _call("encode", data="hello", scheme="base64")
    assert result == "aGVsbG8="


@pytest.mark.asyncio
async def test_decode_base64():
    result = await _call("decode", data="aGVsbG8=", scheme="base64")
    assert result == "hello"


@pytest.mark.asyncio
async def test_encode_hex():
    result = await _call("encode", data="AB", scheme="hex")
    assert result == "4142"


@pytest.mark.asyncio
async def test_decode_hex():
    result = await _call("decode", data="4142", scheme="hex")
    assert result == "AB"


@pytest.mark.asyncio
async def test_encode_url():
    result = await _call("encode", data="hello world", scheme="url")
    assert result == "hello%20world"


@pytest.mark.asyncio
async def test_rot13_roundtrip():
    encoded = await _call("encode", data="Hello", scheme="rot13")
    decoded = await _call("decode", data=encoded, scheme="rot13")
    assert decoded == "Hello"


@pytest.mark.asyncio
async def test_hash_data_defaults():
    result = await _call("hash_data", data="test")
    assert "MD5:" in result
    assert "SHA1:" in result
    assert "SHA256:" in result


@pytest.mark.asyncio
async def test_hash_data_sha256_known():
    result = await _call("hash_data", data="", algorithms=["sha256"])
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in result


@pytest.mark.asyncio
async def test_gzip_roundtrip():
    compressed = await _call("gzip_compress", data="hello world")
    decompressed = await _call("gzip_decompress", data=compressed)
    assert decompressed == "hello world"


@pytest.mark.asyncio
async def test_regex_extract():
    result = await _call("regex_extract", text="IP: 1.2.3.4 and 5.6.7.8", preset="ip")
    assert "1.2.3.4" in result
    assert "5.6.7.8" in result


@pytest.mark.asyncio
async def test_jwt_decode():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = await _call("jwt_decode", token=token)
    assert "HS256" in result
    assert "John Doe" in result


@pytest.mark.asyncio
async def test_xor_single_byte():
    result = await _call("xor", data="4142", key="0x01")
    assert "4043" in result


@pytest.mark.asyncio
async def test_unknown_tool_returns_error():
    result = await _call("nonexistent_tool")
    assert "[error:" in result
