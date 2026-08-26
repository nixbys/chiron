"""Regression coverage for the built-in MCP servers' SDK compatibility line."""

from pathlib import Path


REQUIREMENTS = Path(__file__).resolve().parents[1] / "requirements.txt"


def test_mcp_requirement_excludes_breaking_v2_sdk():
    requirements = [
        line.split("#", 1)[0].strip().replace(" ", "")
        for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
    ]

    # Accept any patch-level spelling of the same constraint (e.g. "mcp<2"
    # upstream, "mcp<2.0.0" on this fork) -- both exclude the breaking v2 SDK.
    assert any(req.startswith("mcp<2") for req in requirements)
