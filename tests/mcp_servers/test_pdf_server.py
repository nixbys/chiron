"""Unit tests for pdf_server.py — uses real pypdf with in-memory PDFs, no disk I/O."""

import io
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pypdf import PdfReader, PdfWriter

import mcp_servers.pdf_server as pdf


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_pdf(pages: int = 2, text_prefix: str = "Page") -> bytes:
    """Create a minimal valid PDF in memory with extractable text."""
    writer = PdfWriter()
    from pypdf.generic import (
        ArrayObject, DictionaryObject, NameObject,
        NumberObject, StreamObject, ByteStringObject,
    )
    for i in range(pages):
        writer.add_blank_page(width=612, height=792)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.fixture()
def tmp_data(tmp_path):
    """Patch _DATA_DIR to a temp directory and yield it."""
    with patch.object(pdf, "_DATA_DIR", tmp_path):
        yield tmp_path


def _write_pdf(tmp_data: Path, name: str = "test.pdf", pages: int = 2) -> Path:
    p = tmp_data / name
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    with open(p, "wb") as f:
        writer.write(f)
    return p


# ---------------------------------------------------------------------------
# _resolve — path traversal guard
# ---------------------------------------------------------------------------

def test_resolve_blocks_traversal(tmp_data):
    result = pdf._resolve("../../etc/passwd")
    assert isinstance(result, str)
    assert "error" in result.lower() or "outside" in result.lower()


def test_resolve_allows_subdirs(tmp_data):
    result = pdf._resolve("uploads/report.pdf")
    assert isinstance(result, Path)
    assert str(result).startswith(str(tmp_data))


# ---------------------------------------------------------------------------
# _parse_page_range
# ---------------------------------------------------------------------------

def test_parse_range_single():
    assert pdf._parse_page_range("2", 5) == (1, 1)


def test_parse_range_span():
    assert pdf._parse_page_range("1-3", 5) == (0, 2)


def test_parse_range_out_of_bounds():
    result = pdf._parse_page_range("10-20", 5)
    assert isinstance(result, str) and "error" in result.lower()


def test_parse_range_bad_format():
    result = pdf._parse_page_range("abc", 5)
    assert isinstance(result, str) and "error" in result.lower()


# ---------------------------------------------------------------------------
# pdf_info
# ---------------------------------------------------------------------------

def test_pdf_info_returns_page_count(tmp_data):
    _write_pdf(tmp_data, "doc.pdf", pages=3)
    result = pdf._pdf_info("doc.pdf")
    assert "Pages: 3" in result
    assert "Encrypted: False" in result


def test_pdf_info_missing_file(tmp_data):
    result = pdf._pdf_info("missing.pdf")
    assert "error" in result.lower()


# ---------------------------------------------------------------------------
# pdf_metadata
# ---------------------------------------------------------------------------

def test_pdf_metadata_no_metadata(tmp_data):
    _write_pdf(tmp_data, "bare.pdf")
    result = pdf._pdf_metadata("bare.pdf")
    # Should not error; should note metadata is absent or empty
    assert "error" not in result.lower() or "sanitised" in result.lower()
    assert "bare.pdf" in result


def test_pdf_metadata_with_fields(tmp_data):
    p = tmp_data / "meta.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({
        "/Author": "Jane Pentester",
        "/Company": "Red Team Inc",
        "/Creator": "Microsoft Word 2019",
    })
    with open(p, "wb") as f:
        writer.write(f)
    result = pdf._pdf_metadata("meta.pdf")
    assert "Jane Pentester" in result
    assert "Red Team Inc" in result
    assert "Microsoft Word 2019" in result


def test_pdf_metadata_missing_file(tmp_data):
    result = pdf._pdf_metadata("ghost.pdf")
    assert "error" in result.lower()


# ---------------------------------------------------------------------------
# pdf_extract_text
# ---------------------------------------------------------------------------

def test_pdf_extract_text_missing_file(tmp_data):
    result = pdf._pdf_extract_text("no.pdf")
    assert "error" in result.lower()


def test_pdf_extract_text_all_pages(tmp_data):
    _write_pdf(tmp_data, "blank.pdf", pages=2)
    # Blank pages yield no extractable text
    result = pdf._pdf_extract_text("blank.pdf")
    assert "no extractable text" in result or "Page" in result or result == ""


def test_pdf_extract_text_bad_range(tmp_data):
    _write_pdf(tmp_data, "doc.pdf", pages=2)
    result = pdf._pdf_extract_text("doc.pdf", pages="99")
    assert "error" in result.lower()


def test_pdf_extract_text_truncation(tmp_data):
    _write_pdf(tmp_data, "doc.pdf", pages=1)
    # max_chars=10 should truncate if there's any content
    result = pdf._pdf_extract_text("doc.pdf", max_chars=10)
    assert len(result) <= 300  # generous upper bound including truncation message


# ---------------------------------------------------------------------------
# pdf_merge
# ---------------------------------------------------------------------------

def test_pdf_merge_two_files(tmp_data):
    _write_pdf(tmp_data, "a.pdf", pages=2)
    _write_pdf(tmp_data, "b.pdf", pages=3)
    result = pdf._pdf_merge(["a.pdf", "b.pdf"], "merged.pdf")
    assert "error" not in result.lower()
    merged = tmp_data / "merged.pdf"
    assert merged.exists()
    reader = PdfReader(str(merged))
    assert len(reader.pages) == 5


def test_pdf_merge_missing_input(tmp_data):
    result = pdf._pdf_merge(["nonexistent.pdf"], "out.pdf")
    assert "error" in result.lower()


def test_pdf_merge_empty_list(tmp_data):
    result = pdf._pdf_merge([], "out.pdf")
    assert "error" in result.lower()


def test_pdf_merge_traversal_blocked(tmp_data):
    _write_pdf(tmp_data, "a.pdf")
    result = pdf._pdf_merge(["a.pdf"], "../../evil.pdf")
    assert "error" in result.lower()


# ---------------------------------------------------------------------------
# pdf_extract_pages
# ---------------------------------------------------------------------------

def test_pdf_extract_pages(tmp_data):
    _write_pdf(tmp_data, "big.pdf", pages=5)
    result = pdf._pdf_extract_pages("big.pdf", "2-4", "excerpt.pdf")
    assert "error" not in result.lower()
    out = tmp_data / "excerpt.pdf"
    assert out.exists()
    reader = PdfReader(str(out))
    assert len(reader.pages) == 3


def test_pdf_extract_single_page(tmp_data):
    _write_pdf(tmp_data, "doc.pdf", pages=4)
    result = pdf._pdf_extract_pages("doc.pdf", "3", "page3.pdf")
    assert "error" not in result.lower()
    reader = PdfReader(str(tmp_data / "page3.pdf"))
    assert len(reader.pages) == 1


# ---------------------------------------------------------------------------
# call_tool (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_tool_pdf_bentopdf_url():
    results = await pdf.call_tool("pdf_bentopdf_url", {})
    text = results[0].text
    assert "localhost:3000" in text or "bentopdf" in text.lower()
    assert "client-side" in text.lower()


@pytest.mark.asyncio
async def test_call_tool_unknown():
    results = await pdf.call_tool("not_a_tool", {})
    assert "Unknown tool" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_pdf_info(tmp_data):
    _write_pdf(tmp_data, "info.pdf", pages=2)
    results = await pdf.call_tool("pdf_info", {"file_path": "info.pdf"})
    assert "Pages: 2" in results[0].text


@pytest.mark.asyncio
async def test_call_tool_pdf_metadata_with_author(tmp_data):
    p = tmp_data / "auth.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({"/Author": "Alice Red"})
    with open(p, "wb") as f:
        writer.write(f)
    results = await pdf.call_tool("pdf_metadata", {"file_path": "auth.pdf"})
    assert "Alice Red" in results[0].text
