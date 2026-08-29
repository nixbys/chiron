"""Unit tests for pdf_server.py — uses real pypdf with in-memory PDFs, no disk I/O."""

import io
import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

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


# ---------------------------------------------------------------------------
# generate_engagement_report (Phase 1 checkpoint F)
# ---------------------------------------------------------------------------

def _seed_engagement_db(db_path: Path, engagement_id: str = "eng-1") -> None:
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE engagements (
            id TEXT PRIMARY KEY, name TEXT, description TEXT, client TEXT,
            scope TEXT, out_of_scope TEXT, status TEXT, start_date REAL, end_date REAL,
            tags TEXT, created_at REAL, updated_at REAL
        );
        CREATE TABLE engagement_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT, event_type TEXT,
            summary TEXT, detail TEXT, ts REAL
        );
    """)
    now = time.time()
    conn.execute(
        "INSERT INTO engagements VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (engagement_id, "Acme Corp Pentest", "Annual external pentest", "Acme Corp",
         json.dumps(["acme.com", "10.0.0.0/24"]), json.dumps(["10.0.1.0/24"]), "active",
         now, None, json.dumps(["pentest", "external"]), now, now),
    )
    conn.execute(
        "INSERT INTO engagement_events (engagement_id, event_type, summary, detail, ts) VALUES (?,?,?,?,?)",
        (engagement_id, "scan_completed", "Initial recon complete", "", now),
    )
    conn.commit()
    conn.close()


@pytest.fixture()
def engagement_db(tmp_data):
    """Seeds a fake engagements.db and points pdf._ENGAGEMENTS_DB_PATH at it.
    _ENGAGEMENTS_DB_PATH is computed once from _DATA_DIR at import time, so
    patching _DATA_DIR alone (the tmp_data fixture) doesn't move it -- it
    needs its own patch."""
    db_path = tmp_data / "engagements.db"
    _seed_engagement_db(db_path)
    with patch.object(pdf, "_ENGAGEMENTS_DB_PATH", db_path):
        yield db_path


def test_get_engagement_for_report_missing_db_returns_none(tmp_data):
    with patch.object(pdf, "_ENGAGEMENTS_DB_PATH", tmp_data / "does_not_exist.db"):
        assert pdf._get_engagement_for_report("eng-1") is None


def test_get_engagement_for_report_missing_id_returns_none(engagement_db):
    assert pdf._get_engagement_for_report("no-such-id") is None


def test_get_engagement_for_report_found(engagement_db):
    data = pdf._get_engagement_for_report("eng-1")
    assert data is not None
    assert data["engagement"]["name"] == "Acme Corp Pentest"
    assert len(data["events"]) == 1
    assert data["events"][0]["event_type"] == "scan_completed"


def test_fetch_engagement_findings_unreachable_returns_none():
    with patch.object(pdf.requests, "post", side_effect=ConnectionError("refused")):
        assert pdf._fetch_engagement_findings("eng-1", 50) is None


def test_fetch_engagement_findings_success():
    search_resp = MagicMock()
    search_resp.json.return_value = {
        "hits": {"total": {"value": 1}, "hits": [
            {"_source": {"title": "Open port 22", "severity": "medium", "status": "open", "tool": "scheduled_recon"}},
        ]},
    }
    agg_resp = MagicMock()
    agg_resp.json.return_value = {"aggregations": {
        "by_severity": {"buckets": [{"key": "medium", "doc_count": 1}]},
        "by_status": {"buckets": [{"key": "open", "doc_count": 1}]},
    }}
    with patch.object(pdf.requests, "post", side_effect=[search_resp, agg_resp]):
        result = pdf._fetch_engagement_findings("eng-1", 50)
    assert result["total"] == 1
    assert result["hits"][0]["_source"]["title"] == "Open port 22"
    assert result["by_severity"] == [{"key": "medium", "doc_count": 1}]


@pytest.mark.asyncio
async def test_generate_engagement_report_not_found(engagement_db):
    results = await pdf.call_tool("generate_engagement_report", {"engagement_id": "no-such-id"})
    assert "[error]" in results[0].text
    assert "no-such-id" in results[0].text


@pytest.mark.asyncio
async def test_generate_engagement_report_end_to_end(engagement_db, tmp_data):
    with patch.object(pdf, "_fetch_engagement_findings", return_value=None):
        results = await pdf.call_tool("generate_engagement_report", {
            "engagement_id": "eng-1",
            "compliance_summary": "AC, SC families flagged.",
        })
    text = results[0].text
    assert "Report saved" in text
    out_path = tmp_data / "reports" / "engagement_eng-1.pdf"
    assert out_path.exists()
    reader = PdfReader(str(out_path))
    body = "\n".join(p.extract_text() for p in reader.pages)
    assert "Acme Corp Pentest" in body
    assert "acme.com" in body
    assert "OpenSearch unreachable" in body
    assert "AC, SC families flagged." in body


@pytest.mark.asyncio
async def test_generate_engagement_report_includes_findings_section(engagement_db, tmp_data):
    fake_findings = {
        "total": 1,
        "hits": [{"_source": {"title": "Open port 22", "severity": "medium", "status": "open", "tool": "scheduled_recon"}}],
        "by_severity": [{"key": "medium", "doc_count": 1}],
        "by_status": [{"key": "open", "doc_count": 1}],
    }
    with patch.object(pdf, "_fetch_engagement_findings", return_value=fake_findings):
        results = await pdf.call_tool("generate_engagement_report", {"engagement_id": "eng-1"})
    out_path = tmp_data / "reports" / "engagement_eng-1.pdf"
    reader = PdfReader(str(out_path))
    body = "\n".join(p.extract_text() for p in reader.pages)
    assert "Open port 22" in body
    assert "Total findings: 1" in body


@pytest.mark.asyncio
async def test_generate_report_bullet_list_does_not_crash(tmp_data):
    """Regression test: '•' isn't in Helvetica's latin-1 charset and used to
    raise FPDFUnicodeEncodingException on any bulleted generate_report call."""
    results = await pdf.call_tool("generate_report", {
        "title": "Bullet Test",
        "content": "# Heading\n- first item\n- second item\n",
        "output_file": "bullets.pdf",
    })
    assert "[error]" not in results[0].text
    out_path = tmp_data / "bullets.pdf"
    assert out_path.exists()
    reader = PdfReader(str(out_path))
    body = reader.pages[0].extract_text()
    assert "first item" in body
    assert "second item" in body
