"""
pdf_server.py

MCP server for programmatic PDF operations using pypdf (already in requirements).
Covers the cybersecurity-relevant subset of PDF work:

  - Metadata extraction   — OSINT gold: author, company, software, creation dates,
                            internal paths, GPS coordinates in embedded images.
  - Text extraction       — Pull content from PDFs collected during recon for
                            analysis or keyword search.
  - Document info         — Page count, encryption status, PDF version, embedded
                            files list.
  - Merge                 — Assemble multi-source pentest reports into one file.
  - Page extraction       — Carve specific pages from a large document.

Interactive editing (redaction, compression, format conversion, signing) is handled
by the BentoPDF web UI running at http://localhost:3000. Direct users there for
anything that requires a visual interface.

Files are resolved relative to the Odysseus workspace data directory, configurable
via ODYSSEUS_DATA_DIR (default: ./data). Paths must stay within that directory.
"""

import asyncio
import io
import os
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from pypdf import PdfReader, PdfWriter
    _PYPDF_AVAILABLE = True
except ImportError:
    _PYPDF_AVAILABLE = False

try:
    from fpdf import FPDF
    _FPDF_AVAILABLE = True
except ImportError:
    _FPDF_AVAILABLE = False

server = Server("pdf")

# Base directory all file paths are resolved against.
_DATA_DIR = Path(os.environ.get("ODYSSEUS_DATA_DIR", "./data")).resolve()
_BENTOPDF_URL = os.environ.get("BENTOPDF_URL", "http://localhost:3000")

TOOLS = [
    Tool(
        name="pdf_metadata",
        description=(
            "Extract all metadata from a PDF file. "
            "Useful for OSINT — reveals author names, company, creation software, "
            "internal file paths, and creation/modification timestamps. "
            "File path is relative to the Odysseus data directory."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to PDF file, relative to the data directory (e.g. 'uploads/document.pdf')",
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="pdf_extract_text",
        description=(
            "Extract readable text content from a PDF. "
            "Optionally limit to specific pages. Useful for analysing documents "
            "collected during OSINT or reviewing scan output reports."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "pages": {
                    "type": "string",
                    "description": "Page range to extract, e.g. '1-3' or '2' (1-indexed). Leave empty for all pages.",
                    "default": "",
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Truncate output at this many characters (0 = no limit)",
                    "default": 8000,
                },
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="pdf_info",
        description=(
            "Return general document info: page count, PDF version, encryption "
            "status, and list of embedded files. Quick triage before deeper analysis."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="pdf_merge",
        description=(
            "Merge multiple PDFs into one file. Useful for assembling a final "
            "pentest report from per-tool outputs. Input and output paths are "
            "relative to the Odysseus data directory."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "input_files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Ordered list of PDF paths to merge (relative to data directory)",
                },
                "output_file": {
                    "type": "string",
                    "description": "Output path for merged PDF (relative to data directory)",
                },
            },
            "required": ["input_files", "output_file"],
        },
    ),
    Tool(
        name="pdf_extract_pages",
        description=(
            "Extract a range of pages from a PDF into a new file. "
            "Useful for carving relevant sections from large documents."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "pages": {
                    "type": "string",
                    "description": "Page range to extract, e.g. '1-5' or '3' (1-indexed)",
                },
                "output_file": {
                    "type": "string",
                    "description": "Output path for extracted pages (relative to data directory)",
                },
            },
            "required": ["file_path", "pages", "output_file"],
        },
    ),
    Tool(
        name="generate_report",
        description=(
            "Generate a formatted PDF report from markdown or plain text content. "
            "Use this to produce OSINT summaries, pentest findings, or research reports. "
            "The PDF is saved to the Odysseus data directory and the file path is returned. "
            "Supports headings (#, ##, ###), bullet lists (- item), bold (**text**), "
            "horizontal rules (---), and plain paragraphs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Report title shown on the cover/header",
                },
                "content": {
                    "type": "string",
                    "description": "Markdown-formatted report body",
                },
                "output_file": {
                    "type": "string",
                    "description": "Output filename under the data directory (e.g. 'reports/osint_report.pdf')",
                    "default": "reports/report.pdf",
                },
                "author": {
                    "type": "string",
                    "description": "Author name shown in the report header",
                    "default": "Odysseus",
                },
            },
            "required": ["title", "content"],
        },
    ),
    Tool(
        name="pdf_bentopdf_url",
        description=(
            "Return the BentoPDF web UI URL for interactive PDF operations: "
            "redaction, compression, format conversion, signing, splitting, "
            "and annotation. Open this URL in a browser."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
]


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _resolve(rel_path: str) -> Path | str:
    """Resolve rel_path under _DATA_DIR, blocking path traversal."""
    resolved = (_DATA_DIR / rel_path).resolve()
    if not str(resolved).startswith(str(_DATA_DIR)):
        return f"[error] Path '{rel_path}' is outside the data directory."
    return resolved


def _parse_page_range(spec: str, total: int) -> tuple[int, int] | str:
    """Parse '1-5' or '3' into 0-indexed (start, end) inclusive. Returns error str on bad input."""
    spec = spec.strip()
    try:
        if "-" in spec:
            parts = spec.split("-", 1)
            start, end = int(parts[0]) - 1, int(parts[1]) - 1
        else:
            start = end = int(spec) - 1
    except ValueError:
        return f"[error] Invalid page range '{spec}'. Use '1-5' or '3'."
    if start < 0 or end >= total or start > end:
        return f"[error] Page range {spec} is out of bounds for a {total}-page document."
    return start, end


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def _pdf_metadata(file_path: str) -> str:
    path = _resolve(file_path)
    if isinstance(path, str):
        return path
    if not path.exists():
        return f"[error] File not found: {file_path}"
    try:
        reader = PdfReader(str(path))
        meta = reader.metadata or {}
        lines = [f"File: {path.name}", f"Pages: {len(reader.pages)}", ""]
        # Normalise pypdf's /Key → human label
        field_map = {
            "/Title": "Title",
            "/Author": "Author",
            "/Subject": "Subject",
            "/Keywords": "Keywords",
            "/Creator": "Creator (application)",
            "/Producer": "Producer (PDF library)",
            "/CreationDate": "Created",
            "/ModDate": "Modified",
            "/Company": "Company",
            "/SourceModified": "Source Modified",
            "/LastModifiedBy": "Last Modified By",
        }
        found_any = False
        for key, label in field_map.items():
            val = meta.get(key)
            if val:
                lines.append(f"{label}: {val}")
                found_any = True
        # Catch any non-standard keys
        standard_keys = set(field_map.keys())
        for key, val in meta.items():
            if key not in standard_keys and val:
                lines.append(f"{key}: {val}")
                found_any = True
        if not found_any:
            lines.append("(no metadata fields found — document may have been sanitised)")
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


def _pdf_extract_text(file_path: str, pages: str = "", max_chars: int = 8000) -> str:
    path = _resolve(file_path)
    if isinstance(path, str):
        return path
    if not path.exists():
        return f"[error] File not found: {file_path}"
    try:
        reader = PdfReader(str(path))
        total = len(reader.pages)
        if pages:
            result = _parse_page_range(pages, total)
            if isinstance(result, str):
                return result
            start, end = result
            page_list = list(range(start, end + 1))
        else:
            page_list = list(range(total))

        chunks = []
        for i in page_list:
            text = reader.pages[i].extract_text() or ""
            if text.strip():
                chunks.append(f"--- Page {i + 1} ---\n{text}")

        full = "\n\n".join(chunks)
        if not full.strip():
            return "(no extractable text — PDF may be scanned/image-only)"
        if max_chars and len(full) > max_chars:
            full = full[:max_chars] + f"\n\n[truncated — {len(full) - max_chars} chars remaining]"
        return full
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


def _pdf_info(file_path: str) -> str:
    path = _resolve(file_path)
    if isinstance(path, str):
        return path
    if not path.exists():
        return f"[error] File not found: {file_path}"
    try:
        reader = PdfReader(str(path))
        lines = [
            f"File: {path.name}",
            f"Size: {path.stat().st_size / 1024:.1f} KB",
            f"Pages: {len(reader.pages)}",
            f"Encrypted: {reader.is_encrypted}",
            f"PDF version: {getattr(reader, 'pdf_header', 'unknown')}",
        ]
        embedded = list(reader.attachments.keys()) if hasattr(reader, "attachments") else []
        if embedded:
            lines.append(f"Embedded files: {', '.join(embedded)}")
        else:
            lines.append("Embedded files: none")
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


def _pdf_merge(input_files: list[str], output_file: str) -> str:
    if not input_files:
        return "[error] No input files provided."
    out_path = _resolve(output_file)
    if isinstance(out_path, str):
        return out_path
    writer = PdfWriter()
    for rel in input_files:
        p = _resolve(rel)
        if isinstance(p, str):
            return p
        if not p.exists():
            return f"[error] File not found: {rel}"
        try:
            reader = PdfReader(str(p))
            for page in reader.pages:
                writer.add_page(page)
        except Exception as exc:  # noqa: BLE001
            return f"[error] Could not read '{rel}': {exc}"
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            writer.write(f)
        return f"Merged {len(input_files)} files → {out_path.name}  ({out_path.stat().st_size // 1024} KB)"
    except Exception as exc:  # noqa: BLE001
        return f"[error] Writing output failed: {exc}"


def _pdf_extract_pages(file_path: str, pages: str, output_file: str) -> str:
    path = _resolve(file_path)
    if isinstance(path, str):
        return path
    if not path.exists():
        return f"[error] File not found: {file_path}"
    out_path = _resolve(output_file)
    if isinstance(out_path, str):
        return out_path
    try:
        reader = PdfReader(str(path))
        result = _parse_page_range(pages, len(reader.pages))
        if isinstance(result, str):
            return result
        start, end = result
        writer = PdfWriter()
        for i in range(start, end + 1):
            writer.add_page(reader.pages[i])
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            writer.write(f)
        count = end - start + 1
        return f"Extracted {count} page(s) (p.{start+1}–{end+1}) → {out_path.name}"
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


def _generate_report(title: str, content: str, output_file: str, author: str) -> str:
    """Render markdown-ish content to a PDF using fpdf2."""
    if not _FPDF_AVAILABLE:
        return "[error] fpdf2 not installed. Run: pip install fpdf2"

    out_path = _resolve(output_file)
    if isinstance(out_path, str):
        return out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    import re
    from datetime import datetime
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header banner
    pdf.set_fill_color(30, 30, 30)
    pdf.rect(0, 0, 210, 28, style="F")
    pdf.set_text_color(220, 50, 50)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_xy(10, 6)
    pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(180, 180, 180)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(10)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    pdf.cell(0, 6, f"Author: {author}    Generated: {stamp}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    def _render_line(line: str) -> None:
        line = line.rstrip()
        if not line:
            pdf.ln(3)
            return

        # Headings
        if line.startswith("### "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(0, 6, line[4:])
            pdf.set_text_color(0, 0, 0)
            return
        if line.startswith("## "):
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(30, 30, 30)
            pdf.set_fill_color(240, 240, 240)
            pdf.multi_cell(0, 7, line[3:], fill=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
            return
        if line.startswith("# "):
            pdf.set_font("Helvetica", "B", 15)
            pdf.set_text_color(20, 20, 20)
            pdf.multi_cell(0, 8, line[2:])
            pdf.set_draw_color(200, 200, 200)
            pdf.line(pdf.get_x(), pdf.get_y(), 200, pdf.get_y())
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            return

        # Horizontal rule
        if re.match(r"^-{3,}$", line) or re.match(r"^={3,}$", line):
            pdf.set_draw_color(180, 180, 180)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)
            return

        # Bullet list
        if line.startswith("- ") or line.startswith("* "):
            pdf.set_font("Helvetica", "", 10)
            pdf.set_x(14)
            text = line[2:]
            text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
            pdf.multi_cell(0, 5, f"•  {text}")
            return

        # Plain paragraph — strip inline bold markers
        pdf.set_font("Helvetica", "", 10)
        text = re.sub(r"\*\*(.+?)\*\*", r"\1", line)
        pdf.multi_cell(0, 5, text)

    for line in content.splitlines():
        _render_line(line)

    pdf.output(str(out_path))
    size_kb = out_path.stat().st_size // 1024
    return (
        f"Report saved: {out_path.name}  ({size_kb} KB)\n"
        f"Full path: {out_path}\n"
        f"Open in browser: {_BENTOPDF_URL} (use 'Merge/View' to open the file)"
    )


# ---------------------------------------------------------------------------
# MCP handlers
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools() -> list[Tool]:
    if not _PYPDF_AVAILABLE:
        return [Tool(
            name="pdf_unavailable",
            description="pypdf is not installed. Run: pip install pypdf",
            inputSchema={"type": "object", "properties": {}},
        )]
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if not _PYPDF_AVAILABLE:
        return [TextContent(type="text", text="[error] pypdf not installed. Run: pip install pypdf")]

    if name == "generate_report":
        text = _generate_report(
            title=arguments["title"],
            content=arguments["content"],
            output_file=arguments.get("output_file", "reports/report.pdf"),
            author=arguments.get("author", "Odysseus"),
        )

    elif name == "pdf_metadata":
        text = _pdf_metadata(arguments["file_path"])

    elif name == "pdf_extract_text":
        text = _pdf_extract_text(
            arguments["file_path"],
            pages=arguments.get("pages", ""),
            max_chars=int(arguments.get("max_chars", 8000)),
        )

    elif name == "pdf_info":
        text = _pdf_info(arguments["file_path"])

    elif name == "pdf_merge":
        text = _pdf_merge(arguments["input_files"], arguments["output_file"])

    elif name == "pdf_extract_pages":
        text = _pdf_extract_pages(
            arguments["file_path"],
            arguments["pages"],
            arguments["output_file"],
        )

    elif name == "pdf_bentopdf_url":
        text = (
            f"BentoPDF web UI: {_BENTOPDF_URL}\n\n"
            "Available interactive tools:\n"
            "  Merge / Split / Compress PDFs\n"
            "  Redact sensitive content\n"
            "  Convert to/from PDF (Office, images)\n"
            "  Edit, annotate, and sign\n"
            "  Remove metadata\n\n"
            "Open the URL in your browser. All processing runs client-side — no data leaves your machine."
        )

    else:
        text = f"[error] Unknown tool: {name}"

    return [TextContent(type="text", text=text)]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
