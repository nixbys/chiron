# ADR 004: BentoPDF Integration — Sidecar UI + pypdf MCP Server

**Status:** Accepted
**Date:** 2026-06-21

## Context

PDF handling is relevant to odysseus-red in two distinct ways:

1. **OSINT / intelligence extraction** — PDFs collected during reconnaissance often contain metadata (author, company, software version, internal paths) that constitutes high-value intelligence. The agent needs programmatic access to this data without manual steps.

2. **Report assembly** — Pentest deliverables are typically PDFs. The agent should be able to merge, split, and reference findings across multiple PDF artifacts during report generation.

Additionally, users need an interactive tool for tasks that require a visual interface: redaction, compression, format conversion, annotation, and signing.

## Decision

**Dual approach:**

### 1. BentoPDF web UI sidecar (`odysseus-bentopdf`)
Add `ghcr.io/alam00000/bentopdf-simple:latest` to `docker-compose.security.yml`, exposed on `127.0.0.1:3000`. The agent directs users to `http://localhost:3000` for interactive PDF work. All processing runs client-side (WebAssembly/JS) — no data leaves the machine.

### 2. `pdf_server.py` MCP server using `pypdf`
Implement a new MCP server using `pypdf`, which is already a dependency in Odysseus's `requirements.txt`. This gives the agent programmatic PDF access without installing anything new. Covers: metadata extraction, text extraction, merge, page extraction, and a `pdf_bentopdf_url` tool that hands off to the interactive UI when needed.

## Why Not Server-Side BentoPDF API

BentoPDF has no server-side REST API — all processing runs in the browser via WebAssembly. It is not callable from Python code. The MCP server therefore uses `pypdf` for programmatic operations, and the BentoPDF container provides the interactive layer.

## Why pypdf Over PyMuPDF

`pypdf` is already in `requirements.txt` (upstream dependency). PyMuPDF (fitz) is more powerful (better text extraction, image handling) but adds a compiled dependency and is AGPL-licensed, which creates no new licensing issue but adds install complexity. `pypdf` is sufficient for the target use cases (metadata read, text extract, merge/split). PyMuPDF can be added to the toolchain sidecar later if richer PDF analysis is needed.

## Licensing

- BentoPDF: AGPL-3.0 (compatible — we're using the Docker image, not embedding source)
- pypdf: BSD-3-Clause (permissive)

## Security Considerations

- All file paths in `pdf_server.py` are resolved against `ODYSSEUS_DATA_DIR` with a traversal guard — paths outside this directory are rejected.
- BentoPDF processes files client-side; no PDF content passes through or is stored by the container.
- BentoPDF is bound to `127.0.0.1:3000` only — not accessible from outside the host.

## Consequences

**Positive:**
- Zero new Python dependencies — `pypdf` already present.
- Agent can autonomously extract PDF intelligence during OSINT workflows.
- Users have a full-featured, privacy-respecting interactive PDF editor at `localhost:3000`.
- Split between programmatic (MCP) and interactive (BentoPDF UI) is clean and idiomatic.

**Negative:**
- Advanced PDF text extraction (scanned/OCR PDFs) is not supported by `pypdf` — requires Tesseract or PyMuPDF.
- BentoPDF advanced features (PyMuPDF WASM, Ghostscript WASM, CoherentPDF WASM) load from jsDelivr CDN by default; air-gapped deployments need additional setup.
