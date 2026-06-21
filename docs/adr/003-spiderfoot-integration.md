# ADR 003: SpiderFoot OSINT Integration via REST API Sidecar

**Status:** Accepted
**Date:** 2026-06-20

## Context

`osint_server.py` provides targeted OSINT tools (theHarvester, Sherlock, DNS enum, WHOIS) via exec calls into the toolchain container. These tools operate independently with no cross-correlation. SpiderFoot was evaluated as a potential addition covering 200+ correlated OSINT modules.

## Decision

Integrate SpiderFoot as a **dedicated sidecar container** (`odysseus-spiderfoot`, image `smicallef/spiderfoot:latest`) exposing its REST API on port 5001 on the internal Podman network. A new MCP server (`spiderfoot_server.py`) communicates with this API using `requests`, implementing the full async scan lifecycle: start → poll → retrieve.

SpiderFoot is **not** added to the Kali toolchain container. It runs independently.

## Why REST API, Not exec

SpiderFoot scans are inherently long-running (minutes to hours depending on module count and target responsiveness). The exec-based pattern used for nmap/sqlmap is unsuitable here because:

1. `podman exec` is synchronous from the subprocess perspective — holding the call open for an hour-long scan is not viable.
2. SpiderFoot's own REST API supports the correct async pattern: start scan → return ID → poll status → fetch results.
3. The REST API returns structured JSON with event types, modules, and source chains — far richer than raw CLI stdout.

## Overlap with Existing OSINT Tools

`osint_server.py` tools remain valuable for **quick, targeted lookups** (a single WHOIS, a fast DNS query). SpiderFoot is the right tool for **comprehensive, correlated intelligence gathering**. Both coexist — the agent can choose based on task scope.

## Licensing

SpiderFoot is MIT licensed. This is compatible with odysseus-red's AGPL-3.0 license (MIT code can be incorporated into AGPL projects).

## Consequences

**Positive:**
- 200+ correlated OSINT modules covering email, infrastructure, social media, cloud assets, breaches, and threat intel — all from one tool call.
- Async scan model established in the MCP server is a reusable pattern for any future long-running tool.
- SpiderFoot's built-in deduplication and correlation surfaces relationships that running tools independently cannot.
- API keys already configured in `.env` (Shodan, VirusTotal, OTX) are forwarded to the SpiderFoot container.

**Negative:**
- Adds a persistent container to the stack (~200MB image, non-trivial memory usage during active scans).
- Port 5001 must be reserved on the internal network.
- SpiderFoot passive scans still take 5–30 minutes for a typical domain, requiring the agent to use the async tools (`sf_scan_start` + `sf_scan_status` + `sf_scan_results`) rather than blocking.

## Alternatives Considered

**CLI exec via toolchain:** Rejected. `python3 sf.py -s target -o json` is a blocking call that can run for hours, unsuitable for the exec pattern. Also, SpiderFoot installed inside the Kali sidecar would bloat that image significantly.

**HX (commercial):** Rejected. MIT open-source version covers all needed capabilities without licensing cost or data leaving the local network.
