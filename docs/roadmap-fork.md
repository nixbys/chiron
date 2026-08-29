# Chiron Roadmap (Fork-Specific)

This tracks work on **this fork's own additions** — the security overlay, its MCP servers,
and the rebrand/redesign that brought the two together under one identity. It does not cover
the base platform; see [`ROADMAP.md`](../ROADMAP.md) for that (upstream-owned — never edited
here, per [ADR 005](adr/005-upstream-sync-strategy.md)).

Update this file at the end of every phase/checkpoint, same discipline as `CHANGELOG.md`.

## Current State

- **20 security MCP servers** (recon, osint, intel, web_vuln, hashcrack, spiderfoot, pdf,
  yara, sigma, exploit, transform, asset, attck, risk, findings, engagement, watchlist,
  monitor, host_telemetry, compliance), a Kali-based toolchain sidecar, SpiderFoot,
  OpenSearch-backed findings persistence, and BentoPDF — all wired through one detection
  pipeline (`docs/adr/007-security-detection-lifecycle.md`): every finding lands in
  `findings_server`/`asset_server`, every engagement gets one timeline, one event
  (`security_finding_added`), one notification path (`dispatch_reminder`).
- A from-scratch dark-first design system (Chakra Petch / IBM Plex Sans / IBM Plex Mono,
  the "Duality" blue/crimson palette, a sharper/flatter shape language) applied app-wide,
  not just the security surfaces.
- Renamed from "Odysseus Red" to **Chiron** — see
  [ADR 008](adr/008-project-rebrand.md) for the naming rationale and exactly what did and
  didn't change.

## Phase History

- [x] **Phase 0 — Naming.** Chiron, picked after a collision check against existing
      security tooling and open-source projects.
- [x] **Phase 1 — 8 backend red/blue additions**, shipped as v0.6.0: Sigma/YARA sweeps,
      host telemetry, remediation verification, multi-target recon, a NIST 800-53 OSCAL
      compliance server, one-call PDF engagement reports, a security dashboard, release
      packaging. `CHANGELOG.md`'s `[0.6.0]` section has the full list.
- [x] **Phase 2.1 — Measure how token-driven the CSS already was**, to scope the redesign
      honestly instead of guessing: color was ~90% centralized, shape (radius/shadow) was
      0% — that gap became 2.3's actual scope.
- [x] **Phase 2.2 — Design system tokens.** Palette, type, and a new shape-token layer
      defined and made live across `style.css` and `theme.js`.
- [x] **Phase 2.3 — Apply the shape language app-wide.** ~1,098 hardcoded `border-radius`
      declarations and 117 elevation `box-shadow` layers swept onto the new tokens; ~380
      stale `var(--token, #oldhex)` defensive fallbacks cleaned up along the way (this also
      caught and fixed a genuine pre-existing bug, an `--hl-string` fallback that never
      matched its own token's real value).
- [x] **Phase 2.5 — Rebrand visual assets** (new wordmark, new shield icon replacing the
      old boat icon) — done together with Phase 3, since both are "the new identity becomes
      real" work.
- [x] **Phase 3 — Rebrand.** "Odysseus Red" → "Chiron" across the live UI and the fork's own
      docs/config; the underlying upstream platform's own name, its container/service names,
      and its `ODYSSEUS_*` env var prefix were deliberately left alone (renaming those would
      break every existing self-hosted install for no real gain). Full scope and rationale
      in [ADR 008](adr/008-project-rebrand.md).

## Near-Term

- [ ] **Phase 2.4 — Security Hub UI.** The security dashboard (Phase 1 checkpoint G) already
      renders with the new design system, but engagements, watchlist entries, and Sigma/YARA
      rules are still chat/MCP-only — no way to browse or manage them from the web UI. Add
      thin list/CRUD endpoints over `engagement_server`/`watchlist_server`/`sigma_server`/
      `yara_server`'s existing private helpers (same pattern as
      `routes/security_dashboard_routes.py`), plus the panels to drive them.

## Ideas, Not Commitments

Pulled from a standing gap audit and re-checked against the current codebase before being
listed here, so this section doesn't rot into a wishlist of things already shipped:

- **Structured audit logging for tool invocations.** Only one MCP server module currently
  uses Python's `logging` module in any real way — there's no consistent "what ran, against
  what target, when, by which engagement" trail across all 20 security servers. Findings
  persistence covers *results*; this would cover *actions*, which matters more once this is
  ever run somewhere with more than one operator.
- **Rate limiting on MCP tool calls.** Nothing currently stops an agent loop from firing
  `nmap`/`nuclei`/`sqlmap` back-to-back with no backoff. Low risk solo-operator, real risk if
  this is ever pointed at infrastructure that isn't fully owned by the operator.
- **STIX/TAXII threat-intel feed ingestion** into `intel_server`, beyond the existing
  on-demand Shodan/VirusTotal/OTX/Censys/CVE lookups — a standing feed instead of
  query-on-demand.
- **Incident-response playbooks** as a skill category, similar in spirit to the existing
  `skills/threat_hunting/detection_engineering.yaml` but for response rather than detection.
- Heavier SIEM/EDR/PCAP tooling (Velociraptor, Wazuh, Zeek/Arkime) was in an earlier version
  of this list and has been deliberately dropped — that's a different product shape (a
  team-operated SOC stack) than a self-hosted single-operator AI workspace. Not planned
  unless the project's actual usage pattern changes.

Before promoting anything from this section to "Near-Term," re-verify it's still actually
missing — this codebase moves fast enough that yesterday's gap is sometimes today's shipped
feature (Censys, `ffuf`/`amass`/`subfinder`/`httpx`/`trivy` in the toolchain, and exec-API
Bearer auth were all on an earlier version of this list before being confirmed already done).
