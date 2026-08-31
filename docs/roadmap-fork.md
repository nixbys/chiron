# Chiron Roadmap (Fork-Specific)

This tracks work on **this fork's own additions** — the security overlay, its MCP servers,
and the rebrand/redesign that brought the two together under one identity. It does not cover
the base platform; see [`ROADMAP.md`](../ROADMAP.md) for that (upstream-owned — never edited
here, per [ADR 005](adr/005-upstream-sync-strategy.md)).

Update this file at the end of every phase/checkpoint, same discipline as `CHANGELOG.md`.

## Current State

- **22 security MCP servers** (recon, osint, intel, web_vuln, hashcrack, spiderfoot, pdf,
  yara, sigma, exploit, msf, transform, asset, attck, risk, findings, engagement, watchlist,
  monitor, host_telemetry, compliance, audit), a Kali-based toolchain sidecar, SpiderFoot,
  OpenSearch-backed findings persistence, and BentoPDF — all wired through one detection
  pipeline (`docs/adr/007-security-detection-lifecycle.md`): every finding lands in
  `findings_server`/`asset_server`, every engagement gets one timeline, one event
  (`security_finding_added`), one notification path (`dispatch_reminder`). Every toolchain
  invocation (not just findings) is also audited and rate-limited. Chat sessions can be
  linked to an engagement ("Project") and get real-time scope enforcement (block by default,
  audited override) on every tool call with a network target.
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
      in [ADR 008](adr/008-project-rebrand.md). A follow-up pass also caught several
      "Odysseus" strings the file-level sweep missed because JS writes them into the DOM at
      runtime rather than sitting in `index.html` source (chat placeholder, assistant role
      labels, onboarding copy, various toasts/tooltips) — see `CHANGELOG.md`'s Unreleased
      section for the full list and what was deliberately left alone (the built-in
      "Odysseus" AI persona, an Odyssey-themed research example, an easter egg, real
      `swift/odysseus-mlx-image-bridge` path references, the `X-Odysseus-Run-Id` wire header).
- [x] **Phase 2.4 — Security Hub UI.** The security dashboard is now a tabbed Security Hub —
      Overview (unchanged) plus Engagements (browse/expand/create/close), Watchlist
      (browse/add/pause/resume/remove), Rules (browse + view raw content for stored Sigma
      rules and YARA rule names), and Connected Services (below). Every write goes through
      the same MCP server module's `call_tool()` the chat/MCP-tool path already used, not a
      second write path. See `CHANGELOG.md`'s Unreleased section for the full list of new
      structured-read helpers each `mcp_servers/*.py` module gained.
- [x] **Phase 2.4 follow-up — Security Hub is a standalone page, plus real sidecar access.**
      Converted from a modal to a real page at `/security` (`static/security.html` +
      `static/js/securityHub.js`) — every other sidebar tool deep-links into the chat SPA's
      modal system, but this gets its own page shell instead, matching how `/login` is a
      standalone page rather than another modal. New Connected Services tab
      (`GET /api/security/services`) links directly to BentoPDF and SpiderFoot (now
      published on `127.0.0.1`, alongside the already-loopback-bound OpenSearch/Ollama) with
      live server-side-probed reachability; the toolchain's exec API is shown status-only,
      never a clickable link (arbitrary command execution surface). Bringing the full
      containerized stack up for real (not the native-Python shortcut used for most UI work)
      surfaced and fixed 5 real bugs that had never been exercised before — toolchain
      tool-install URLs, OpenSearch's startup password validation, a `findings_server.py`
      crash on its own steady-state `HEAD` check, and two `yara_server.py` calls that used
      binaries the toolchain's own exec-API allowlist didn't permit. Full details in
      `CHANGELOG.md`'s Unreleased section.
- [x] **Audit trail + rate limiting for toolchain invocations, plus a CyberChef sidecar.**
      Both had been sitting in "Ideas, Not Commitments" below since Phase 2.4 — closed the
      gap directly in `mcp_servers/common.py`'s `exec_in_toolchain()` (the one chokepoint
      every red-team MCP server's calls pass through), so no changes were needed in any of
      the other 20 server modules. New `audit_server.py` (21st security MCP server) is the
      read side: `audit_list`/`audit_stats` tools, plus a new Audit Log tab in the Security
      Hub (`GET /api/security/audit`). Rate limiting reuses the same audit table as its own
      source of truth for a *global* per-binary limit across every MCP server process
      (`TOOLCHAIN_RATE_LIMIT`/`_WINDOW`/`_<BINARY>` env vars). New
      `scripts/register_fork_mcp_servers.py` registers all 21 fork servers against a running
      instance in one shot (idempotent) — added after finding that a real, long-running
      instance had only ever had the original 7 servers registered via Settings; Odysseus
      has no static MCP config file by design, so this doesn't change that, it just closes
      the "click through Settings 21 times" gap for a fresh install or a fork update.
      CyberChef (`docker.io/mcoutinho/cyberchef` on `127.0.0.1:8000`, per the standing
      "Connected Services" pattern) rounds out the manual-analyst-workflow story next to a
      Kali toolchain. Full details in `CHANGELOG.md`'s Unreleased section.
- [x] **Engagement-scoped Projects + `msf_server` (Phases A-D of a plan approved 2026-08-29,
      executed 2026-08-30).** Chat sessions can be linked to an Engagement; any tool call with
      a real network target is checked against that engagement's declared scope before it
      runs, block by default with an audited override. New 22nd MCP server, `msf_server`
      (Metasploit `msf_search`/`msf_module_info`, read-only). Security Hub gained the missing
      `out_of_scope` field, a "New Project" flow, a manual link-to-engagement action, and an
      Audit Log engagement filter + badges for the two new scope outcomes. Full details in
      `CHANGELOG.md`'s Unreleased section.
- [x] **Engagement-scoped Projects addenda, Phases E-H (same plan).** RoE/SOW PDF scope
      ingestion (extract-and-review, never auto-commit); a `scope_violation_check` scheduled
      action for batched reminders on scope events (polling, not push — `check_scope()` runs
      in an MCP server subprocess with no way to call `dispatch_reminder()` directly); a
      "Project" badge in the chat header itself; a new `secrets_scan` tool on `osint_server`
      (gitleaks against a cloned repo's full history, redacted output, flag-injection-safe).
      Full details in `CHANGELOG.md`'s Unreleased section.
- [x] **Engagement-scoped Projects, Phase I (second-order addendum, on top of Phase E).**
      Temporal scope: engagements can declare a daily authorized testing window and blackout
      dates; `check_scope()` enforces both independently of target scope, same block/override
      shape. RoE/SOW parsing extracts candidates for both. Full details in `CHANGELOG.md`'s
      Unreleased section.
- [x] **Engagement-scoped Projects, Phase J (second-order addendum, on top of Phase F).**
      Escalation: a rolling pattern of scope violations on one engagement (3+ in 24h by
      default, both tunable via env vars) files a real `findings_server` finding instead of
      only ever being a dismissible reminder. Fires once per crossing. Full details in
      `CHANGELOG.md`'s Unreleased section.

## Near-Term

The same plan's remaining second-order addenda (Phase K: a first-run unscoped-session nudge;
Phase L: wiring `secrets_scan` findings into the correlation fabric) are approved but not
started — see the durable copy at `/home/nixbys/.claude/projects/-var-home-nixbys-source-repos-
odysseus-red/memory/engagement_scope_enforcement_plan.md` for full design detail. Otherwise
nothing else is queued; see "Ideas, Not Commitments" below for what's next if this fork keeps
growing.

## Ideas, Not Commitments

Pulled from a standing gap audit and re-checked against the current codebase before being
listed here, so this section doesn't rot into a wishlist of things already shipped:

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
