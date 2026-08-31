# Changelog

All notable changes to **Chiron** (this fork, formerly named Odysseus Red) are documented here. Changes to the upstream Odysseus platform appear in the [upstream repository](https://github.com/pewdiepie-archdaemon/odysseus).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Releases in progress may be tagged `vX.Y.Z-alpha.N` / `-beta.N` / `-rc.N` before the final `vX.Y.Z` — see [ADR 006](docs/adr/006-release-channel-strategy.md). Those prerelease tags don't get their own section here; their GitHub Release notes are generated from whatever's under `[Unreleased]` at tag time.

---

## [Unreleased]

### Added
- **`scripts/demo_full_stack.py`** — a single guided-tour script exercising all 22 fork
  security MCP servers (and, through them, every sidecar: the Kali toolchain, SpiderFoot,
  OpenSearch, BentoPDF, CyberChef) under one Engagement, speaking the real MCP stdio protocol
  directly to each server rather than depending on the chat/LLM tool-calling layer. Run it
  inside the app container with `python3 scripts/demo_full_stack.py`.

### Fixed
- **Five real bugs found while building and live-testing the new demo script above** —
  each confirmed against the running stack, not just reasoned about:
  - `mcp_servers/common.py`'s `_target_matches()` (Phase A/I scope enforcement) never
    extracted a bare hostname from a URL-shaped target before comparing, so a scope entry
    declared as e.g. `"odysseus-cyberchef"` could never match a `web_vuln_server` tool's
    full-URL target (`"http://odysseus-cyberchef:8000"`) — every such call was wrongly
    blocked as out-of-scope. Fixed by also trying `urlparse(value).hostname` when the target
    looks like a URL.
  - `findings_server.py`'s `finding_index` defaulted a missing `ip` argument to `""`, which
    OpenSearch's `ip`-typed field mapping rejects outright (`mapper_parsing_exception`) —
    every finding indexed without an IP failed. Fixed to omit the field entirely when the
    caller doesn't provide one.
  - `spiderfoot_server.py`'s `_start_scan()` posted to `/startscan` without `typelist`/
    `modulelist`, which this SpiderFoot build 404s on ("Missing parameters") even with
    `usecase` set — every scan start failed. Fixed by including both, empty, alongside
    `usecase`. On success this build also returns the scan-list HTML page as the response
    body instead of the new scan's ID; added a fallback lookup by scan name via `/scanlist`.
  - `spiderfoot_server.py`'s `_get_status()` treated `/scanstatus/<id>`'s response as a
    list-of-rows and indexed `data[0]` — but it's actually one flat row directly. `data[0]`
    silently picked off the scan's *name string* and indexed into its individual characters,
    so the parsed "status" could never equal `"FINISHED"`/`"ABORTED"`/`"ERROR-FAILED"` and
    `_wait_for_scan()`'s poll loop ran until timeout no matter how fast the scan actually
    finished. Fixed to read the flat row directly.
  - `spiderfoot_server.py`'s `_get_results()` called `/scaneventresults/<id>` as a path
    segment (404s — SpiderFoot takes `id`/`eventType` as query params) with a wrong field
    mapping (`type` assumed to be the row's first element; it's actually the last, per
    SpiderFoot's own `sfwebui.py`). Fixed both the request shape and the field indices.
- **The env-passthrough bug the demo script itself needed fixing for**: `mcp.
  StdioServerParameters(env=None)` does NOT mean "inherit the parent process's environment"
  — the `mcp` package's `stdio_client` treats `None` as "use only a hardcoded safe-inherit
  allowlist" (`HOME`/`LOGNAME`/`PATH`/`SHELL`/`TERM`/`USER`), silently dropping
  `EXEC_API_TOKEN`, `SHODAN_API_KEY`, `OPENSEARCH_URL`, `SPIDERFOOT_URL`, `BENTOPDF_URL`, and
  every other secret/URL the spawned MCP server subprocess actually needs. This produced two
  distinct, initially-confusing failures — every toolchain-backed tool call 401ing, and
  `shodan_host` reporting `SHODAN_API_KEY not set` despite the key being correctly set in the
  parent container's own environment — both traced to the same root cause and both fixed by
  passing `env=dict(os.environ)` explicitly.
- **Ollama unreachable from the app container (`Cannot reach http://odysseus-ollama:11434`)**,
  plus a real, separate bug found while chasing it: `docker-compose.security.yml`'s `odysseus`
  service hardcoded `OLLAMA_BASE_URL`/`LLM_HOST` with no `.env` interpolation at all, so the
  var's own neighboring `.env` comment ("change this to point at a host Ollama instead") was
  never actually true — editing `.env` had zero effect whenever this overlay was in use.
  Fixed both to `${VAR:-default}`, matching every other overlay var's own pattern. The
  unreachable-container symptom itself was a leftover from re-running `podman-compose up`
  under this repo's new "chiron" project name (after the local rename from odysseus-red):
  podman found the sidecars' fixed `container_name`s already claimed by *stopped* containers
  from the old "odysseus-red" project and just started those instead of creating fresh ones —
  landing them on the old `odysseus-red_default` network while the freshly built `chiron_*`
  containers sat on a different `chiron_default` network, so they could never resolve each
  other by hostname despite all being "up." Recreating the affected containers (stop, `rm`,
  re-`up`) put everything on one network again; the 19GB of already-pulled Ollama models
  living in the orphaned `odysseus-red_ollama-models` volume were copied over rather than
  re-downloaded.
- **Ollama now pulls a default model automatically.** New `ollama-pull` one-shot init service
  in `docker-compose.security.yml` (not gated behind any profile, like `ollama` itself):  pulls
  `DEFAULT_OLLAMA_MODEL` (default `llama3.2:3b`, `.env`-configurable) into the `ollama` sidecar
  on every `up`. `ollama pull` is idempotent against an already-present model (confirmed: a
  second run completes in well under a second, vs. a real multi-second transfer on the first),
  so this doesn't meaningfully slow down a normal `up` once the model's there — a fresh install
  now has a usable local model without a manual `ollama pull` step.
- Phase 2.4's own `yara_server.py` additions were broken against the real toolchain sidecar
  (only ever exercised through mocked tests until this session actually got the container
  stack running): `_list_rule_names()` used `sh -c "ls ... 2>/dev/null"`, but the exec API's
  `ALLOWED_BINARIES` allowlist (`docker/toolchain/exec_api.py`) deliberately has no
  general-purpose shell — every call 400'd with `binary_not_allowed`. `_read_rule()` used
  `cat`, which was never in that allowlist either. Fixed `_list_rule_names()` to call `ls`
  directly (treating "No such file or directory" — a nonexistent rules dir — as "no rules
  yet" instead of an error) and added `cat` to `ALLOWED_BINARIES` (a plain read-only utility,
  no more capable than `grep`, already on the list). Verified against the real toolchain
  container: `Rules` tab now lists and displays a real YARA rule end-to-end.
- Five Kali toolchain binaries (`nuclei`, `httpx`, `subfinder`, `amass`, `trivy`) were
  silently failing to install on every fresh build — `docker/toolchain/Dockerfile`'s
  fixed-filename `.../releases/latest/download/<name>_linux_amd64.zip` URLs 404'd
  unconditionally because ProjectDiscovery's tools and trivy now embed the version number in
  the release asset filename (e.g. `nuclei_3.11.1_linux_amd64.zip`, not
  `nuclei_linux_amd64.zip`); amass's URL also had the wrong case (`Linux` vs `linux`) and the
  wrong extension (`.zip` vs the real `.tar.gz`). Fixed by resolving each tool's actual latest
  release tag via the GitHub API first, then building the exact filename that tag really
  published. All five verified installing successfully in a real rebuild.
- The bundled OpenSearch service couldn't start at all: `OPENSEARCH_INITIAL_ADMIN_PASSWORD`
  defaults to the literal string `admin`, which OpenSearch 2.12+'s security plugin rejects
  outright (needs 8+ chars with upper/lower/digit/special), so the container crash-looped
  indefinitely on every start. `docker-compose.security.yml`'s own comment already said
  "Disable security plugin for dev" but the default value did the opposite (`plugins.security.
  disabled` defaulted to `false`, i.e. enabled) — flipped the default to match the stated
  intent, and to match `findings_server.py`/`sigma_server.py`'s own plain-`http://` default
  for `OPENSEARCH_URL` (the security plugin also forces HTTPS, which those callers were never
  set up for either). A production deployment that wants OpenSearch's own auth on top of
  Chiron's can still opt in via `OPENSEARCH_SECURITY_DISABLED=false` + `https://` + a real
  `OPENSEARCH_PASSWORD`.
- `findings_server.py`'s `_ensure_index()` crashed on every call after the very first one:
  its `HEAD` existence-check response never carries a body (per HTTP spec), but `_req()`
  unconditionally called `.json()` on every response, so once the index existed, the empty
  body raised `json.JSONDecodeError` — an exception `_ensure_index`'s own `except requests.
  HTTPError` clause doesn't catch, so it escaped uncaught into every findings-summary/search
  call as `Expecting value: line 1 column 1 (char 0)`. This had presumably been broken since
  the feature was written; it was only just discovered because OpenSearch itself had never
  successfully stayed up long enough to exercise it (see above). Fixed `_req()` to skip
  `.json()` on an empty response body. New `tests/mcp_servers/test_findings_server.py`
  (the module had no dedicated tests before this) covers the regression directly.
- The new Security Hub Audit Log tab (see Added below) 500'd on a brand-new instance's very
  first request: `routes/security_dashboard_routes.py` ran `audit_server._list_invocations()`
  and `_stats()` concurrently via `asyncio.gather`, and on a fresh `audit.db` both threads
  raced through `_get_db()`'s one-time `CREATE TABLE`/`CREATE INDEX` setup, one of them losing
  the race with `sqlite3.OperationalError: database is locked` even with a 10s connect
  timeout. Fixed by making the two calls sequential in the route handler. Verified with 5
  repeated cold-start requests all returning 200, then a real `exec_in_toolchain()` call
  showing up correctly in the tab afterward. New `test_concurrent_first_access_does_not_deadlock`
  in `tests/mcp_servers/test_audit_server.py` guards `_get_db()` itself against the same race.
- `ACKNOWLEDGMENTS.md` had one genuine leftover "Odysseus Red" reference the Phase 3 rebrand's
  line-based sweep missed because it was wrapped across two source lines
  (`**Odysseus\nRed** (this fork)`) — fixed to `**Chiron** (this fork)`.

### Added
- **Engagement-scoped "Projects" + a Metasploit MCP server.** Chat sessions can now be
  linked to an Engagement (`Session.engagement_id`, new migration), and any tool call with a
  real network target is checked against that engagement's declared `scope`/`out_of_scope`
  before it runs — block by default, with an explicit `override_scope=true` (+
  `override_reason`) always logged as its own flagged audit outcome (`scope_override`), never
  a silent pass-through; a plain block logs `blocked_out_of_scope`. New `check_scope()`/
  `_target_matches()` (exact/CIDR/domain-suffix) in `mcp_servers/common.py`, reading
  `engagement_server`'s own SQLite directly (the fork's standard no-cross-import pattern).
  Wired into every tool with a real target: `recon_server`, `web_vuln_server`, `osint_server`,
  `intel_server`, `watchlist_server` (skipped for hash indicators, which have no network
  scope); `yara_server`'s `yara_scan` gets `engagement_id` audit tagging only (a filesystem
  path has no in/out-of-scope concept). `src/tool_execution.py`'s MCP dispatch auto-injects a
  linked session's `engagement_id` into these calls (mirroring the existing email-owner
  injection precedent) — a model-supplied `engagement_id` in the call always wins. Security
  Hub: the Engagements tab gained the missing `out_of_scope` field (the backend already
  accepted it) and a "New Project" flow that creates an engagement and a linked chat session
  in one step; existing sessions get a manual "Link current chat" action; the Audit Log tab
  gained an engagement filter and badges for the two new outcomes. New 22nd MCP server,
  `msf_server` (Metasploit): `msf_search`/`msf_module_info`, read-only module search/info via
  a one-shot `msfconsole -q -x` — no RPC daemon, no session-driven exploit execution, that's a
  separate follow-up. Also fixed a real bug found while wiring the Audit Log's new filter
  through: `GET /api/security/audit` called `audit_server._list_invocations(binary, outcome,
  limit)` positionally, so inserting `engagement_id` before `limit` in that function's
  signature had been silently passing `limit` into the `engagement_id` slot — every existing
  test for the route mocks the function entirely, so none of them caught it.
- **Four follow-on additions to the Engagement-scoped Projects work above** (approved
  addenda, same plan): (1) RoE/SOW PDF scope ingestion — new `POST /api/security/
  roe/parse-scope` extracts IP/CIDR/domain-shaped candidate targets from an uploaded
  authorization document (`pdf_server.py`'s existing `pdf_extract_text`, validated the same
  way every other target-taking tool validates one) and pre-fills the "New Project" form's
  scope field — reviewed and confirmed by the user, never auto-committed. (2) A new
  `scope_violation_check` scheduled action polls the audit trail for new
  `blocked_out_of_scope`/`scope_override` rows and sends one batched reminder per run, the
  same polling shape every other drift-detection reminder in this fork already uses (`check_
  scope()` runs inside an MCP server subprocess and has no way to call `dispatch_reminder()`
  itself). (3) A "Project" badge in the chat header itself when the active session is linked
  to an engagement, linking through to that engagement's Security Hub detail view — `GET
  /api/sessions` now also reports each session's `engagement_id`. (4) New `secrets_scan` tool
  on `osint_server` (the 22nd server's 23rd tool, no new server needed): clones a git repo and
  scans its full history for leaked credentials with `gitleaks` (new toolchain sidecar
  dependency, plus `rm` newly allowlisted in `docker/toolchain/exec_api.py` so the tool can
  clear its own fixed scratch checkout before each run) — matched secret values are redacted
  in the output, never shown in full, and a crafted `repo_url` starting with `-` is rejected
  outright (closes a `git clone` flag-injection vector, e.g. `--upload-pack=...`, before it
  shipped).
- **Temporal scope, on top of the RoE/SOW ingestion above (Phase I of the same plan).**
  Engagements can now declare a daily `authorized_hours` window (`HH:MM-HH:MM`, server-local)
  and `blackout_dates` (`YYYY-MM-DD`) — new columns + migration on `engagement_server.py`'s
  `engagements` table, new `engagement_create`/`engagement_update` fields. `check_scope()`
  gains a second, independent check alongside target scope: an in-scope target run outside
  the authorized window, or on a blackout date, is still blocked (same block-by-default +
  logged-override shape, reusing the existing `blocked_out_of_scope`/`scope_override`
  outcomes rather than adding new ones — the audit `detail` field explains which check
  actually failed). `POST /api/security/roe/parse-scope` also extracts a candidate time
  window and blackout dates from the uploaded document now, pre-filling both new form fields
  the same reviewed-not-auto-committed way target candidates already work.
- **Escalation, on top of the scope_violation_check reminders above (Phase J of the same
  plan).** A single override is normal pentest work (scope sometimes legitimately expands
  mid-engagement); a *pattern* is a signal worth a permanent record. `scope_violation_check`
  now also tracks each engagement's rolling violation count and, once
  `SCOPE_VIOLATION_ESCALATION_THRESHOLD` (default 3) is crossed within
  `SCOPE_VIOLATION_ESCALATION_WINDOW_HOURS` (default 24), files one `findings_server` finding
  (severity `medium`, tagged `process`/`scope-deviation`) plus an `engagement_server` timeline
  event — fires exactly once per crossing (computed as "count before this run's new rows was
  under the threshold, count including them is at or over it"), not on every subsequent poll
  once an engagement is already over. New `audit_server._count_scope_violations_in_window()`
  helper backs the rolling count.
- **A soft nudge for unscoped sessions, on top of the chat-header Project badge (Phase K of
  the same plan).** The complementary case to the badge (Phase G): the first time a session
  with no linked engagement runs a scope-enforceable tool, its result now carries one small
  notice ("this chat isn't linked to a Project...") — then never repeats for the rest of that
  chat. Nudge, not a gate: unscoped execution stays fully allowed, exactly as before. In-
  memory and best-effort by design (a process restart can re-nudge a long-lived session once
  more — an accepted trade-off for something this low-stakes, not worth a persisted column).
  Also fixed a real gap found while wiring this: `secrets_scan` (Phase H) was added to
  `osint_server.py`'s own `check_scope_from_args` call but never to `src/tool_execution.py`'s
  `_ENGAGEMENT_SCOPED_MCP_TOOLS` set, so a linked session's `engagement_id` was silently never
  auto-injected into it — the tool worked, but only ever as if called from an unscoped session
  unless the model happened to pass `engagement_id` explicitly.
- **Feed `secrets_scan` discoveries back into the correlation fabric (Phase L, the last phase
  of the same plan).** A leaked secret was previously a dead-end chat message; a positive
  `secrets_scan` result now auto-files a `findings_server` finding (severity `high`, tagged
  `secrets`/`credential-leak`) the same way every other detector in this fork's pipeline does
  (ADR 007) — parsed best-effort from gitleaks' own `-v` summary line ("leaks found: N"), same
  scrape-free-text-output philosophy `action_scheduled_recon`'s own parser already documents.
  `osint_server.py` can't file this itself (MCP servers never call another server's tools
  directly); it happens in `src/tool_execution.py`'s MCP dispatch layer instead — the one
  place that already sits between every call and its result with a live MCP manager on hand.
  Deliberately doesn't also watchlist the leaked value (the one further step the plan left
  optional): `--redact` never exposes the actual secret, and un-redacting it just to enable
  watchlisting would undo the exact safety property that flag exists for.
- **Toolchain invocation audit trail + rate limiting**, both enforced at `mcp_servers/
  common.py`'s `exec_in_toolchain()` — the one chokepoint every red-team MCP server's tool
  calls pass through, so no changes were needed in any of the other 20 server modules. Every
  call is now logged (binary, arguments, exec mode, duration, outcome) to a new WAL-mode
  SQLite table (`$ODYSSEUS_DATA_DIR/audit.db`), and the same table backs a hard per-binary
  rate limit (`TOOLCHAIN_RATE_LIMIT` invocations per `TOOLCHAIN_RATE_LIMIT_WINDOW` seconds,
  with `TOOLCHAIN_RATE_LIMIT_<BINARY>` overrides — same override shape as the existing
  `TOOLCHAIN_EXEC_MODE_<BINARY>`) checked against the table directly rather than an
  in-memory counter, since every MCP server is its own subprocess and an in-memory counter
  would only ever throttle one server's own calls. A rejected call returns
  `[error:rate_limited]` immediately without reaching the toolchain, and is itself logged
  with that outcome. New `audit_server` MCP server (the 21st) is the read side —
  `audit_list` and `audit_stats` tools — since `common.py` itself only ever writes.
- Security Hub gained a sixth tab, **Audit Log** (`GET /api/security/audit`): every toolchain
  invocation, filterable by binary/outcome, with a trailing-24h summary row.
- New **CyberChef** sidecar (`docker.io/mpepping/cyberchef:latest`, Apache-2.0), listed in
  Connected Services alongside BentoPDF/SpiderFoot/OpenSearch/Ollama — a pure link target for
  manual encode/decode/crypto work; no MCP server calls it programmatically, so unlike the
  other sidecars there's no `CYBERCHEF_URL` to redirect if you'd rather use the public
  instance or a native install.
- New `scripts/register_fork_mcp_servers.py`: idempotent bulk-registration script for all 21
  fork security MCP servers against a running instance's own `POST /api/mcp/servers` API —
  reads current registrations back first and only adds what's missing, so it's always safe to
  re-run after a fork update. Closes a real practical gap found by inspecting a live,
  long-running instance directly: Odysseus's MCP servers are rows in the app's own database by
  design (no static config file — see `docs/develop-mcp-servers.md`), so a fresh install or a
  fork update that adds a server otherwise means clicking through Settings once per server
  with no way to check what's still missing.
- Security Hub "Connected Services" tab plus real host access to the sidecars it lists:
  SpiderFoot and OpenSearch are now published on `127.0.0.1` (matching BentoPDF's and
  Ollama's existing loopback-only posture — `docker-compose.security.yml` already had a
  comment anticipating this exact change for SpiderFoot). The toolchain's exec API is
  deliberately still never published, not even to loopback — it accepts arbitrary command
  execution. New `GET /api/security/services` reports live reachability (probed server-side
  against each sidecar's internal container address, so the browser never needs a CORS
  workaround) plus the loopback URL to open each one.
- Security Hub is now a genuinely standalone page (`/security`, `static/security.html` +
  `static/js/securityHub.js`) instead of a modal — every other sidebar tool (Notes, Calendar,
  Gallery, ...) deep-links into the chat SPA's own modal system, but Security Hub gets its
  own page shell (header, tab bar, back-to-chat link) the same way `/login` does, not a
  floating dialog over the chat. Same five tabs, same REST endpoints, same `.sec-*`
  component CSS — only the chrome changed. The old modal (`static/js/securityDashboard.js`)
  is retired; the sidebar/icon-rail button now does a real navigation instead of toggling it,
  and its label changed from "Security Dashboard" to "Security Hub" to match.
- New PWA icons (`static/icons/icon-192.png`, `icon-512.png`, `icon-maskable-512.png`) — the
  new crimson shield mark on the Duality dark background, replacing icons generated before
  the rebrand (the old boat logo in the pre-redesign pink/rose palette). A new README hero
  screenshot (`docs/chiron-interface.png`, a real Playwright capture of the current
  interface) replaces `docs/odysseus-browser.jpg`; a second, unreferenced pre-rebrand
  screenshot (`docs/odysseus.jpg`) was also removed.

- Security Hub management sub-panels (Phase 2.4): the security dashboard
  (Phase 1 checkpoint G) is now a tabbed Security Hub — Overview (the
  original aggregated snapshot, unchanged) plus Engagements, Watchlist, and
  Rules. Engagements: browse, expand for scope/timeline detail, create,
  close. Watchlist: browse, add, pause/resume, remove. Rules: browse
  stored Sigma rules and YARA rule names (the latter via the toolchain
  sidecar, reporting "toolchain sidecar unreachable" as a normal degraded
  state rather than an error when it's down) with a raw-content viewer for
  either. Every write goes through the *same* MCP server module's
  `call_tool()` the chat/MCP-tool path already used — `routes/
  security_dashboard_routes.py`'s new `_call_tool()` helper awaits it
  directly and maps its `[error:code]` convention onto an HTTP status, so
  there's exactly one place each write's validation lives, not a second
  copy reimplemented in SQL for the REST route. New structured (JSON, not
  text-table) read helpers added to `engagement_server.py`
  (`_get_timeline`), `watchlist_server.py` (`_list_watchlist`,
  `_list_checks`), `sigma_server.py` (`_list_rules`, `_read_rule`), and
  `yara_server.py` (`_list_rule_names`, `_read_rule`) — each also adopted
  by that module's own MCP tool handler in place of its old inline query,
  so the dashboard and the chat/MCP path share one source of truth instead
  of two. New `.sec-hub-btn`/`.sec-hub-input`/`.sec-rule-item` component
  CSS alongside the existing `.sec-*` primitives; reuses the site's
  existing `.admin-tab` tab-bar component for the new tab strip rather
  than inventing another one.

### Changed
- README consistency pass: reworded or removed every remaining "Odysseus" reference that
  wasn't either (a) the explicit upstream-credit line/badge/link, or (b) a real technical
  identifier (`ODYSSEUS_*` env vars, the `odysseus`/`odysseus-toolchain`/`odysseus-spiderfoot`/
  `odysseus-bentopdf` container names, the `odysseus-findings` OpenSearch index) that must
  stay as-is for running installs to keep working. Also refreshed two stale sections: "ADR
  001–006" → "ADR 001–008" in the repo-layout tree, the `modules/engagement_manager`/
  `finding_tracker`/`report_builder` placeholders (empty since the fork's initial scaffold
  commit, long since superseded by `engagement_server.py`/`findings_server.py`/`pdf_server.py`)
  no longer labeled "in development", and the "Security Dashboard" section rewritten to
  describe the actual four-tab Security Hub shipped in Phase 2.4 rather than the old
  single-page v1 description. `.gitignore`'s own "Odysseus-red additions" section header
  updated to "Chiron additions". `static/manifest.json`'s PWA description updated to describe
  Chiron's actual security-focused identity instead of the generic base-platform wording.
  The GitHub repository's own description/topics were also updated to match (credit to
  Odysseus retained in the description text). The local `origin` git remote now points
  directly at `https://github.com/nixbys/chiron.git` instead of relying on GitHub's redirect
  from the old `odysseus-red` URL.
- Found and fixed several "Odysseus" strings the Phase 3 rebrand's file-
  level sweep missed because they're written into the DOM by JavaScript
  rather than sitting in `index.html`/`login.html` source: `app.js`'s
  responsive chat-input placeholder and default session-name fallback;
  `chatRenderer.js`/`slashCommands.js`/`sessions.js`/
  `keyboard-shortcuts.js`'s assistant role labels shown in the chat
  transcript; onboarding-tour copy and various toast/tooltip/help text in
  `slashCommands.js`, `settings.js`, `emailLibrary.js`, `cookbook.js`,
  `cookbook-diagnosis.js`, `cookbookRunning.js`, `cookbookServe.js`,
  `document.js` (including a downloaded attachment-bundle filename,
  `odysseus-attachments.zip` → `chiron-attachments.zip`). Deliberately
  left alone: the built-in "Odysseus" AI persona (`presets.js`/`tasks.js`
  — a mythological-hero character, unrelated to the platform's own name),
  an Odyssey-themed research-topic example (`research/panel.js`) and an
  easter-egg quote (`slashCommands.js`), the real
  `swift/odysseus-mlx-image-bridge` checkout path referenced in a
  Cookbook shell snippet, the `X-Odysseus-Run-Id` wire header, and every
  internal-only function/variable name (`startOdysseusApp`,
  `_closeOdysseusAttachMenu`, etc.) — same rationale as ADR 008: rename
  user-facing branding, not internal identifiers or genuine mythological
  references that happen to share the name.
- Renamed the fork from "Odysseus Red" to **Chiron** (Phase 3). New wordmark
  (`docs/chiron-wordmark.png`, self-hosted Chakra Petch, replaces the deleted
  `docs/odysseus-wordmark.png`) and a new single-path shield icon (favicon,
  login logo, welcome screen) replacing the old three-path boat icon.
  "Odysseus" → "Chiron" swept through the live UI (`static/index.html`,
  `static/login.html`, `theme.js`, `manifest.json` — page titles, sidebar
  header, welcome screen, chat placeholder, settings/help text) and through
  the fork's own docs and config (`README.md`, `CONTRIBUTING.md`,
  `SECURITY.md`, `ACKNOWLEDGMENTS.md`, `.env.example`, `.github/CODEOWNERS`,
  CodeQL config, release-drafter, `ci-security.yml`, `release.yml`,
  `setup.py`, `mcp_servers/common.py`, `exploit_server.py`,
  `spiderfoot_server.py`, `scripts/mcp_health_check.py`). The fork-version
  constant `ODYSSEUS_RED_VERSION` is now `CHIRON_VERSION`
  (`src/constants.py`). Left deliberately untouched: the upstream "Odysseus"
  platform itself (its own code, container/service names like
  `odysseus-toolchain`, the `odysseus-*` env var prefixes, upstream-owned
  files per [ADR 005](docs/adr/005-upstream-sync-strategy.md)) and every
  historical ADR / dated changelog entry, which stay accurate to what was
  true when written. See [ADR 008](docs/adr/008-project-rebrand.md).
- Applied the Phase 2.2 design system's shape language app-wide (Phase 2.3):
  swept nearly all 1,098 hardcoded `border-radius` declarations in
  `style.css` onto the `--radius-sm/md/lg` scale (2/4/6px, capped well
  below the old up-to-20px range), added a `--radius-pill` token for the
  999px pill shapes. Circular (`50%`) and already-zero radii were left
  alone — a different shape language than "how rounded is this card,"
  not part of the sweep. Directional/asymmetric shadows (docked-panel
  edges, chat-bubble tails) shrunk proportionally rather than tokenized
  to a fixed scale, preserving direction/shape while flattening the
  effect — 117 pure-black elevation-shadow layers reduced (offset/blur
  ~35-40% of original, opacity ~80%); shadows using a themed color
  (focus rings, active-state outlines, glow/pulse indicators) were left
  untouched, they're functional state indicators, not decorative
  elevation. Verified with real Playwright screenshots against a locally
  booted instance (chat, calendar, notes, gallery, security dashboard,
  theme picker, injected `.msg`/`.msg-user`/`.msg-ai` bubbles) — no
  visual regressions, asymmetric bubble corners confirmed correct.
- Cleaned up the ~380 remaining `var(--token, #oldhex)` defensive
  fallback literals across `style.css` and 20 JS files (16 top-level +
  4 in subdirectories missed by an earlier pass) that still referenced
  pre-redesign hex values. These never actually triggered (the real
  tokens are always defined), but left dead/misleading literals in the
  source — fixed by looking up each fallback's *actual* current token
  value rather than a blind find-replace (this caught and fixed a
  pre-existing, unrelated bug: a `var(--hl-string, #98c379)` fallback
  that didn't match `--hl-string`'s real value at all, `#e5c07b`).
  Several bare (non-`var()`) literals also updated where they clearly
  tracked the old accent/success colors (a note-color swatch, a memory
  category tag, a search-icon SVG data-URI, an image-editor default
  brush color and active-handle indicator). Left alone: a calendar
  event-type color palette that coincidentally shared a hex with the
  old accent but is explicitly a fixed, theme-independent palette; two
  unlinked dev-prototype pages not in any route.
- New dark-first design system (Phase 2.2 of the rebrand/redesign):
  self-hosted Chakra Petch (display), IBM Plex Sans (body/interface), and
  IBM Plex Mono (code/data — replaces Fira Code as the default) via real
  `@font-face` rules (latin + latin-ext subsets); `--bg`/`--panel`/
  `--border`/`--fg` retinted to a near-black palette; `--red` retinted to
  a crimson offense accent; `--accent` (blue, defense) and `--fg-muted`
  *defined* in `:root` for the first time (previously silent phantom
  tokens — see Fixed below); new `--radius-sm/md/lg` shape tokens and a
  5-step `--sev-critical/high/medium/low/info` severity scale; new
  `.sec-badge`/`.sec-stat-tile`/`.sec-timeline` component classes, now
  used by the security dashboard instead of ad-hoc inline styles. Every
  first-paint surface (favicon, `<meta name="theme-color">`, the boot
  loader, `manifest.json`, the standalone login page) updated to match.
  All contrast pairs verified WCAG AA.

### Fixed
- `--accent` was referenced ~850 times across `style.css`
  (`var(--accent, var(--red))` fallback chains) but never once defined —
  every call site silently fell through to `--red`. `--fg-muted` was
  worse: 93 of its 101 call sites had no fallback at all, silently
  inheriting/unstyled. Both now defined for real.
- `static/fonts/Inter-{Regular,Medium,SemiBold}.woff2` sat on disk and 5
  CSS rules referenced `font-family: 'Inter', ...`, but no `@font-face`
  for Inter existed anywhere — it never actually loaded. Removed the
  dead files; those call sites now use the new `--font-body` token.
- `static/js/theme.js`'s `THEMES.dark`/`FONT_MAP.mono` set `--bg`/`--fg`/
  `--panel`/`--border`/`--red`/`--font-family` as inline styles on
  `:root`, which beat the stylesheet's own `:root` block entirely —
  updated to match, and documented that the two must be kept in sync by
  hand (no shared source of truth between them today).
- `static/js/securityDashboard.js` referenced a nonexistent
  `--border-color` token, always silently falling back to a hardcoded
  `#3336`.

---

## [0.6.0] — 2026-08-28

Eight additions rebalancing the security toolset from red-team-coded
toward genuinely red-*and*-blue, all wired hand-in-hand into the *same*
pipeline v0.5.0 established rather than as parallel systems — see
[ADR 007](docs/adr/007-security-detection-lifecycle.md) for the concrete
data-plumbing rule this release was built against. Scheduled Sigma/YARA
sweeps, defensive host telemetry, a remediation-verification loop,
multi-target recon, a NIST 800-53 compliance mapping server, one-call
engagement reporting, and a security dashboard aggregating all of it.
2 new MCP servers (20 total), 3 modified, 74 new tests.

### Added
- Security dashboard (`GET /api/security/dashboard`,
  `routes/security_dashboard_routes.py`, admin-gated) — an aggregated
  snapshot across the security MCP servers' own stores: findings summary
  (reuses `findings_server`'s `finding_stats` aggregation), active
  watchlist entries, recent scan drift across every scheduled task (new
  `monitor_server._list_recent_diffs`, an all-tasks variant of the
  existing per-task `monitor_diff_history`), the engagement list (new
  `engagement_server._list_engagements`), and a host telemetry summary.
  Every source is independently best-effort — one section failing never
  breaks the rest. Opens from a new "Security Dashboard" sidebar/rail
  button (`static/js/securityDashboard.js`). This is the minimal v1 page;
  a later redesign pass turns it into the full Security Hub.
- `generate_engagement_report` tool in `mcp_servers/pdf_server.py` — a
  one-call PDF summary for an engagement: scope/description/tags,
  a findings summary (severity/status counts plus top findings,
  best-effort from OpenSearch — the report still generates without that
  section if it's unreachable), and the recent timeline, in one PDF.
  Accepts an optional `compliance_summary` passthrough string (e.g.
  pre-built from `compliance_server`'s `nist_map`) instead of importing
  `compliance_server`. Duplicates minimal SQLite/OpenSearch read helpers
  from `engagement_server.py`/`findings_server.py` rather than importing
  them (same convention `sigma_server.py` already used), and reuses
  `generate_report`'s existing markdown-rendering pipeline rather than
  adding a second templating path.
- `mcp_servers/compliance_server.py` (20th MCP server) — NIST SP 800-53
  Rev 5 control lookup and mapping, same fetch-and-cache shape as
  `attck_server.py`: downloads and caches NIST's free OSCAL JSON catalog
  (`usnistgov/oscal-content` on GitHub, 7-day TTL). Tools:
  `nist_update`/`nist_control`/`nist_family`/`nist_search`/`nist_map`.
  `nist_map` maps ATT&CK tactic names and/or Odysseus finding tags to
  control families via a small hand-authored heuristic table — a rough
  compliance-summary grouping, explicitly not authoritative NIST
  guidance. CIS Controls v8 is deliberately out of scope — unlike NIST's
  OSCAL catalog, its control text isn't freely redistributable.
- Multi-target support for `scheduled_recon` (`src/builtin_actions.py`): the
  task prompt now also accepts a `"targets"` array (merged with a single
  `"target"` string if both are present) and a `"use_engagement_assets":
  true` flag that resolves targets from an engagement's own asset
  inventory (`asset_server`'s `asset_list`) instead of listing them by
  hand. One reminder is sent per run covering every target's drift, not
  one per target — same batching `watchlist_check` already used. Fully
  backward compatible with a single `"target"` string.
- `verify_remediation` scheduled-task action (`src/builtin_actions.py`) — the
  remediation-verification loop: re-checks every `scheduled_recon`-sourced
  finding marked `remediated` to confirm the underlying issue is actually
  still gone, reconstructing what to re-test entirely from the finding's
  own `title`/`description` (no separate state store). Reopens the
  finding + sends a reminder if it's back; logs a confirming
  `engagement_server` event if it's genuinely still remediated. Scoped to
  `scheduled_recon` findings only — deliberately not `watchlist_check`/
  `sigma_sweep`/`host_monitor` findings, none of which carry an
  equivalently well-defined single re-testable item.
- `sigma_sweep` and `yara_sweep` scheduled-task actions (`src/builtin_actions.py`)
  — the scheduled-sweep fast-follow `sigma_server`/`yara_server` called out
  in 0.5.0's "v1 is on-demand only" notes. `sigma_sweep` converts every
  stored Sigma rule (or a configured subset) and re-runs it against
  OpenSearch; `yara_sweep` re-runs `yara_scan` against a configured target
  in the Kali toolchain container. Both diff their results against the last
  stored snapshot (`monitor_server`, extended with per-rule/per-target
  check types) and only file a finding + send a reminder when something
  actually changed since the last sweep — same drift-only-alerting design
  as `scheduled_recon`/`watchlist_check`. `sigma_sweep` reads each rule's
  own `level:` field for the filed finding's severity.
- `mcp_servers/host_telemetry_server.py` (19th MCP server) + `src/
  builtin_actions.py`'s new `host_monitor` action — read-only host
  telemetry (processes, listening sockets, logged-in users, cron jobs,
  installed packages) for the host/container Odysseus itself runs in, via
  `psutil` rather than the Kali toolchain sidecar (querying the sidecar's
  own process list would be useless for defensive monitoring of anything
  real). `host_monitor` diffs each check against the last stored snapshot
  (`monitor_server`) the same drift-only-alerting way as the other
  scheduled actions, filtering out kernel-thread name churn
  (`kworker/N:M`, renumbered by the kernel constantly) before diffing so
  it doesn't look like drift on every run. Container-boundary caveat: when
  Odysseus runs in Docker (the default), this only sees the container's
  own namespace, not the true host — documented in the module and README,
  not solved in this pass.
- Shared `_file_drift_finding()` helper in `src/builtin_actions.py`,
  extracted from the file-a-finding-and-log-an-engagement-event block that
  `scheduled_recon`/`watchlist_check`/`sigma_sweep`/`yara_sweep`/
  `host_monitor` all repeated. Also fixes a real gap this surfaced:
  `watchlist_check` was filing findings but never logging the
  corresponding engagement timeline event; it now does, like every other
  drift-detecting action.

### Fixed
- `pdf_server.py`'s `generate_report` (and everything built on it, now
  including `generate_engagement_report`) could crash on any bulleted
  content: the bullet character was a Unicode "•", which isn't in
  Helvetica's latin-1 charset (`FPDFUnicodeEncodingException`) — replaced
  with a plain "-". Separately, none of `_render_line`'s `multi_cell`
  calls reset the cursor's x-position back to the left margin afterward
  (fpdf2's own default leaves it wherever the last wrapped line of text
  ended), so a bullet line immediately followed by a paragraph line could
  strand the next `multi_cell` with almost no width left to render into
  (`FPDFException: Not enough horizontal space to render a single
  character`) — every `multi_cell` call now explicitly passes
  `new_x=XPos.LMARGIN, new_y=YPos.NEXT`. Found while building
  `generate_engagement_report` above; no prior test exercised bullets
  followed by another line, so this had gone undetected.

---

## [0.5.0] — 2026-08-27

Five additions aimed at turning the security toolset from a one-shot toolbox
into something that keeps working while nobody's watching: case/engagement
grouping, continuous scheduled scanning with drift-only alerting, a
persistent IOC watchlist, notification wiring for both (reusing the existing
reminder-channel system — no new channel), and a Sigma detection-rule server
closing the log-detection gap next to YARA's file-pattern detection. 4 new
MCP servers (18 total), 2 modified, 61 new tests.

### Added
- `mcp_servers/sigma_server.py` — a new MCP server for authoring and
  testing Sigma detection rules, the log-detection complement to
  `yara_server.py`'s file-pattern detection. Runs entirely in-process
  (no Kali sidecar — Sigma rules match structured log/finding data, not
  files) via the optional `pysigma` + `pysigma-backend-opensearch`
  packages (`requirements-optional.txt`); without them,
  `sigma_rule_write`/`list`/`delete` still work (a rule just needs to be
  valid YAML), and `sigma_rule_convert`/`sigma_rule_test` return a clear
  `not_installed` error instead of crashing server registration.
  `sigma_rule_test` converts a stored rule to an OpenSearch Lucene query
  and runs it against `findings_server.py`'s `odysseus-findings` index by
  default. v1 is on-demand only — no scheduled rule sweep yet.
- `mcp_servers/watchlist_server.py` + `src/builtin_actions.py`'s new
  `watchlist_check` action — a persistent IOC watchlist (`watchlist_add`,
  IPs/domains/hashes/URLs, validated per kind) re-checked on a cron
  schedule against whichever of Shodan/VirusTotal/OTX/Censys are
  configured for that indicator's kind, filing a finding and sending one
  batched reminder only when a provider's result changes since the last
  check (open ports, VirusTotal detection counts, OTX pulse count,
  Censys services). The first check per (entry, provider) establishes the
  baseline silently, same as `scheduled_recon`.
- `mcp_servers/monitor_server.py` + `src/builtin_actions.py`'s new
  `scheduled_recon` action — turns one-shot recon into continuous
  monitoring. A `ScheduledTask` with `task_type="action"` and
  `action="scheduled_recon"` (configured via its `prompt` as JSON, e.g.
  `{"target": "example.com", "checks": ["ports", "cert"]}`) re-runs
  `nmap_scan`/`subdomain_enum`/the new `tls_cert_info` (`recon_server.py`)/a
  Shodan CVE lookup on whatever cron schedule the task uses, diffs the
  result against the last stored snapshot in `monitor_server.py`, and files
  a finding (via `findings_server`) plus a reminder (`dispatch_reminder`,
  respecting the user's existing `reminder_channel` setting) only when
  something actually changed — a new open port, new subdomain, changed TLS
  cert fingerprint, or a new CVE. The first run for a target/check
  establishes the baseline without filing anything. Fires a new
  `security_finding_added` event (`src/event_bus.py`) other scheduled tasks
  can trigger off of. `intel_server.py`'s Shodan/VirusTotal/NVD/OTX/Censys
  lookups were each split into a `_X_fetch() -> dict` (raw data) plus
  `_X_format() -> str` (existing text output, unchanged) so this and future
  callers can diff structured data instead of parsing formatted strings.
- `mcp_servers/engagement_server.py` — a new MCP server for grouping recon
  scans, findings, and watchlist activity under a named engagement/case
  (scope, client, start/end date), with an event timeline
  (`engagement_log_event` / `engagement_timeline`) for report assembly.
  `asset_server.py`'s `assets`/`findings` tables gained an `engagement_id`
  column (migrated in place for existing databases) and `findings_server.py`'s
  existing `engagement` field is now documented as accepting the id
  `engagement_create` returns. There's no shared database between MCP
  servers, so `engagement_id` is a convention key threaded through each
  server's own tools, not a real foreign key — see `engagement_server.py`'s
  module docstring.
- `src/host_capabilities.py` + `setup.py` — a new interactive host-capability
  scan (setup.py step 6, native installs) that probes `PATH` for the 16
  toolchain binaries and the well-known ports of the 6 sidecar services
  (Ollama, ChromaDB, SearXNG, SpiderFoot, OpenSearch, BentoPDF), verifies
  each service by its actual response shape rather than "port is open"
  alone (avoids mistaking an unrelated service on the same port for the
  real one), then offers to write the matching `TOOLCHAIN_EXEC_MODE_*` /
  service-URL lines into `.env` and logs accepted suggestions to
  `logs/host_capability_scan.log`. Self-detects when running inside the
  container (via `docker/entrypoint.sh`'s automatic `setup.py` invocation)
  and skips the binary scan there — container isolation makes it
  structurally meaningless — while still running the service scan against
  `host.docker.internal`. No-ops without prompting when stdin isn't a TTY
  or `ODYSSEUS_SKIP_HOST_SCAN` is set.
- `docker-compose.security.yml` — `toolchain`, `spiderfoot`, `bentopdf`,
  and `opensearch` each gained their own Compose profile name alongside
  the shared `sidecars` profile, so a subset of sidecars can now actually
  be started independently (e.g. `--profile toolchain --profile bentopdf
  --profile opensearch`). Previously all four shared one profile value,
  making the existing "omit `--profile sidecars` to skip just this one"
  doc comment literally false.
- [ADR 006](docs/adr/006-release-channel-strategy.md) — documents the
  chosen release-channel strategy: one working branch (`main`) with
  SemVer prerelease tags (`vX.Y.Z-alpha.N` → `-beta.N` → `-rc.N` →
  `vX.Y.Z`) instead of parallel long-lived alpha/beta/rc branches, plus
  the matching `release.yml` changes (prerelease detection, `[Unreleased]`
  fallback for prerelease tag CHANGELOG extraction).

### Fixed
- `src/agent_loop.py` — tool output, live progress tails, and displayed
  commands now get redacted for common secret shapes (cookies, URL
  credentials, `Authorization` headers, provider-shaped bare tokens,
  PEM private keys) before reaching the model or the SSE stream to the
  client. There was previously no redaction anywhere in this pipeline.
  Salvaged from an unlanded local branch discovered during a repo
  cleanup pass; see that commit for full detail.
- `README.md` — MCP tool tables had drifted from the actual server
  code: `intel_server` was missing `censys_host`/`censys_search`,
  `osint_server` was missing `subdomain_enum`, `web_vuln_server` was
  missing `ffuf_fuzz`, `pdf_server` was missing `generate_report`, and
  `asset_server` listed two tools (`asset_get`, `service_list`) that
  don't exist in the code while omitting two that do (`asset_summary`,
  `finding_update`). Also fixed a stale `docs/adr/` count (004 → 005)
  and the Quick Start's Podman/Docker command wording.
- `.env.example` / `README.md` — the Censys config comment referenced
  a `censys_server` module that was never created; Censys support
  actually lives in `intel_server.py`.
- `docs/develop-mcp-servers.md` — the "registering a new server" step
  referenced a `config.json` (or equivalent) file that doesn't exist;
  MCP servers are registered as rows in the app's own database via
  Settings → Integrations → MCP or `POST /api/mcp/servers`, not a
  static config file.

### Removed
- 9 stale/superseded branches on `origin` (all content already present
  on `dev`, confirmed individually rather than assumed from merge
  ancestry). One of them held real unlanded work (the redaction fix
  above) that was ported to `dev` first.

---

## [0.4.0] — 2026-08-26

Full upstream re-sync (dev fully converged with upstream `dev`) plus an
MCP-reliability and security-hardening pass, released as `main`'s first
promotion since `v0.3.1`.

### Upstream sync

`dev` had drifted a very long way behind `upstream/dev`
(pewdiepie-archdaemon/odysseus) since the last release. Merged upstream in
24 reviewed batches (each with full per-hunk provenance review — no blanket
"take theirs"/"take ours" — verified individually via compile checks, JS
syntax checks, an AST duplicate-definition scanner, and a full pytest run
compared against a passing baseline), bringing `dev` to zero commits behind
`upstream/dev` at merge time. See the individual
`merge: sync upstream pewdiepie-archdaemon/odysseus dev (batch N, ...)`
commits on `dev` for full per-batch detail (each documents exactly which
upstream commits landed and how every conflict was resolved). Notable
upstream features absorbed this cycle include: per-tool capability/
result-integrity gating for indirect prompt-injection defense
(`src/tool_capabilities.py`, `src/tool_approvals.py`), a model-capability
reader framework (`src/model_capability_readers/`), several route
domain-subpackage splits (document, mcp, webhook, task, note, search, vault,
cleanup, admin_wipe, compare), and the platform version advancing to
`1.0.3`.

### Added

- `scripts/mcp_health_check.py` — speaks the real MCP stdio protocol
  (spawn → initialize → list_tools) to each of the 14 security-focused MCP
  servers plus the 4 core-platform servers (email, memory, image_gen, rag),
  independent of the app's own MCP server registry. Confirms every server
  starts cleanly and correctly advertises its tools — upstream has open
  reports of MCP servers intermittently failing to register with tools
  "disappearing" silently rather than raising a visible error, and this
  fork's headline differentiator is its 14 cybersecurity MCP servers.
  Usable standalone (`--json` for CI, `--core-only`/`--security-only` to
  scope a run) and as a manual pre-release check.
- `GET /api/ready` now reports an `mcp_servers` check: configured/connected
  counts and any server currently in `error`/`timeout` status, sourced from
  the existing `McpManager` connection-status snapshot (no new connection
  attempts, so it stays fast). Informational only — never fails overall
  readiness — but a broken MCP server is now visible here instead of only
  discoverable by a user hitting a missing tool mid-session.
- `.github/workflows/ci.yml`: new `sensitive-paths` job. Runs
  `git ls-files` on every push/PR and fails if any tracked file matches
  `data/`, `logs/`, `backups/`, `.env` (excluding `.env.example`), or
  private-key filename patterns. Automates the "confirm no secrets/data
  ever get committed" checklist item as a real CI gate instead of relying
  on a human to remember it before every push.

### Fixed

- `mcp_servers/asset_server.py` — schema init ran unconditionally at
  *module import time*, before the MCP stdio handshake could even begin.
  Any unwritable or missing data directory (bad volume mount, full disk, a
  misconfigured read-only mount) crashed the whole server process before it
  could register a single tool, surfacing to the MCP client only as an
  opaque low-level transport exception — not an actionable message. Its
  sibling stateful servers (`risk_server`, `memory_server`, `rag_server`,
  `image_gen_server`) already use a safe lazy-init pattern that only
  touches the filesystem when a tool is actually invoked; `asset_server`
  was the sole outlier. Fixed to match: schema init now runs lazily on
  first real DB access. A genuinely broken data directory now surfaces as
  a normal per-call `[error:db_error] ...` MCP response instead of taking
  down the process.
- `.gitignore` / `.dockerignore` — `backups/` (full data-directory
  snapshots written by `scripts/odysseus-backup`: DB, uploads, personal
  docs — everything `data/` itself is gitignored for) was not covered by
  either file. A `git add -A` after running a backup would have staged a
  complete personal-data snapshot; a Docker build from a checkout with a
  stray `backups/` dir would have baked it into an image layer. Audited
  currently-tracked files first — confirmed clean, so this closes a latent
  gap rather than an active leak.
- `.gitleaksignore` — the allowlisted fingerprint for the known jwt.io
  demo-token false positive in `tests/mcp_servers/test_transform_server.py`
  pinned a commit SHA (`36edb229...`) reachable only via the `v0.3.1` tag.
  This fork's `dev` history reconstruction during the upstream-sync merges
  produced a *different* commit SHA (`6a7ce654...`) for the same
  byte-identical content, which was never allowlisted — so the Secret scan
  CI check had been failing on every push since the upstream-sync effort
  began, mischaracterized along the way as "confirmed pre-existing and
  unrelated" rather than actually run down. Added the correct fingerprint;
  verified locally with the exact pinned gitleaks binary before pushing.
- `.github/workflows/release.yml` — the release-notes template hardcoded
  "Upstream base: Odysseus `1.0.1`", stale since the upstream-sync batches
  above advanced the platform to `1.0.3`.

---

## [0.3.1] — 2026-06-25

SDLC hardening, CI consolidation, and release cycle.

### Added
- `CHANGELOG.md` — version history following Keep a Changelog
- `ODYSSEUS_RED_VERSION` in `src/constants.py` — fork version independent of upstream
- `.github/release-drafter.yml` + `workflows/release-drafter.yml` — auto-draft release notes from merged PRs
- `.github/workflows/release.yml` — creates GitHub Release from CHANGELOG on `v*` tag push
- `.github/codeql/codeql-config.yml` — restrict CodeQL analysis to fork paths only
- CODEOWNERS entries for all fork-specific paths (`@nixbys`)
- Fork-specific sections in `SECURITY.md` (toolchain, OpenSearch, exec API guidance) and `CONTRIBUTING.md` (setup, MCP dev, release process)
- `tests/mcp_servers/test_transform_server.py` — 13 tests (all in-process, no mocking)
- `tests/mcp_servers/test_yara_server.py` — 5 tests with path-traversal rejection
- `tests/mcp_servers/test_asset_server.py` — 5 SQLite lifecycle tests (77 total)
- CI: `python-syntax`, `hadolint`, `yaml-lint` jobs in `ci-security.yml`
- CI: `mcp_servers/ modules/` added to `compileall` in `ci.yml`
- CI: `dev` branch added to push triggers for `ci.yml`, `secret-scan.yml`, `workflow-security.yml`
- `findings_server.py` added to bandit CI job

### Fixed
- Missing env vars in `.env.example` (`EXEC_API_TOKEN`, `CENSYS_API_ID/SECRET`, `OPENSEARCH_*`)
- `*.jsonl` missing from `.gitignore` (exec API audit log)
- All 30 CodeQL `py/path-injection` alerts dismissed — all were in unmodified upstream files

---

## [0.3.0] — 2026-06-24

Tier 3 intelligence, risk management, and IR playbooks.

### Added
- `mcp_servers/asset_server.py` — SQLite-backed asset and findings inventory (WAL mode)
- `mcp_servers/attck_server.py` — MITRE ATT&CK STIX lookup with 7-day local cache
- `mcp_servers/risk_server.py` — CVSS-based risk scoring and prioritized remediation plans
- `mcp_servers/findings_server.py` — OpenSearch findings persistence and search
- `skills/incident_response/ransomware_response.yaml` — host triage → IOC → ATT&CK → remediation
- `skills/incident_response/network_compromise.yaml` — entry scan → C2 intel → lateral movement TTPs
- `skills/incident_response/credential_breach.yaml` — attacker intel → credential-focused TTPs
- `skills/incident_response/ioc_triage.yaml` — rapid IOC triage against threat intel
- `skills/incident_response/threat_actor_profile.yaml` — threat actor dossier from OSINT + ATT&CK
- `skills/threat_hunting/ioc_hunt.yaml` — IOC hunt across asset inventory
- `skills/threat_hunting/network_exposure_audit.yaml` — unexpected exposure on known assets
- `skills/malware_analysis/file_triage.yaml` — static file triage with YARA, exiftool, hashes
- OpenSearch service added to `docker-compose.security.yml`

---

## [0.2.0] — 2026-06-24

Tier 2 new servers, toolchain hardening, and shared library.

### Added
- `mcp_servers/common.py` — shared `exec_in_toolchain()`, `mcp_error()`, `validate_ip()`, `validate_url()`, `validate_domain()`
- `mcp_servers/yara_server.py` — YARA scan, rule write, rule list
- `mcp_servers/exploit_server.py` — searchsploit, Exploit-DB lookup, CVE-to-exploit
- `mcp_servers/transform_server.py` — encode/decode, hash, gzip, regex, JWT decode, XOR (in-process)
- Bearer token auth on exec API (`EXEC_API_TOKEN`)
- `GET /health` endpoint on exec API
- Structured JSON audit logging to `/var/log/exec_api.jsonl`
- `docker/toolchain/Dockerfile` — HEALTHCHECK, new tools (ffuf, exploitdb, yara, trivy, subfinder, amass, httpx), Go binary retry wrapper
- `docs/develop-mcp-servers.md` — MCP server development guide
- `docs/reverse-proxy.md` — Caddy, nginx, Traefik HTTPS setup with exec API protection

### Changed
- All 5 original MCP servers refactored to use `common.py`
- Error format standardized to `[error:code] message` across all servers
- Input validation added to recon, web_vuln, hashcrack servers
- Toolchain base image changed from `kalilinux/kali-rolling:2025.2` (non-existent) to `latest`

### Fixed
- `kalilinux/kali-rolling:2025.2` tag did not exist on Docker Hub

---

## [0.1.0] — 2026-06-24

Tier 1 initial fork with 7 security MCP servers and CI.

### Added
- `mcp_servers/recon_server.py` — nmap, masscan
- `mcp_servers/intel_server.py` — Shodan, VirusTotal, CVE/NVD, OTX
- `mcp_servers/osint_server.py` — theHarvester, Sherlock, DNS, WHOIS
- `mcp_servers/web_vuln_server.py` — nikto, gobuster, sqlmap, nuclei
- `mcp_servers/hashcrack_server.py` — hashid, john
- `mcp_servers/spiderfoot_server.py` — SpiderFoot REST API client
- `mcp_servers/pdf_server.py` — PDF intel and report assembly (pypdf)
- `docker/toolchain/Dockerfile` — Kali Rolling sidecar with exec API
- `docker/toolchain/exec_api.py` — HTTP exec API for MCP-to-Kali bridge
- `docker-compose.security.yml` — toolchain + SpiderFoot + BentoPDF overlay
- `skills/recon/full_recon.yaml`
- `skills/osint/target_profile.yaml`, `spiderfoot_deep_scan.yaml`, `pdf_intel.yaml`
- `skills/web_assessment/web_full.yaml`
- `skills/reporting/pentest_report.md`
- `docs/adr/001-toolchain-sidecar-isolation.md`
- `docs/adr/002-podman-over-docker.md`
- `docs/adr/003-spiderfoot-integration.md`
- `docs/adr/004-bentopdf-integration.md`
- `.github/workflows/ci-security.yml` — bandit, pip-audit, unit tests, Dockerfile build, Trivy, upstream-drift

### Security
- Authorization requirement notice on all active tool documentation

---

## Upstream Sync History

| Date | Commits Merged | Notes |
|------|---------------|-------|
| 2026-06-24 | 65 | llama.cpp detection, credential URL redaction, atomic API key writes, OpenDyslexic font, ReDoS fix in calendar extractor, 30+ bug fixes |
