# Contributing to Odysseus

Thanks for helping. The project is moving quickly, so the best contributions are focused, easy to review, and easy to test.

## Branch model

Odysseus has two branches:

- **`dev`** — where all PRs land. Things can be in flux here; the merge button gets used freely.
- **`main`** — what users run. Curated and tested by the maintainer. Fast-forwarded to a stable `dev` commit at each release.

**Open your PR against `dev`, not `main`.** The GitHub "base" dropdown defaults to `dev`. If you opened a PR against `main` by accident, click "Edit" on the PR and change the base — no rebase needed.

End-users cloning the repo will land on `dev` by default. To run the curated/stable version: `git checkout main` after clone.

## Before You Start

- Search existing issues and pull requests before opening a new one.
- Prefer one bug fix or feature per pull request.
- Avoid broad rewrites, formatting-only changes, or moving many files unless the issue is specifically about structure.
- If you want to work on a large feature, open an issue first and describe the approach.

## Setup

Docker is the recommended path for normal testing:

```bash
git clone https://github.com/pewdiepie-archdaemon/odysseus.git
cd odysseus
cp .env.example .env
docker compose up -d --build
```

Manual development uses Python 3.11+:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 7000
```

Windows is not actively tested. Docker on Linux or a Linux/macOS manual install is the safer path for now.

## Running Checks

Run the smallest relevant checks for your change:

```bash
python -m pytest
python -m py_compile app.py routes/*.py src/*.py
node --check static/js/<file-you-changed>.js
```

For Docker-related changes:

```bash
docker compose config
docker compose up -d --build
docker compose logs --tail=120 odysseus
```

Mention what you ran in the pull request description. If you could not run a check, say so.

## Pull Requests

Good pull requests usually include:

- A short explanation of the bug or feature.
- The files or areas changed.
- Manual test steps or automated test results from running the actual app, not just the test suite.
- Screenshots or short recordings for UI changes.
- Links to related issues, for example `Fixes #123`.

Please keep PRs small. Large PRs that mix unrelated cleanup, formatting, refactors, and behavior changes are much harder to review.

> **Auto-generated PRs.** If you are running an LLM agent (Devin, Cursor, OpenHands, Claude Code, etc.) against this repo: please open an issue describing the problem first instead of opening a PR directly. Bulk agent-generated PRs that don't match the project's visual style or contribution format will be closed without review, even when the underlying fix is correct.

## Style and visual changes

Odysseus has an intentional visual style. PRs that ignore it will be closed without merge, no matter how correct the underlying code is.

Before submitting any change that affects what the app looks like — buttons, icons, fonts, colors, spacing, layout, CSS, HTML, SVG, or any `static/js/` module that draws to the DOM — please:

1. **Run the app locally** and view the change in a browser. Type-checks and unit tests are not enough.
2. **Attach a screenshot or short clip** of the change in the running app. Add a mobile screenshot too if the change affects mobile.
3. **Match the existing visual language.** Specifically:
   - Reuse existing CSS variables (`--red`, `--fg`, `--bg`, `--card`, `--border`, …). Do not introduce new color values, font sizes, or spacing units.
   - Reuse existing button, input, card, and border classes. Don't invent parallel styling for similar widgets.
   - **No Unicode emoji in UI or code.** Use inline SVG (matching the monochrome icon style already in `static/index.html`) or plain text.
   - Monospaced font (`Fira Code`) for primary UI text. Don't override.
   - Dark theme is the default; any light-mode work goes through the existing theme system, not hard-coded.
4. **Don't add parallel components.** If a similar widget already exists in the app, extend it instead of writing a new one.

If you are unsure whether a change is "visual," it is. Default to attaching a screenshot.

## Code conventions

Don't hardcode values that the project already exposes through a constant or a helper. Hardcoded literals drift out of sync, break on non-default deployments, and reintroduce bugs we've already fixed.

- **Filesystem paths:** never build writable paths from `Path(__file__)...` into the source tree, hardcode `/app/...`, or use a relative `"data/..."` string. Every persisted file and directory has a named constant in `src/constants.py` (for example `AUTH_FILE`, `USER_PREFS_FILE`, `SETTINGS_FILE`, `TTS_CACHE_DIR`, `CHROMA_DIR`). Import and use that named constant; do not re-derive the path locally with `os.path.join(DATA_DIR, "x.json")` or `DATA_DIR / "x.json"`. `DATA_DIR` is the single place that reads `ODYSSEUS_DATA_DIR`, so use it directly only for dynamic paths that have no fixed name (for example per-owner files). If a data file or directory has no constant yet, add one to `src/constants.py`. The source tree is read-only in Docker and `/app/...` does not exist on native runs; guard directory creation so an unwritable path degrades gracefully instead of crashing at import.
- **Internal API / loopback URLs:** don't hardcode `http://localhost:7000`. Use `internal_api_base()` from `src.constants` (it honors `ODYSSEUS_INTERNAL_BASE` / `APP_PORT`).
- **Ports, limits, model lists, and similar:** reuse the existing constant if one exists; if it doesn't and the value is used in more than one place, add a constant rather than copying the literal.

If you need a value that has no constant or helper yet, add it to `src/constants.py` (the single source of truth for paths and config; `core/constants.py` only re-exports it for backward compatibility) and import it, rather than repeating a literal across files.

**Commits:** use [Conventional Commits](https://www.conventionalcommits.org), `type(scope): summary` (e.g. `fix(search): ...`, `feat(notes): ...`, `docs(contributing): ...`). Common types: `fix`, `feat`, `refactor`, `docs`, `test`, `chore`, `ci`. Keep the subject short and imperative; put the "why" in the body when it isn't obvious.

## Issue Reports

For bugs, include:

- Install method: Docker, manual Python, WSL, etc.
- OS, browser, and device if relevant.
- Exact steps to reproduce.
- Expected behavior and actual behavior.
- Logs, screenshots, or terminal output.

For model-serving issues, include:

- Backend: Ollama, vLLM, SGLang, llama.cpp, LM Studio, etc.
- Model name.
- GPU/CPU and operating system.
- Cookbook task logs or server logs.

Issues with only "help", "does not work", or a screenshot without context may be closed as not actionable.

## Security

Do not post secrets, API keys, private logs, personal documents, or public IPs in issues or pull requests.

For security reports, follow [SECURITY.md](SECURITY.md).

---

## Contributing to Odysseus Red (Fork-specific)

Odysseus Red is a security-focused fork of [`pewdiepie-archdaemon/odysseus`](https://github.com/pewdiepie-archdaemon/odysseus). The fork adds MCP servers, a Kali toolchain sidecar, incident response skills, and threat-intelligence integrations.

If you are contributing to the base Odysseus platform (chat, agents, research, documents), follow the upstream guidelines above and consider whether your contribution belongs upstream instead.

### Setup for Fork Development

```bash
git clone https://github.com/nixbys/odysseus-red.git
cd odysseus-red
cp .env.example .env
# Fill in EXEC_API_TOKEN and any API keys you need for testing
podman-compose -f docker-compose.yml -f docker-compose.security.yml up -d --build
```

For MCP server development only (no containers needed):

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt pytest pytest-asyncio bandit
pytest tests/mcp_servers/ -v
```

### Adding a New MCP Server

See [`docs/develop-mcp-servers.md`](docs/develop-mcp-servers.md) for the full guide including the minimal template, error format, input validation, security checklist, and testing patterns.

The short version:

1. Create `mcp_servers/my_server.py` following the template.
2. Use `exec_in_toolchain()` from `mcp_servers.common` for any Kali binary call.
3. Use `mcp_error(code, message)` for all error returns — no bare strings.
4. Validate all user-supplied paths, IPs, and domains using helpers from `mcp_servers.common`.
5. Add unit tests in `tests/mcp_servers/test_my_server.py` — mock `mcp_servers.common.requests.post`.
6. Add the server to the bandit list in `.github/workflows/ci-security.yml`.

### Commit and PR Conventions

Fork commits follow the upstream Conventional Commits style (`feat(yara): ...`, `fix(common): ...`, `chore(ci): ...`).

PR descriptions must:
- Identify whether the change is in fork-specific code or upstream code.
- Include test output (`pytest tests/mcp_servers/ -v`).
- For new MCP servers: list all tools, their inputs, and the corresponding Kali binary/API.
- For skill YAML changes: verify the skill runs end-to-end against an authorized test target.

### Cutting a Release

Releases follow [Semantic Versioning](https://semver.org/). The fork version (`ODYSSEUS_RED_VERSION`) tracks the security overlay independently of the upstream Odysseus `APP_VERSION`.

**When to bump:**
- `PATCH` (0.3.x) — bug fixes, CI, docs, dependency updates, SDLC improvements
- `MINOR` (0.x.0) — new MCP server, new skill category, new sidecar service
- `MAJOR` (x.0.0) — breaking change to MCP tool interface, major architecture change

**Steps:**

1. On `dev`, open a release prep commit:

   ```bash
   # 1. Bump version in src/constants.py
   sed -i 's/ODYSSEUS_RED_VERSION = ".*"/ODYSSEUS_RED_VERSION = "X.Y.Z"/' src/constants.py

   # 2. Update CHANGELOG.md — move [Unreleased] → [X.Y.Z] with today's date
   #    Add a new empty [Unreleased] section at the top.

   # 3. Commit
   git add src/constants.py CHANGELOG.md
   git commit -m "chore(release): bump to vX.Y.Z"
   git push origin dev
   ```

2. Open a PR from `dev` → `main`. Wait for all CI jobs in `ci-security.yml` to pass.

3. Merge the PR (squash or merge commit — either is fine).

4. On `main`, create and push the tag:

   ```bash
   git checkout main && git pull origin main
   git tag -a vX.Y.Z -m "Odysseus Red vX.Y.Z"
   git push origin vX.Y.Z
   ```

5. The `release.yml` workflow triggers automatically — it extracts the `[X.Y.Z]` section from `CHANGELOG.md` and creates a GitHub Release. No manual release creation needed.

> **Note:** Tags `v*` on `main` should be protected in GitHub repository settings (Settings → Branches → Add rule for `v*`) so only maintainers can push them.

### Upstream Sync

This fork tracks `pewdiepie-archdaemon/odysseus` `dev` branch. Sync when the upstream-drift CI job warns:

```bash
git fetch https://github.com/pewdiepie-archdaemon/odysseus.git dev
git merge FETCH_HEAD --no-ff -m "chore: sync upstream dev $(date +%Y-%m-%d)"
git push origin dev
```

Conflicts are rare — fork additions live in paths that upstream doesn't touch (`mcp_servers/`, `skills/`, `docker/toolchain/`, `docs/adr/`). The most likely conflict is `README.md` since both upstream and this fork maintain it; resolve by keeping our security sections and incorporating upstream's changes above the "What This Is" heading.

