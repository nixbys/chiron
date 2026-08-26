# ADR 005: Upstream Sync Strategy — Branch Tracking, Cadence, and Changelog Discipline

**Status:** Accepted
**Date:** 2026-08-26

## Context

Upstream Odysseus (`pewdiepie-archdaemon/odysseus`) is under active development — frequent commits, two live branches (`dev` for bleeding-edge work, `main` as its own curated/stable branch). This fork's own `dev` had drifted a very long way behind `upstream/dev` before a 24-batch catch-up sync (2026-08), and this fork's own `main` had independently drifted 2230 commits behind this fork's own `dev`, frozen since the `v0.3.1` release in June 2026. Both gaps stemmed from the same root cause: no explicit cadence or promotion discipline, so drift only got addressed in occasional large catch-up efforts instead of continuously.

A natural recommendation, given upstream itself splits bleeding-edge (`dev`) from stable (`main`), is to pin this fork's sync source to upstream's `main` rather than `upstream/dev` for anything shipped as stable — avoiding inheriting upstream's own in-progress instability. This ADR records why that recommendation is *not* adopted as literally stated, what's done instead to achieve the same underlying goal, and the cadence/changelog discipline going forward.

## Decision

**Keep syncing this fork's `dev` from `upstream/dev`, not `upstream/main`.** Use this fork's own `dev` → `main` promotion (already the documented release process in `.github/workflows/release.yml`) as the stability gate instead of switching which upstream branch feeds this fork.

### Why not switch to `upstream/main`

- `upstream/main` lags `upstream/dev` by ~185 commits at any given time (confirmed 2026-08-26). Re-pointing this fork's ongoing sync at `upstream/main` after 24 batches of `upstream/dev`-tracking tooling and technique (per-batch boundary selection, conflict-provenance discipline, verification sequence — all documented in project memory) would mean re-deriving a parallel process for a branch this fork has never synced against, for a benefit (avoiding upstream's most recent commits) that this fork's own promotion gate already provides.
- This fork's `dev` is *already* a superset of `upstream/main`'s content (confirmed: only 2 commits reachable from `upstream/main` are not already on this fork's `dev`, both trivial). Switching sync sources now would not recover anything currently missing — there is nothing to gain by re-basing the sync process onto a branch this fork's `dev` has already absorbed and moved past.
- Upstream's own `dev`→`main` promotion already filters upstream's instability once; re-filtering through this fork's own sync process would double a merge/review this fork does not need to duplicate as long as this fork applies its own equivalent gate downstream (see below).

### How the same goal is achieved instead

- This fork's `dev` continues to sync from `upstream/dev` on the established cadence (below), absorbing upstream's latest work — including its in-progress instability — the same way it always has.
- This fork's `main` is only ever updated by promoting `dev`'s current tip, once `dev` has been running the full verification sequence clean for a period (not immediately after absorbing a large, freshly-merged upstream batch). This is this fork's own stability gate, playing the same role upstream's own `main` plays for upstream's own users.
- **Promotion mechanics**: because `main` is a promoted snapshot of `dev`, not an independently-evolving branch, promotion is a direct reset (`git checkout main && git reset --hard dev && git push --force origin main`), not a merge. A real `git merge dev` into a `main` that has drifted independently (as happened when `main` sat frozen for 2230 commits) produces hundreds of spurious file-level conflicts against content `dev` has already superseded — discovered and resolved this way during the `v0.4.0` promotion. Keeping promotions frequent avoids ever facing that scale of conflict again; a stale, rarely-promoted `main` is the actual failure mode this whole ADR exists to prevent, more so than the upstream-branch question that motivated it.

## Cadence

- **`dev` ← `upstream/dev`**: sync monthly at minimum, or sooner if a security-relevant upstream fix lands (matching the fork's existing practice of checking `git log --oneline --first-parent dev..upstream/dev` at the start of each sync session). Batch size stays ~20-40 commits per merge, per the established boundary-selection heuristic (avoid oversized hidden merges; route around or absorb a revealed side-branch on its own merits — see `upstream_sync_progress` project memory for the full worked methodology).
- **`main` ← `dev` (release promotion)**: promote whenever `dev` has a clean, CI-green run and there's a meaningful set of changes to ship — not on a fixed calendar, but *don't let it go longer than a few sync cycles* without a promotion. A `main` that's many sync cycles behind `dev` is the exact staleness this ADR is meant to prevent.

## Changelog Discipline

- Every upstream-sync merge commit on `dev` documents its own provenance in full: which upstream commits landed, how every conflict was resolved, and full verification output (compile checks, JS syntax, AST duplicate scan, whole-repo diff stat, full pytest run vs. baseline). This is *the* per-sync changelog — `git log` on `dev` is the source of truth for "what changed upstream vs. what's fork-specific" at batch granularity.
- `CHANGELOG.md` stays a *summary*, not a duplicate of the batch commits — each release's entry names the upstream-sync range by its outermost commit SHAs and highlights notable absorbed features, then covers this fork's own genuinely new work (MCP servers, security hardening, tooling) in full "Added"/"Fixed" detail, in the existing Keep a Changelog format.

## Consequences

**Positive:**
- No new sync tooling/process needed — the existing, battle-tested `upstream/dev`-tracking discipline (24 batches deep) continues unchanged.
- `main` staleness becomes a visible, checkable condition (`git log --oneline main..dev | wc -l`) rather than something that silently compounds for months.
- Promotion-by-reset is simple and has no conflict-resolution risk, as long as promotions stay frequent enough that `main` never independently accumulates unique content worth preserving (it shouldn't — anything worth keeping belongs on `dev` first).

**Negative:**
- This fork inherits `upstream/dev`'s occasional instability between promotions, same as before this ADR — mitigated by the full verification sequence run on every sync batch and by not promoting to `main` immediately after a large absorption, but not eliminated the way tracking `upstream/main` directly would.
- Promotion-by-reset means `main`'s branch history does not tell its own story between releases — it simply *is* whatever `dev` was at promotion time. Anyone auditing "what changed between releases" should diff release tags, not read `main`'s own commit log in isolation.
