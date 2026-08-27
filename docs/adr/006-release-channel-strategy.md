# ADR 006: Release Channel Strategy — SemVer Prerelease Tags, Not Parallel Branches

**Status:** Accepted
**Date:** 2026-08-26

## Context

Odysseus Red had no tagged prereleases and no way to signal "this build is still being validated" before v0.4.0. The question raised: would a structure like `dev → alpha → beta → rc#.#.# → main/rel#.#.#` (a dedicated long-lived branch per maturity stage, the way some large open-source projects — and pre-1.0 Minecraft — are sometimes remembered as working) be worth adopting here?

## Decision

**Signal maturity with SemVer prerelease tags on the existing single working branch (`main`), not with additional long-lived branches.** Tag sequence for a release in progress: `vX.Y.Z-alpha.N` → `vX.Y.Z-beta.N` → `vX.Y.Z-rc.N` → `vX.Y.Z`. No `alpha`/`beta`/`rc` branch is created or kept alive; every tag in the sequence is cut from whatever commit on `main` is ready at that point.

## Why Not Parallel Branches

- **The Minecraft comparison, examined closely, argues against it.** Minecraft's alpha → beta → release was a one-time sequence during initial development, not permanent parallel branches maintained forever. After 1.0, Minecraft itself moved to dated development snapshots plus a short pre-release/RC window immediately before each version ships — not long-lived alpha/beta branches running alongside a stable branch indefinitely. That later model is much closer to what this ADR adopts than the model the question described.
- **This project already has one recurring branch-sync obligation**: `dev` tracks `upstream/dev` on a monthly cadence (ADR 005). Adding four or five more permanently-live branches that each need to stay current multiplies that sync burden for a single maintainer — exactly the kind of process overhead that erodes "smooth running" rather than serving it.
- **Full parallel-channel models exist where there's a team large enough to keep several branches simultaneously releasable at once** (browsers, language toolchains). A solo-maintained fork isn't at that scale, and building the process for that scale now is solving a problem this project doesn't have yet.

## What This Looks Like In Practice

- One working branch (`main`), synced from `dev` per ADR 005's existing promotion cadence.
- `.github/workflows/release.yml`'s prerelease detection now also recognizes a `-alpha`, `-beta`, or `-rc` suffix (with or without a numeric qualifier) as a prerelease tag, alongside the existing pre-1.0 (`0.x`) rule — so any of these gets marked "Pre-release" on GitHub (excluded from "Latest Release") automatically, with zero additional tooling.
- A prerelease tag is not expected to have its own `CHANGELOG.md` section — the release-notes extraction falls back to whatever has accumulated in `[Unreleased]` when no exact `[X.Y.Z-stage.N]` entry exists, so the generated release notes stay genuinely informative without requiring a CHANGELOG rewrite on every alpha/beta bump. The final `vX.Y.Z` tag is still expected to have its own dedicated section, same as before this ADR.
- Mapped onto the release plan's sections (see `release_plan_v0_4_0` in project memory / the original 5-section plan): cut `alpha` once the license audit and MCP-reliability verification are done; `beta` once security gating is applied and the build has seen some real usage; `rc` once feature-frozen with only bug fixes and the documentation pass happening in parallel; the final tag ships once that's clean.

## When To Revisit

If this project ever grows past one maintainer, that's the actual trigger to reconsider dedicated parallel branches per channel — not a calendar date, not a specific version number.

## Consequences

**Positive:**
- Real maturity signaling (alpha/beta/rc distinguishable from a final release on the Releases page) with no new git branches, no new sync obligations, and no new CI workflows — `release.yml`'s existing tag-triggered job handles every stage.
- A user who only wants stable code can keep ignoring anything marked Pre-release; GitHub's own UI already does the filtering.

**Negative:**
- Prerelease tags don't get their own permanent CHANGELOG section by design — anyone wanting a precise diff between two prerelease tags of the same version needs `git log`/`git diff` between the tags themselves, not a curated changelog entry. Acceptable since the final tag's entry still covers the whole cycle.
