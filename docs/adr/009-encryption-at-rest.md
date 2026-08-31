# ADR 009: One Key, One Convention — Encryption at Rest

**Status:** Accepted
**Date:** 2026-08-31

## Context

A pass over the whole app (not just the security-MCP overlay) for anything
sensitive stored unencrypted found a real, if narrow, mess: solid
encryption-at-rest infrastructure already existed
(`src/secret_storage.py`, Fernet, one key at `data/.app_key`), but it was
applied inconsistently — some columns used it via a schema-enforced type,
some only if the call site remembered to wrap `encrypt()`/`decrypt()` by
hand, a second *separate* Fernet key (`src/api_key_manager.py`) did the
same job more weakly for two other secrets, and one field of real user
content (`Note.content`) was fully plaintext. Session tokens were stored
raw where API tokens were correctly hashed. None of this was a deliberate
design choice anywhere — it was drift, one feature at a time, with no
single place that said what "encrypted at rest" is supposed to mean in
this codebase.

This ADR writes that down, the way ADR 007 wrote down the detection
pipeline's own "every detector writes into the same shared plumbing"
rule after the fact.

## Decision

**One key, one module, two conventions — reused everywhere, not
reinvented per feature.**

`src/secret_storage.py` owns a single Fernet key at `data/.app_key`
(mode `0600`, gitignored, auto-generated on first use). Two primitives
built on it cover every case a feature has actually needed:

1. **`encrypt()`/`decrypt()`** (reversible) — for anything the app needs
   to read back as plaintext: provider API keys, OAuth tokens, IMAP/SMTP
   passwords, webhook signing secrets, signature images, note/checklist
   content, and — as of this pass — the audit trail's raw tool-output
   log files and (optionally, passphrase-derived) exported data bundles.
   Values carry an `enc:` prefix so `encrypt()` is idempotent (a
   double-encrypt is a no-op) and `decrypt()` degrades gracefully (a
   plaintext/legacy value passes through unchanged; a corrupt or
   wrong-key token returns `""` rather than raising) — the same
   tolerance that makes a rolling migration from plaintext safe.

2. **`hmac_hex()`** (one-way, deterministic) — for anything that needs
   to be looked up by exact match without ever being reversible, where
   Fernet is the wrong tool: session tokens (`core/auth.py`, hashed
   before being persisted to `data/sessions.json` — the raw token is
   never stored, matching how `ApiToken` already handled its own
   tokens) and the audit trail's tamper-evident hash chain
   (`mcp_servers/common.py`/`audit_server.py` — each row's hash folds
   in the previous row's hash plus its own columns, keyed the same way).

Where a column is schema-level (SQLAlchemy), it uses the `EncryptedText`
type decorator (`core/database.py`) rather than relying on every call
site to remember — this is what "encrypted at rest" should have meant
from the start: a property of the schema, not a habit call sites either
have or don't.

`src/api_key_manager.py`'s separate key is retired. Everything it used
to protect goes through the same key/convention above now, with a
one-time migration (decrypt under the old key if a value is still in that
form, re-encrypt under this one) so existing data isn't lost.

## Threat model — stated plainly

This protects against a **stolen disk, a leaked backup, or a leaked
container image** — anyone who gets `data/*.db`, `data/audit_logs/*.log`,
or an exported `.zip` without also getting `data/.app_key` has ciphertext,
not secrets.

This does **not** protect against a **live process compromise**. Anyone
who can read this app's own memory, or read `data/.app_key` directly off
disk, can decrypt everything the key protects — there is no separate
secrets manager, no HSM, no per-secret key, no hardware-backed key
storage. `src/secret_storage.py`'s own docstring already says this; this
ADR just makes it the stated policy for the whole app, not one module's
private caveat.

**Key rotation: none exists today.** There is no mechanism to rotate
`data/.app_key` and re-encrypt everything under a new one. Losing that
file means every encrypted value it protects is unrecoverable — there is
no backup key, no recovery path. Worth stating outright rather than
letting the file's mere existence imply a rotation story that isn't
there.

## Consequences

**Positive:**
- One place to audit for "is this actually encrypted" instead of
  grepping for scattered `encrypt()` calls and hoping none were missed.
- Schema-enforced columns (`EncryptedText`) can't silently regress to
  plaintext the way a manually-wrapped `String` column already had
  (`EmailAccount`'s passwords, before this pass).
- `hmac_hex()` reuses the same key/infrastructure instead of a third
  encryption scheme being invented for session tokens or the audit hash
  chain — one less thing to key-manage, one less thing to get wrong.

**Negative:**
- Single point of failure: `data/.app_key` protects everything this ADR
  covers, with no rotation and no recovery if it's lost or leaked.
- Process-compromise is explicitly out of scope — this raises the bar
  for a stolen-disk/backup attacker, not a live RCE against the app
  itself.
- `mcp_servers/*.py` subprocesses touching `secret_storage` for the
  first time in a fresh process can trigger a real (if pre-existing and
  harmless) circular-import chain through `core.platform_compat` →
  `core/__init__.py` → `core.database`'s own startup migrations, which
  silently no-op in that one subprocess as a result. Doesn't affect
  correctness (that subprocess never uses `core.database`'s ORM for
  anything real, and the main app process — which does — doesn't hit
  this path), but it's a known wart, not a deliberate design choice.

## Alternatives considered

**Whole-database encryption (SQLCipher or similar):** rejected for this
pass. Would protect columns this ADR doesn't touch (most of the schema
is genuinely non-sensitive — settings, chat metadata, task definitions),
at the cost of a new native dependency and a real migration for every
existing SQLite file in the data directory. Column-level, applied to
what's actually sensitive, is the better fit for how much of this
schema needs it.

**A dedicated secrets manager / KMS / HSM integration:** rejected as out
of scope for this project's shape — a self-hosted, single-operator
workspace, not a multi-tenant service with a security team operating a
Vault cluster. Revisit if that ever changes.

**Per-secret or per-tenant keys:** rejected. This app has one operator
and one trust boundary; per-secret keys would add real complexity
(key management, rotation-per-key) without a corresponding security
benefit at this scale.
