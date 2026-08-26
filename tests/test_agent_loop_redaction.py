"""Regression coverage for agent_loop.py's secret-redaction pipeline.

Ported from an unlanded local branch (fix/native-agent-loop-guard-signals)
that was never merged on this fork or upstream, but whose redaction work is
real and this fork's tool-output-to-model/client pipeline had none at all
before this port -- confirmed by diffing against dev's prior state, which
called `_truncate(raw)` directly with no redaction wrapper anywhere. Only the
redaction-specific tests are ported here; the branch's loop-guard-signal
tests (`loop_breaker_triggered` / `intent_nudge_exhausted` emission itself)
are not, since dev already covers that via a separate, independently-arrived
implementation (see c2d20758 upstream).
"""

import asyncio
import json

import pytest

import src.agent_loop as al
from src.tool_approvals import ToolApprovalStore
from src.tool_capabilities import capabilities_for_action


def _collect(gen):
    async def _run():
        return [c async for c in gen]
    return asyncio.run(_run())


def _types(chunks):
    out = []
    for c in chunks:
        if c.startswith("data: ") and not c.startswith("data: [DONE]"):
            try:
                out.append(json.loads(c[6:]))
            except Exception:
                pass
    return out


def _patch_common(monkeypatch):
    monkeypatch.setattr(al, "get_setting", lambda key, default=None: default, raising=False)
    monkeypatch.setattr(al, "get_mcp_manager", lambda: None, raising=False)
    monkeypatch.setattr(al, "estimate_tokens", lambda *a, **k: 10, raising=False)
    # No owner is passed in these tests, and bash is in NON_ADMIN_BLOCKED_TOOLS
    # for a non-admin/non-single-user owner (see blocked_tools_for_owner) --
    # without this, every bash call below gets rejected before it ever reaches
    # the mocked execute_tool_block, and these tests would silently exercise
    # only the pre-execution "blocked by policy" path instead of real output/
    # progress redaction. Not what these tests are about, so bypass it.
    monkeypatch.setattr(al, "blocked_tools_for_owner", lambda owner: set(), raising=False)


def test_redacts_sensitive_tool_output_before_surfacing():
    text = al._redact_sensitive_text(
        "password: private-value\n"
        "api_key=private-key\n"
        "Authorization: Bearer private-token\n"
        "normal output"
    )

    assert "private-value" not in text
    assert "private-key" not in text
    assert "private-token" not in text
    assert "password: [redacted]" in text
    assert "api_key=[redacted]" in text
    assert "Authorization: Bearer [redacted]" in text
    assert "normal output" in text


_GCP_API_KEY_SAMPLE = "AI" + "za" + ("A" * 35)

# (input, secret substring that must be gone, expected substring that must remain)
_REDACTION_CASES = [
    ("Authorization: Bearer abc123tok", "abc123tok", "Authorization: Bearer [redacted]"),
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz", "Authorization: Basic [redacted]"),
    # Quoted Authorization value (spaces) must be redacted whole.
    ('Authorization: Bearer "two word secret"', "two word secret", "Authorization: Bearer [redacted]"),
    # Escaped quote inside a quoted secret must not leak the tail.
    (r'password="abc\"def secret"', "def secret", "password=[redacted]"),
    # URL password containing a colon must still be redacted whole.
    ("postgres://user:pa:ss@host/db", "pa:ss", "postgres://[redacted]@host/db"),
    # Provider-shaped bare tokens.
    ("token is hf_abcdefghij1234567890XYZ", "hf_abcdefghij1234567890XYZ", "[redacted]"),
    ("key " + _GCP_API_KEY_SAMPLE, _GCP_API_KEY_SAMPLE, "[redacted]"),
    ("Cookie: session=abc123secret", "abc123secret", "Cookie: [redacted]"),
    ("Set-Cookie: sid=xyz789; HttpOnly", "xyz789", "Set-Cookie: [redacted]"),
    ("postgres://user:pa55word@host/db", "pa55word", "postgres://[redacted]@host/db"),
    ("client_secret=supersecretvalue", "supersecretvalue", "client_secret=[redacted]"),
    ("OPENAI_API_KEY=abcd1234deadbeef", "abcd1234deadbeef", "OPENAI_API_KEY=[redacted]"),
    # Quoted multi-word env value must be fully redacted, not clipped at the space.
    ('OPENAI_API_KEY="two word secret"', "two word secret", "OPENAI_API_KEY=[redacted]"),
    ('password: "my secret value"', "my secret value", "password: [redacted]"),
    ("here is sk-abcdefghij1234567890", "sk-abcdefghij1234567890", "[redacted]"),
    (
        "-----BEGIN PRIVATE KEY-----\nMIIfakeKEYbody\n-----END PRIVATE KEY-----",
        "MIIfakeKEYbody",
        "[redacted private key]",
    ),
]


@pytest.mark.parametrize("raw, secret, expected", _REDACTION_CASES)
def test_redaction_covers_requested_secret_shapes(raw, secret, expected):
    out = al._redact_sensitive_text(raw)
    assert secret not in out, out
    assert expected in out, out


@pytest.mark.parametrize("raw", [
    "the build completed in 3.2s with 0 errors",
    "password reset email sent to the user",
    "Listing 5 files: a.py b.py c.py d.py e.py",
    "https://example.com/path?page=2",
    # Benign uppercase names that merely end in KEY must not be redacted.
    "MONKEY=banana",
    "TURKEY=dinner",
])
def test_redaction_keeps_normal_output_readable(raw):
    assert al._redact_sensitive_text(raw) == raw


def test_redacts_before_truncating():
    # A secret near the start must be gone even if truncation would otherwise
    # only clip the tail — redaction runs first.
    raw = "api_key=topsecretvalue " + ("x" * 50_000)
    out = al._truncate(al._redact_sensitive_text(raw))
    assert "topsecretvalue" not in out
    assert "api_key=[redacted]" in out


def test_redacts_command_display_in_streamed_events(monkeypatch):
    # A tool command line can carry a secret. The streamed command display
    # (tool_start / tool_output) must be redacted, even though the real command
    # passed to execution is left untouched.
    _patch_common(monkeypatch)

    async def _fake_exec(block, *a, **k):
        return ("bash", {"output": "ok", "exit_code": 0})
    monkeypatch.setattr(al, "execute_tool_block", _fake_exec, raising=False)

    round_text = "```bash\necho api_key=secret123\n```"

    async def _fake_stream(_candidates, messages, **kwargs):
        yield f'data: {json.dumps({"delta": round_text})}\n\n'
        yield "data: [DONE]\n\n"
    monkeypatch.setattr(al, "stream_llm_with_fallback", _fake_stream, raising=False)

    gen = al.stream_agent_loop(
        "http://x/v1", "m",
        [{"role": "user", "content": "run it"}],
        max_rounds=2,
        relevant_tools={"bash"},
    )
    events = _types(_collect(gen))
    cmds = [e for e in events if e.get("type") in ("tool_start", "tool_output")]
    assert cmds, events
    assert all("secret123" not in (e.get("command") or "") for e in cmds), cmds
    assert any("api_key=[redacted]" in (e.get("command") or "") for e in cmds), cmds


def test_redacts_live_tool_progress_tail(monkeypatch):
    # A secret in the live progress tail must be redacted before streaming —
    # otherwise it flashes by before the (already redacted) final tool_output.
    _patch_common(monkeypatch)

    async def _fake_exec(block, *a, **k):
        await k["progress_cb"]({"tail": "api_key=secret123", "elapsed_s": 1})
        return ("bash", {"output": "done", "exit_code": 0})
    monkeypatch.setattr(al, "execute_tool_block", _fake_exec, raising=False)

    round_text = "```bash\necho hi\n```"

    async def _fake_stream(_candidates, messages, **kwargs):
        yield f'data: {json.dumps({"delta": round_text})}\n\n'
        yield "data: [DONE]\n\n"
    monkeypatch.setattr(al, "stream_llm_with_fallback", _fake_stream, raising=False)

    gen = al.stream_agent_loop(
        "http://x/v1", "m",
        [{"role": "user", "content": "run it"}],
        max_rounds=2,
        relevant_tools={"bash"},
    )
    events = _types(_collect(gen))
    prog = [e for e in events if e.get("type") == "tool_progress"]
    assert prog, events
    assert all("secret123" not in (e.get("tail") or "") for e in prog), prog
    assert any("api_key=[redacted]" in (e.get("tail") or "") for e in prog), prog
    # Other fields are preserved.
    assert any(e.get("elapsed_s") == 1 for e in prog), prog


def _grant_exact_approval(tool_name="bash", content="echo hi"):
    """Build a real, one-use ExactToolApproval grant the way a chat 'approve'
    click does, so the approved-replay path in stream_agent_loop (a separate
    code path from the main per-round dispatch above, added after the
    original redaction work and never covered by it) gets exercised for
    real rather than only reviewed by inspection."""
    store = ToolApprovalStore()
    pending = store.create(
        owner="alice",
        session_id="session-1",
        origin_run_id="run-1",
        tool_name=tool_name,
        content=content,
        workspace=None,
        external_untrusted_context_seen=True,
        capabilities=capabilities_for_action(tool_name, content),
    )
    return store.consume(
        pending.approval_id,
        decision="approve",
        owner="alice",
        session_id="session-1",
    )


def test_redacts_approved_replay_command_and_output(monkeypatch):
    # The exact-approval replay path (an approved action re-run at the top of
    # a turn) builds its own command-display and output strings separately
    # from the main per-round dispatch above -- same leak surface, different
    # code path, so it needs the same redaction.
    _patch_common(monkeypatch)
    grant = _grant_exact_approval(content="echo api_key=secret123")

    async def _fake_exec(block, *a, **k):
        return ("bash", {"output": "token=secret123 done", "exit_code": 0})
    monkeypatch.setattr(al, "execute_tool_block", _fake_exec, raising=False)

    async def _fake_stream(_candidates, messages, **kwargs):
        yield f'data: {json.dumps({"delta": "ok"})}\n\n'
        yield "data: [DONE]\n\n"
    monkeypatch.setattr(al, "stream_llm_with_fallback", _fake_stream, raising=False)

    gen = al.stream_agent_loop(
        "http://x/v1", "m",
        [{"role": "user", "content": "run the approved command"}],
        max_rounds=1,
        relevant_tools={"bash"},
        owner="alice",
        session_id="session-1",
        exact_approval=grant,
    )
    events = _types(_collect(gen))
    approved = [e for e in events if e.get("approved") is True]
    assert approved, events
    assert all("secret123" not in json.dumps(e) for e in approved), approved
    assert any("api_key=[redacted]" in (e.get("command") or "") for e in approved), approved
    assert any("token=[redacted]" in (e.get("output") or "") for e in approved), approved
