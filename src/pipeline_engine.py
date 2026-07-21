"""
src/pipeline_engine.py

Executes skills/*.yaml pipelines: declarative multi-step chains of MCP tool
calls with Jinja-templated args/conditions. Until this module existed, these
YAML files were read by the LLM as plain documentation — nothing parsed or
ran them. Steps with no data dependency on one another (no {{ steps.<id>.* }}
reference between them) run concurrently; dependent steps wait their turn.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

import yaml
from jinja2.sandbox import SandboxedEnvironment

from src.constants import BASE_DIR

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(BASE_DIR) / "skills"

# Matches exec_in_toolchain()'s own default in mcp_servers/common.py.
DEFAULT_STEP_TIMEOUT = 300

_STEP_REF_RE = re.compile(r"\bsteps\.(\w+)\b")
_PLACEHOLDER_TOKENS = {"", "change_me_before_deploy"}

ProgressCallback = Callable[[dict], Awaitable[None]]


class PipelineError(Exception):
    """Raised for skill-definition or pipeline-execution errors."""


class ConfirmationRequired(PipelineError):
    """Raised when a skill declares authorization_prompt and confirmed=False.

    Callers should render `.prompt` to the user/API caller and re-invoke
    run() with confirmed=True once authorization has been given.
    """

    def __init__(self, prompt: str):
        self.prompt = prompt
        super().__init__(prompt)


def _regex_extract(text: Any, pattern: str, group: int = 1, default: str = "") -> str:
    """Jinja filter: pull a value out of a tool's free-text stdout, e.g.
    {{ steps.start_scan.stdout | regex_extract('ID: (\\S+)') }}"""
    match = re.search(pattern, text if isinstance(text, str) else "")
    return match.group(group) if match else default


def _make_env() -> SandboxedEnvironment:
    env = SandboxedEnvironment()
    env.filters["regex_extract"] = _regex_extract
    return env


def _load_yaml_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise PipelineError(f"{path}: expected a YAML mapping at the top level")
    return data


def list_skills() -> dict[str, dict]:
    """Return {skill_name: parsed_yaml} for every skills/**/*.yaml file."""
    skills: dict[str, dict] = {}
    if not SKILLS_DIR.is_dir():
        return skills
    for path in sorted(SKILLS_DIR.rglob("*.yaml")):
        try:
            data = _load_yaml_file(path)
        except (yaml.YAMLError, PipelineError) as exc:
            logger.warning("Skipping invalid skill file %s: %s", path, exc)
            continue
        name = data.get("name")
        if not name:
            logger.warning("Skipping skill file %s: missing 'name'", path)
            continue
        data["_path"] = str(path)
        skills[name] = data
    return skills


def load_skill(name: str) -> dict:
    skills = list_skills()
    if name not in skills:
        raise PipelineError(f"Unknown skill: {name!r}")
    return skills[name]


def _resolve_inputs(skill: dict, provided: dict) -> dict:
    resolved: dict[str, Any] = {}
    schema = skill.get("inputs") or {}
    for key, spec in schema.items():
        spec = spec or {}
        if key in provided and provided[key] is not None:
            resolved[key] = provided[key]
        elif "default" in spec:
            resolved[key] = spec["default"]
        elif spec.get("required", True):
            raise PipelineError(f"Missing required input: {key!r}")
        else:
            resolved[key] = None
    for key, value in provided.items():
        resolved.setdefault(key, value)
    return resolved


def _resolve_tool_qualified_name(tool_name: str, available_tools: list[dict]) -> str:
    if tool_name.startswith("mcp__"):
        return tool_name
    matches = [t["qualified_name"] for t in available_tools if t["name"] == tool_name]
    if not matches:
        raise PipelineError(f"Tool {tool_name!r} not found among connected MCP servers")
    if len(matches) > 1:
        raise PipelineError(
            f"Tool {tool_name!r} is ambiguous across servers ({matches}) — "
            "use a qualified mcp__<server>__<tool> name in the skill YAML"
        )
    return matches[0]


def _step_dependencies(step: dict) -> set[str]:
    """Statically scan a step's raw (unrendered) args/condition text for
    {{ steps.<id>... }} references, without doing a live Jinja render."""
    raw = yaml.dump({"args": step.get("args"), "condition": step.get("condition")})
    return set(_STEP_REF_RE.findall(raw))


def _render_value(env: SandboxedEnvironment, value: Any, context: dict) -> Any:
    if isinstance(value, str):
        return env.from_string(value).render(**context)
    if isinstance(value, dict):
        return {k: _render_value(env, v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_value(env, v, context) for v in value]
    return value


def _eval_condition(env: SandboxedEnvironment, condition: Optional[str], context: dict) -> bool:
    if not condition:
        return True
    expr = condition.strip()
    if expr.startswith("{{") and expr.endswith("}}"):
        expr = expr[2:-2].strip()
    try:
        compiled = env.compile_expression(expr, undefined_to_none=True)
        return bool(compiled(**context))
    except Exception as exc:  # noqa: BLE001
        raise PipelineError(f"Failed to evaluate condition {condition!r}: {exc}") from exc


def _token_is_placeholder() -> bool:
    return os.environ.get("EXEC_API_TOKEN", "").strip() in _PLACEHOLDER_TOKENS


def _global_exec_mode_is_container() -> bool:
    return os.environ.get("TOOLCHAIN_EXEC_MODE", "container").strip().lower() != "local"


def _check_exec_api_token_precondition() -> None:
    """Fail closed rather than silently auto-chaining through an
    unauthenticated exec API. See mcp_servers/common.py / docker/toolchain/
    exec_api.py: an unset or placeholder EXEC_API_TOKEN makes the sidecar's
    /exec endpoint accept requests from anything on the internal network.
    A human calling one tool at a time already carries that risk; an
    orchestrator that auto-chains many steps without per-step confirmation
    raises the stakes enough that this needs to be a hard stop, not a log
    line, when the toolchain is running in its default container mode."""
    if _global_exec_mode_is_container() and _token_is_placeholder():
        raise PipelineError(
            "Refusing to run pipeline: EXEC_API_TOKEN is unset or still the "
            "placeholder value while TOOLCHAIN_EXEC_MODE is 'container'. Set a "
            "real token (openssl rand -hex 32) in .env, or switch the tools "
            "this pipeline uses to TOOLCHAIN_EXEC_MODE=local, before running "
            "automated multi-step pipelines."
        )


async def run(
    skill_name: str,
    inputs: Optional[dict],
    mcp_manager,
    progress_cb: Optional[ProgressCallback] = None,
    confirmed: bool = False,
    step_timeout: int = DEFAULT_STEP_TIMEOUT,
) -> dict:
    """Execute a skill pipeline.

    Returns {"steps": {step_id: {"stdout", "stderr", "exit_code", ...}}, "skipped": [...]}.
    Raises ConfirmationRequired if the skill has a non-empty authorization_prompt
    and confirmed is False. Raises PipelineError for definition/execution errors.
    """
    skill = load_skill(skill_name)
    env = _make_env()
    resolved_inputs = _resolve_inputs(skill, inputs or {})

    auth_prompt = (skill.get("authorization_prompt") or "").strip()
    if auth_prompt and not confirmed:
        raise ConfirmationRequired(env.from_string(auth_prompt).render(**resolved_inputs))

    _check_exec_api_token_precondition()

    steps = skill.get("steps") or []
    if not steps:
        raise PipelineError(f"Skill {skill_name!r} has no steps")

    step_by_id: dict[str, dict] = {}
    for step in steps:
        step_id = step.get("id")
        if not step_id:
            raise PipelineError("Every step must have an 'id'")
        if step_id in step_by_id:
            raise PipelineError(f"Duplicate step id: {step_id!r}")
        step_by_id[step_id] = step

    dependencies = {sid: _step_dependencies(step) for sid, step in step_by_id.items()}
    unknown = {sid: deps - step_by_id.keys() for sid, deps in dependencies.items() if deps - step_by_id.keys()}
    if unknown:
        raise PipelineError(f"Steps reference unknown step ids: {unknown}")

    available_tools = mcp_manager.get_all_tools()
    results: dict[str, dict] = {}
    skipped: list[str] = []
    remaining = set(step_by_id.keys())

    async def _run_step(step_id: str) -> None:
        step = step_by_id[step_id]
        context = {**resolved_inputs, "steps": results}

        try:
            should_run = _eval_condition(env, step.get("condition"), context)
        except PipelineError as exc:
            results[step_id] = {"stdout": "", "stderr": str(exc), "exit_code": 1}
            if progress_cb:
                await progress_cb({"step": step_id, "status": "error", "error": str(exc)})
            return

        if not should_run:
            skipped.append(step_id)
            if progress_cb:
                await progress_cb({"step": step_id, "status": "skipped"})
            return

        if progress_cb:
            await progress_cb({"step": step_id, "status": "running"})

        try:
            qualified_name = _resolve_tool_qualified_name(step["tool"], available_tools)
            rendered_args = _render_value(env, step.get("args") or {}, context)
            result = await asyncio.wait_for(
                mcp_manager.call_tool(qualified_name, rendered_args),
                timeout=step_timeout,
            )
        except asyncio.TimeoutError:
            result = {"stdout": "", "stderr": f"Step {step_id!r} exceeded {step_timeout}s", "exit_code": 1}
        except PipelineError as exc:
            result = {"stdout": "", "stderr": str(exc), "exit_code": 1}
        except Exception as exc:  # noqa: BLE001
            result = {"stdout": "", "stderr": str(exc), "exit_code": 1}

        results[step_id] = result
        if progress_cb:
            await progress_cb({"step": step_id, "status": "done", "exit_code": result.get("exit_code", 0)})

    while remaining:
        resolved_ids = results.keys() | set(skipped)
        wave = {sid for sid in remaining if dependencies[sid] <= resolved_ids}
        if not wave:
            raise PipelineError(f"Cycle or unresolved dependency among steps: {sorted(remaining)}")
        await asyncio.gather(*(_run_step(sid) for sid in wave))
        remaining -= wave

    return {"steps": results, "skipped": skipped}
