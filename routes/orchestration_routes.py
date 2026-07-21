# routes/orchestration_routes.py
"""Programmatic/scheduled triggering of skills/*.yaml pipelines.

For interactive use from chat, see the `run_skill` tool_type wired in
src/tool_execution.py — that path streams step progress into the same
SSE tool_progress channel as any other long-running tool. This route is
the additive, non-chat entrypoint (e.g. for src/task_scheduler.py or
direct API callers) that runs the same src/pipeline_engine.py underneath.
"""
import asyncio
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.middleware import require_admin
from src import pipeline_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/orchestration", tags=["orchestration"])

# In-memory run log — pipeline runs are short-lived operational tasks, not
# durable records; a process restart losing in-flight run status is
# acceptable (same tradeoff src/bg_jobs.py makes for detached shell jobs).
_runs: dict[str, dict] = {}


class RunPipelineRequest(BaseModel):
    inputs: Optional[dict] = None
    confirmed: bool = False


def setup_orchestration_routes(mcp_manager):
    """Setup pipeline orchestration routes with the provided MCP manager."""

    @router.get("/pipelines")
    def list_pipelines(request: Request):
        """List every parsed skills/*.yaml pipeline with its input schema."""
        require_admin(request)
        skills = pipeline_engine.list_skills()
        return {
            "pipelines": [
                {
                    "name": name,
                    "version": skill.get("version"),
                    "description": skill.get("description"),
                    "inputs": skill.get("inputs") or {},
                    "requires_authorization": bool((skill.get("authorization_prompt") or "").strip()),
                    "step_count": len(skill.get("steps") or []),
                }
                for name, skill in sorted(skills.items())
            ]
        }

    @router.post("/pipelines/{name}/run")
    async def run_pipeline(name: str, body: RunPipelineRequest, request: Request):
        """Kick off a pipeline run in the background; poll it via GET /runs/{run_id}."""
        require_admin(request)
        try:
            pipeline_engine.load_skill(name)
        except pipeline_engine.PipelineError as exc:
            raise HTTPException(404, str(exc)) from exc

        run_id = uuid.uuid4().hex
        _runs[run_id] = {
            "run_id": run_id,
            "skill": name,
            "status": "running",
            "steps": {},
            "skipped": [],
            "error": None,
            "prompt": None,
        }

        async def _progress_cb(event: dict) -> None:
            _runs[run_id]["steps"][event["step"]] = event

        async def _execute() -> None:
            try:
                result = await pipeline_engine.run(
                    name,
                    body.inputs,
                    mcp_manager,
                    progress_cb=_progress_cb,
                    confirmed=body.confirmed,
                )
                _runs[run_id]["status"] = "done"
                _runs[run_id]["steps"] = result["steps"]
                _runs[run_id]["skipped"] = result["skipped"]
            except pipeline_engine.ConfirmationRequired as exc:
                _runs[run_id]["status"] = "needs_confirmation"
                _runs[run_id]["prompt"] = exc.prompt
            except pipeline_engine.PipelineError as exc:
                _runs[run_id]["status"] = "error"
                _runs[run_id]["error"] = str(exc)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Pipeline run %s failed unexpectedly", run_id)
                _runs[run_id]["status"] = "error"
                _runs[run_id]["error"] = str(exc)

        asyncio.create_task(_execute())
        return {"run_id": run_id, "status": "running"}

    @router.get("/runs/{run_id}")
    def get_run(run_id: str, request: Request):
        """Poll a pipeline run's status and per-step results."""
        require_admin(request)
        run = _runs.get(run_id)
        if not run:
            raise HTTPException(404, f"Unknown run_id: {run_id!r}")
        return run

    return router
