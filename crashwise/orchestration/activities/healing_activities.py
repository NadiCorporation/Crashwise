# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Temporal activities for the CrashWise Healing Engine.

Two activities expose the unified LangGraph + openhands-sdk pipeline to
the wider Temporal orchestrator:

* :func:`run_adaptive_build_activity` — spins up a fresh sandbox, drives
  the graph in :attr:`HealingMode.BUILD`, and returns the resolved build
  configuration once the agent produces a clean instrumented binary.

* :func:`run_autonomous_repair_activity` — re-engages a sandbox for a
  campaign that already has an instrumented build, drives the graph in
  :attr:`HealingMode.REPAIR` against an ASAN/KASAN crash log, and
  returns the verified ``.patch`` (unified diff) text.

Both activities are designed to be:

* **Idempotent within an attempt** — the sandbox is allocated, used, and
  torn down within a single activity invocation, so Temporal retries
  always start from a clean slate.
* **Heartbeating** — long-running LangGraph turns must not be killed by
  Temporal's start-to-close timeout, so we run a background heartbeat
  task for the duration of the graph invocation.
* **Cancel-safe** — on cancellation we still tear the sandbox down,
  which prevents container leaks in the worker.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from temporalio import activity
from temporalio.exceptions import ApplicationError

from crashwise.agents.healing.graph import (
    DEFAULT_MAX_ATTEMPTS,
    HealingMode,
    HealingState,
    build_healing_graph,
)
from crashwise.agents.healing.tools import (
    OpenHandsSandbox,
    bind_sandbox,
    unbind_sandbox,
)
from crashwise.core.llm_factory import get_llm_provider
from crashwise.core.logging import get_logger

log = get_logger(__name__)


# ── Tunables ────────────────────────────────────────────────────────────────
_HEARTBEAT_INTERVAL_SECONDS: Final[float] = 15.0
_WORKSPACE_ROOT: Final[Path] = Path("/tmp/crashwise/healing")
_REPO_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(?:https?://|git@|file://|/)[\w.\-:/@]+(?:\.git)?$")


# ── Activity 1: Adaptive Build ──────────────────────────────────────────────
@activity.defn(name="run_adaptive_build")
async def run_adaptive_build_activity(
    campaign_id: str,
    repo_url: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> dict[str, Any]:
    """Drive the healing graph in BUILD mode for ``campaign_id``.

    Allocates a workspace under ``/tmp/crashwise/healing/<campaign_id>``,
    boots an openhands-sdk runtime, asks the LangGraph machine to clone
    ``repo_url``, install missing system dependencies, inject ASAN /
    UBSan / coverage flags, and produce a clean instrumented build.

    Note on signature: the Temporal Python SDK conveys activity context
    via :func:`temporalio.activity.info` / :func:`temporalio.activity.heartbeat`
    rather than a positional ``ctx`` argument, so we follow the
    project's existing convention of multi-arg activities.

    Returns
    -------
    dict
        Keys: ``success`` (bool), ``campaign_id``, ``container_id``,
        ``workspace_path``, ``build_config`` (str — agent-supplied
        artefact, typically JSON), ``summary`` (str), ``attempt_count``
        (int), ``started_at`` / ``finished_at`` (ISO timestamps),
        ``transcript`` (list of role/content dicts for downstream audit).
    """
    info = activity.info()
    started_at = datetime.now(tz=UTC)
    log.info(
        "healing.build.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        campaign_id=campaign_id,
        repo_url=repo_url,
        max_attempts=max_attempts,
    )

    _validate_campaign_id(campaign_id)
    workspace = _allocate_workspace(campaign_id, mode="build")

    # Pre-clone the repo into the workspace so the sandbox has the codebase on attempt 1.
    if not (workspace / ".git").exists() and not any(workspace.iterdir()):
        try:
            clone_proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", repo_url, str(workspace),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(clone_proc.communicate(), timeout=60.0)
        except Exception as clone_exc:
            log.warning("healing.build.preclone_failed", error=str(clone_exc)[:200])

    sandbox: OpenHandsSandbox | None = None
    heartbeat_task: asyncio.Task[None] | None = None
    try:
        sandbox = await OpenHandsSandbox.allocate(
            workspace_path=workspace,
            llm_config=get_llm_provider().openhands_llm_config,
        )
        heartbeat_task = _start_heartbeat(
            tag="healing.build",
            container_id=sandbox.container_id,
            campaign_id=campaign_id,
        )

        initial = HealingState(
            workspace_path=workspace,
            container_id=sandbox.container_id,
            mode=HealingMode.BUILD,
            repo_url=repo_url,
            max_attempts=max_attempts,
        )

        final_state = await _drive_graph(initial=initial, sandbox=sandbox)

    except ApplicationError:
        raise  # Already structured — propagate verbatim.
    except Exception as exc:
        log.error(
            "healing.build.unexpected_error",
            campaign_id=campaign_id,
            error=str(exc)[:300],
        )
        # SDK not installed is a permanent failure — don't retry.
        is_sdk_missing = "openhands" in str(exc).lower() and "not installed" in str(exc).lower()
        raise ApplicationError(
            f"Adaptive build failed: {exc}",
            type="HealingBuildError",
            non_retryable=is_sdk_missing,
        ) from exc
    finally:
        if heartbeat_task is not None:
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task
        if sandbox is not None:
            with contextlib.suppress(Exception):
                await sandbox.shutdown()

    finished_at = datetime.now(tz=UTC)
    payload: dict[str, Any] = {
        "success": final_state.is_successful,
        "campaign_id": campaign_id,
        "container_id": final_state.container_id,
        "workspace_path": str(final_state.workspace_path),
        "build_config": final_state.artefact,
        "summary": final_state.final_summary,
        "attempt_count": final_state.attempt_count,
        "max_attempts": final_state.max_attempts,
        "repo_url": repo_url,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "transcript": _serialise_transcript(final_state.messages),
    }

    log.info(
        "healing.build.complete",
        workflow_id=info.workflow_id,
        campaign_id=campaign_id,
        success=payload["success"],
        attempts=payload["attempt_count"],
        artefact_chars=len(payload["build_config"]),
    )
    return payload


# ── Activity 2: Autonomous Repair ───────────────────────────────────────────
@activity.defn(name="run_autonomous_repair")
async def run_autonomous_repair_activity(
    crash_id: str,
    asan_log: str,
    workspace_path: str | None = None,
    campaign_id: str | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    crash_file_path: str | None = None,
    bug_type: str | None = None,
    root_cause: str | None = None,
) -> dict[str, Any]:
    """Drive the healing graph in REPAIR mode for a single crash.

    Re-engages the sandboxed runtime against the workspace that already
    contains the instrumented build (either reusing the build activity's
    workspace via ``workspace_path`` or allocating a sibling one).
    Feeds the ASAN/KASAN log into the graph as the kickoff message, lets
    the security-researcher persona patch the source, recompiles, and
    verifies that the original crasher seed no longer reproduces.

    Returns
    -------
    dict
        Keys: ``success`` (bool), ``crash_id``, ``patch`` (unified diff
        text — empty string when ``success`` is False), ``summary``
        (str), ``attempt_count`` (int), ``started_at`` / ``finished_at``,
        ``container_id``, ``workspace_path``, ``transcript``.
    """
    info = activity.info()
    started_at = datetime.now(tz=UTC)
    log.info(
        "healing.repair.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        crash_id=crash_id,
        campaign_id=campaign_id,
        log_chars=len(asan_log),
        max_attempts=max_attempts,
    )

    _validate_crash_id(crash_id)
    if not asan_log or not asan_log.strip():
        raise ApplicationError(
            "asan_log must be a non-empty crash report",
            type="HealingRepairBadInput",
            non_retryable=True,
        )

    workspace = (
        Path(workspace_path).resolve()
        if workspace_path
        else _allocate_workspace(campaign_id or crash_id, mode="repair")
    )
    workspace.mkdir(parents=True, exist_ok=True)

    sandbox: OpenHandsSandbox | None = None
    heartbeat_task: asyncio.Task[None] | None = None
    try:
        sandbox = await OpenHandsSandbox.allocate(
            workspace_path=workspace,
            llm_config=get_llm_provider().openhands_llm_config,
        )
        heartbeat_task = _start_heartbeat(
            tag="healing.repair",
            container_id=sandbox.container_id,
            campaign_id=campaign_id or crash_id,
        )

        initial = HealingState(
            workspace_path=workspace,
            container_id=sandbox.container_id,
            mode=HealingMode.REPAIR,
            crash_context=asan_log,
            crash_id=crash_id,
            crash_file_path=crash_file_path,
            bug_type=bug_type,
            root_cause=root_cause,
            max_attempts=max_attempts,
        )

        final_state = await _drive_graph(initial=initial, sandbox=sandbox)

    except ApplicationError:
        raise
    except Exception as exc:
        log.error(
            "healing.repair.unexpected_error",
            crash_id=crash_id,
            error=str(exc)[:300],
        )
        raise ApplicationError(
            f"Autonomous repair failed: {exc}",
            type="HealingRepairError",
            non_retryable=False,
        ) from exc
    finally:
        if heartbeat_task is not None:
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task
        if sandbox is not None:
            with contextlib.suppress(Exception):
                await sandbox.shutdown()

    finished_at = datetime.now(tz=UTC)
    patch_text = final_state.artefact if final_state.is_successful else ""
    payload: dict[str, Any] = {
        "success": final_state.is_successful,
        "crash_id": crash_id,
        "campaign_id": campaign_id,
        "container_id": final_state.container_id,
        "workspace_path": str(final_state.workspace_path),
        "patch": patch_text,
        "summary": final_state.final_summary,
        "attempt_count": final_state.attempt_count,
        "max_attempts": final_state.max_attempts,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "transcript": _serialise_transcript(final_state.messages),
    }

    log.info(
        "healing.repair.complete",
        workflow_id=info.workflow_id,
        crash_id=crash_id,
        success=payload["success"],
        attempts=payload["attempt_count"],
        patch_chars=len(payload["patch"]),
    )
    return payload


# ── Internals ───────────────────────────────────────────────────────────────
async def _drive_graph(
    *,
    initial: HealingState,
    sandbox: OpenHandsSandbox,
) -> HealingState:
    """Bind ``sandbox`` to the active context and run the compiled graph."""
    graph = build_healing_graph()

    token = bind_sandbox(sandbox)
    try:
        raw = await graph.ainvoke(initial)
    finally:
        unbind_sandbox(token)

    # LangGraph may return either the Pydantic state or a dict depending on
    # version — normalise both back to HealingState so callers get strict
    # typing.
    if isinstance(raw, HealingState):
        return raw
    return HealingState.model_validate(raw)


def _allocate_workspace(scope_id: str, *, mode: str) -> Path:
    """Return a deterministic workspace path scoped by campaign / crash id.

    Using ``/tmp/crashwise/healing/<mode>/<scope_id>`` keeps the
    Temporal worker's filesystem usage bounded and traceable. Repeated
    invocations for the same ``scope_id`` reuse the directory — this is
    desirable for repair runs that follow a build run.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", scope_id)[:64] or "anonymous"
    target = _WORKSPACE_ROOT / mode / safe
    target.mkdir(parents=True, exist_ok=True)
    return target


def _start_heartbeat(
    *,
    tag: str,
    container_id: str,
    campaign_id: str | None,
) -> asyncio.Task[None]:
    """Spawn a background task that heartbeats Temporal every N seconds."""

    async def _loop() -> None:
        try:
            while True:
                with contextlib.suppress(Exception):
                    activity.heartbeat(
                        {
                            "tag": tag,
                            "container_id": container_id,
                            "campaign_id": campaign_id,
                            "ts": datetime.now(tz=UTC).isoformat(),
                        }
                    )
                await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            return

    task: asyncio.Task[None] = asyncio.create_task(_loop(), name=f"{tag}.heartbeat")
    return task


def _serialise_transcript(messages: list[Any]) -> list[dict[str, Any]]:
    """Render the LangGraph message list as JSON-friendly audit data."""
    out: list[dict[str, Any]] = []
    for msg in messages:
        role = _role_for(msg)
        raw_content: Any = getattr(msg, "content", "")
        content: str = raw_content if isinstance(raw_content, str) else str(raw_content)
        entry: dict[str, Any] = {"role": role, "content": content}
        tool_calls = getattr(msg, "tool_calls", None)
        if tool_calls:
            entry["tool_calls"] = [
                {
                    "name": call.get("name"),
                    "args": call.get("args"),
                    "id": call.get("id"),
                }
                for call in tool_calls
            ]
        tool_call_id = getattr(msg, "tool_call_id", None)
        if tool_call_id:
            entry["tool_call_id"] = tool_call_id
        out.append(entry)
    return out


def _role_for(msg: Any) -> str:
    if isinstance(msg, SystemMessage):
        return "system"
    if isinstance(msg, HumanMessage):
        return "human"
    if isinstance(msg, AIMessage):
        return "ai"
    if isinstance(msg, ToolMessage):
        return "tool"
    return str(msg.__class__.__name__).lower()


# ── Input validation ────────────────────────────────────────────────────────
def _validate_campaign_id(campaign_id: str) -> None:
    if not campaign_id or not campaign_id.strip():
        raise ApplicationError(
            "campaign_id is required",
            type="HealingBuildBadInput",
            non_retryable=True,
        )
    if len(campaign_id) > 128:
        raise ApplicationError(
            "campaign_id is too long (max 128 chars)",
            type="HealingBuildBadInput",
            non_retryable=True,
        )


def _validate_crash_id(crash_id: str) -> None:
    if not crash_id or not crash_id.strip():
        raise ApplicationError(
            "crash_id is required",
            type="HealingRepairBadInput",
            non_retryable=True,
        )
    if len(crash_id) > 128:
        raise ApplicationError(
            "crash_id is too long (max 128 chars)",
            type="HealingRepairBadInput",
            non_retryable=True,
        )


def _validate_repo_url(repo_url: str) -> None:
    if not repo_url or not repo_url.strip():
        raise ApplicationError(
            "repo_url is required",
            type="HealingBuildBadInput",
            non_retryable=True,
        )
    if not _REPO_URL_PATTERN.match(repo_url.strip()):
        raise ApplicationError(
            f"repo_url does not look like a git URL: {repo_url[:120]!r}",
            type="HealingBuildBadInput",
            non_retryable=True,
        )


__all__ = [
    "run_adaptive_build_activity",
    "run_autonomous_repair_activity",
]
