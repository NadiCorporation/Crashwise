# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""LangChain-compatible wrappers around the ``openhands-sdk`` runtime tools.

The CrashWise Healing Engine drives two autonomous loops:

* Adaptive Build (compile a target with full sanitizer + coverage flags).
* Autonomous Repair (root-cause an ASAN/KASAN crash and apply a patch).

Both loops need *stateful* shell access (so that ``apt install`` /
``export CFLAGS=...`` / ``cd build`` persist across turns) and *precise*
file-block edits so that the LLM can apply C/C++ patches without
clobbering surrounding code. The ``openhands-sdk`` provides exactly
those primitives:

* :class:`openhands_sdk.TerminalTool`   — persistent shell session.
* :class:`openhands_sdk.FileEditorTool` — block-replacement editor.

This module exposes both as native LangChain ``@tool`` functions so the
agent in :mod:`crashwise.agents.healing.graph` can invoke them through
the standard ``bind_tools`` -> ``ToolNode`` plumbing. The active
sandbox is pinned via a :class:`contextvars.ContextVar`, which keeps
concurrent Temporal activities isolated (each activity runs in its
own asyncio task and therefore its own context).

Lifecycle (managed by :mod:`crashwise.orchestration.activities.healing_activities`)::

    sandbox = await OpenHandsSandbox.allocate(workspace=...)
    token = bind_sandbox(sandbox)
    try:
        await graph.ainvoke(initial_state)   # tools resolve via ContextVar
    finally:
        unbind_sandbox(token)
        await sandbox.shutdown()
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import shlex
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, cast

from langchain_core.tools import tool
from pydantic import BaseModel, ConfigDict, Field

from crashwise.core.logging import get_logger

# ── openhands-sdk integration ────────────────────────────────────────────────
#
# The package is published as ``openhands-sdk`` on PyPI; its Python import
# root is ``openhands_sdk``. We import lazily-tolerantly so that unit tests
# (which stub the runtime via :func:`bind_sandbox`) can still execute on a
# host that doesn't have the SDK installed — at runtime the activity layer
# will refuse to start without it. The ``unused-ignore`` meta-code keeps the
# annotations valid both when the SDK is present (real classes) and when
# it is absent (treated as :data:`Any` placeholders).
try:  # pragma: no cover - exercised only when SDK is installed
    from openhands_sdk import (  # type: ignore[import-not-found,unused-ignore]
        FileEditorTool,
        TerminalTool,
    )
except ImportError:  # pragma: no cover - test/CI hosts without SDK
    TerminalTool = None  # type: ignore[assignment,misc,unused-ignore]
    FileEditorTool = None  # type: ignore[assignment,misc,unused-ignore]


log = get_logger(__name__)

# ── Defaults ────────────────────────────────────────────────────────────────
_DEFAULT_COMMAND_TIMEOUT_SECONDS: Final[float] = 600.0
_DEFAULT_IMAGE: Final[str] = "ghcr.io/all-hands-ai/runtime:0.39-nikolaik"
_OUTPUT_TRUNCATION_BUDGET: Final[int] = 16_384


# ── Sandbox handle ──────────────────────────────────────────────────────────
@dataclass(slots=True)
class _ToolResult:
    """Normalised output of an openhands-sdk tool invocation."""

    output: str
    exit_code: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.error is None


@dataclass(slots=True)
class OpenHandsSandbox:
    """A live openhands-sdk runtime that the healing graph can drive.

    The object is created by :meth:`allocate` (which spins up the
    container and instantiates :class:`TerminalTool` / :class:`FileEditorTool`)
    and torn down by :meth:`shutdown`. Between those calls every shell
    command is executed inside the **same** persistent shell, so
    environment mutations (``export``, ``cd``, ``apt install``…) are
    observable on subsequent calls — which is exactly what the LangGraph
    agent expects when iterating on a compilation.

    Attributes
    ----------
    container_id:
        Stable identifier for the underlying runtime container.
    workspace_path:
        Absolute path inside the container that maps to the cloned target.
    image:
        OCI image used to provision the runtime.
    terminal:
        The instantiated ``TerminalTool`` (``None`` until :meth:`allocate`).
    editor:
        The instantiated ``FileEditorTool`` (``None`` until :meth:`allocate`).
    """

    container_id: str
    workspace_path: Path
    image: str = _DEFAULT_IMAGE
    terminal: Any = None  # TerminalTool when SDK is loaded
    editor: Any = None  # FileEditorTool when SDK is loaded
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── Construction / teardown ──────────────────────────────────────────
    @classmethod
    async def allocate(
        cls,
        *,
        workspace_path: Path,
        image: str = _DEFAULT_IMAGE,
        container_id: str | None = None,
        terminal: Any = None,
        editor: Any = None,
        llm_config: dict[str, Any] | None = None,
    ) -> OpenHandsSandbox:
        """Provision a fresh openhands-sdk runtime.

        ``terminal`` / ``editor`` may be supplied for tests; production
        callers leave them ``None`` and the SDK builds the real instances
        bound to a Docker container.

        ``llm_config`` is the openhands-sdk LLM configuration dict
        produced by :attr:`LLMProviderConfig.openhands_llm_config`. When
        supplied, the SDK tools use the same model/key/endpoint as the
        LangGraph orchestration layer. When ``None``, the SDK falls back
        to its own environment-variable resolution.
        """
        if container_id is None:
            container_id = f"crashwise-heal-{uuid.uuid4().hex[:12]}"
        workspace_path.mkdir(parents=True, exist_ok=True)

        # Build kwargs that may include llm_config for the SDK.
        sdk_kwargs: dict[str, Any] = {
            "workspace_path": str(workspace_path),
            "container_id": container_id,
        }
        if llm_config is not None:
            sdk_kwargs["llm_config"] = llm_config

        if terminal is None:
            if TerminalTool is None:  # pragma: no cover - SDK absent
                raise RuntimeError(
                    "openhands-sdk is not installed. Add `openhands-sdk` to "
                    "your dependency manifest before invoking the healing engine."
                )
            terminal_kwargs = {**sdk_kwargs, "image": image}
            terminal = await _maybe_await(TerminalTool.create(**terminal_kwargs))

        if editor is None:
            if FileEditorTool is None:  # pragma: no cover - SDK absent
                raise RuntimeError(
                    "openhands-sdk is not installed. Add `openhands-sdk` to "
                    "your dependency manifest before invoking the healing engine."
                )
            editor = await _maybe_await(FileEditorTool.create(**sdk_kwargs))

        log.info(
            "healing.sandbox.allocated",
            container_id=container_id,
            workspace=str(workspace_path),
            image=image,
            llm_synced=llm_config is not None,
            llm_model=llm_config.get("model", "default") if llm_config else "default",
        )

        return cls(
            container_id=container_id,
            workspace_path=workspace_path,
            image=image,
            terminal=terminal,
            editor=editor,
        )

    async def shutdown(self) -> None:
        """Tear the runtime down. Idempotent."""
        for handle, name in ((self.terminal, "terminal"), (self.editor, "editor")):
            if handle is None:
                continue
            closer = getattr(handle, "close", None) or getattr(handle, "shutdown", None)
            if closer is None:
                continue
            try:
                await _maybe_await(closer())
            except Exception as exc:  # pragma: no cover - best-effort teardown
                log.warning(
                    "healing.sandbox.shutdown_partial",
                    container_id=self.container_id,
                    component=name,
                    error=str(exc)[:200],
                )
        log.info(
            "healing.sandbox.shutdown",
            container_id=self.container_id,
        )

    # ── Tool primitives ──────────────────────────────────────────────────
    async def execute(
        self,
        command: str,
        *,
        timeout_seconds: float = _DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> _ToolResult:
        """Run ``command`` inside the persistent shell and return its result."""
        if self.terminal is None:
            raise RuntimeError("OpenHandsSandbox is not initialised (terminal is None)")
        if not command or not command.strip():
            return _ToolResult(output="", exit_code=0)

        log.info(
            "healing.sandbox.execute",
            container_id=self.container_id,
            command=command[:160],
        )

        try:
            raw = await asyncio.wait_for(
                _invoke_tool_method(
                    self.terminal,
                    method_names=("execute", "run", "invoke", "call", "__call__"),
                    payload={"command": command},
                ),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            log.warning(
                "healing.sandbox.execute.timeout",
                container_id=self.container_id,
                timeout=timeout_seconds,
                command=command[:120],
            )
            return _ToolResult(
                output="",
                exit_code=124,
                error=f"command timed out after {timeout_seconds}s",
            )
        except Exception as exc:
            log.warning(
                "healing.sandbox.execute.error",
                container_id=self.container_id,
                error=str(exc)[:200],
                command=command[:120],
            )
            return _ToolResult(output="", exit_code=1, error=str(exc))

        return _normalise_tool_result(raw)

    async def str_replace(self, path: str, old_str: str, new_str: str) -> _ToolResult:
        """Apply a precise block replacement to a file inside the sandbox."""
        if self.editor is None:
            raise RuntimeError("OpenHandsSandbox is not initialised (editor is None)")
        if not old_str:
            return _ToolResult(
                output="",
                exit_code=2,
                error="old_str must be non-empty for safe block replacement",
            )

        log.info(
            "healing.sandbox.str_replace",
            container_id=self.container_id,
            path=path,
            old_chars=len(old_str),
            new_chars=len(new_str),
        )

        try:
            raw = await _invoke_tool_method(
                self.editor,
                method_names=("str_replace", "replace", "edit", "invoke", "call", "__call__"),
                payload={
                    "command": "str_replace",
                    "path": path,
                    "old_str": old_str,
                    "new_str": new_str,
                },
            )
        except Exception as exc:
            log.warning(
                "healing.sandbox.str_replace.error",
                container_id=self.container_id,
                path=path,
                error=str(exc)[:200],
            )
            return _ToolResult(output="", exit_code=1, error=str(exc))

        return _normalise_tool_result(raw)


# ── Active-sandbox context plumbing ─────────────────────────────────────────
_active_sandbox: contextvars.ContextVar[OpenHandsSandbox | None] = contextvars.ContextVar(
    "crashwise_active_sandbox", default=None
)


def bind_sandbox(sandbox: OpenHandsSandbox) -> contextvars.Token[OpenHandsSandbox | None]:
    """Pin ``sandbox`` as the active runtime for the current async context.

    Returns a token that callers must pass to :func:`unbind_sandbox` once
    the graph invocation is complete. Using a :mod:`contextvars`
    primitive (rather than a module-level global) keeps Temporal
    activities running concurrently in the same worker process safely
    isolated.
    """
    return _active_sandbox.set(sandbox)


def unbind_sandbox(token: contextvars.Token[OpenHandsSandbox | None]) -> None:
    """Reverse a previous :func:`bind_sandbox` call."""
    _active_sandbox.reset(token)


def get_active_sandbox() -> OpenHandsSandbox:
    """Return the sandbox currently bound to this async context.

    Raises
    ------
    RuntimeError
        If no sandbox has been bound. This indicates a programming error
        — the activity layer must always call :func:`bind_sandbox` before
        invoking the healing graph.
    """
    sandbox = _active_sandbox.get()
    if sandbox is None:
        raise RuntimeError(
            "No OpenHandsSandbox is bound to the current context. "
            "Did you forget to call bind_sandbox(...) before driving the graph?"
        )
    return sandbox


# ── LangChain tool: execute_sandbox_command ─────────────────────────────────
class _ExecuteSandboxCommandArgs(BaseModel):
    """Arguments for :func:`execute_sandbox_command`."""

    model_config = ConfigDict(extra="forbid")

    cmd: str = Field(
        ...,
        min_length=1,
        max_length=8_192,
        description=(
            "Single shell command to run inside the persistent sandbox shell. "
            "State (cwd, exported variables, installed apt packages) is "
            "preserved between calls. Use compound commands (`a && b`) to "
            "guarantee ordering within one turn."
        ),
    )
    timeout_seconds: float = Field(
        default=_DEFAULT_COMMAND_TIMEOUT_SECONDS,
        ge=1.0,
        le=3_600.0,
        description="Hard wall-clock cap for the command (seconds).",
    )


@tool("execute_sandbox_command", args_schema=_ExecuteSandboxCommandArgs)
async def execute_sandbox_command(
    cmd: str,
    timeout_seconds: float = _DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> str:
    """Run ``cmd`` inside the persistent sandboxed shell.

    Use this for *every* shell interaction the agent needs: ``apt install``,
    ``cmake -B build``, ``make``, ``gdb -ex bt``, ``./harness crash.bin``,
    ``export CFLAGS='-fsanitize=address'``, etc. The shell is sticky — a
    later call sees the side effects of earlier calls (current directory,
    exported variables, installed packages).

    Returns a structured, length-bounded transcript that the LLM can
    parse: a header line listing the exit code, then stdout, then stderr.
    """
    sandbox = get_active_sandbox()

    # Defensive: refuse blatantly destructive commands targeting the host's
    # filesystem outside the workspace. This is belt-and-braces — the
    # openhands-sdk runtime itself runs inside a container, but we still
    # don't want the LLM to wipe the workspace it's trying to repair.
    forbidden = _detect_forbidden_command(cmd)
    if forbidden:
        log.warning(
            "healing.tool.command_blocked",
            container_id=sandbox.container_id,
            reason=forbidden,
            command=cmd[:160],
        )
        return f"BLOCKED: {forbidden}. Refusing to run `{cmd[:120]}`."

    result = await sandbox.execute(cmd, timeout_seconds=timeout_seconds)
    return _format_tool_transcript(
        header=f"exit_code={result.exit_code}",
        body=result.output,
        error=result.error,
    )


# ── LangChain tool: edit_sandbox_file ───────────────────────────────────────
class _EditSandboxFileArgs(BaseModel):
    """Arguments for :func:`edit_sandbox_file`."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        ...,
        min_length=1,
        max_length=4_096,
        description="Absolute path of the file inside the sandbox to edit.",
    )
    old_str: str = Field(
        ...,
        min_length=1,
        description=(
            "Exact, contiguous block of source to replace. Must occur "
            "exactly once in the target file. Include enough surrounding "
            "context (3-5 lines) to guarantee uniqueness."
        ),
    )
    new_str: str = Field(
        ...,
        description=(
            "Replacement block. May be empty (effectively a deletion). "
            "Preserve original indentation and trailing newline conventions."
        ),
    )


@tool("edit_sandbox_file", args_schema=_EditSandboxFileArgs)
async def edit_sandbox_file(path: str, old_str: str, new_str: str) -> str:
    """Apply a precise block replacement to a source file inside the sandbox.

    This is *not* a regex replace and *not* a whole-file overwrite. The
    underlying ``FileEditorTool`` uses anchored block-replacement
    semantics, which is exactly what LLM-generated C/C++ patches need:
    the model declares an old block (with surrounding context) and a new
    block, and the editor refuses the edit if ``old_str`` does not appear
    exactly once in the file.

    Returns a structured transcript describing the edit, including a
    short diff-like preview when the SDK supplies one.
    """
    sandbox = get_active_sandbox()
    result = await sandbox.str_replace(path=path, old_str=old_str, new_str=new_str)
    return _format_tool_transcript(
        header=f"edit_path={path}",
        body=result.output or "(no output from FileEditorTool)",
        error=result.error,
    )


# ── Public tool registry ────────────────────────────────────────────────────
HEALING_TOOLS: Final[list[Any]] = [execute_sandbox_command, edit_sandbox_file]
"""LangChain tools that the healing agent may invoke."""


# ── Internals ───────────────────────────────────────────────────────────────
async def _maybe_await(value: Any) -> Any:
    """Await ``value`` if it is awaitable, otherwise return as-is."""
    if inspect.isawaitable(value):
        return await value
    return value


async def _invoke_tool_method(
    handle: Any,
    *,
    method_names: tuple[str, ...],
    payload: dict[str, Any],
) -> Any:
    """Call the first available method on ``handle`` with ``payload``.

    The openhands-sdk has gone through several API revisions; some
    versions expose ``.execute(command=...)``, others ``.run(action=...)``,
    others ``.__call__(**kwargs)``. We probe the candidates in order so
    the wrapper survives minor SDK upgrades.
    """
    last_exc: Exception | None = None
    for name in method_names:
        method = getattr(handle, name, None)
        if method is None:
            continue
        try:
            try:
                return await _maybe_await(method(**payload))
            except TypeError:
                # Some SDK methods expect a single action object rather
                # than kwargs — fall through to positional invocation.
                return await _maybe_await(method(payload))
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc is not None:
        raise last_exc
    raise AttributeError(
        f"openhands-sdk handle {type(handle).__name__!r} exposes none of "
        f"{method_names!r}; the SDK API may have changed."
    )


def _normalise_tool_result(raw: Any) -> _ToolResult:
    """Coerce whatever the openhands-sdk tool returned into :class:`_ToolResult`."""
    if isinstance(raw, _ToolResult):
        return raw
    if isinstance(raw, dict):
        return _ToolResult(
            output=_truncate(str(raw.get("output", raw.get("stdout", "")))),
            exit_code=int(raw.get("exit_code", raw.get("returncode", 0)) or 0),
            error=cast(str | None, raw.get("error") or raw.get("stderr") or None),
        )
    if isinstance(raw, str):
        return _ToolResult(output=_truncate(raw))

    # Generic SDK observation object — pull canonical attributes if present.
    output = getattr(raw, "output", None)
    if output is None:
        output = getattr(raw, "stdout", None)
    if output is None:
        output = getattr(raw, "content", None)
    if output is None:
        output = str(raw)

    exit_code = getattr(raw, "exit_code", None)
    if exit_code is None:
        exit_code = getattr(raw, "returncode", 0)

    error = getattr(raw, "error", None) or getattr(raw, "stderr", None)

    return _ToolResult(
        output=_truncate(str(output)),
        exit_code=int(exit_code or 0),
        error=str(error) if error else None,
    )


def _format_tool_transcript(*, header: str, body: str, error: str | None) -> str:
    """Render a tool result as a compact transcript for the LLM."""
    parts: list[str] = [header]
    if body:
        parts.append("--- output ---")
        parts.append(_truncate(body))
    if error:
        parts.append("--- error ---")
        parts.append(_truncate(error))
    return "\n".join(parts)


def _truncate(value: str, limit: int = _OUTPUT_TRUNCATION_BUDGET) -> str:
    """Trim long outputs so the LLM context window stays sane."""
    if len(value) <= limit:
        return value
    head = value[: limit // 2]
    tail = value[-limit // 2 :]
    return f"{head}\n…[truncated {len(value) - limit} chars]…\n{tail}"


# ── Command guardrails ──────────────────────────────────────────────────────
_FORBIDDEN_PATTERNS: Final[tuple[str, ...]] = (
    "rm -rf /",
    ":(){:|:&};:",
    "mkfs",
    "dd if=/dev/zero of=/dev/sd",
    "shutdown",
    "reboot",
)


def _detect_forbidden_command(cmd: str) -> str | None:
    """Return a reason if ``cmd`` should be refused, ``None`` otherwise."""
    lowered = cmd.strip().lower()
    for needle in _FORBIDDEN_PATTERNS:
        if needle in lowered:
            return f"command matches forbidden pattern '{needle}'"
    # Detect ``rm -rf <path>`` whose path escapes the workspace.
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if len(tokens) >= 3 and tokens[0] == "rm" and any(t in {"-rf", "-fr"} for t in tokens[1:2]):
        for tok in tokens[2:]:
            if tok.startswith("/") and not tok.startswith(
                ("/tmp", "/var/tmp", "/workspace", "/srv")
            ):
                return f"refusing recursive delete of out-of-workspace path '{tok}'"
    return None


__all__ = [
    "HEALING_TOOLS",
    "OpenHandsSandbox",
    "bind_sandbox",
    "edit_sandbox_file",
    "execute_sandbox_command",
    "get_active_sandbox",
    "unbind_sandbox",
]
