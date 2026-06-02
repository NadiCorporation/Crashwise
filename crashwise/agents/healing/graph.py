# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unified LangGraph state machine for the CrashWise Healing Engine.

The graph drives two distinct missions through a *single* topology:

::

         ┌────────────┐
    ────▶│ agent_node │──── (no tool calls) ─────────────▶ END
         └─────┬──────┘
               │ (tool_calls present)
               ▼
         ┌────────────┐        ┌──────────────────┐
         │ tools_node │ ─────▶ │ post_tools_node  │ ── (terminate?) ──▶ END
         └────────────┘        └────────┬─────────┘
                                        │ (continue)
                                        └──────────▶ agent_node

The mode is selected on the very first turn via ``state.mode`` and
re-applied on every subsequent agent turn — so the same compiled graph
serves both flows. Termination is *absolute*: the graph stops as soon as
the agent calls ``signal_completion`` (which sets
``state.is_successful``) **or** ``state.attempt_count`` exceeds the
hard cap (default 10). This protects the platform from runaway LLM
spending.

State management:
    The :class:`HealingState` model is Pydantic-backed for strict
    validation and JSON-friendly serialisation, while exposing the
    ``messages`` field with the LangGraph ``add_messages`` reducer so
    the graph behaves like a TypedDict-backed agent loop.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Literal, cast

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, ConfigDict, Field

from crashwise.agents.healing.tools import HEALING_TOOLS
from crashwise.core.llm_factory import get_llm_provider
from crashwise.core.logging import get_logger

log = get_logger(__name__)


# ── Constants ───────────────────────────────────────────────────────────────
DEFAULT_MAX_ATTEMPTS: Final[int] = 10
"""Hard cap on agent_node iterations. The graph terminates the moment
``state.attempt_count > DEFAULT_MAX_ATTEMPTS`` regardless of progress —
this is the absolute boundary protecting against runaway LLM spend."""

_COMPLETION_TOOL_NAME: Final[str] = "signal_completion"


# ── Modes ───────────────────────────────────────────────────────────────────
class HealingMode(StrEnum):
    """Operational mode driving the agent's persona and termination heuristic."""

    BUILD = "build"
    """Adaptive Build loop — produce a clean instrumented binary."""

    REPAIR = "repair"
    """Autonomous Repair loop — eliminate a known crash via a source patch."""


# ── State ───────────────────────────────────────────────────────────────────
class HealingState(BaseModel):
    """Pydantic-backed state for the healing graph.

    ``messages`` carries the conversation between the agent and its
    tools — the :func:`add_messages` reducer ensures multi-node updates
    merge correctly. Every other field is owned exclusively by either
    the activity layer (inputs) or the graph (outputs).
    """

    model_config = ConfigDict(
        extra="forbid",
        arbitrary_types_allowed=True,
        validate_assignment=True,
    )

    # ── Conversation ────────────────────────────────────────────────────
    messages: Annotated[list[AnyMessage], add_messages] = Field(default_factory=list)

    # ── Inputs / sandbox handle ─────────────────────────────────────────
    workspace_path: Path = Field(
        ...,
        description="Absolute path inside the sandbox that maps to the target source.",
    )
    container_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Identifier of the openhands-sdk runtime container.",
    )
    mode: HealingMode = Field(
        ...,
        description="Healing persona: 'build' or 'repair'.",
    )
    crash_context: str | None = Field(
        default=None,
        description=(
            "Raw ASAN/KASAN crash log. Required when ``mode == 'repair'`` "
            "so the security-researcher persona has a concrete artefact to "
            "diagnose. Ignored in 'build' mode."
        ),
    )
    repo_url: str | None = Field(
        default=None,
        description="Optional git URL the agent should clone (Adaptive Build only).",
    )
    crash_id: str | None = Field(
        default=None,
        description="Database identifier for the crash being repaired (Repair only).",
    )
    crash_file_path: str | None = Field(
        default=None,
        description="Absolute path to the crash-triggering input file (Repair only).",
    )
    bug_type: str | None = Field(
        default=None,
        description="Classified bug type from triage (e.g. heap-buffer-overflow).",
    )
    root_cause: str | None = Field(
        default=None,
        description="LLM-generated root cause analysis from triage.",
    )

    # ── Loop control ────────────────────────────────────────────────────
    attempt_count: int = Field(
        default=0,
        ge=0,
        description="Number of times the agent_node has been entered.",
    )
    max_attempts: int = Field(
        default=DEFAULT_MAX_ATTEMPTS,
        ge=1,
        le=50,
        description="Absolute hard cap on agent iterations.",
    )
    is_successful: bool = Field(
        default=False,
        description=(
            "Set to True when the agent calls signal_completion(success=True). "
            "Once True the conditional edge routes the graph to END."
        ),
    )

    # ── Outputs the activity layer harvests on completion ──────────────
    final_summary: str = Field(
        default="",
        description="Free-form summary written by the agent at completion.",
    )
    artefact: str = Field(
        default="",
        description=(
            "Mode-dependent artefact. In 'build' mode this is the resolved "
            "build configuration; in 'repair' mode this is the unified diff."
        ),
    )


# ── System prompts ──────────────────────────────────────────────────────────
_BUILD_SYSTEM_PROMPT: Final[str] = """\
You are an elite Principal Systems Compiler Engineer specialising in C/C++
build systems (CMake, GNU Make, autotools, meson, Bazel) on Linux. You are
embedded inside a sandboxed openhands-sdk runtime and have two tools:

* `execute_sandbox_command(cmd)` — a stateful Bash shell. `cd`, `export`,
  `apt install`, etc. all persist across calls. Always confirm exit codes.
* `edit_sandbox_file(path, old_str, new_str)` — block replacement editor
  for surgical Makefile / CMakeLists.txt / configure script edits.

Mission: produce a clean instrumented build of the target at
WORKSPACE: {workspace_path}{repo_clause}

Required instrumentation flags (inject into BOTH CFLAGS and CXXFLAGS):
    -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard
    -g -O1 -fno-omit-frame-pointer

Required environment:
    CC=clang  CXX=clang++  LDFLAGS='-fsanitize=address,undefined'

Operating procedure:
1. Discover the build system (look for CMakeLists.txt, Makefile, meson.build,
   configure, configure.ac).
2. Resolve missing system dependencies via `apt-get update && apt-get install -y …`
   when linker errors complain about missing libraries (e.g. liblzma-dev,
   libssl-dev, zlib1g-dev). Pin to package names; never assume.
3. Inject the sanitizer + coverage flags into the build configuration.
4. Run the build. Stream stderr; reason about every error before re-trying.
5. When `make` / `cmake --build` exits 0 and produces a binary on disk,
   immediately call `signal_completion(success=True, summary=<build commands you ran>,
   artefact=<resolved CFLAGS/LDFLAGS/configure commands as JSON>)`.
   Do NOT run additional verification steps (nm, ldd, etc.) — they waste budget.

Hard rules:
- Do not modify source code under the project's `src/`, `lib/`, or
  `include/` trees. You may *only* edit build files (Makefile,
  CMakeLists.txt, configure scripts) and create wrapper compile scripts.
- Call signal_completion(success=True) as soon as the build exits 0 with a binary.
  Do not second-guess a successful build with extra checks.
- Be terse. Each tool call should advance the build by at least one step.
"""

_REPAIR_SYSTEM_PROMPT: Final[str] = """\
You are an elite Principal C/C++ Security Researcher specialising in
memory-safety vulnerabilities (use-after-free, out-of-bounds reads/writes,
heap/stack overflows, double-free, integer overflow). You are embedded
inside the same sandboxed openhands-sdk runtime that previously built the
target — the workspace is intact and the instrumented binary already exists.

Tools:
* `execute_sandbox_command(cmd)` — stateful Bash. Use it to run GDB on the
  crasher seed, inspect source, recompile after a patch, and re-run the
  binary against the seed to verify the crash is gone.
* `edit_sandbox_file(path, old_str, new_str)` — apply your patch with
  surgical block replacements. Always include 3-5 lines of surrounding
  context in `old_str` to guarantee uniqueness.

Mission inputs:
- WORKSPACE      : {workspace_path}
- CRASH_ID       : {crash_id}
- ASAN/KASAN LOG : (provided in the next user message)

Operating procedure:
1. Read the ASAN log. Identify: bug class (UAF / heap-buffer-overflow /
   stack-buffer-overflow / int-overflow / double-free / NPD), the crashing
   function, the source file and line number, and the access size.
2. Run GDB on the binary with the crasher seed to confirm the backtrace
   matches and to inspect register / variable state.
3. Open the offending source file and locate the precise root cause (off-by-one,
   missing length check, dangling pointer, integer truncation, etc.).
4. Synthesize a minimal targeted patch. Apply it via `edit_sandbox_file`.
5. Recompile (`make` or `cmake --build build` — do NOT regenerate from scratch).
6. Re-run the binary against the crasher seed and inspect for the absence of
   ASAN errors.
7. Run `git -C {workspace_path} diff` to capture the unified diff of your fix.
8. Call `signal_completion(success=True, summary=<root-cause sentence>,
   artefact=<git diff>)` ONLY when ASAN reports zero errors on the seed.

Hard rules:
- Patches must be minimal and confined to the offending function. Do not
  rewrite surrounding code or rename symbols.
- Do not declare success unless ASAN comes back clean on the original
  crasher seed. False positives waste verification budget.
- If after thorough diagnosis you cannot devise a safe patch, call
  `signal_completion(success=False, summary=<why>, artefact='')` so the
  pipeline can fall back to manual triage.
"""


# ── Internal terminator tool ────────────────────────────────────────────────
class _SignalCompletionArgs(BaseModel):
    """Arguments accepted by the terminator tool."""

    model_config = ConfigDict(extra="forbid")

    success: bool = Field(..., description="True when the mission is verified, False to abort.")
    summary: str = Field(
        default="",
        max_length=4_096,
        description="One-paragraph human-readable summary of what was done.",
    )
    artefact: str = Field(
        default="",
        description=(
            "In 'build' mode: JSON of the resolved build configuration. "
            "In 'repair' mode: the unified diff of the applied patch."
        ),
    )


@tool("signal_completion", args_schema=_SignalCompletionArgs)
async def signal_completion(success: bool, summary: str = "", artefact: str = "") -> str:
    """Signal that the mission is complete.

    The graph's post-tools router consumes this call to mark
    ``state.is_successful`` and route to END.
    """
    marker = "MISSION_COMPLETE" if success else "MISSION_ABORTED"
    return f"{marker} :: {summary[:300]}"


_GRAPH_TOOLS: Final[list[Any]] = [*HEALING_TOOLS, signal_completion]


# ── Nodes ───────────────────────────────────────────────────────────────────
async def agent_node(state: HealingState) -> dict[str, Any]:
    """The Unified Brain.

    Selects the persona prompt from ``state.mode``, binds the full tool
    set, and asks the LLM for the next action. Increments
    ``attempt_count`` *before* calling the LLM so the termination gate
    sees the up-to-date counter.
    """
    next_attempt = state.attempt_count + 1
    log.info(
        "healing.graph.agent.start",
        mode=str(state.mode),
        attempt=next_attempt,
        max_attempts=state.max_attempts,
        container_id=state.container_id,
    )

    # ── Build the message list ─────────────────────────────────────────
    history: list[AnyMessage] = list(state.messages)
    if not history:
        # First turn — seed the conversation with the system prompt and
        # the mission-specific kickoff message.
        history = _seed_conversation(state)

    # Always re-prepend (or replace) the system prompt for this turn so the
    # persona never drifts as the message list grows. We do this by
    # constructing a fresh prefix; the original SystemMessage in history
    # is preserved for full audit.
    system_prompt = _select_system_prompt(state)
    invocation: list[AnyMessage] = [SystemMessage(content=system_prompt)]
    invocation.extend(m for m in history if not isinstance(m, SystemMessage))

    # ── Call the LLM ───────────────────────────────────────────────────
    # Use the unified LLM factory for provider-agnosticism.
    chat = get_llm_provider().chat_model
    chat_with_tools = chat.bind_tools(_GRAPH_TOOLS)

    try:
        response = await chat_with_tools.ainvoke(invocation)
    except Exception as exc:
        log.warning(
            "healing.graph.agent.llm_error",
            mode=str(state.mode),
            attempt=next_attempt,
            error=str(exc)[:200],
        )
        # Fail loudly but gracefully: emit an AIMessage with no tool calls,
        # which causes the post-agent edge to route to END. The activity
        # layer will see ``is_successful=False`` and surface the failure.
        response = AIMessage(content=f"LLM invocation failed: {exc}. Aborting healing run.")

    log.info(
        "healing.graph.agent.complete",
        mode=str(state.mode),
        attempt=next_attempt,
        tool_calls=len(getattr(response, "tool_calls", []) or []),
        content_chars=len(_text_of(response)),
    )

    # Strip reasoning_content from DeepSeek responses to prevent the
    # "reasoning_content must be passed back" error on subsequent turns.
    response = _strip_reasoning_content(response)

    # The state-update dict is merged by LangGraph; ``messages`` uses the
    # ``add_messages`` reducer so we only return the *new* messages.
    return {
        "messages": [response],
        "attempt_count": next_attempt,
    }


# ToolNode is built once at graph compile time; it dispatches the LLM's
# tool_calls to the matching @tool function and emits ToolMessage objects.
_tools_node: Final[ToolNode] = ToolNode(_GRAPH_TOOLS, name="tools_node")


async def post_tools_node(state: HealingState) -> dict[str, Any]:
    """Inspect the ToolMessages just produced and update terminal flags.

    Specifically, if the agent called ``signal_completion`` we mirror its
    outcome into ``state.is_successful`` / ``state.final_summary`` /
    ``state.artefact`` so the absolute termination gate downstream can
    route to END.
    """
    update: dict[str, Any] = {}

    # Walk back through the most recent run of ToolMessages until we find
    # the originating AIMessage. Anything older is from a prior turn.
    completion_call: Any = None
    for msg in reversed(state.messages):
        if isinstance(msg, AIMessage):
            for call in msg.tool_calls or []:
                if call.get("name") == _COMPLETION_TOOL_NAME:
                    completion_call = call
                    break
            break

    if completion_call is None:
        log.debug(
            "healing.graph.post_tools.no_completion",
            attempt=state.attempt_count,
        )
        return update

    args = completion_call.get("args") or {}
    success = bool(args.get("success", False))
    summary = str(args.get("summary", "") or "")
    artefact = str(args.get("artefact", "") or "")

    update["is_successful"] = success
    update["final_summary"] = summary
    update["artefact"] = artefact

    log.info(
        "healing.graph.post_tools.completion_detected",
        success=success,
        summary_chars=len(summary),
        artefact_chars=len(artefact),
        attempt=state.attempt_count,
    )
    return update


# ── Routing ─────────────────────────────────────────────────────────────────
def route_after_agent(state: HealingState) -> Literal["tools_node", "__end__"]:
    """Route based on whether the agent emitted any tool calls."""
    if not state.messages:
        return "__end__"
    last = state.messages[-1]
    tool_calls = getattr(last, "tool_calls", None) or []
    if isinstance(last, AIMessage) and tool_calls:
        return "tools_node"
    return "__end__"


def termination_gate(state: HealingState) -> Literal["agent_node", "__end__"]:
    """Absolute termination boundary.

    The graph stops as soon as either:
      * ``state.is_successful`` is True, or
      * ``state.attempt_count >= state.max_attempts``.

    Otherwise we loop back to the agent for another turn.
    """
    if state.is_successful:
        log.info(
            "healing.graph.terminate.success",
            mode=str(state.mode),
            attempt=state.attempt_count,
        )
        return "__end__"

    if state.attempt_count >= state.max_attempts:
        log.warning(
            "healing.graph.terminate.budget_exhausted",
            mode=str(state.mode),
            attempt=state.attempt_count,
            max_attempts=state.max_attempts,
        )
        return "__end__"

    return "agent_node"


# ── Compilation ─────────────────────────────────────────────────────────────
def build_healing_graph() -> Any:
    """Return a compiled LangGraph executable for the healing engine.

    The graph is mode-agnostic at compile time; runtime behaviour is
    driven entirely by ``HealingState.mode`` so a single compiled object
    services both the Adaptive Build and Autonomous Repair activities.
    """
    graph: StateGraph[HealingState, Any, HealingState, HealingState] = StateGraph(
        state_schema=HealingState,
    )

    graph.add_node("agent_node", agent_node)
    graph.add_node("tools_node", _tools_node)
    graph.add_node("post_tools_node", post_tools_node)

    graph.add_edge(START, "agent_node")

    graph.add_conditional_edges(
        "agent_node",
        route_after_agent,
        {
            "tools_node": "tools_node",
            "__end__": END,
        },
    )
    graph.add_edge("tools_node", "post_tools_node")
    graph.add_conditional_edges(
        "post_tools_node",
        termination_gate,
        {
            "agent_node": "agent_node",
            "__end__": END,
        },
    )

    compiled = graph.compile()
    log.info("healing.graph.compiled", nodes=3)
    return compiled


# ── Internals ───────────────────────────────────────────────────────────────
def _select_system_prompt(state: HealingState) -> str:
    """Render the persona prompt for the active mode."""
    if state.mode == HealingMode.BUILD:
        repo_clause = f"\nREPO: {state.repo_url}" if state.repo_url else ""
        return _BUILD_SYSTEM_PROMPT.format(
            workspace_path=state.workspace_path,
            repo_clause=repo_clause,
        )
    if state.mode == HealingMode.REPAIR:
        return _REPAIR_SYSTEM_PROMPT.format(
            workspace_path=state.workspace_path,
            crash_id=state.crash_id or "unknown",
        )
    raise ValueError(f"unsupported HealingMode: {state.mode!r}")


def _seed_conversation(state: HealingState) -> list[AnyMessage]:
    """Construct the initial message list when ``state.messages`` is empty."""
    seed: list[AnyMessage] = [SystemMessage(content=_select_system_prompt(state))]
    if state.mode == HealingMode.BUILD:
        seed.append(
            HumanMessage(
                content=(
                    "Begin the adaptive build. Discover the build system inside "
                    f"{state.workspace_path}, install missing system dependencies, "
                    "inject the required sanitizer + coverage flags, and produce a "
                    "clean instrumented binary. Call signal_completion when done."
                )
            )
        )
    elif state.mode == HealingMode.REPAIR:
        log_blob = state.crash_context or "(no crash log was supplied)"
        # Build enriched context from triage data.
        extra_context = ""
        if state.crash_file_path:
            extra_context += f"\nCRASHER SEED PATH: {state.crash_file_path}"
        if state.bug_type:
            extra_context += f"\nBUG TYPE: {state.bug_type}"
        if state.root_cause:
            extra_context += f"\nROOT CAUSE (from triage): {state.root_cause}"
        seed.append(
            HumanMessage(
                content=(
                    "Diagnose and repair the following crash. The instrumented "
                    "binary already exists in the workspace. After applying your "
                    "patch, recompile and verify the original crasher seed no "
                    "longer triggers ASAN.\n"
                    f"{extra_context}\n\n"
                    "----- ASAN/KASAN LOG -----\n"
                    f"{log_blob}\n"
                    "--------------------------"
                )
            )
        )
    return seed


def _strip_reasoning_content(message: AIMessage) -> AIMessage:
    """Remove ``reasoning_content`` from an AIMessage's additional_kwargs.

    DeepSeek models in "thinking mode" return a ``reasoning_content`` field
    alongside the normal ``content``. If this field is present in the message
    history on subsequent turns, the API requires it to be passed back
    verbatim — but LangChain's serialization doesn't guarantee this. The
    simplest fix is to strip it before storing, so the next turn never
    triggers the "reasoning_content must be passed back" validation error.
    """
    kwargs = message.additional_kwargs
    if not kwargs or "reasoning_content" not in kwargs:
        return message
    cleaned = {k: v for k, v in kwargs.items() if k != "reasoning_content"}
    return AIMessage(
        content=message.content,
        additional_kwargs=cleaned,
        tool_calls=message.tool_calls,
        id=message.id,
    )


def _text_of(message: AnyMessage) -> str:
    """Best-effort string render of a chat message's content."""
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(str(block.get("text", "")))
        return "\n".join(parts)
    return str(content)


# Re-export ``cast`` to avoid mypy "unused import" complaints on hosts where
# the optional Annotated import path is dead-stripped — it documents the
# explicit cast pattern used inside the post_tools_node.
_ = cast


__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "HealingMode",
    "HealingState",
    "agent_node",
    "build_healing_graph",
    "post_tools_node",
    "route_after_agent",
    "signal_completion",
    "termination_gate",
]
