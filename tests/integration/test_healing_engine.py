# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Integration tests for the CrashWise Healing Engine.

Verifies the full LangGraph state machine (agent_node → tools_node →
post_tools_node → termination_gate) for both the Adaptive Build and
Autonomous Repair loops, using mock LLM responses and stubbed sandbox
tools so no real API tokens or Docker containers are consumed.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import AIMessage

from crashwise.agents.healing.graph import (
    HealingMode,
    HealingState,
    build_healing_graph,
)
from crashwise.agents.healing.tools import (
    OpenHandsSandbox,
    bind_sandbox,
    unbind_sandbox,
)
from crashwise.core.llm_factory import LLMProviderConfig, set_llm_provider_override

# ── Fake LLM that supports bind_tools ───────────────────────────────────────


class FakeChatModelWithTools:
    """A minimal mock chat model that supports bind_tools + ainvoke.

    Each call to ``ainvoke`` pops the next response from the queue.
    ``bind_tools`` returns ``self`` (tools are ignored — the test
    pre-programs the exact tool_calls the LLM should emit).
    """

    def __init__(self, responses: list[AIMessage]) -> None:
        self._responses = list(responses)
        self._call_count = 0

    def bind_tools(self, tools: Any, **kwargs: Any) -> FakeChatModelWithTools:
        return self

    async def ainvoke(self, messages: Any, **kwargs: Any) -> AIMessage:
        if self._call_count < len(self._responses):
            resp = self._responses[self._call_count]
        else:
            # Exhausted — return a no-op message that routes to END.
            resp = AIMessage(content="No more programmed responses.")
        self._call_count += 1
        return resp


# ── Fake LLMProviderConfig ──────────────────────────────────────────────────


def _make_fake_provider(responses: list[AIMessage]) -> LLMProviderConfig:
    """Build a frozen LLMProviderConfig whose .chat_model is our fake."""
    fake_model = FakeChatModelWithTools(responses)

    class _PatchedConfig(LLMProviderConfig):
        """Override chat_model to return the fake."""

        class Config:
            frozen = False

        @property
        def chat_model(self) -> Any:
            return fake_model

    # Construct via __new__ + manual init to bypass frozen dataclass.
    cfg = object.__new__(_PatchedConfig)
    object.__setattr__(cfg, "provider", "anthropic")
    object.__setattr__(cfg, "model", "claude-test-fake")
    object.__setattr__(cfg, "temperature", 0.0)
    object.__setattr__(cfg, "api_key", "sk-test-fake-key")
    object.__setattr__(cfg, "base_url", None)
    object.__setattr__(cfg, "max_tokens", 4096)
    object.__setattr__(cfg, "timeout_seconds", 180)
    object.__setattr__(cfg, "max_retries", 2)
    return cfg


# ── Stub sandbox ────────────────────────────────────────────────────────────


def _make_stub_sandbox(
    tmp_path: Path, tool_outputs: dict[str, str] | None = None
) -> OpenHandsSandbox:
    """Create a sandbox with mocked terminal/editor that return canned output."""
    outputs = tool_outputs or {}

    async def _fake_execute(command: str, **kwargs: Any) -> dict[str, Any]:
        # Match on substrings to simulate different command outcomes.
        for pattern, output in outputs.items():
            if pattern in command:
                return {"output": output, "exit_code": 0}
        return {"output": f"(stub) ran: {command}", "exit_code": 0}

    async def _fake_str_replace(path: str, old_str: str, new_str: str) -> dict[str, Any]:
        return {"output": f"Applied edit to {path}", "exit_code": 0}

    terminal = AsyncMock()
    terminal.execute = _fake_execute
    terminal.run = _fake_execute

    editor = AsyncMock()
    editor.str_replace = _fake_str_replace
    editor.replace = _fake_str_replace

    return OpenHandsSandbox(
        container_id=f"test-{uuid.uuid4().hex[:8]}",
        workspace_path=tmp_path,
        terminal=terminal,
        editor=editor,
    )


# ── Helper: build an AIMessage with tool_calls ──────────────────────────────


def _ai_tool_call(tool_name: str, args: dict[str, Any], call_id: str | None = None) -> AIMessage:
    """Construct an AIMessage that requests a single tool invocation."""
    cid = call_id or f"call_{uuid.uuid4().hex[:12]}"
    return AIMessage(
        content="",
        tool_calls=[{"name": tool_name, "args": args, "id": cid}],
    )


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _cleanup_provider_override() -> Any:
    """Ensure the global LLM provider override is cleared after each test."""
    yield
    set_llm_provider_override(None)


# ── Test 1: Adaptive Build Loop Success ─────────────────────────────────────


@pytest.mark.asyncio
async def test_adaptive_build_loop_success(tmp_path: Path) -> None:
    """The build agent installs a missing dep, re-runs make, and signals success."""

    # Program the mock LLM response sequence:
    # Turn 1: agent sees the initial prompt, runs `make` which will "fail"
    # Turn 2: agent sees the error, installs liblzma-dev
    # Turn 3: agent re-runs make (succeeds)
    # Turn 4: agent calls signal_completion(success=True)
    responses = [
        _ai_tool_call("execute_sandbox_command", {"cmd": "make -j$(nproc)"}),
        _ai_tool_call("execute_sandbox_command", {"cmd": "apt-get install -y liblzma-dev"}),
        _ai_tool_call("execute_sandbox_command", {"cmd": "make -j$(nproc)"}),
        _ai_tool_call(
            "signal_completion",
            {
                "success": True,
                "summary": "Build succeeded after installing liblzma-dev",
                "artefact": '{"CFLAGS": "-fsanitize=address"}',
            },
        ),
    ]

    provider = _make_fake_provider(responses)
    set_llm_provider_override(provider)

    # Stub sandbox: first `make` fails, second succeeds.
    call_count = {"make": 0}

    original_outputs = {
        "apt-get": "Reading package lists... Done\nliblzma-dev is already the newest version.",
    }

    sandbox = _make_stub_sandbox(tmp_path, tool_outputs=original_outputs)

    # Patch the sandbox execute to simulate make failure then success.

    async def _patched_execute(command: str, **kwargs: Any) -> dict[str, Any]:
        if "make" in command:
            call_count["make"] += 1
            if call_count["make"] == 1:
                return {
                    "output": "fatal error: lzma.h: No such file or directory\nmake: *** [all] Error 1",
                    "exit_code": 2,
                }
            return {"output": "Build complete. 0 errors.", "exit_code": 0}
        # Delegate to the stub for everything else.
        for pattern, output in original_outputs.items():
            if pattern in command:
                return {"output": output, "exit_code": 0}
        return {"output": f"(stub) ran: {command}", "exit_code": 0}

    sandbox.terminal.execute = _patched_execute
    sandbox.terminal.run = _patched_execute

    # Drive the graph.
    graph = build_healing_graph()
    initial = HealingState(
        workspace_path=tmp_path,
        container_id=sandbox.container_id,
        mode=HealingMode.BUILD,
        repo_url="https://github.com/example/target.git",
        max_attempts=10,
    )

    token = bind_sandbox(sandbox)
    try:
        result = await graph.ainvoke(initial)
    finally:
        unbind_sandbox(token)

    # Normalize result.
    state = HealingState.model_validate(result) if isinstance(result, dict) else result

    assert state.is_successful is True
    assert state.mode == HealingMode.BUILD
    assert state.attempt_count == 4
    assert "liblzma-dev" in state.final_summary
    assert state.artefact != ""


# ── Test 2: Autonomous Crash Repair Success ─────────────────────────────────


@pytest.mark.asyncio
async def test_autonomous_repair_loop_success(tmp_path: Path) -> None:
    """The repair agent diagnoses a heap-buffer-overflow, patches, and verifies."""

    asan_log = (
        "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014\n"
        "READ of size 4 at 0x602000000014 thread T0\n"
        "    #0 0x4a3b2c in parse_packet src/parser.c:42\n"
        "    #1 0x4a1000 in main src/main.c:10\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.c:42 in parse_packet\n"
    )

    patch_diff = (
        "--- a/src/parser.c\n"
        "+++ b/src/parser.c\n"
        "@@ -40,3 +40,4 @@\n"
        "     int len = get_length(buf);\n"
        "+    if (len > buf_size) len = buf_size;  // bounds check\n"
        "     memcpy(dst, buf, len);\n"
    )

    responses = [
        # Turn 1: view the source file.
        _ai_tool_call("execute_sandbox_command", {"cmd": "cat src/parser.c"}),
        # Turn 2: apply the fix.
        _ai_tool_call(
            "edit_sandbox_file",
            {
                "path": "/workspace/src/parser.c",
                "old_str": "    int len = get_length(buf);\n    memcpy(dst, buf, len);",
                "new_str": "    int len = get_length(buf);\n    if (len > buf_size) len = buf_size;\n    memcpy(dst, buf, len);",
            },
        ),
        # Turn 3: recompile.
        _ai_tool_call("execute_sandbox_command", {"cmd": "make -C build"}),
        # Turn 4: re-run binary with crasher seed — no ASAN error.
        _ai_tool_call("execute_sandbox_command", {"cmd": "./build/target crash.bin"}),
        # Turn 5: capture git diff.
        _ai_tool_call("execute_sandbox_command", {"cmd": "git diff"}),
        # Turn 6: signal completion with the patch.
        _ai_tool_call(
            "signal_completion",
            {
                "success": True,
                "summary": "Fixed heap-buffer-overflow in parse_packet by adding bounds check",
                "artefact": patch_diff,
            },
        ),
    ]

    provider = _make_fake_provider(responses)
    set_llm_provider_override(provider)

    sandbox = _make_stub_sandbox(
        tmp_path,
        tool_outputs={
            "cat src/parser.c": "int parse_packet(char *buf, int buf_size) {\n    int len = get_length(buf);\n    memcpy(dst, buf, len);\n}",
            "make": "Build complete.",
            "./build/target": "Execution finished normally. No errors.",
            "git diff": patch_diff,
        },
    )

    graph = build_healing_graph()
    initial = HealingState(
        workspace_path=tmp_path,
        container_id=sandbox.container_id,
        mode=HealingMode.REPAIR,
        crash_context=asan_log,
        crash_id="crash-001",
        max_attempts=10,
    )

    token = bind_sandbox(sandbox)
    try:
        result = await graph.ainvoke(initial)
    finally:
        unbind_sandbox(token)

    state = HealingState.model_validate(result) if isinstance(result, dict) else result

    assert state.is_successful is True
    assert state.mode == HealingMode.REPAIR
    assert "parser.c" in state.artefact
    assert state.attempt_count == 6
    assert "bounds check" in state.final_summary or "parse_packet" in state.final_summary


# ── Test 3: Termination Gate Enforcement ────────────────────────────────────


@pytest.mark.asyncio
async def test_loop_termination_gate(tmp_path: Path) -> None:
    """The graph terminates at max_attempts even when the LLM never signals completion."""

    max_attempts = 3

    # Program the LLM to always run a failing command — never calls signal_completion.
    responses = [
        _ai_tool_call("execute_sandbox_command", {"cmd": "make"})
        for _ in range(
            max_attempts + 5
        )  # More responses than max_attempts to prove the gate works.
    ]

    provider = _make_fake_provider(responses)
    set_llm_provider_override(provider)

    sandbox = _make_stub_sandbox(
        tmp_path,
        tool_outputs={"make": "error: compilation failed\nexit code 1"},
    )

    graph = build_healing_graph()
    initial = HealingState(
        workspace_path=tmp_path,
        container_id=sandbox.container_id,
        mode=HealingMode.BUILD,
        repo_url="https://github.com/example/stuck.git",
        max_attempts=max_attempts,
    )

    token = bind_sandbox(sandbox)
    try:
        result = await graph.ainvoke(initial)
    finally:
        unbind_sandbox(token)

    state = HealingState.model_validate(result) if isinstance(result, dict) else result

    # The graph MUST have stopped at exactly max_attempts.
    assert state.is_successful is False
    assert state.attempt_count == max_attempts
    # Verify it didn't consume more responses than allowed.
    fake_model = provider.chat_model
    assert fake_model._call_count == max_attempts
