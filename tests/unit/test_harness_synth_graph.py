# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""End-to-end tests for the harness-synthesis LangGraph state machine.

The LLM is stubbed via :func:`set_chat_model_override` so the loop is
deterministic. clang++ is required; tests are skipped without it.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from crashwise.agents.harness_synth.llm import (
    ChatModelLike,
    set_chat_model_override,
)
from crashwise.agents.harness_synth.synth import synthesize_harness

pytestmark = pytest.mark.skipif(
    shutil.which("clang++") is None,
    reason="clang++ not installed",
)


_TARGET_C_SRC = """\
#include <cstddef>
#include <cstdint>

inline int parse_packet(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    if (data[0] == 'X') return 1;
    return 0;
}
"""

_GOOD_HARNESS_RESPONSE = """\
Here you go.

```cpp
#include <cstddef>
#include <cstdint>
#include "target.cpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)parse_packet(data, size);
    return 0;
}
```
"""

_BAD_HARNESS_RESPONSE = """\
```cpp
#include <cstdint>
#include "target.cpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return totally_undefined_symbol(data, size);
}
```
"""


class _StubChatModel:
    """Minimal :class:`ChatModelLike` that returns canned responses in order."""

    def __init__(self, responses: list[str]) -> None:
        self._responses: Iterator[str] = iter(responses)

    async def ainvoke(self, _messages: list[BaseMessage]) -> AIMessage:
        try:
            text = next(self._responses)
        except StopIteration:
            text = ""
        return AIMessage(content=text)


@pytest.fixture(autouse=True)
def _restore_llm() -> Iterator[None]:
    yield
    set_chat_model_override(None)


@pytest.fixture(autouse=True)
def _stub_sanity_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the 5-second sanity gate.

    ``sanity_check`` runs the freshly compiled harness for 5s (libFuzzer
    ``-max_total_time=5``) to confirm it reaches target code. That's a real
    subprocess with a real 5s wall-clock cost per test — not LLM work. We
    stub it to report a passing result so the graph tests exercise the
    compile/retry/fallback flow without the delay.
    """
    from crashwise.agents.harness_synth import nodes
    from crashwise.agents.harness_synth.compiler import SanityResult

    async def _fake_sanity_check(
        binary_path: Path,
        *,
        timeout: float = 5.0,
        corpus_dir: Path | None = None,
    ) -> SanityResult:
        return SanityResult(passed=True, edges_hit=2)

    monkeypatch.setattr(nodes, "sanity_check", _fake_sanity_check)


@pytest.mark.asyncio
async def test_first_attempt_compiles(tmp_path: Path) -> None:
    src = tmp_path / "target.cpp"
    src.write_text(_TARGET_C_SRC, encoding="utf-8")

    set_chat_model_override(_StubChatModel([_GOOD_HARNESS_RESPONSE]))

    result = await synthesize_harness(
        source_path=src,
        workdir=tmp_path / "out",
        max_retries=2,
    )

    assert result.success is True
    assert result.simplified is False
    assert result.retry_count == 0
    assert result.binary_path is not None and result.binary_path.exists()
    assert result.selected_entry_point is not None
    assert result.selected_entry_point.name == "parse_packet"


@pytest.mark.asyncio
async def test_retry_then_succeed(tmp_path: Path) -> None:
    src = tmp_path / "target.cpp"
    src.write_text(_TARGET_C_SRC, encoding="utf-8")

    set_chat_model_override(_StubChatModel([_BAD_HARNESS_RESPONSE, _GOOD_HARNESS_RESPONSE]))

    result = await synthesize_harness(
        source_path=src,
        workdir=tmp_path / "out",
        max_retries=3,
    )

    assert result.success is True
    assert result.simplified is False
    assert result.retry_count == 1


@pytest.mark.asyncio
async def test_falls_back_to_simplified_after_max_retries(tmp_path: Path) -> None:
    src = tmp_path / "target.cpp"
    src.write_text(_TARGET_C_SRC, encoding="utf-8")

    # Always return broken code; the agent must engage the deterministic
    # fallback after exhausting retries.
    set_chat_model_override(_StubChatModel([_BAD_HARNESS_RESPONSE] * 10))

    result = await synthesize_harness(
        source_path=src,
        workdir=tmp_path / "out",
        max_retries=2,
    )

    assert result.simplified is True
    # Fallback wraps a takes_buffer entry point — should compile cleanly.
    assert result.success is True
    assert result.binary_path is not None and result.binary_path.exists()


@pytest.mark.asyncio
async def test_llm_exception_engages_fallback(tmp_path: Path) -> None:
    src = tmp_path / "target.cpp"
    src.write_text(_TARGET_C_SRC, encoding="utf-8")

    class _ExplodingModel:
        async def ainvoke(self, _messages: list[BaseMessage]) -> AIMessage:
            raise RuntimeError("network down")

    set_chat_model_override(_ExplodingModel())

    result = await synthesize_harness(
        source_path=src,
        workdir=tmp_path / "out",
        max_retries=1,
    )

    # Fallback path must produce a working harness regardless of LLM outage.
    assert result.simplified is True
    assert result.success is True


def test_chat_model_like_protocol_runtime() -> None:
    stub = _StubChatModel([])
    assert isinstance(stub, ChatModelLike)
