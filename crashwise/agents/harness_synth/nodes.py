# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""LangGraph nodes for the harness-synthesis agent.

Three nodes drive the loop:

* :func:`analyze_code`     — populate ``state.entry_points``.
* :func:`generate_harness` — call the LLM, write source to disk.
* :func:`validate_harness` — invoke clang++; on failure increment retry
  count and feed stderr back into the next ``generate_harness`` pass.

A fourth helper, :func:`simplify_harness`, writes a deterministic
fall-back harness when the LLM has exhausted its retries — the agent must
never return an empty result.
"""

from __future__ import annotations

import re

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from crashwise.agents.harness_synth.analyzer import detect_language, find_entry_points
from crashwise.agents.harness_synth.compiler import compile_harness
from crashwise.agents.harness_synth.llm import ChatModelLike, get_chat_model
from crashwise.agents.harness_synth.prompts import (
    FEEDBACK_SECTION_TEMPLATE,
    PROFILE_SECTION_TEMPLATE,
    RETRY_SECTION_TEMPLATE,
    SIMPLIFY_NOTE,
    SYSTEM_PROMPT,
    USER_PROMPT_TEMPLATE,
)
from crashwise.agents.harness_synth.state import EntryPoint, HarnessState
from crashwise.core.logging import get_logger

log = get_logger(__name__)

_FENCE_RE = re.compile(
    r"```(?:cpp|c\+\+|c)?\s*\n(?P<body>.*?)```",
    re.DOTALL | re.IGNORECASE,
)
_PRIOR_ERRORS_LIMIT = 3
_PRIOR_ERROR_LINE_BUDGET = 6


# ── Node: analyze_code ───────────────────────────────────────────────────────
async def analyze_code(state: HarnessState) -> HarnessState:
    """Read the source file, run the static analyser, pick the best target."""
    log.info(
        "harness_synth.node.analyze.start",
        source_path=str(state.source_path),
    )

    if not state.source_path.exists():
        raise FileNotFoundError(f"source file not found: {state.source_path}")

    source_code = state.source_path.read_text(encoding="utf-8", errors="replace")
    language = detect_language(state.source_path)
    entry_points = find_entry_points(source_code)

    selected: EntryPoint | None = entry_points[0] if entry_points else None

    log.info(
        "harness_synth.node.analyze.complete",
        source_chars=len(source_code),
        entry_points=len(entry_points),
        selected=selected.name if selected else None,
        selected_score=selected.score if selected else None,
    )

    state.source_code = source_code
    state.language = language
    state.entry_points = entry_points
    state.selected_entry_point = selected
    return state


# ── Node: generate_harness ───────────────────────────────────────────────────
async def generate_harness(state: HarnessState) -> HarnessState:
    """Ask the LLM for a harness; persist the extracted code on disk."""
    log.info(
        "harness_synth.node.generate.start",
        retry_count=state.retry_count,
        simplified_mode=state.simplified,
    )

    chat: ChatModelLike = get_chat_model()
    user_prompt = _build_user_prompt(state)
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]

    try:
        response = await chat.ainvoke(messages)
    except Exception as exc:
        log.warning("harness_synth.node.generate.llm_error", error=str(exc))
        # Drop straight into fallback path; ValidateHarness will see the
        # simplified harness and either succeed or terminate the loop.
        return await _apply_fallback(state, reason=f"LLM call failed: {exc}")

    code = _extract_code_block(_message_text(response))
    if not code.strip():
        log.warning("harness_synth.node.generate.empty_response")
        return await _apply_fallback(state, reason="LLM returned no code block")

    # Semantic validation — block dangerous LLM-generated code.
    from crashwise.agents.harness_synth.validator import validate_harness as _validate_safety

    safety_result = _validate_safety(code)
    if not safety_result.passed:
        log.warning(
            "harness_synth.node.generate.validation_blocked",
            issues=len(safety_result.blocking_issues),
            summary=safety_result.summary(),
        )
        return await _apply_fallback(
            state,
            reason=f"LLM code blocked by validator: {safety_result.summary()}",
        )

    harness_path = state.workdir / "harness.cpp"
    harness_path.parent.mkdir(parents=True, exist_ok=True)
    harness_path.write_text(code, encoding="utf-8")

    state.harness_code = code
    state.harness_path = harness_path
    log.info(
        "harness_synth.node.generate.complete",
        harness_path=str(harness_path),
        harness_chars=len(code),
    )
    return state


# ── Node: validate_harness ───────────────────────────────────────────────────
async def validate_harness(state: HarnessState) -> HarnessState:
    """Compile the harness and decide whether to retry."""
    if state.harness_path is None:
        # Should not happen — generate_harness is upstream — but be defensive.
        log.warning("harness_synth.node.validate.no_harness")
        state.done = True
        return state

    # Discover built libraries and include paths from the target workdir.
    # The source_path is inside the target checkout; walk up to find build artifacts.
    target_root = state.source_path.parent
    # Walk up to find the project root (where build/ or CMakeLists.txt lives).
    for parent in [state.source_path.parent] + list(state.source_path.parents):
        if (parent / "build").is_dir() or (parent / "CMakeLists.txt").is_file():
            target_root = parent
            break

    extra_includes = [state.source_path.parent, target_root]
    extra_link_args: list[str] = []
    for lib in target_root.rglob("*.a"):
        if "CMakeFiles" not in str(lib) and "test" not in str(lib).lower():
            extra_link_args.append(str(lib))
    # Add common include dirs.
    for subdir in ("include", "src", "build"):
        inc = target_root / subdir
        if inc.is_dir():
            extra_includes.append(inc)

    result = await compile_harness(
        harness_path=state.harness_path,
        workdir=state.workdir,
        language=state.language,
        extra_includes=extra_includes,
        extra_args=extra_link_args,
    )
    state.last_compile = result

    if result.success:
        state.done = True
        log.info(
            "harness_synth.node.validate.success",
            attempt=state.retry_count + 1,
            binary=str(result.binary_path),
        )
        return state

    # Failure path.
    summary = _summarise_stderr(result.stderr)
    state.error_history.append(summary)
    state.retry_count += 1

    log.warning(
        "harness_synth.node.validate.failure",
        attempt=state.retry_count,
        max_retries=state.max_retries,
        returncode=result.returncode,
        summary=summary,
    )

    if state.retry_count > state.max_retries:
        # Final fallback: deterministic minimal harness.
        await _apply_fallback(state, reason="max retries exceeded")
        if state.harness_path is not None:
            final_result = await compile_harness(
                harness_path=state.harness_path,
                workdir=state.workdir,
                language=state.language,
                extra_includes=extra_includes,
                extra_args=extra_link_args,
            )
            state.last_compile = final_result
        state.done = True
    return state


# ── Routing ──────────────────────────────────────────────────────────────────
def should_retry(state: HarnessState) -> str:
    """Conditional edge router: ``generate`` to retry, ``__end__`` to stop."""
    if state.done:
        return "__end__"
    return "generate"


# ── Internals ────────────────────────────────────────────────────────────────
def _message_text(message: AIMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    # LangChain may return list-of-blocks for multi-modal models.
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and "text" in block:
            parts.append(str(block["text"]))
    return "\n".join(parts)


def _extract_code_block(text: str) -> str:
    match = _FENCE_RE.search(text)
    if match:
        return match.group("body").strip() + "\n"
    # If the model ignored the fence rule, accept the whole response if it
    # at least contains the libFuzzer entry point.
    if "LLVMFuzzerTestOneInput" in text:
        return text.strip() + "\n"
    return ""


def _summarise_stderr(stderr: str) -> str:
    """Compact a clang stderr blob to the lines most useful to an LLM."""
    if not stderr.strip():
        return "(no stderr)"
    interesting: list[str] = []
    for line in stderr.splitlines():
        lower = line.lower()
        if any(tok in lower for tok in ("error:", "warning:", "fatal", "undefined reference")):
            interesting.append(line.strip())
        if len(interesting) >= 10:
            break
    if not interesting:
        # Keep the tail — it usually contains the linker's last word.
        interesting = stderr.strip().splitlines()[-6:]
    return "\n".join(interesting)


def _build_user_prompt(state: HarnessState) -> str:
    ep = state.selected_entry_point

    # Phase 16: inject TargetProfile context.
    profile_section = ""
    if state.target_profile:
        profile = state.target_profile
        domain = profile.get("domain", "general")
        complexity = profile.get("complexity_score", 0.0)
        attack_surface = profile.get("attack_surface", [])
        dangerous = profile.get("dangerous_functions", [])
        strategy = profile.get("recommended_strategy", "standard")
        profile_section = PROFILE_SECTION_TEMPLATE.format(
            domain=domain,
            complexity=complexity,
            attack_surface=", ".join(attack_surface[:10]) if attack_surface else "(unknown)",
            dangerous_functions=", ".join(dangerous[:10]) if dangerous else "(none detected)",
            strategy=strategy,
        )

    # Feedback from previous fuzzing iteration (Phase 6).
    feedback_section = ""
    if state.feedback.strip():
        feedback_section = FEEDBACK_SECTION_TEMPLATE.format(
            feedback=state.feedback,
        )

    retry_section = ""
    if state.retry_count > 0 and state.last_compile is not None:
        # Show the *previous* (not current) errors so the LLM sees a trend.
        history = state.error_history[:-1][-_PRIOR_ERRORS_LIMIT:] or ["(none)"]
        prior = "\n".join(f"- {line}" for line in history)
        retry_section = RETRY_SECTION_TEMPLATE.format(
            attempt_number=state.retry_count,
            compile_stderr=_truncate_lines(state.last_compile.stderr, _PRIOR_ERROR_LINE_BUDGET * 4),
            prior_errors=prior,
        )
    if state.simplified:
        retry_section += "\n" + SIMPLIFY_NOTE

    return (
        USER_PROMPT_TEMPLATE.format(
            source_path=state.source_path,
            entry_point_name=ep.name if ep else "(none — pick anything reasonable)",
            entry_point_signature=ep.signature if ep else "(unknown)",
            entry_point_line=ep.line if ep else 0,
            language=state.language,
            profile_section=profile_section,
            source_code=_truncate_source(state.source_code),
            feedback_section=feedback_section,
            retry_section=retry_section,
        ).rstrip()
        + "\n"
    )


def _truncate_lines(text: str, line_budget: int) -> str:
    lines = text.splitlines()
    if len(lines) <= line_budget:
        return text
    head = "\n".join(lines[: line_budget // 2])
    tail = "\n".join(lines[-line_budget // 2 :])
    return f"{head}\n... [{len(lines) - line_budget} lines elided]\n{tail}"


def _truncate_source(source: str, max_chars: int = 12_000) -> str:
    if len(source) <= max_chars:
        return source
    return source[:max_chars] + f"\n/* ... [{len(source) - max_chars} bytes elided] */\n"


# ── Fallback harness ─────────────────────────────────────────────────────────
async def _apply_fallback(state: HarnessState, *, reason: str) -> HarnessState:
    """Write a deterministic, minimal harness that always compiles.

    The fallback simply forwards the libFuzzer input buffer to the most
    promising entry point if its signature matches one of two well-known
    shapes; otherwise it just consumes the buffer (still useful — catches
    UB inside any included headers).
    """
    log.warning("harness_synth.fallback.engage", reason=reason)
    state.simplified = True

    ep = state.selected_entry_point
    include_basename = state.source_path.name

    body: str
    if ep is not None and ep.takes_buffer:
        body = f"  (void){ep.name}(data, size);\n  return 0;\n"
    elif ep is not None and "char *" in ep.signature.replace(" ", " "):
        body = (
            "  if (size == 0) return 0;\n"
            "  std::string s(reinterpret_cast<const char*>(data), size);\n"
            f"  (void){ep.name}(s.c_str());\n"
            "  return 0;\n"
        )
    else:
        body = (
            "  // Trivial consumer — exercises ASan against included headers.\n"
            "  volatile uint8_t sink = 0;\n"
            "  for (size_t i = 0; i < size; ++i) sink ^= data[i];\n"
            "  (void)sink;\n"
            "  return 0;\n"
        )

    harness = (
        "// SPDX-License-Identifier: MIT\n"
        "// CrashWise auto-generated fallback harness.\n"
        "#include <cstddef>\n"
        "#include <cstdint>\n"
        "#include <string>\n"
        f'#include "{include_basename}"\n'
        "\n"
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        f"{body}"
        "}\n"
    )

    harness_path = state.workdir / "harness.cpp"
    harness_path.parent.mkdir(parents=True, exist_ok=True)
    harness_path.write_text(harness, encoding="utf-8")
    state.harness_path = harness_path
    state.harness_code = harness
    return state


__all__ = [
    "analyze_code",
    "generate_harness",
    "should_retry",
    "validate_harness",
]
