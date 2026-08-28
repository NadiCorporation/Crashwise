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
from pathlib import Path

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage

from crashwise.agents.harness_synth.analyzer import (
    analyze_source,
    detect_language,
    find_entry_points,
)
from crashwise.agents.harness_synth.compiler import compile_harness, sanity_check
from crashwise.agents.harness_synth.debug_engine import debug_crash
from crashwise.agents.harness_synth.llm import ChatModelLike, get_chat_model
from crashwise.agents.harness_synth.prompts import (
    FEEDBACK_SECTION_TEMPLATE,
    PROFILE_SECTION_TEMPLATE,
    RETRY_SECTION_TEMPLATE,
    SEQUENCE_SECTION_TEMPLATE,
    SIMPLIFY_NOTE,
    SYSTEM_PROMPT,
    SYSTEM_PROMPT_AFLPP,
    USER_PROMPT_TEMPLATE,
)
from crashwise.agents.harness_synth.sequence_builder import (
    build_api_sequences,
    generate_stateful_harness,
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
    """Read the source file, run the static analyser, pick the best target and API sequence."""
    log.info(
        "harness_synth.node.analyze.start",
        source_path=str(state.source_path),
    )

    if not state.source_path.exists():
        raise FileNotFoundError(f"source file not found: {state.source_path}")

    source_code = state.source_path.read_text(encoding="utf-8", errors="replace")
    language = detect_language(state.source_path)

    # Full AST analysis pass
    ast_res = analyze_source(source_code, source_path=state.source_path)
    entry_points = ast_res.entry_points if ast_res.entry_points else find_entry_points(source_code)

    # Stateful API lifecycle sequence discovery (M2)
    sequences = build_api_sequences(
        source_code,
        entry_points=entry_points,
        call_graph=ast_res.call_graph,
        reachability_depths=ast_res.reachability_depths,
    )
    selected_seq = sequences[0] if sequences else None

    selected: EntryPoint | None = None
    if selected_seq and selected_seq.process_function:
        for ep in entry_points:
            if ep.name == selected_seq.process_function.name:
                selected = ep
                break
        if not selected:
            selected = EntryPoint(
                name=selected_seq.process_function.name,
                signature=selected_seq.process_function.signature,
                line=selected_seq.process_function.line,
                takes_buffer=any(p.is_buffer for p in selected_seq.process_function.params),
                score=selected_seq.process_function.score,
                call_depth=selected_seq.process_function.call_depth,
            )
    elif entry_points:
        selected = entry_points[0]

    # Operation Hydra Phase 3: Extract type definitions for the selected entry point.
    type_defs = ""
    if selected:
        from crashwise.agents.harness_synth.type_extractor import extract_types_for_signature
        target_root = state.source_path.parent
        for parent in state.source_path.parents:
            if (parent / "include").is_dir() or (parent / "CMakeLists.txt").is_file():
                target_root = parent
                break
        type_defs = extract_types_for_signature(target_root, selected.signature)
    elif source_code:
        # No entry point selected — extract types from all function signatures in the file.
        import re as _re

        from crashwise.agents.harness_synth.type_extractor import extract_types_for_signature
        target_root = state.source_path.parent
        for parent in state.source_path.parents:
            if (parent / "include").is_dir() or (parent / "CMakeLists.txt").is_file():
                target_root = parent
                break
        # Find all function signatures in the source.
        func_sigs = _re.findall(r"^\w[\w\s\*]*\s+\w+\s*\([^)]+\)", source_code[:8000], _re.MULTILINE)
        combined_sig = " ".join(func_sigs[:5])
        type_defs = extract_types_for_signature(target_root, combined_sig)

    log.info(
        "harness_synth.node.analyze.complete",
        source_chars=len(source_code),
        entry_points=len(entry_points),
        sequences=len(sequences),
        selected=selected.name if selected else None,
        selected_seq=selected_seq.process_function.name if selected_seq else None,
        selected_score=selected.score if selected else None,
        type_defs_chars=len(type_defs),
    )

    state.source_code = source_code
    state.language = language
    state.entry_points = entry_points
    state.selected_entry_point = selected
    state.api_sequences = sequences
    state.selected_sequence = selected_seq
    state.type_definitions = type_defs
    return state


# ── Node: generate_harness ───────────────────────────────────────────────────
async def generate_harness(state: HarnessState) -> HarnessState:
    """Ask the LLM for a harness; persist the extracted code on disk."""
    log.info(
        "harness_synth.node.generate.start",
        retry_count=state.retry_count,
        simplified_mode=state.simplified,
    )

    try:
        chat: ChatModelLike = get_chat_model()
        user_prompt = _build_user_prompt(state)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT_AFLPP if state.engine == "aflpp" else SYSTEM_PROMPT),
            HumanMessage(content=user_prompt),
        ]
        response = await _invoke_with_backoff(chat, messages)
    except Exception as exc:
        log.warning("harness_synth.node.generate.llm_error", error=str(exc))
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

    # Operation Hydra Fix 4: Anti-hallucination guardrail.
    # The harness must NOT redefine or modify target source functions.
    # It may only: #include headers, call target APIs, define LLVMFuzzerTestOneInput.
    hallucination = _check_target_redefinition(code, state.source_path)
    if hallucination:
        log.warning(
            "harness_synth.node.generate.hallucination_blocked",
            reason=hallucination,
        )
        state.error_history.append(
            f"BLOCKED: {hallucination}. "
            "Do NOT redefine target functions. Only #include headers and call the API."
        )
        state.retry_count += 1
        if state.retry_count > state.max_retries:
            return await _apply_fallback(state, reason=hallucination)
        return state

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
        # This can happen when generate_harness detects hallucination and returns
        # without setting harness_path. Check if we should retry.
        if state.retry_count < state.max_retries:
            log.warning(
                "harness_synth.node.validate.no_harness_retry",
                attempt=state.retry_count,
                max_retries=state.max_retries,
            )
            # Don't set done=True - let should_retry decide
            return state
        else:
            # Max retries exhausted - apply fallback
            log.warning("harness_synth.node.validate.no_harness_fallback")
            return await _apply_fallback(state, reason="No valid harness generated after max retries")

    # Discover built libraries and include paths from the target workdir.
    # The source_path is inside the target checkout; walk up to find build artifacts.
    target_root = state.source_path.parent
    # Walk up to find the project root (where build/ or CMakeLists.txt lives).
    for parent in [state.source_path.parent, *state.source_path.parents]:
        if (parent / "build").is_dir() or (parent / "CMakeLists.txt").is_file():
            target_root = parent
            break

    extra_includes = [state.source_path.parent, target_root]
    rpath_dirs: set[Path] = set()
    for lib in target_root.rglob("*.a"):
        if "CMakeFiles" not in str(lib) and "test" not in str(lib).lower():
            extra_link_args.append(str(lib))
    for lib in target_root.rglob("*.so"):
        if "CMakeFiles" not in str(lib) and "test" not in str(lib).lower():
            extra_link_args.append(str(lib))
            rpath_dirs.add(lib.parent)
    for rd in sorted(rpath_dirs):
        extra_link_args.extend(["-Wl,-rpath", str(rd)])
    # Add common include dirs.
    for subdir in ("include", "src", "build", "lib", "libarchive"):
        inc = target_root / subdir
        if inc.is_dir():
            extra_includes.append(inc)
    # Auto-discover directories containing public headers.
    for h in target_root.glob("*/*.h"):
        hdir = h.parent
        if hdir not in extra_includes and "CMakeFiles" not in str(hdir):
            extra_includes.append(hdir)
    # Define HAVE_CONFIG_H if config.h exists (common for autotools/cmake projects).
    if any((target_root / d / "config.h").exists() for d in ("build", ".")):
        extra_link_args.append("-DHAVE_CONFIG_H")

    extra_link_args.append("-Wno-deprecated-declarations")
    if (
        not any(a.endswith(".a") for a in extra_link_args)
        and state.source_path.exists()
        and state.source_path.suffix in (".c", ".cpp", ".cc")
        and not any(a.endswith(".so") for a in extra_link_args)
    ):
        extra_link_args.append(str(state.source_path))
    extra_link_args.extend(["-lm", "-lz", "-lpthread", "-lssl", "-lcrypto"])

    result = await compile_harness(
        engine=state.engine,
        harness_path=state.harness_path,
        workdir=state.workdir,
        language=state.language,
        extra_includes=extra_includes,
        extra_args=extra_link_args,
    )
    state.last_compile = result

    if result.success:
        # Operation Hydra: 5-second sanity gate.
        # Verify the harness actually hits target code before accepting it.
        if result.binary_path:
            sanity = await sanity_check(result.binary_path)
            if not sanity.passed:
                # Phase 2 ReAct: If it crashed, run GDB to get precise diagnosis.
                diagnosis_text = ""
                if sanity.crashed_immediately and result.binary_path:
                    try:
                        diag = await debug_crash(result.binary_path)
                        diagnosis_text = diag.to_prompt()
                        state.crash_diagnosis = diagnosis_text
                        log.info(
                            "harness_synth.node.validate.gdb_diagnosis",
                            signal=diag.signal,
                            function=diag.crash_function,
                            location=diag.crash_location,
                            summary=diag.summary[:100],
                        )
                    except Exception as exc:
                        log.warning("harness_synth.node.validate.gdb_failed", error=str(exc)[:100])

                # Build a detailed error message for the LLM.
                if diagnosis_text:
                    reason = (
                        f"CRASH DETECTED during sanity check.\n"
                        f"{diagnosis_text}\n"
                        f"FIX: Properly initialize all buffers, structs, and pointers "
                        f"before calling the target function."
                    )
                else:
                    reason = (
                        f"Sanity check FAILED: {sanity.edges_hit} edges hit in 5s. "
                        f"The harness does not exercise target code. "
                        f"Ensure the harness calls the target's API functions with valid arguments."
                    )

                state.error_history.append(reason)
                state.retry_count += 1
                log.warning(
                    "harness_synth.node.validate.sanity_failed",
                    attempt=state.retry_count,
                    edges_hit=sanity.edges_hit,
                    crashed=sanity.crashed_immediately,
                    has_gdb=bool(diagnosis_text),
                )
                if state.retry_count > state.max_retries:
                    await _apply_fallback(state, reason="sanity check failed after max retries")
                    if state.harness_path is not None:
                        final_result = await compile_harness(
                            engine=state.engine,
            harness_path=state.harness_path,
                            workdir=state.workdir,
                            language=state.language,
                            extra_includes=extra_includes,
                            extra_args=extra_link_args,
                        )
                        state.last_compile = final_result
                    state.done = True
                return state

        state.done = True
        log.info(
            "harness_synth.node.validate.success",
            attempt=state.retry_count + 1,
            binary=str(result.binary_path),
        )
        return state

    # Failure path.
    # Operation Hydra Phase 3: The Linker Hand — auto-fix compilation errors.
    from crashwise.agents.harness_synth.build_resolver import diagnose_compile_error
    auto_fixes = diagnose_compile_error(result.stderr, target_root)
    if auto_fixes:
        log.info("harness_synth.node.validate.auto_fix", fixes=len(auto_fixes))
        # Retry compilation with discovered paths.
        retry_result = await compile_harness(
            engine=state.engine,
            harness_path=state.harness_path,
            workdir=state.workdir,
            language=state.language,
            extra_includes=extra_includes,
            extra_args=extra_link_args + auto_fixes,
        )
        if retry_result.success:
            state.last_compile = retry_result
            # Still need to pass sanity gate.
            if retry_result.binary_path:
                sanity = await sanity_check(retry_result.binary_path)
                if sanity.passed:
                    state.done = True
                    log.info("harness_synth.node.validate.auto_fix_success")
                    return state

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
                engine=state.engine,
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

# ── Rate-Limit Resilient LLM Invocation (Operation Hydra Frontier Upgrade) ──

_RATE_LIMIT_MAX_RETRIES = 5
_RATE_LIMIT_BASE_DELAY = 2.0  # seconds
_RATE_LIMIT_MAX_DELAY = 60.0  # seconds


def _is_rate_limit_error(exc: Exception) -> bool:
    """Detect rate-limit / quota errors from any provider."""
    msg = str(exc).lower()
    # HTTP 429 (Too Many Requests)
    if "429" in msg or "rate" in msg or "quota" in msg:
        return True
    # Anthropic-specific
    if "overloaded" in msg or "rate_limit" in msg:
        return True
    # OpenAI-specific
    if "tokens per min" in msg or "requests per min" in msg:
        return True
    # Timeout (treat as transient — API may be overloaded)
    return "timed out" in msg or "timeout" in msg


async def _invoke_with_backoff(chat: ChatModelLike, messages: list[BaseMessage]) -> AIMessage:
    """Invoke the LLM with exponential backoff on rate-limit errors.

    This ensures transient API blocks (429, quota, timeout) don't consume
    the harness synthesis retry budget. The LangGraph loop's 3-life budget
    is reserved for actual code-quality failures, not API throttling.
    """
    import asyncio
    import random

    last_exc: Exception | None = None

    for attempt in range(_RATE_LIMIT_MAX_RETRIES):
        try:
            return await chat.ainvoke(messages)
        except Exception as exc:
            if not _is_rate_limit_error(exc):
                raise  # Not a rate limit — propagate immediately.

            last_exc = exc
            delay = min(
                _RATE_LIMIT_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1),
                _RATE_LIMIT_MAX_DELAY,
            )
            log.warning(
                "harness_synth.llm.rate_limited",
                attempt=attempt + 1,
                max_retries=_RATE_LIMIT_MAX_RETRIES,
                delay_seconds=round(delay, 1),
                error=str(exc)[:100],
            )
            await asyncio.sleep(delay)

    # All retries exhausted — raise the last error.
    raise last_exc or RuntimeError("LLM invocation failed after rate-limit retries")

def _check_target_redefinition(harness_code: str, source_path: Path) -> str | None:
    """Detect if the LLM redefined target functions (anti-hallucination).

    Returns a reason string if hallucination detected, None if clean.
    The harness is ONLY allowed to:
    - #include header files
    - Define LLVMFuzzerTestOneInput
    - Define helper wrappers that call target APIs
    It must NOT redefine functions that exist in the target source.
    """
    import re as _re

    # Read target source to find its function names.
    try:
        target_content = source_path.read_text(encoding="utf-8", errors="replace")[:16000]
    except OSError:
        return None  # Can't check — allow.

    # Find function definitions in the target.
    target_funcs: set[str] = set()
    for m in _re.finditer(r"^\w[\w\s\*]*\s+(\w+)\s*\([^)]*\)\s*\{", target_content, _re.MULTILINE):
        name = m.group(1)
        if name not in ("main", "if", "for", "while", "switch"):
            target_funcs.add(name)

    if not target_funcs:
        return None

    # Check if the harness redefines any target function.
    for m in _re.finditer(r"^\w[\w\s\*]*\s+(\w+)\s*\([^)]*\)\s*\{", harness_code, _re.MULTILINE):
        name = m.group(1)
        if name == "LLVMFuzzerTestOneInput":
            continue  # This is expected.
        if name in target_funcs:
            return f"Harness redefines target function '{name}' — target source is read-only"

    return None


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
        domain = str(profile.get("domain", "general"))
        complexity = float(profile.get("complexity_score", 0.0))  # type: ignore[arg-type]
        raw_surface = profile.get("attack_surface")
        attack_surface: list[object] = raw_surface if isinstance(raw_surface, list) else []
        raw_dangerous = profile.get("dangerous_functions")
        dangerous: list[object] = raw_dangerous if isinstance(raw_dangerous, list) else []
        strategy = str(profile.get("recommended_strategy", "standard"))
        profile_section = PROFILE_SECTION_TEMPLATE.format(
            domain=domain,
            complexity=complexity,
            attack_surface=", ".join(str(x) for x in attack_surface[:10]) if attack_surface else "(unknown)",
            dangerous_functions=", ".join(str(x) for x in dangerous[:10]) if dangerous else "(none detected)",
            strategy=strategy,
        )

    # Stateful API lifecycle sequence section (M2)
    sequence_section = ""
    if state.selected_sequence:
        seq = state.selected_sequence
        init_sig = seq.init_function.signature if seq.init_function else "(none)"
        config_sigs = (
            ", ".join(c.signature for c in seq.configure_functions)
            if seq.configure_functions
            else "(none)"
        )
        process_sig = seq.process_function.signature
        cleanup_sig = seq.cleanup_function.signature if seq.cleanup_function else "(none)"
        sequence_section = SEQUENCE_SECTION_TEMPLATE.format(
            context_type=seq.context_type or "(inferred)",
            init_signature=init_sig,
            config_signatures=config_sigs,
            process_signature=process_sig,
            cleanup_signature=cleanup_sig,
            init_name=seq.init_function.name if seq.init_function else "init",
            process_name=seq.process_function.name,
            cleanup_name=seq.cleanup_function.name if seq.cleanup_function else "cleanup",
        )

    # Feedback from previous fuzzing iteration (Phase 6).
    feedback_section = ""
    if state.feedback.strip():
        feedback_section = FEEDBACK_SECTION_TEMPLATE.format(
            feedback=state.feedback,
        )

    # Operation Hydra Phase 2: Crash diagnosis from GDB.
    crash_section = ""
    if state.crash_diagnosis.strip():
        crash_section = (
            "\n## GDB CRASH DIAGNOSIS (from your previous harness)\n"
            "Your previous harness CRASHED. Here is the GDB backtrace:\n"
            "```\n"
            f"{state.crash_diagnosis}\n"
            "```\n"
            "YOU MUST fix the initialization that caused this crash. "
            "Allocate buffers with sufficient size, initialize all struct fields, "
            "and ensure pointers are valid before calling the target function.\n"
        )

    # Operation Hydra Phase 2: Usage example from tests/examples.
    usage_section = ""
    if state.usage_example.strip():
        usage_section = (
            "\n## REFERENCE: How this API is used in the project's own tests\n"
            "```c\n"
            f"{state.usage_example}\n"
            "```\n"
            "Use this as a reference for proper initialization and calling convention.\n"
        )

    # Operation Hydra Phase 3: Type definitions for custom types.
    types_section = ""
    if state.type_definitions.strip():
        types_section = (
            "\n## TYPE DEFINITIONS (from project headers)\n"
            "These are the exact types used in the target function's signature:\n"
            "```c\n"
            f"{state.type_definitions}\n"
            "```\n"
            "Use these definitions to correctly allocate and initialize variables.\n"
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
            sequence_section=sequence_section,
            source_code=_truncate_source(state.source_code),
            feedback_section=feedback_section,
            retry_section=types_section + crash_section + usage_section + retry_section,
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

    If an API sequence or multi-parameter target is detected, synthesizes a
    stateful FuzzedDataProvider harness with full lifecycle and guaranteed teardown.
    Otherwise, forwards the buffer to the entry point or exercises included headers.
    """
    log.warning("harness_synth.fallback.engage", reason=reason)
    state.simplified = True

    include_basename = state.source_path.name

    # Check for stateful API sequence fallback (M2)
    seq = state.selected_sequence
    if seq is None and state.source_code:
        seqs = build_api_sequences(state.source_code, entry_points=state.entry_points)
        if seqs:
            seq = seqs[0]

    if seq is not None and (
        seq.init_function is not None
        or seq.configure_functions
        or seq.cleanup_function is not None
        or (seq.process_function and len(seq.process_function.params) > 1)
    ):
        harness = generate_stateful_harness(
            sequence=seq,
            header_include=include_basename,
            language=state.language,
        )
    else:
        ep = state.selected_entry_point
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
