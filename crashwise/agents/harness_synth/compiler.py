# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Async wrapper around ``clang++`` for harness compilation.

We use ``-fsanitize=fuzzer,address,undefined`` by default — the canonical
libFuzzer + ASan + UBSan combo. Compilation happens inside the workdir
established by ``setup_target`` so all artefacts stay sandboxed.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from collections.abc import Sequence
from pathlib import Path

from crashwise.agents.harness_synth.state import CompileResult
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Hard cap on stderr captured per attempt; the LLM doesn't need megabytes.
_STDERR_BYTE_LIMIT: int = 16 * 1024


def _resolve_compiler(language: str) -> str:
    """Pick ``clang`` for C, ``clang++`` for C++. Fail early if neither is on PATH."""
    candidate = "clang" if language == "c" else "clang++"
    found = shutil.which(candidate)
    if found is None:
        raise FileNotFoundError(f"{candidate} not found on PATH. Install it via scripts/setup.sh.")
    return found


async def compile_harness(
    *,
    harness_path: Path,
    workdir: Path,
    language: str = "cpp",
    sanitizers: Sequence[str] = ("fuzzer", "address", "undefined"),
    extra_args: Sequence[str] = (),
    extra_includes: Sequence[Path] = (),
    timeout_seconds: float = 60.0,
) -> CompileResult:
    """Compile ``harness_path`` to ``<workdir>/harness.out``.

    Returns a :class:`CompileResult` regardless of success — failures are
    structured data, not exceptions, so the LangGraph retry loop can act on
    them.
    """
    compiler = _resolve_compiler(language)
    output = workdir / "harness.out"
    workdir.mkdir(parents=True, exist_ok=True)

    sanitizer_flag = "-fsanitize=" + ",".join(sanitizers)
    cmd: list[str] = [
        compiler,
        "-O1",
        "-g",
        sanitizer_flag,
        str(harness_path),
        "-o",
        str(output),
    ]
    for inc in extra_includes:
        cmd.extend(["-I", str(inc)])
    cmd.extend(extra_args)

    log.info(
        "harness_synth.compile.start",
        compiler=compiler,
        harness=str(harness_path),
        sanitizers=list(sanitizers),
    )

    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(workdir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            duration = time.monotonic() - started
            log.warning(
                "harness_synth.compile.timeout",
                duration=duration,
                timeout=timeout_seconds,
            )
            return CompileResult(
                success=False,
                returncode=124,
                stdout="",
                stderr=f"clang timed out after {timeout_seconds:.1f}s",
                binary_path=None,
                duration_seconds=duration,
            )
    except FileNotFoundError as exc:
        return CompileResult(
            success=False,
            returncode=127,
            stdout="",
            stderr=str(exc),
            binary_path=None,
            duration_seconds=0.0,
        )

    duration = time.monotonic() - started
    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    if len(stderr) > _STDERR_BYTE_LIMIT:
        stderr = (
            stderr[:_STDERR_BYTE_LIMIT]
            + f"\n... [{len(stderr) - _STDERR_BYTE_LIMIT} bytes truncated]"
        )

    success = proc.returncode == 0 and output.exists()
    log.info(
        "harness_synth.compile.complete",
        success=success,
        returncode=proc.returncode,
        duration=round(duration, 3),
    )
    return CompileResult(
        success=success,
        returncode=int(proc.returncode or 0),
        stdout=stdout,
        stderr=stderr,
        binary_path=output if success else None,
        duration_seconds=duration,
    )


__all__ = ["compile_harness"]
