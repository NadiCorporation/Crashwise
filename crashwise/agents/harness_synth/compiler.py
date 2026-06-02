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
    engine: str = "libfuzzer",
) -> CompileResult:
    """Compile ``harness_path`` to ``<workdir>/harness.out``.

    Returns a :class:`CompileResult` regardless of success — failures are
    structured data, not exceptions, so the LangGraph retry loop can act on
    them.
    """
    # Engine-aware compiler and sanitizer selection.
    if engine == "aflpp":
        # AFL++ mode: use afl-clang-fast, no -fsanitize=fuzzer, static link.
        compiler = shutil.which("afl-clang-fast") or _resolve_compiler(language)
        san_list = [s for s in sanitizers if s != "fuzzer"]
        sanitizer_flag = f"-fsanitize={','.join(san_list)}" if san_list else ""
    else:
        compiler = _resolve_compiler(language)
        sanitizer_flag = "-fsanitize=" + ",".join(sanitizers)

    output = workdir / "harness.out"
    workdir.mkdir(parents=True, exist_ok=True)
    cmd: list[str] = [
        compiler,
        "-O1",
        "-g",
    ]
    if sanitizer_flag:
        cmd.append(sanitizer_flag)
    # AFL++ mode: static link for cross-container portability.
    if engine == "aflpp":
        cmd.append("-static")
    cmd.extend([
        str(harness_path),
        "-o",
        str(output),
    ])
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


# ── 5-Second Sanity Gate (Operation Hydra Phase 1) ───────────────────────────

class SanityResult:
    """Result of the fast-fail sanity check."""

    __slots__ = ("crashed_immediately", "edges_hit", "output", "passed")

    def __init__(self, *, passed: bool, edges_hit: int = 0,
                 crashed_immediately: bool = False, output: str = ""):
        self.passed = passed
        self.edges_hit = edges_hit
        self.crashed_immediately = crashed_immediately
        self.output = output


async def sanity_check(
    binary_path: Path,
    *,
    timeout: float = 5.0,
    corpus_dir: Path | None = None,
) -> SanityResult:
    """Run the compiled harness for a few seconds to verify it hits target code.

    This is a fast-fail gate: if the harness compiles but doesn't actually
    exercise the target (0 edges), we reject it before wasting a full
    fuzzing iteration.

    The binary is run directly (not in Docker) since it was compiled in
    the same environment. We parse libFuzzer's stdout for coverage info.
    """
    if not binary_path.exists():
        return SanityResult(passed=False, output="Binary not found")

    # Create a minimal seed if no corpus provided.
    import tempfile
    tmp_corpus = None
    if corpus_dir is None or not corpus_dir.exists():
        tmp_corpus = Path(tempfile.mkdtemp(prefix="sanity_corpus_"))
        (tmp_corpus / "seed0").write_bytes(b"A" * 64)
        corpus_dir = tmp_corpus

    cmd = [
        str(binary_path),
        str(corpus_dir),
        f"-max_total_time={int(timeout)}",
        "-max_len=4096",
        "-print_final_stats=1",
        "-detect_leaks=0",
        "-handle_segv=0",
        "-handle_abrt=0",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={"ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0"},
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 5.0
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            stdout_bytes = b""
    except OSError as exc:
        return SanityResult(passed=False, output=f"Failed to run: {exc}")
    finally:
        # Cleanup temp corpus.
        if tmp_corpus and tmp_corpus.exists():
            import shutil as _shutil
            _shutil.rmtree(tmp_corpus, ignore_errors=True)

    output = stdout_bytes.decode("utf-8", errors="replace")

    # Parse libFuzzer output for coverage.
    edges_hit = 0
    import re as _re
    # libFuzzer prints: "#N INITED cov: X ft: Y" or "#N pulse cov: X"
    cov_matches = _re.findall(r"cov:\s*(\d+)", output)
    if cov_matches:
        edges_hit = max(int(m) for m in cov_matches)

    # Detect immediate crash (exit code != 0 within first second, or ASAN error).
    crashed_immediately = (
        proc.returncode != 0
        and "ERROR: AddressSanitizer" not in output  # Real crash = good, not a harness bug
        and edges_hit == 0
    )

    # Pass if we hit at least 1 meaningful edge (beyond the harness entry itself).
    passed = edges_hit >= 2 and not crashed_immediately

    log.info(
        "harness_synth.sanity_check",
        binary=str(binary_path),
        edges_hit=edges_hit,
        passed=passed,
        crashed_immediately=crashed_immediately,
        returncode=proc.returncode,
    )

    return SanityResult(
        passed=passed,
        edges_hit=edges_hit,
        crashed_immediately=crashed_immediately,
        output=output[:2000],
    )


__all__ = ["SanityResult", "compile_harness", "sanity_check"]
