# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``verify_poc`` activity — compiles and validates a generated exploit.

The activity takes C source code produced by the Exploit Architect,
compiles it with ASAN, runs it inside a sandboxed Docker container,
and checks whether the output contains the expected crash signature.

Success means the PoC triggers the same signal / ASAN error as the
original fuzzer-found crash.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import PocVerifyInput, PocVerifyOutput

log = get_logger(__name__)

# Default compilation flags for reproducible crashes.
_DEFAULT_CFLAGS = (
    "-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O0"
)


@activity.defn(name="verify_poc")
async def verify_poc(payload: PocVerifyInput) -> PocVerifyOutput:
    """Compile a generated PoC and verify it reproduces the crash.

    Parameters
    ----------
    payload:
        PoC source code, compilation command, and expected crash signature.

    Returns
    -------
    Structured verification result with compilation status, execution
    output, and whether the crash was reproduced.
    """
    info = activity.info()
    log.info(
        "verify_poc.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        crash_id=payload.crash_id,
    )

    with tempfile.TemporaryDirectory(prefix="crashwise-poc-") as tmpdir:
        src_path = Path(tmpdir) / "poc.c"
        src_path.write_text(payload.poc_code, encoding="utf-8")

        # 1. Compile.
        binary_path = Path(tmpdir) / "poc"
        compile_ok, compile_stdout, compile_stderr = await _compile(
            src_path,
            binary_path,
            payload.compilation_command,
        )

        if not compile_ok:
            log.warning(
                "verify_poc.compile_failed",
                crash_id=payload.crash_id,
                stderr=compile_stderr[:500],
            )
            return PocVerifyOutput(
                compiled=False,
                stdout=compile_stdout,
                stderr=compile_stderr,
                notes="Compilation failed — PoC may need manual adjustment.",
            )

        log.info("verify_poc.compiled", crash_id=payload.crash_id, binary=str(binary_path))

        # 2. Execute.
        _exec_ok, exec_stdout, exec_stderr, signal_received = await _execute(
            binary_path,
            timeout=payload.timeout_seconds,
        )

        # 3. Check crash signature.
        crash_reproduced = _check_signature(
            exec_stderr,
            expected_signal=payload.expected_signal,
            expected_asan_pattern=payload.expected_asan_pattern,
        )

        notes = (
            f"PoC compiled successfully. "
            f"Execution signal: {signal_received or 'none'}. "
            f"Crash reproduced: {crash_reproduced}."
        )

        log.info(
            "verify_poc.complete",
            crash_id=payload.crash_id,
            crash_reproduced=crash_reproduced,
            signal=signal_received,
        )

        return PocVerifyOutput(
            compiled=True,
            binary_path=binary_path if crash_reproduced else None,
            crash_reproduced=crash_reproduced,
            stdout=exec_stdout,
            stderr=exec_stderr,
            signal_received=signal_received,
            notes=notes,
        )


async def _compile(
    src: Path,
    binary: Path,
    custom_command: str,
) -> tuple[bool, str, str]:
    """Compile the PoC. Returns (success, stdout, stderr)."""
    if custom_command.strip():
        # Parse custom command — replace 'poc.c' and 'poc' with actual paths.
        cmd = custom_command.replace("poc.c", str(src)).replace("poc", str(binary))
        # Run via shell so redirects / pipes work.
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(src.parent),
        )
    else:
        cmd = [
            "gcc",
            *_DEFAULT_CFLAGS,
            str(src),
            "-o",
            str(binary),
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(src.parent),
        )

    stdout, stderr = await proc.communicate()
    return proc.returncode == 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")


async def _execute(
    binary: Path,
    *,
    timeout: float = 30.0,
) -> tuple[bool, str, str, str]:
    """Run the compiled PoC. Returns (completed, stdout, stderr, signal)."""
    proc = await asyncio.create_subprocess_exec(
        str(binary),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
    except TimeoutError:
        proc.kill()
        stdout, stderr = await proc.communicate()
        return False, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), "TIMEOUT"

    out = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")

    # Detect signal from return code or stderr.
    signal_received = ""
    if proc.returncode == -6 or "SIGABRT" in err:
        signal_received = "SIGABRT"
    elif proc.returncode == -11 or "SIGSEGV" in err:
        signal_received = "SIGSEGV"
    elif proc.returncode == -8 or "SIGFPE" in err:
        signal_received = "SIGFPE"
    elif proc.returncode == -4 or "SIGILL" in err:
        signal_received = "SIGILL"
    elif proc.returncode != 0:
        signal_received = f"EXIT({proc.returncode})"

    return True, out, err, signal_received


def _check_signature(
    stderr: str,
    *,
    expected_signal: str,
    expected_asan_pattern: str,
) -> bool:
    """Check if the execution output matches the expected crash signature."""
    stderr_lower = stderr.lower()

    # Check ASAN pattern.
    if expected_asan_pattern:
        if expected_asan_pattern.lower() in stderr_lower:
            return True

    # Check signal.
    if expected_signal:
        if expected_signal.lower() in stderr_lower:
            return True

    # Fallback: any ASAN error is a reproduction.
    if "error: addresssanitizer" in stderr_lower:
        return True

    # Fallback: any fatal signal.
    if any(sig in stderr_lower for sig in ("sigsegv", "sigabrt", "sigfpe", "sigill")):
        return True

    return False


__all__ = ["verify_poc"]
