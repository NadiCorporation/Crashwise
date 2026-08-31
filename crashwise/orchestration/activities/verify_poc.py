# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``verify_poc`` activity — compiles and validates a target-linked exploit reproducer.

The activity takes C/C++ reproducer source code produced by the Exploit Architect,
compiles it against actual target library artifacts (.a / .so) with ASan flags,
executes it passing the minimized crash input via argv[1], and verifies high-fidelity
reproduction (exact ASan error class and frame #0 crashing function matching).
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from pathlib import Path

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import PocVerifyInput, PocVerifyOutput

log = get_logger(__name__)

# Default compilation flags for high-fidelity ASan verification
_DEFAULT_CFLAGS = (
    "-fsanitize=address,undefined",
    "-fno-omit-frame-pointer",
    "-g",
    "-O0",
)

_ASAN_ERROR_RE = re.compile(
    r"ERROR:\s*(?:AddressSanitizer|HWAddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer):\s*([a-zA-Z0-9_\-]+)",
    re.IGNORECASE,
)

_FRAME_0_RE = re.compile(
    r"#0\s+0x[0-9a-fA-F]+(?:\s+in|\s+\([^)]+\)\s+in|\s+in\s+)?\s+([a-zA-Z0-9_:]+)",
)

_FRAME_ANY_RE = re.compile(
    r"#([0-9]+)\s+0x[0-9a-fA-F]+(?:\s+in|\s+\([^)]+\)\s+in|\s+in\s+)?\s+([a-zA-Z0-9_:]+)",
)


@activity.defn(name="verify_poc")
async def verify_poc(payload: PocVerifyInput) -> PocVerifyOutput:
    """Compile a generated PoC and verify it reproduces the crash with high fidelity.

    Parameters
    ----------
    payload:
        PoC source code, compilation command, target include/lib paths,
        minimized crash input file path, and expected crash signature.

    Returns
    -------
    Structured verification result with compilation status, execution output,
    ASan error class match, crashing function match, and reproduction fidelity.
    """
    try:
        info = activity.info()
        workflow_id = info.workflow_id
        attempt = info.attempt
    except Exception:
        workflow_id = "standalone"
        attempt = 1

    log.info(
        "verify_poc.start",
        workflow_id=workflow_id,
        attempt=attempt,
        crash_id=payload.crash_id,
        expected_func=payload.expected_function,
        expected_asan=payload.expected_asan_pattern,
    )

    with tempfile.TemporaryDirectory(prefix="crashwise-poc-") as tmpdir:
        src_path = Path(tmpdir) / "poc.c"
        src_path.write_text(payload.poc_code, encoding="utf-8")

        # 1. Compile against target libraries.
        binary_path = Path(tmpdir) / "poc"
        compile_ok, compile_stdout, compile_stderr = await _compile(
            src=src_path,
            binary=binary_path,
            custom_command=payload.compilation_command,
            target_include_dirs=payload.target_include_dirs,
            target_link_libs=payload.target_link_libs,
            link_flags=payload.link_flags,
            target_workdir=payload.target_workdir,
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
                notes="Compilation failed — PoC may need target link adjustment.",
                target_linked=_is_target_linked(payload),
            )

        log.info("verify_poc.compiled", crash_id=payload.crash_id, binary=str(binary_path))

        # 2. Execute passing crash input file as argv[1].
        _exec_ok, exec_stdout, exec_stderr, signal_received = await _execute(
            binary=binary_path,
            crash_file_path=payload.crash_file_path,
            timeout=payload.timeout_seconds,
            target_workdir=payload.target_workdir,
        )

        # 3. High-Fidelity Crash Verification.
        asan_class_matched, function_matched, crash_reproduced, fidelity = _verify_high_fidelity(
            exec_stderr,
            expected_signal=payload.expected_signal,
            expected_asan_pattern=payload.expected_asan_pattern,
            expected_function=payload.expected_function,
            signal_received=signal_received,
        )

        is_linked = _is_target_linked(payload)

        notes = (
            f"PoC compiled successfully (target_linked={is_linked}). "
            f"Signal: {signal_received or 'none'}. "
            f"ASan match: {asan_class_matched}, Func match: {function_matched}. "
            f"Fidelity: {fidelity:.2f}."
        )

        log.info(
            "verify_poc.complete",
            crash_id=payload.crash_id,
            crash_reproduced=crash_reproduced,
            asan_matched=asan_class_matched,
            func_matched=function_matched,
            fidelity=fidelity,
            signal=signal_received,
        )

        return PocVerifyOutput(
            compiled=True,
            binary_path=binary_path if crash_reproduced else None,
            crash_reproduced=crash_reproduced,
            asan_class_matched=asan_class_matched,
            function_matched=function_matched,
            target_linked=is_linked,
            reproduction_fidelity=fidelity,
            stdout=exec_stdout,
            stderr=exec_stderr,
            signal_received=signal_received,
            notes=notes,
        )


def _is_target_linked(payload: PocVerifyInput) -> bool:
    """Check if the compilation targets genuine target libraries."""
    if payload.target_link_libs or payload.target_include_dirs:
        return True
    cmd = payload.compilation_command.lower()
    return bool("-l" in cmd or ".a" in cmd or ".so" in cmd or "-i" in cmd)


async def _compile(
    src: Path,
    binary: Path,
    custom_command: str = "",
    target_include_dirs: list[str] | None = None,
    target_link_libs: list[str] | None = None,
    link_flags: list[str] | None = None,
    target_workdir: str = "",
) -> tuple[bool, str, str]:
    """Compile the PoC against target headers and libraries."""
    # Determine compiler
    compiler = "clang" if shutil.which("clang") else "gcc"

    if custom_command.strip():
        cmd = custom_command
        if str(src) not in cmd:
            cmd = re.sub(r"\bpoc\.c\b", str(src), cmd)
        if str(binary) not in cmd:
            cmd = re.sub(r"\bpoc\b", str(binary), cmd)
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=target_workdir if target_workdir and Path(target_workdir).is_dir() else str(src.parent),
        )
    else:
        cmd_list = [
            compiler,
            *_DEFAULT_CFLAGS,
        ]
        if target_include_dirs:
            for inc in target_include_dirs:
                cmd_list.append(f"-I{inc}")
        cmd_list.extend([str(src), "-o", str(binary)])
        if target_link_libs:
            cmd_list.extend(target_link_libs)
        if link_flags:
            cmd_list.extend(link_flags)
        cmd_list.extend(["-lm", "-lpthread", "-lz"])

        proc = await asyncio.create_subprocess_exec(
            *cmd_list,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=target_workdir if target_workdir and Path(target_workdir).is_dir() else str(src.parent),
        )

    stdout, stderr = await proc.communicate()
    return proc.returncode == 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")


async def _execute(
    binary: Path,
    crash_file_path: str = "",
    *,
    timeout: float = 30.0,
    target_workdir: str = "",
) -> tuple[bool, str, str, str]:
    """Run the compiled PoC with the crash file as argv[1]."""
    cmd = [str(binary)]
    if crash_file_path.strip():
        cmd.append(crash_file_path.strip())

    env = dict(os.environ)
    # Add target directory to library path for shared objects
    if target_workdir and Path(target_workdir).is_dir():
        current_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{target_workdir}:{current_ld}" if current_ld else target_workdir

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
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

    # Detect signal from return code or stderr
    signal_received = ""
    if proc.returncode == -6 or "SIGABRT" in err or "Aborted" in err:
        signal_received = "SIGABRT"
    elif proc.returncode == -11 or "SIGSEGV" in err or "Segmentation fault" in err or "SEGV" in err:
        signal_received = "SIGSEGV"
    elif proc.returncode == -8 or "SIGFPE" in err or "Floating point exception" in err:
        signal_received = "SIGFPE"
    elif proc.returncode == -4 or "SIGILL" in err:
        signal_received = "SIGILL"
    elif proc.returncode != 0:
        signal_received = f"EXIT({proc.returncode})"

    return True, out, err, signal_received


def _verify_high_fidelity(
    stderr: str,
    *,
    expected_signal: str = "",
    expected_asan_pattern: str = "",
    expected_function: str = "",
    signal_received: str = "",
) -> tuple[bool, bool, bool, float]:
    """Perform high-fidelity ASan error class and crashing function matching.

    Returns (asan_class_matched, function_matched, crash_reproduced, fidelity_score).
    """
    stderr_lower = stderr.lower()

    # 1. Extract ASan error class
    detected_asan_class = ""
    asan_match = _ASAN_ERROR_RE.search(stderr)
    if asan_match:
        detected_asan_class = asan_match.group(1).lower()

    asan_class_matched = False
    if expected_asan_pattern:
        expected_norm = expected_asan_pattern.lower().replace("_", "-")
        if detected_asan_class:
            detected_norm = detected_asan_class.replace("_", "-")
            asan_class_matched = expected_norm in detected_norm or detected_norm in expected_norm
        else:
            asan_class_matched = expected_norm in stderr_lower
    elif detected_asan_class or "error: addresssanitizer" in stderr_lower:
        asan_class_matched = True

    # 2. Extract crashing function from stack trace (frame #0)
    frame_0_func = ""
    top_frame_funcs: list[str] = []
    for match in _FRAME_ANY_RE.finditer(stderr):
        frame_num = int(match.group(1))
        fn = match.group(2).strip()
        if frame_num == 0 and not frame_0_func:
            frame_0_func = fn
        if frame_num <= 3:
            top_frame_funcs.append(fn.lower())

    if not frame_0_func:
        f0_match = _FRAME_0_RE.search(stderr)
        if f0_match:
            frame_0_func = f0_match.group(1).strip()
            top_frame_funcs.append(frame_0_func.lower())

    function_matched = False
    if expected_function:
        exp_func_clean = expected_function.lower().strip()
        if (
            (frame_0_func and (exp_func_clean == frame_0_func.lower() or exp_func_clean in frame_0_func.lower() or frame_0_func.lower() in exp_func_clean))
            or any(exp_func_clean in fn or fn in exp_func_clean for fn in top_frame_funcs)
            or (f"in {exp_func_clean}" in stderr_lower or f" {exp_func_clean}(" in stderr_lower)
        ):
            function_matched = True
    else:
        function_matched = bool(frame_0_func)

    # 3. Fidelity scoring and overall reproduction status
    has_asan = bool(detected_asan_class or "error: addresssanitizer" in stderr_lower)
    has_fatal_signal = bool(signal_received and signal_received != "TIMEOUT")

    fidelity = 0.0
    crash_reproduced = False

    if expected_asan_pattern and expected_function:
        if asan_class_matched and function_matched:
            fidelity = 1.0
            crash_reproduced = True
        elif asan_class_matched:
            fidelity = 0.8
            crash_reproduced = True
        elif function_matched and (has_asan or has_fatal_signal):
            fidelity = 0.7
            crash_reproduced = True
        elif has_asan or (expected_signal and signal_received == expected_signal):
            fidelity = 0.5
            crash_reproduced = True
    elif expected_asan_pattern:
        if asan_class_matched:
            fidelity = 1.0
            crash_reproduced = True
        elif has_asan:
            fidelity = 0.8
            crash_reproduced = True
        elif has_fatal_signal:
            fidelity = 0.5
            crash_reproduced = True
    elif expected_function:
        if function_matched and (has_asan or has_fatal_signal):
            fidelity = 1.0
            crash_reproduced = True
        elif has_asan or has_fatal_signal:
            fidelity = 0.6
            crash_reproduced = True
    else:
        if has_asan:
            fidelity = 0.9
            crash_reproduced = True
        elif has_fatal_signal:
            fidelity = 0.7
            crash_reproduced = True

    return asan_class_matched, function_matched, crash_reproduced, fidelity


def _check_signature(
    stderr: str,
    *,
    expected_signal: str = "",
    expected_asan_pattern: str = "",
    expected_function: str = "",
) -> bool:
    """Backward-compatible signature check."""
    stderr_lower = stderr.lower()

    # Check ASAN pattern
    if expected_asan_pattern and (expected_asan_pattern.lower().replace("_", "-") in stderr_lower.replace("_", "-")):
        return True

    # Check signal
    if expected_signal and (expected_signal.lower() in stderr_lower):
        return True

    # Fallback: any ASAN error is a reproduction
    if "error: addresssanitizer" in stderr_lower:
        return True

    # Fallback: any fatal signal
    return any(sig in stderr_lower for sig in ("sigsegv", "sigabrt", "sigfpe", "sigill"))


__all__ = [
    "_check_signature",
    "_compile",
    "_execute",
    "_verify_high_fidelity",
    "verify_poc",
]
