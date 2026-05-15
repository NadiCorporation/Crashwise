# SPDX-License-Identifier: MIT
"""GDB-based crash diagnosis for the harness synthesis ReAct loop.

Operation Hydra Phase 2: When a harness crashes during the sanity gate,
this engine runs it under GDB to extract a precise backtrace, crash
location, and register state. This data is fed back to the LLM so it
can fix the exact initialization error.
"""
from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from crashwise.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class CrashDiagnosis:
    """Structured output from GDB crash analysis."""

    backtrace: str = ""
    crash_function: str = ""
    crash_location: str = ""
    registers: str = ""
    signal: str = ""
    summary: str = ""

    def to_prompt(self) -> str:
        """Format for injection into the LLM prompt."""
        parts = []
        if self.signal:
            parts.append(f"Signal: {self.signal}")
        if self.crash_location:
            parts.append(f"Crash location: {self.crash_location}")
        if self.crash_function:
            parts.append(f"Crashed in function: {self.crash_function}")
        if self.backtrace:
            parts.append(f"Backtrace:\n{self.backtrace}")
        if self.summary:
            parts.append(f"Root cause: {self.summary}")
        return "\n".join(parts) if parts else "No diagnosis available."


async def debug_crash(binary_path: Path, *, timeout: float = 10.0) -> CrashDiagnosis:
    """Run the crashing harness under GDB and extract diagnostic info.

    Creates a minimal seed, runs the binary under GDB in batch mode,
    and parses the backtrace to identify the crash location.
    """
    if not binary_path.exists():
        return CrashDiagnosis(summary="Binary not found")

    # Create a dummy seed for the harness to consume.
    tmp_dir = Path(tempfile.mkdtemp(prefix="gdb_debug_"))
    seed_file = tmp_dir / "seed"
    seed_file.write_bytes(b"A" * 128)

    # GDB batch commands: run with the seed as corpus, get backtrace.
    gdb_commands = tmp_dir / "gdb_cmds"
    gdb_commands.write_text(
        f"set disable-randomization off\n"
        f"set pagination off\n"
        f"run {seed_file} -max_total_time=2 -detect_leaks=0\n"
        f"backtrace 20\n"
        f"info registers\n"
        f"quit\n",
        encoding="utf-8",
    )

    cmd = [
        "gdb",
        "--batch",
        "--quiet",
        "-x", str(gdb_commands),
        str(binary_path),
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            stdout_bytes = b"(gdb timed out)"
    except OSError as exc:
        return CrashDiagnosis(summary=f"Failed to run GDB: {exc}")
    finally:
        # Cleanup temp files.
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

    output = stdout_bytes.decode("utf-8", errors="replace")
    return _parse_gdb_output(output)


def _parse_gdb_output(output: str) -> CrashDiagnosis:
    """Parse GDB batch output into structured diagnosis."""
    import re

    diag = CrashDiagnosis()

    # Extract signal.
    sig_match = re.search(r"Program received signal (\w+)", output)
    if sig_match:
        diag.signal = sig_match.group(1)

    # Extract backtrace (lines starting with #N).
    bt_lines = []
    in_bt = False
    for line in output.splitlines():
        if line.strip().startswith("#"):
            in_bt = True
            bt_lines.append(line.strip())
        elif in_bt and not line.strip():
            break
    diag.backtrace = "\n".join(bt_lines[:15])

    # Extract crash location from frame #0.
    if bt_lines:
        frame0 = bt_lines[0]
        # Pattern: #0  0x... in function_name (args) at file:line
        loc_match = re.search(r"in (\w+)\s*\(.*?\)\s*at\s+(.+:\d+)", frame0)
        if loc_match:
            diag.crash_function = loc_match.group(1)
            diag.crash_location = loc_match.group(2)
        else:
            # Pattern: #0  function_name (args) at file:line
            loc_match2 = re.search(r"#0\s+(?:0x\w+\s+in\s+)?(\w+)", frame0)
            if loc_match2:
                diag.crash_function = loc_match2.group(1)

    # Extract registers (first 8 lines after "info registers").
    reg_lines = []
    in_regs = False
    for line in output.splitlines():
        if "info registers" in line.lower() or (in_regs and line.strip()):
            in_regs = True
            if line.strip() and not line.startswith("(gdb)"):
                reg_lines.append(line.strip())
        elif in_regs and not line.strip():
            break
    diag.registers = "\n".join(reg_lines[:8])

    # Generate summary.
    if diag.signal == "SIGSEGV":
        if "0x0" in (diag.registers or "") or "NULL" in output:
            diag.summary = f"NULL pointer dereference in {diag.crash_function or 'unknown'}. A pointer was not initialized before use."
        else:
            diag.summary = f"Segmentation fault in {diag.crash_function or 'unknown'}. Likely invalid memory access due to uninitialized or incorrectly sized buffer."
    elif diag.signal == "SIGABRT":
        diag.summary = f"Abort in {diag.crash_function or 'unknown'}. Likely assertion failure or double-free."
    elif diag.signal:
        diag.summary = f"{diag.signal} in {diag.crash_function or 'unknown'}."
    else:
        diag.summary = "Crash without identifiable signal."

    log.info(
        "debug_engine.diagnosis",
        signal=diag.signal,
        function=diag.crash_function,
        location=diag.crash_location,
    )

    return diag


__all__ = ["CrashDiagnosis", "debug_crash"]
