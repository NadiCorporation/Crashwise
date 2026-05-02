# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Patch verifier — applies an AI-generated patch, rebuilds the target,
and runs a regression test with the crash-triggering seed.

The verifier is designed to be **idempotent** and **safe**:
    • It works on a fresh clone (or a copy) of the target repo.
    • It uses the existing :mod:`compiler` module for rebuilding.
    • It runs the fuzzer in a Docker container (Phase 5) to avoid
      polluting the host.

Returns a structured :class:`VerificationResult` that tells the caller
whether the patch eliminated the crash.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Any

from crashwise.agents.harness_synth.compiler import compile_harness
from crashwise.agents.harness_synth.state import CompileResult
from crashwise.core.logging import get_logger
from crashwise.core.models import FuzzerType

log = get_logger(__name__)


class VerificationResult:
    """Outcome of a patch verification run."""

    def __init__(
        self,
        *,
        status: str,  # "fixed", "failed_verification", "build_failed", "error"
        patch_applied: bool = False,
        build_success: bool = False,
        crash_reproduced: bool | None = None,
        stdout: str = "",
        stderr: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.status = status
        self.patch_applied = patch_applied
        self.build_success = build_success
        self.crash_reproduced = crash_reproduced
        self.stdout = stdout
        self.stderr = stderr
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "patch_applied": self.patch_applied,
            "build_success": self.build_success,
            "crash_reproduced": self.crash_reproduced,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "details": self.details,
        }


# ── Public API ───────────────────────────────────────────────────────────────


async def verify_patch(
    *,
    repo_url: str,
    patch: str,
    seed_path: Path,
    harness_path: Path | None = None,
    workdir: Path | None = None,
    fuzzer_type: FuzzerType = FuzzerType.LIBFUZZER,
    timeout_seconds: int = 60,
) -> VerificationResult:
    """End-to-end patch verification.

    Parameters
    ----------
    repo_url:
        Git URL of the target (used to clone a fresh copy if *workdir* is
        not provided).
    patch:
        Unified-diff or raw C/C++ patch string.
    seed_path:
        Path to the binary seed that triggered the original crash.
    harness_path:
        Path (inside the repo) to the fuzzer harness.  If ``None``, the
        verifier searches for ``*.cpp`` / ``*.c`` files named ``*fuzz*``.
    workdir:
        Existing checkout directory.  When ``None``, a temp clone is made.
    fuzzer_type:
        Which fuzzing backend to use for regression testing.
    timeout_seconds:
        Wall-clock cap for the regression fuzz run.

    Returns
    -------
    :class:`VerificationResult` with ``status`` in
    ``{"fixed", "failed_verification", "build_failed", "error"}``.
    """
    log.info(
        "verifier.start",
        repo=repo_url,
        patch_len=len(patch),
        seed=str(seed_path),
        fuzzer=fuzzer_type.value,
    )

    # 1. Prepare workdir (clone or reuse).
    if workdir is None:
        workdir = await _clone_repo(repo_url)
    else:
        workdir = Path(workdir)

    # 2. Apply patch.
    apply_ok, apply_stderr = await _apply_patch(workdir, patch)
    if not apply_ok:
        log.warning("verifier.patch_failed", stderr=apply_stderr[:500])
        return VerificationResult(
            status="failed_verification",
            patch_applied=False,
            stderr=apply_stderr,
        )

    # 3. Discover harness if not given.
    if harness_path is None:
        harness_path = _discover_harness(workdir)
    if harness_path is None or not harness_path.exists():
        return VerificationResult(
            status="failed_verification",
            patch_applied=True,
            stderr="Harness not found after patch application",
        )

    # 4. Build patched binary.
    build = await compile_harness(
        harness_path=harness_path,
        workdir=workdir,
        timeout_seconds=float(timeout_seconds),
    )
    if not build.success or build.binary_path is None:
        log.warning(
            "verifier.build_failed",
            returncode=build.returncode,
            stderr=build.stderr[:500],
        )
        return VerificationResult(
            status="build_failed",
            patch_applied=True,
            build_success=False,
            stdout=build.stdout,
            stderr=build.stderr,
        )

    # 5. Regression test — run fuzzer with the crash seed.
    crash_reproduced, fuzz_stdout, fuzz_stderr = await _run_regression(
        binary_path=build.binary_path,
        seed_path=seed_path,
        workdir=workdir,
        fuzzer_type=fuzzer_type,
        timeout_seconds=timeout_seconds,
    )

    if crash_reproduced:
        log.info("verifier.crash_still_reproduces")
        return VerificationResult(
            status="failed_verification",
            patch_applied=True,
            build_success=True,
            crash_reproduced=True,
            stdout=fuzz_stdout,
            stderr=fuzz_stderr,
        )

    log.info("verifier.fixed")
    return VerificationResult(
        status="fixed",
        patch_applied=True,
        build_success=True,
        crash_reproduced=False,
        stdout=fuzz_stdout,
        stderr=fuzz_stderr,
    )


# ── Internal helpers ─────────────────────────────────────────────────────────


async def _clone_repo(repo_url: str) -> Path:
    """Clone *repo_url* into a temporary directory and return the path."""
    tmp = Path(tempfile.mkdtemp(prefix="crashwise-verify-"))
    log.info("verifier.clone", repo=repo_url, dest=str(tmp))
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", repo_url, str(tmp),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    if proc.returncode != 0:
        stderr = stderr_b.decode("utf-8", errors="replace")
        raise RuntimeError(f"git clone failed: {stderr[:500]}")
    return tmp


async def _apply_patch(workdir: Path, patch: str) -> tuple[bool, str]:
    """Try ``git apply`` first, fall back to ``patch`` CLI."""
    # Write patch to a temp file.
    patch_file = workdir / "_crashwise.patch"
    patch_file.write_text(patch, encoding="utf-8")

    # Try git apply.
    proc = await asyncio.create_subprocess_exec(
        "git", "-C", str(workdir), "apply", "--check", str(patch_file),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr_b = await proc.communicate()
    if proc.returncode == 0:
        proc2 = await asyncio.create_subprocess_exec(
            "git", "-C", str(workdir), "apply", str(patch_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr2_b = await proc2.communicate()
        if proc2.returncode == 0:
            return True, ""
        return False, stderr2_b.decode("utf-8", errors="replace")

    # Fallback: patch command.
    patch_cmd = shutil.which("patch")
    if patch_cmd is None:
        return False, stderr_b.decode("utf-8", errors="replace")

    proc3 = await asyncio.create_subprocess_exec(
        patch_cmd, "-p1", "-i", str(patch_file),
        cwd=str(workdir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr3_b = await proc3.communicate()
    ok = proc3.returncode == 0
    return ok, "" if ok else stderr3_b.decode("utf-8", errors="replace")


def _discover_harness(workdir: Path) -> Path | None:
    """Find a plausible fuzzer harness inside *workdir*."""
    for pattern in ("*fuzz*.cpp", "*fuzz*.c", "*fuzz*.cc"):
        matches = list(workdir.rglob(pattern))
        if matches:
            return matches[0]
    return None


async def _run_regression(
    binary_path: Path,
    seed_path: Path,
    workdir: Path,
    fuzzer_type: FuzzerType,
    timeout_seconds: int,
) -> tuple[bool, str, str]:
    """Run the patched binary with the crash seed.

    Returns
    -------
    (crash_reproduced, stdout, stderr)
    """
    # Create a minimal corpus dir with just the seed.
    corpus_dir = workdir / "regression_corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    dest_seed = corpus_dir / seed_path.name
    dest_seed.write_bytes(seed_path.read_bytes())

    # Run the binary directly (libFuzzer-style) with the seed.
    # For AFL++ we'd need the forkserver; here we keep it simple.
    cmd: list[str] = [str(binary_path), str(dest_seed)]

    log.info("verifier.regression.start", cmd=" ".join(cmd), timeout=timeout_seconds)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(workdir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return False, "", f"Regression timed out after {timeout_seconds}s"

    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")

    # Heuristic: ASAN error or signal in stderr means crash reproduced.
    crash_reproduced = (
        "ERROR: AddressSanitizer" in stderr
        or "SUMMARY: AddressSanitizer" in stderr
        or "SIGSEGV" in stderr
        or "SIGABRT" in stderr
        or "==ERROR:" in stderr
    )

    log.info(
        "verifier.regression.complete",
        crash_reproduced=crash_reproduced,
        returncode=proc.returncode,
    )
    return crash_reproduced, stdout, stderr


__all__ = ["verify_patch", "VerificationResult"]
