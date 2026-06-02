# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Verification activities for the VerifyPatchWorkflow (Phase 12).

Each activity is a discrete, retryable step in the patch-verification
pipeline.  They are designed to be idempotent where possible and to
fail fast with structured error info.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from temporalio import activity

from crashwise.agents.harness_synth.compiler import compile_harness
from crashwise.core.database import Crash, get_session
from crashwise.core.logging import get_logger
from crashwise.core.models import FuzzerType

log = get_logger(__name__)


@activity.defn(name="apply_patch")
async def apply_patch(
    repo_url: str,
    patch: str,
) -> dict:
    """Clone the repo and apply the patch.

    Returns
    -------
    dict with keys ``patch_applied`` (bool), ``workdir`` (str), ``stderr`` (str).
    """
    info = activity.info()
    log.info(
        "apply_patch.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        repo=repo_url,
    )

    from crashwise.agents.feedback.verifier import _apply_patch, _clone_repo

    try:
        workdir = await _clone_repo(repo_url)
    except Exception as exc:
        log.error("apply_patch.clone_failed", error=str(exc))
        return {"patch_applied": False, "workdir": "", "stderr": str(exc)}

    ok, stderr = await _apply_patch(workdir, patch)
    log.info("apply_patch.complete", applied=ok, workdir=str(workdir))
    return {
        "patch_applied": ok,
        "workdir": str(workdir),
        "stderr": stderr,
    }


@activity.defn(name="build_patched")
async def build_patched(
    workdir: str,
    harness_path: str | None,
) -> dict:
    """Compile the patched harness.

    Returns
    -------
    dict with keys ``success`` (bool), ``binary_path`` (str), ``stdout``, ``stderr``.
    """
    log.info("build_patched.start", workdir=workdir, harness=harness_path)

    wd = Path(workdir)
    hp = Path(harness_path) if harness_path else None

    # Auto-discover if not given.
    if hp is None or not hp.exists():
        from crashwise.agents.feedback.verifier import _discover_harness

        hp = _discover_harness(wd)

    if hp is None or not hp.exists():
        return {
            "success": False,
            "binary_path": "",
            "stdout": "",
            "stderr": "Harness not found",
        }

    build = await compile_harness(
        harness_path=hp,
        workdir=wd,
        timeout_seconds=120.0,
    )

    log.info(
        "build_patched.complete",
        success=build.success,
        binary=str(build.binary_path) if build.binary_path else None,
    )
    return {
        "success": build.success,
        "binary_path": str(build.binary_path) if build.binary_path else "",
        "stdout": build.stdout,
        "stderr": build.stderr,
    }


@activity.defn(name="verify_with_seed")
async def verify_with_seed(
    binary_path: str,
    seed_path: str,
    workdir: str,
    fuzzer_type: str,
    timeout_seconds: int,
) -> dict:
    """Run the patched binary with the crash-triggering seed.

    Returns
    -------
    dict with keys ``crash_reproduced`` (bool), ``stdout``, ``stderr``.
    """
    log.info(
        "verify_with_seed.start",
        binary=binary_path,
        seed=seed_path,
        timeout=timeout_seconds,
    )

    from crashwise.agents.feedback.verifier import _run_regression

    ft = FuzzerType(fuzzer_type) if fuzzer_type in {f.value for f in FuzzerType} else FuzzerType.LIBFUZZER

    crash_reproduced, stdout, stderr = await _run_regression(
        binary_path=Path(binary_path),
        seed_path=Path(seed_path),
        workdir=Path(workdir),
        fuzzer_type=ft,
        timeout_seconds=timeout_seconds,
    )

    log.info(
        "verify_with_seed.complete",
        crash_reproduced=crash_reproduced,
    )
    return {
        "crash_reproduced": crash_reproduced,
        "stdout": stdout,
        "stderr": stderr,
    }


@activity.defn(name="update_verification_status")
async def update_verification_status(
    crash_id: str,
    status: str,
    stdout: str,
    stderr: str,
) -> None:
    """Persist the verification outcome to the DB."""
    log.info(
        "update_verification_status.start",
        crash_id=crash_id,
        status=status,
    )

    try:
        async with get_session() as session:
            crash = await session.get(Crash, UUID(crash_id))
            if crash is not None:
                crash.verification_status = status
                crash.verification_stdout = stdout[:8192]
                crash.verification_stderr = stderr[:8192]
                crash.verified_at = datetime.now(tz=UTC)
                await session.commit()
                log.info("update_verification_status.complete", crash_id=crash_id)
            else:
                log.warning("update_verification_status.not_found", crash_id=crash_id)
    except Exception:
        log.warning("update_verification_status.failed", crash_id=crash_id, exc_info=True)


__all__ = [
    "apply_patch",
    "build_patched",
    "update_verification_status",
    "verify_with_seed",
]
