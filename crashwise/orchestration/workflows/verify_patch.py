# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""VerifyPatchWorkflow — autonomous "Fix & Verify" cycle (Phase 12).

Orchestrates the end-to-end patch verification pipeline:

    Apply Patch  ──▶  Build Patched Binary  ──▶  Regression Test  ──▶  Update DB

The workflow is triggered on-demand (via API or UI) for a specific crash.
It runs in a clean environment and updates the crash record with the
verification outcome.
"""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from crashwise.core.models import (
        VerificationStatus,
        VerifyPatchInput,
        VerifyPatchOutput,
    )


# Retry policies
_PATCH_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=2,
    non_retryable_error_types=["PatchApplyFailed"],
)

_BUILD_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=60),
    maximum_attempts=2,
    non_retryable_error_types=["BuildFailed"],
)

_REGRESSION_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=2,
)


@workflow.defn(name="VerifyPatchWorkflow")
class VerifyPatchWorkflow:
    """Verify that an AI-generated patch fixes a crash."""

    def __init__(self) -> None:
        self._status: str = "pending"

    @workflow.query(name="verification_status")
    def verification_status(self) -> str:
        return self._status

    @workflow.run
    async def run(self, payload: VerifyPatchInput) -> VerifyPatchOutput:
        log = workflow.logger
        log.info(
            "verify_patch.start",
            crash_id=payload.crash_id,
            campaign_id=payload.campaign_id,
            repo=payload.repo_url,
        )

        # ── Step A: Apply patch ─────────────────────────────────────────────
        self._status = "applying_patch"
        apply_result: dict = await workflow.execute_activity(
            "apply_patch",
            {
                "repo_url": payload.repo_url,
                "patch": payload.patch,
            },
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_PATCH_RETRY,
        )

        if not apply_result.get("patch_applied"):
            log.warning("verify_patch.apply_failed", stderr=apply_result.get("stderr", ""))
            self._status = "failed_verification"
            return VerifyPatchOutput(
                status=VerificationStatus.FAILED_VERIFICATION,
                patch_applied=False,
            )

        workdir_str: str = apply_result["workdir"]

        # ── Step B: Build patched binary ────────────────────────────────────
        self._status = "building"
        build_result: dict = await workflow.execute_activity(
            "build_patched",
            {
                "workdir": workdir_str,
                "harness_path": str(payload.harness_path) if payload.harness_path else None,
            },
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_BUILD_RETRY,
        )

        if not build_result.get("success"):
            log.warning("verify_patch.build_failed", stderr=build_result.get("stderr", ""))
            self._status = "build_failed"
            return VerifyPatchOutput(
                status=VerificationStatus.BUILD_FAILED,
                patch_applied=True,
                build_success=False,
                stdout=build_result.get("stdout", ""),
                stderr=build_result.get("stderr", ""),
            )

        binary_path: str = build_result["binary_path"]

        # ── Step C: Regression test ─────────────────────────────────────────
        self._status = "regression_testing"
        regression_result: dict = await workflow.execute_activity(
            "verify_with_seed",
            {
                "binary_path": binary_path,
                "seed_path": str(payload.seed_path),
                "workdir": workdir_str,
                "fuzzer_type": payload.fuzzer_type.value,
                "timeout_seconds": payload.timeout_seconds,
            },
            start_to_close_timeout=timedelta(seconds=payload.timeout_seconds)
            + timedelta(minutes=2),
            retry_policy=_REGRESSION_RETRY,
        )

        crash_reproduced = regression_result.get("crash_reproduced", True)
        stdout = regression_result.get("stdout", "")
        stderr = regression_result.get("stderr", "")

        if crash_reproduced:
            log.info("verify_patch.crash_still_reproduces")
            self._status = "failed_verification"
            result = VerifyPatchOutput(
                status=VerificationStatus.FAILED_VERIFICATION,
                patch_applied=True,
                build_success=True,
                crash_reproduced=True,
                stdout=stdout,
                stderr=stderr,
            )
        else:
            log.info("verify_patch.fixed")
            self._status = "fixed"
            result = VerifyPatchOutput(
                status=VerificationStatus.FIXED,
                patch_applied=True,
                build_success=True,
                crash_reproduced=False,
                stdout=stdout,
                stderr=stderr,
            )

        # ── Step D: Calculate CVSS and generate report ──────────────────────
        from crashwise.agents.reporting.cvss import calculate_cvss

        cvss_result = await calculate_cvss(
            bug_type="unknown",  # Would be enriched from crash metadata in production.
            exploitability_score=5.0,  # Placeholder — real value from DB.
        )
        cvss_score = cvss_result["score"]
        cvss_vector = cvss_result["vector"]
        cvss_severity = cvss_result["severity"]

        log.info(
            "verify_patch.cvss",
            score=cvss_score,
            vector=cvss_vector,
            severity=cvss_severity,
        )

        # ── Step E: Update DB ───────────────────────────────────────────────
        await workflow.execute_activity(
            "update_verification_status",
            {
                "crash_id": payload.crash_id,
                "status": result.status.value,
                "stdout": stdout,
                "stderr": stderr,
            },
            start_to_close_timeout=timedelta(minutes=1),
        )

        # ── Step F: Notify stakeholders (conditional on severity) ───────────
        if result.status == VerificationStatus.FIXED and cvss_score >= 7.0:
            log.info(
                "verify_patch.notify",
                crash_id=payload.crash_id,
                cvss=cvss_score,
            )
            await workflow.execute_activity(
                "notify_stakeholders",
                {
                    "title": f"Verified fix: Crash {payload.crash_id}",
                    "body": f"Patch verified. CVSS: {cvss_score} ({cvss_vector}).\n{stderr}",
                    "severity": cvss_severity.lower(),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "target": payload.repo_url,
                    "crash_id": payload.crash_id,
                },
                start_to_close_timeout=timedelta(minutes=2),
            )

        return result


__all__ = ["VerifyPatchWorkflow"]
