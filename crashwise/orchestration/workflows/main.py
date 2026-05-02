# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Main fuzzing workflow with autonomous feedback loop (Phase 6).

Top-level orchestration entry point for a CrashWise campaign:

    SetupTarget  ──▶  [Loop]  ──▶  TriageResults
                        │
                        ├─ ExecuteFuzzing
                        ├─ AnalyzeProgress
                        └─ MutateHarness (if stalled)

The workflow loops until:
    • A crash is found,
    • Coverage stalls and max iterations are reached, or
    • The user cancels.

Workflow code stays deterministic — all I/O lives in activities.
"""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from pathlib import Path

    from crashwise.core.models import (
        AnalyzeProgressInput,
        CampaignStatus,
        ExecuteFuzzingInput,
        ExecuteFuzzingOutput,
        FuzzingCampaignState,
        FuzzingInput,
        FuzzingOutput,
        SeedCorpusInput,
        SetupTargetInput,
        SetupTargetOutput,
        TriageInput,
        TriageOutput,
        WorkflowStage,
    )


# Retry policies
_SEED_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
)

_SETUP_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
    non_retryable_error_types=["WorkdirMissing"],
)

_FUZZ_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=60),
    maximum_attempts=2,
    non_retryable_error_types=["WorkdirMissing", "HarnessUnavailable"],
)

_ANALYZE_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=10),
    maximum_attempts=3,
)

_MUTATE_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=2,
)

_TRIAGE_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
)

_AI_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=60),
    maximum_attempts=2,
    non_retryable_error_types=["ProviderUnavailable"],
)


@workflow.defn(name="MainFuzzingWorkflow")
class MainFuzzingWorkflow:
    """Top-level CrashWise workflow with autonomous feedback loop."""

    def __init__(self) -> None:
        self._stage: WorkflowStage = WorkflowStage.PENDING
        self._iteration: int = 0

    @workflow.query(name="current_stage")
    def current_stage(self) -> str:
        return self._stage.value

    @workflow.query(name="iteration")
    def iteration(self) -> int:
        return self._iteration

    @workflow.run
    async def run(self, payload: FuzzingInput) -> FuzzingOutput:
        started_at = workflow.now()
        log = workflow.logger
        log.info(
            "main_workflow.start "
            f"target_repo={payload.target_repo} fuzzer={payload.fuzzer_type.value} "
            f"timeout_seconds={payload.timeout_seconds}"
        )

        # Derive a short target name from the repo URL for the harvester.
        target_name = str(payload.target_repo).rsplit("/", 1)[-1].replace(".git", "")

        # ── 1. Seed corpus (Phase 7) ────────────────────────────────────────
        self._stage = WorkflowStage.SEEDING
        # Use a deterministic workdir path — the real workdir comes from
        # setup_target, but the harvester needs a place to write seeds.
        seed_workdir = Path("/tmp") / f"crashwise-seed-{workflow.info().run_id}"
        seed_paths: list[Path] = await workflow.execute_activity(
            "seed_corpus",
            SeedCorpusInput(
                target_name=target_name,
                workdir=seed_workdir,
                max_seeds=5,
                campaign_id=payload.campaign_id,
            ),
            result_type=list[Path],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_SEED_RETRY,
        )
        corpus_dir = seed_workdir / "corpus" if seed_paths else None

        # ── 2. Setup target ─────────────────────────────────────────────────
        self._stage = WorkflowStage.SETUP
        setup_out: SetupTargetOutput = await workflow.execute_activity(
            "setup_target",
            SetupTargetInput(
                target_repo=payload.target_repo,
                target_branch=payload.target_branch,
                sanitizers=payload.sanitizers,
            ),
            result_type=SetupTargetOutput,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_SETUP_RETRY,
        )

        harness_path = (
            setup_out.workdir / payload.harness_path
            if payload.harness_path
            else setup_out.harness_path
        )

        # ── 2. Initialise campaign state ────────────────────────────────────
        campaign = FuzzingCampaignState(
            iteration=0,
            max_iterations=payload.max_iterations,
            harness_path=harness_path,
        )

        # ── 3. Feedback loop ────────────────────────────────────────────────
        while campaign.should_continue:
            self._iteration = campaign.iteration
            self._stage = WorkflowStage.EXECUTING

            fuzz_out: ExecuteFuzzingOutput = await workflow.execute_activity(
                "execute_fuzzing",
                ExecuteFuzzingInput(
                    workdir=setup_out.workdir,
                    harness_path=harness_path,
                    fuzzer_type=payload.fuzzer_type,
                    timeout_seconds=payload.timeout_seconds,
                    sanitizers=payload.sanitizers,
                    corpus_dir=corpus_dir,
                    campaign_id=payload.campaign_id,
                    iteration=campaign.iteration,
                ),
                result_type=ExecuteFuzzingOutput,
                start_to_close_timeout=timedelta(seconds=payload.timeout_seconds)
                + timedelta(minutes=5),
                heartbeat_timeout=timedelta(seconds=15),
                retry_policy=_FUZZ_RETRY,
            )

            # Analyze progress.
            self._stage = WorkflowStage.TRIAGE
            campaign = await workflow.execute_activity(
                "analyze_progress",
                AnalyzeProgressInput(
                    fuzz_output=fuzz_out,
                    campaign=campaign,
                ),
                result_type=FuzzingCampaignState,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_ANALYZE_RETRY,
            )

            # If stalled and we should continue, mutate harness.
            if (
                campaign.should_continue
                and campaign.status == CampaignStatus.STALLED
                and campaign.mutation_hint
            ):
                log.info(
                    "main_workflow.mutate",
                    iteration=campaign.iteration,
                    hint=campaign.mutation_hint[:80],
                )
                self._stage = WorkflowStage.SETUP
                new_harness: SetupTargetOutput = await workflow.execute_activity(
                    "mutate_harness",
                    {
                        "workdir": setup_out.workdir,
                        "harness_path": harness_path,
                        "feedback": campaign.mutation_hint,
                    },
                    result_type=SetupTargetOutput,
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=_MUTATE_RETRY,
                )
                harness_path = new_harness.harness_path or harness_path
                campaign.status = CampaignStatus.RUNNING

            campaign.iteration += 1

        # ── 4. Final triage ─────────────────────────────────────────────────
        self._stage = WorkflowStage.TRIAGE
        # Re-scan the final output directory for crashes.
        triage_out: TriageOutput = await workflow.execute_activity(
            "triage_results",
            TriageInput(
                logs_path=setup_out.workdir / "fuzz.log",
                crashes_dir=setup_out.workdir / "crashes",
                crash_count=campaign.crash_count,
                campaign_id=payload.campaign_id,
            ),
            result_type=TriageOutput,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_TRIAGE_RETRY,
        )

        # ── 5. Deep crash analysis (Phase 10) ───────────────────────────────
        # Only run AI triage when unique crashes were found — saves API costs.
        if campaign.crash_count > 0 and payload.campaign_id is not None:
            self._stage = WorkflowStage.TRIAGE
            log.info(
                "main_workflow.analyze_crash",
                crash_count=campaign.crash_count,
                campaign_id=payload.campaign_id,
            )
            # Build a lightweight crash context from the campaign state.
            crash_context = (
                f"Campaign: {payload.campaign_id}\n"
                f"Target: {payload.target_repo}\n"
                f"Fuzzer: {payload.fuzzer_type.value}\n"
                f"Crashes: {campaign.crash_count}\n"
                f"Summary: {triage_out.summary}"
            )
            await workflow.execute_activity(
                "analyze_crash",
                {
                    "crash_id": payload.campaign_id,  # Simplified: use campaign_id as proxy
                    "crash_context": crash_context,
                    "campaign_id": payload.campaign_id,
                },
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_AI_RETRY,
            )

        # ── 6. Compose final result ─────────────────────────────────────────
        self._stage = WorkflowStage.COMPLETED
        finished_at = workflow.now()
        result = FuzzingOutput(
            crash_found=campaign.crash_count > 0,
            logs_path=setup_out.workdir / "fuzz.log",
            crash_count=campaign.crash_count,
            severity=triage_out.severity,
            started_at=started_at,
            finished_at=finished_at,
            summary=triage_out.summary,
        )
        log.info(
            "main_workflow.complete "
            f"iterations={campaign.iteration} "
            f"crash_found={result.crash_found} "
            f"severity={result.severity.value} "
            f"crash_count={result.crash_count}"
        )
        return result


__all__ = ["MainFuzzingWorkflow"]
