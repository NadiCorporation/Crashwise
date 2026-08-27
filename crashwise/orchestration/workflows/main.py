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
    from typing import Any

    from crashwise.agents.execution.strategist import initialise_mab
    from crashwise.core.models import (
        AnalyzeProgressInput,
        BlockerType,
        CampaignStatus,
        CoverageAnalysis,
        CoverageBlocker,
        EvolveHarnessInput,
        EvolveHarnessOutput,
        ExecuteFuzzingInput,
        ExecuteFuzzingOutput,
        FuzzerType,
        FuzzingCampaignState,
        FuzzingInput,
        FuzzingOutput,
        HotSwapInput,
        HotSwapOutput,
        MabState,
        PersistTriagedCrashInput,
        PersistTriagedCrashOutput,
        PivotStrategyInput,
        PivotStrategyOutput,
        SeedCorpusInput,
        SetupTargetInput,
        SetupTargetOutput,
        SynthesizeHarnessInput,
        SynthesizeHarnessOutput,
        TriagedCrashRef,
        TriageInput,
        TriageOutput,
        WorkflowStage,
    )
    from crashwise.orchestration.activities.analyze_coverage import (
        AnalyzeCoverageInput,
    )
    from crashwise.orchestration.activities.healing_activities import (
        run_adaptive_build_activity,
        run_autonomous_repair_activity,
    )


# Retry policies
_SEED_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
)

_SETUP_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=60),
    maximum_attempts=3,
)

# ── Phase 22 — CrashWise Healing Engine retry policies ──────────────────────
#
# The healing activities drive a LangGraph agent that compiles code,
# runs GDB and edits source via openhands-sdk. Each invocation can
# easily take 10+ minutes and cost real money in LLM tokens, so:
#
# * ``start_to_close_timeout`` is generous (15 minutes) — enough for
#   a full multi-turn build/repair conversation.
# * ``heartbeat_timeout`` is 2 minutes — the activities heartbeat every
#   15 s, so any silence beyond two minutes is a genuine hang.
# * ``maximum_attempts`` is intentionally low (1-2). The LangGraph
#   agent already retries up to ``healing_max_attempts`` *internally*;
#   adding Temporal-level retries on top would only inflate API spend.
# * Non-retryable types match the ``ApplicationError.type`` strings
#   raised by the healing activities (HealingBuildBadInput,
#   HealingBuildError, HealingRepairBadInput, HealingRepairError) so
#   permanent agent failures abort the campaign immediately.
_HEALING_BUILD_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=30),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=5),
    maximum_attempts=2,
    non_retryable_error_types=[
        "HealingBuildBadInput",
        "HealingBuildError",
    ],
)

_HEALING_REPAIR_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=15),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=2),
    maximum_attempts=1,
    non_retryable_error_types=[
        "HealingRepairBadInput",
        "HealingRepairError",
    ],
)

_HEALING_BUILD_TIMEOUT = timedelta(minutes=15)
_HEALING_REPAIR_TIMEOUT = timedelta(minutes=15)
_HEALING_HEARTBEAT_TIMEOUT = timedelta(minutes=2)

_PERSIST_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=10),
    maximum_attempts=3,
)

_FUZZ_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=60),
    maximum_attempts=2,
    non_retryable_error_types=["WorkdirMissing", "HarnessUnavailable", "NoHarnessBinary"],
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


_PIVOT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=10),
    maximum_attempts=2,
)

_EVOLVE_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=2,
    non_retryable_error_types=["ProviderUnavailable"],
)

# T2 — coverage-analysis retries are short; the activity is rule-based
# (regex on source) so transient failures are virtually always I/O.
_COVERAGE_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=10),
    maximum_attempts=2,
)


@workflow.defn(name="MainFuzzingWorkflow")
class MainFuzzingWorkflow:
    """Top-level CrashWise workflow with autonomous feedback loop.

    Phase 21: when ``payload.enable_mab`` is set, the workflow asks the
    MAB strategist whether to pivot strategy after each iteration and
    when ``payload.enable_evolution`` is set, escalates to harness
    evolution + hot-swap after two consecutive failed pivots.
    """

    def __init__(self) -> None:
        self._stage: WorkflowStage = WorkflowStage.PENDING
        self._iteration: int = 0
        # Phase 21 — strategy + evolution state.
        self._mab_state: MabState | None = None
        self._consecutive_pivots_no_growth: int = 0
        self._last_coverage_at_pivot: int = 0
        self._pivot_count: int = 0
        self._evolution_count: int = 0
        # ── God-Mode (researcher in-flight controls) ──────────────────────
        self._paused: bool = False
        self._force_pivot_requested: bool = False
        self._pending_seeds: list[tuple[str, str]] = []  # (filename, b64data)
        self._operator_notes: list[str] = []
        # ── Phase 22 — CrashWise Healing Engine telemetry ─────────────────
        self._build_attempts: int = 0
        self._build_succeeded: bool = True
        self._healing_workspace_path: str = ""
        self._total_patches_generated: int = 0
        # ── Phase 3 fix: track the most recent FuzzingRun id so crashes ──
        # can be linked back to the run that produced them (exposes them
        # to the API/UI via the campaign→run→crash join).
        self._last_run_id: str | None = None

    @workflow.query(name="current_stage")
    def current_stage(self) -> str:
        return self._stage.value

    @workflow.query(name="iteration")
    def iteration(self) -> int:
        return self._iteration

    @workflow.query(name="pivot_count")
    def pivot_count(self) -> int:
        return self._pivot_count

    @workflow.query(name="evolution_count")
    def evolution_count(self) -> int:
        return self._evolution_count

    # ── Phase 22 healing telemetry queries ──────────────────────────────
    @workflow.query(name="build_attempts")
    def build_attempts(self) -> int:
        return self._build_attempts

    @workflow.query(name="total_patches_generated")
    def total_patches_generated(self) -> int:
        return self._total_patches_generated

    @workflow.query(name="healing_status")
    def healing_status(self) -> dict[str, object]:
        """Snapshot of the healing engine's progress for live dashboards."""
        return {
            "build_attempts": self._build_attempts,
            "build_succeeded": self._build_succeeded,
            "healing_workspace_path": self._healing_workspace_path,
            "total_patches_generated": self._total_patches_generated,
            "stage": self._stage.value,
        }

    # ── God-Mode queries ────────────────────────────────────────────────
    @workflow.query(name="is_paused")
    def is_paused(self) -> bool:
        return self._paused

    @workflow.query(name="pending_seed_count")
    def pending_seed_count(self) -> int:
        return len(self._pending_seeds)

    @workflow.query(name="operator_notes")
    def operator_notes(self) -> list[str]:
        # Return a copy so callers can't mutate workflow state.
        return list(self._operator_notes)

    @workflow.query(name="signal_status")
    def signal_status(self) -> dict[str, object]:
        """Return the current state of all God-Mode controls.

        Operators can poll this query to confirm their signals were
        received and see what's pending.
        """
        return {
            "paused": self._paused,
            "force_pivot_pending": self._force_pivot_requested,
            "pending_seeds": len(self._pending_seeds),
            "pivot_count": self._pivot_count,
            "evolution_count": self._evolution_count,
            "iteration": self._iteration,
            "stage": self._stage.value,
            "notes_count": len(self._operator_notes),
            "last_note": self._operator_notes[-1] if self._operator_notes else "",
        }

    # ── God-Mode signals ────────────────────────────────────────────────
    @workflow.signal(name="force_pivot")
    def force_pivot(self, reason: str = "operator request") -> None:
        """Operator override — force the next iteration to attempt a pivot.

        Bumps the in-memory ``_consecutive_pivots_no_growth`` counter so
        that on the next loop turn either the MAB pivots OR (if MAB
        re-picks the same arm twice) the workflow escalates to
        evolution.  Idempotent.

        Signal is acknowledged immediately via operator_notes. Query
        ``signal_status`` to confirm receipt.
        """
        self._force_pivot_requested = True
        # Also bump consecutive pivots so evolution escalation is triggered
        # even if the MAB decides not to pivot.
        self._consecutive_pivots_no_growth += 1
        self._operator_notes.append(
            f"[ACK] force_pivot received at iteration {self._iteration}: {reason[:120]}"
        )
        workflow.logger.warning(
            f"main_workflow.force_pivot_signal reason={reason[:80]} iteration={self._iteration}"
        )

    @workflow.signal(name="inject_seed")
    def inject_seed(self, seed: dict[str, str]) -> None:
        """Operator override — drop a manually crafted seed into the
        running corpus.

        The signal payload must be ``{"filename": str, "data_b64": str}``
        where ``data_b64`` is base64-encoded raw bytes.  Validation and
        the actual filesystem write happen in the ``inject_seed``
        activity to keep the workflow body deterministic.

        Signal is acknowledged immediately. Query ``signal_status`` to
        confirm receipt and see pending seed count.
        """
        filename = seed.get("filename", "")
        data_b64 = seed.get("data_b64", "")
        if not filename or not data_b64:
            self._operator_notes.append(
                f"[REJECTED] inject_seed: invalid payload (filename={filename!r})"
            )
            workflow.logger.warning(
                "main_workflow.inject_seed_signal_invalid "
                f"filename={filename!r} has_data={bool(data_b64)}"
            )
            return
        # Sanitise filename — must be a basename, no path separators.
        if "/" in filename or "\\" in filename or ".." in filename:
            self._operator_notes.append(f"[REJECTED] inject_seed: unsafe filename {filename!r}")
            workflow.logger.warning(
                f"main_workflow.inject_seed_signal_rejected filename={filename!r}"
            )
            return
        self._pending_seeds.append((filename, data_b64))
        self._operator_notes.append(
            f"[ACK] inject_seed: {filename} ({len(data_b64)} b64 chars) "
            f"queued at iteration {self._iteration}"
        )
        workflow.logger.info(
            f"main_workflow.inject_seed_signal filename={filename} "
            f"queued={len(self._pending_seeds)}"
        )

    @workflow.signal(name="pause_hunt")
    def pause_hunt(self, paused: bool = True) -> None:
        """Operator override — pause / resume the campaign loop.

        While paused, the loop sleeps in 5 s ticks and checks the flag.
        Heartbeats from the active execute_fuzzing activity (if any)
        keep Temporal happy until the operator resumes.

        Signal is acknowledged immediately. Query ``signal_status`` to
        confirm the paused state.
        """
        self._paused = bool(paused)
        action = "paused" if paused else "resumed"
        self._operator_notes.append(f"[ACK] pause_hunt: {action} at iteration {self._iteration}")
        workflow.logger.warning(
            f"main_workflow.pause_hunt_signal paused={self._paused} iteration={self._iteration}"
        )

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

        # Update campaign status to running.
        if payload.campaign_id:
            await workflow.execute_activity(
                "update_campaign_status",
                {"campaign_id": payload.campaign_id, "status": "running"},
                start_to_close_timeout=timedelta(seconds=10),
            )

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

        # ── 2. Adaptive build via the CrashWise Healing Engine ──────────────
        #
        # Replaces the legacy ``setup_target`` activity. The healing
        # engine clones the repo, installs missing system dependencies,
        # injects ASAN+UBSan+coverage flags and produces a clean
        # instrumented build inside a sandboxed openhands-sdk runtime.
        # On agent failure (``is_successful == False``) we update the
        # campaign to ``failed_compilation`` and exit gracefully — no
        # fuzzing iterations are attempted, since there's nothing to
        # fuzz against.
        #
        # Fallback: if the healing engine is unavailable (SDK not installed
        # or incompatible), fall back to the legacy setup_target activity.
        self._stage = WorkflowStage.HEALING_BUILD
        healing_campaign_id = payload.campaign_id or workflow.info().run_id

        use_legacy_setup = False
        try:
            build_result: dict[str, Any] = await workflow.execute_activity(
                run_adaptive_build_activity,
                args=[
                    healing_campaign_id,
                    str(payload.target_repo),
                    payload.healing_max_attempts,
                ],
                start_to_close_timeout=_HEALING_BUILD_TIMEOUT,
                heartbeat_timeout=_HEALING_HEARTBEAT_TIMEOUT,
                retry_policy=RetryPolicy(maximum_attempts=1, non_retryable_error_types=["HealingBuildError"]),
            )
        except Exception as heal_exc:
            log.warning(
                "main_workflow.healing.fallback_to_setup_target "
                f"reason={str(heal_exc)[:200]}"
            )
            use_legacy_setup = True

        if not use_legacy_setup:
            # Check healing result
            self._build_attempts = int(build_result.get("attempt_count", 0) or 0)
            workspace_str = str(build_result.get("workspace_path", "") or "")
            self._healing_workspace_path = workspace_str

            if bool(build_result.get("success", False)):
                self._build_succeeded = True
                target_workdir = Path(workspace_str) if workspace_str else Path("/tmp")
                log.info(
                    "main_workflow.healing.build_succeeded "
                    f"campaign_id={healing_campaign_id} "
                    f"attempts={self._build_attempts} "
                    f"workspace={target_workdir}"
                )
                
                # If no harness_path provided, synthesize one via dedicated Temporal activity
                if payload.harness_path is None:
                    log.info("main_workflow.healing.synthesizing_harness")
                    fuzzer_engine = (
                        payload.fuzzer_type.value
                        if hasattr(payload.fuzzer_type, "value")
                        else str(payload.fuzzer_type)
                    )
                    synth_out: SynthesizeHarnessOutput = await workflow.execute_activity(
                        "synthesize_harness",
                        SynthesizeHarnessInput(
                            workspace_path=target_workdir,
                            fuzzer_type=fuzzer_engine,
                            max_retries=4,
                            campaign_id=healing_campaign_id,
                        ),
                        start_to_close_timeout=timedelta(minutes=15),
                        retry_policy=RetryPolicy(maximum_attempts=2),
                    )
                    if synth_out.success and synth_out.harness_path:
                        harness_path = synth_out.harness_path
                        log.info(f"main_workflow.healing.harness_synthesized {harness_path}")
                    else:
                        log.warning(
                            f"main_workflow.healing.harness_synthesis_failed: {synth_out.error_message}"
                        )
                        use_legacy_setup = True
                else:
                    harness_path = target_workdir / payload.harness_path
                
                if not use_legacy_setup:
                    setup_out = SetupTargetOutput(
                        workdir=target_workdir,
                        commit_sha="healing-build",
                        harness_path=harness_path,
                    )
            else:
                log.warning(
                    "main_workflow.healing.build_failed_fallback "
                    f"campaign_id={healing_campaign_id} "
                    f"attempts={self._build_attempts}"
                )
                use_legacy_setup = True

        if use_legacy_setup:
            # Legacy path: use setup_target activity.
            setup_out = await workflow.execute_activity(
                "setup_target",
                SetupTargetInput(
                    target_repo=str(payload.target_repo),
                    target_branch=payload.target_branch,
                    sanitizers=payload.sanitizers,
                    synthesize_harness=payload.harness_path is None,
                    max_synth_retries=payload.max_synth_retries,
                    fuzzer_type=payload.fuzzer_type.value,
                    custom_fuzzer_flags=payload.custom_fuzzer_flags,
                    llm_model=payload.llm_model,
                    llm_base_url=payload.llm_base_url,
                    llm_api_key=payload.llm_api_key,
                    llm_temperature=payload.llm_temperature,
                    reasoning_effort=payload.reasoning_effort,
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
            target_workdir = setup_out.workdir
            self._build_succeeded = True

        # ── 2. Initialise campaign state ────────────────────────────────────
        campaign = FuzzingCampaignState(
            iteration=0,
            max_iterations=payload.max_iterations,
            harness_path=harness_path,
        )

        # ── 2b. Phase 21: initialise MAB if requested ───────────────────────
        # ``initialise_mab`` is pure (no I/O / no time-of-day) → safe to call
        # from inside the workflow without a sandbox violation.
        if payload.enable_mab and self._mab_state is None:
            self._mab_state = initialise_mab()
            self._mab_state.current_arm_id = (
                "afl_default" if payload.fuzzer_type == FuzzerType.AFLPP else "libfuzzer_custom"
            )
            log.info(f"main_workflow.mab_initialised arm={self._mab_state.current_arm_id}")

        # ── 3. Feedback loop ────────────────────────────────────────────────
        while campaign.should_continue:
            self._iteration = campaign.iteration
            self._stage = WorkflowStage.EXECUTING

            # ── God-Mode: pause gate ──────────────────────────────────
            # Block until the operator resumes. We use ``workflow.wait_condition``
            # so Temporal knows we are intentionally idle — no busy loop, no
            # forced sleeps that count against activity timeouts.
            if self._paused:
                log.warning(
                    f"main_workflow.paused iteration={campaign.iteration} reason=operator_signal"
                )
                await workflow.wait_condition(lambda: not self._paused)
                log.warning(f"main_workflow.resumed iteration={campaign.iteration}")

            # ── God-Mode: drain pending injected seeds ────────────────
            if self._pending_seeds and corpus_dir is not None:
                seeds_to_inject = self._pending_seeds[:]
                self._pending_seeds.clear()
                try:
                    await workflow.execute_activity(
                        "inject_seeds",
                        {
                            "corpus_dir": str(corpus_dir),
                            "seeds": [
                                {"filename": fn, "data_b64": db} for fn, db in seeds_to_inject
                            ],
                            "campaign_id": payload.campaign_id,
                        },
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=_SEED_RETRY,
                    )
                    log.info(f"main_workflow.seeds_injected count={len(seeds_to_inject)}")
                except Exception as exc:  # broad-except
                    log.warning(
                        "main_workflow.seed_inject_failed "
                        f"count={len(seeds_to_inject)} error={exc!s:.120}"
                    )
            elif self._pending_seeds and corpus_dir is None:
                # Seeds arrived before corpus was set up. Keep them queued
                # — they'll be injected on the next iteration when corpus_dir
                # is available. Log so operator knows they're waiting.
                log.info(
                    "main_workflow.seeds_queued_waiting_for_corpus "
                    f"count={len(self._pending_seeds)}"
                )

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
                    custom_fuzzer_flags=payload.custom_fuzzer_flags,
                ),
                result_type=ExecuteFuzzingOutput,
                start_to_close_timeout=timedelta(seconds=payload.timeout_seconds)
                + timedelta(minutes=10),
                heartbeat_timeout=timedelta(minutes=5),
                retry_policy=_FUZZ_RETRY,
            )

            # Remember the run this iteration persisted so the end-of-
            # campaign triage can attach each crash to the producing run.
            if fuzz_out.run_id:
                self._last_run_id = fuzz_out.run_id

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

            # ── Phase 21: MAB pivot check (autonomous strategy switching) ─
            # God-Mode: a ``force_pivot`` signal short-circuits the
            # iteration-interval gate and evaluates the bandit immediately.
            interval_due = (
                campaign.iteration > 0
                and campaign.iteration % payload.pivot_check_interval_iterations == 0
            )
            should_evaluate_pivot = (
                payload.enable_mab
                and self._mab_state is not None
                and (interval_due or self._force_pivot_requested)
            )
            forced_pivot = self._force_pivot_requested
            if forced_pivot:
                # Consume the request so it doesn't repeat next iteration.
                self._force_pivot_requested = False

            if should_evaluate_pivot:
                pivot_in = PivotStrategyInput(
                    campaign_id=payload.campaign_id or "anon",
                    mab_state=self._mab_state,
                    current_coverage=campaign.last_coverage.edges_hit,
                    current_exec_rate=campaign.last_coverage.exec_per_sec,
                    elapsed_seconds=float(campaign.iteration * payload.timeout_seconds),
                )
                pivot_out: PivotStrategyOutput = await workflow.execute_activity(
                    "pivot_strategy",
                    pivot_in,
                    result_type=PivotStrategyOutput,
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=_PIVOT_RETRY,
                )
                self._mab_state = pivot_out.mab_state
                # When the operator forces a pivot but the bandit refuses
                # (same-arm-wins), bump the no-growth counter so evolution
                # escalates within two iterations regardless.
                if forced_pivot and not pivot_out.should_pivot:
                    self._consecutive_pivots_no_growth += 1
                    log.warning(
                        "main_workflow.force_pivot_overridden_by_bandit "
                        f"current_arm={self._mab_state.current_arm_id} "
                        f"no_growth_streak={self._consecutive_pivots_no_growth}"
                    )
                if pivot_out.should_pivot and pivot_out.new_arm is not None:
                    self._pivot_count += 1
                    log.info(
                        "main_workflow.mab_pivot "
                        f"to={pivot_out.new_arm_id} "
                        f"reason={pivot_out.reason[:80]}"
                    )
                    # Track whether the previous pivot grew coverage.
                    if campaign.last_coverage.edges_hit <= self._last_coverage_at_pivot:
                        self._consecutive_pivots_no_growth += 1
                    else:
                        self._consecutive_pivots_no_growth = 0
                    self._last_coverage_at_pivot = campaign.last_coverage.edges_hit

                    # ── Phase 21: Harness evolution escalation ────────────
                    # Two consecutive pivots failed to grow coverage → the
                    # blocker is structural (magic value, checksum). Ask
                    # the LLM to rewrite the harness, then hot-swap.
                    if (
                        payload.enable_evolution
                        and self._consecutive_pivots_no_growth >= 2
                        and harness_path is not None
                    ):
                        harness_path = await self._run_evolution(
                            payload=payload,
                            setup_out=setup_out,
                            harness_path=harness_path,
                            campaign=campaign,
                        )
                        # Reset growth counter so we don't re-evolve every
                        # subsequent loop.
                        self._consecutive_pivots_no_growth = 0
                    # Loop will pick up the new strategy on next iteration.
                    campaign.status = CampaignStatus.RUNNING

            # ── Phase 6 fallback: mutate harness when MAB is disabled. ────
            elif (
                campaign.should_continue
                and campaign.status == CampaignStatus.STALLED
                and campaign.mutation_hint
            ):
                log.info(
                    f"main_workflow.mutate "
                    f"iteration={campaign.iteration} "
                    f"hint={campaign.mutation_hint[:80]}"
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

        # ── 4. Final triage (defer persistence so we can stitch in patches) ─
        self._stage = WorkflowStage.TRIAGE
        # Re-scan the final output directory for crashes. ``defer_persistence``
        # tells the activity to compute + dedup + return the unique crashes
        # without writing them. The workflow then drives the per-crash
        # autonomous repair step (Phase 22) and persists each crash with
        # its verified patch (when available).
        triage_out: TriageOutput = await workflow.execute_activity(
            "triage_results",
            TriageInput(
                logs_path=target_workdir / "fuzz.log",
                crashes_dir=target_workdir / "crashes",
                crash_count=campaign.crash_count,
                campaign_id=payload.campaign_id,
                defer_persistence=payload.campaign_id is not None,
            ),
            result_type=TriageOutput,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_TRIAGE_RETRY,
        )

        # ── 5. Per-crash autonomous repair + persistence (Phase 22) ─────────
        # The loop is a no-op when ``campaign_id`` is None (anonymous
        # smoke runs); persistence requires a campaign to attach to.
        persisted_crashes: list[tuple[str, TriagedCrashRef]] = []
        if payload.campaign_id is not None and triage_out.unique_crashes:
            persisted_crashes = await self._heal_and_persist_crashes(
                payload=payload,
                target_workdir=target_workdir,
                unique_crashes=triage_out.unique_crashes,
            )

        # ── 6. Deep crash analysis (Phase 10) ───────────────────────────────
        # Run per-crash LLM RCA against the *actual* crash UUID and feed the
        # real ASAN log as context, so the analysis is attached to the crash
        # row instead of being discarded against the campaign id.
        if payload.campaign_id is not None and persisted_crashes:
            self._stage = WorkflowStage.TRIAGE
            for crash_uuid, crash_ref in persisted_crashes:
                crash_context = (
                    crash_ref.asan_log or crash_ref.stack_trace or crash_ref.root_cause
                )
                log.info(
                    f"main_workflow.analyze_crash "
                    f"crash_uuid={crash_uuid} "
                    f"crash_id={crash_ref.crash_id} "
                    f"campaign_id={payload.campaign_id}"
                )
                try:
                    await workflow.execute_activity(
                        "analyze_crash",
                        {
                            "crash_id": crash_uuid,
                            "crash_context": crash_context,
                            "campaign_id": payload.campaign_id,
                            "skip_patch_generation": payload.enable_self_healing,
                        },
                        start_to_close_timeout=timedelta(minutes=5),
                        retry_policy=_AI_RETRY,
                    )
                except Exception as exc:  # broad-except: never break the loop
                    log.warning(
                        "main_workflow.analyze_crash_failed "
                        f"crash_uuid={crash_uuid} "
                        f"error={exc!s:.160}"
                    )

        # ── 7. Compose final result ─────────────────────────────────────────
        self._stage = WorkflowStage.COMPLETED
        finished_at = workflow.now()
        result = FuzzingOutput(
            crash_found=campaign.crash_count > 0,
            logs_path=target_workdir / "fuzz.log",
            crash_count=campaign.crash_count,
            severity=triage_out.severity,
            started_at=started_at,
            finished_at=finished_at,
            summary=triage_out.summary,
            total_patches_generated=self._total_patches_generated,
            build_attempts=self._build_attempts,
            build_succeeded=self._build_succeeded,
            healing_workspace_path=self._healing_workspace_path,
        )
        log.info(
            "main_workflow.complete "
            f"iterations={campaign.iteration} "
            f"crash_found={result.crash_found} "
            f"severity={result.severity.value} "
            f"crash_count={result.crash_count} "
            f"patches_generated={self._total_patches_generated} "
            f"build_attempts={self._build_attempts}"
        )

        # Update campaign status to completed/failed.
        if payload.campaign_id:
            final_status = "completed_with_crashes" if result.crash_found else "completed"
            await workflow.execute_activity(
                "update_campaign_status",
                {
                    "campaign_id": payload.campaign_id,
                    "status": final_status,
                },
                start_to_close_timeout=timedelta(seconds=10),
            )

        # ── 8. Store campaign knowledge for cross-campaign learning ─────────
        # Extract and store insights from this campaign to improve future campaigns.
        # This is best-effort — failures don't affect the campaign result.
        try:
            # Build campaign outcome summary
            campaign_outcome = {
                "crashes_found": result.crash_count,
                "coverage_edges": campaign.best_coverage.edges_hit if campaign.best_coverage else 0,
                "strategies_used": [self._mab_state.current_arm_id] if self._mab_state else [],
                "harness_patterns": [],  # TODO: extract from harness synthesis logs
                "blockers_encountered": [],  # TODO: extract from coverage analysis
            }

            # Get target profile if available
            target_profile_dict = {}
            if hasattr(self, "_target_profile") and self._target_profile:
                target_profile_dict = self._target_profile.model_dump()

            # Extract vulnerability patterns from triage
            vulnerabilities = []
            if triage_out.unique_crashes:
                for crash in triage_out.unique_crashes[:10]:  # Cap at 10
                    vulnerabilities.append({
                        "bug_type": crash.bug_type,
                        "severity": crash.severity.value if crash.severity else "unknown",
                        "severity_score": crash.severity_score if hasattr(crash, "severity_score") else 0,
                        "location_pattern": crash.stack_hash[:32] if crash.stack_hash else "",
                        "root_cause": crash.root_cause[:500] if hasattr(crash, "root_cause") and crash.root_cause else "",
                        "bypass_strategy": "",
                        "crash_id": str(crash.crash_id),
                    })

            # Extract strategy metrics from MAB state
            strategy_metrics = []
            if self._mab_state and self._mab_state.arms:
                for arm in self._mab_state.arms:
                    strategy_metrics.append({
                        "strategy_arm_id": arm.arm_id,
                        "success": self._mab_state.successes.get(arm.arm_id, 0) > 0,
                        "coverage_gain": self._mab_state.successes.get(arm.arm_id, 0),
                        "time_to_crash": 0.0,  # TODO: track this
                    })

            # Store knowledge
            await workflow.execute_activity(
                "store_campaign_knowledge",
                {
                    "target_name": target_name,
                    "target_profile": target_profile_dict,
                    "campaign_outcome": campaign_outcome,
                    "vulnerabilities": vulnerabilities,
                    "strategy_metrics": strategy_metrics,
                },
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )
            log.info(f"main_workflow.knowledge_stored target_name={target_name}")
        except Exception as exc:
            # Knowledge storage is best-effort — don't fail the campaign
            log.warning(
                f"main_workflow.knowledge_storage_failed error={str(exc)[:200]}"
            )

        return result

    # ── Phase 22 — CrashWise Healing Engine: per-crash repair loop ─────
    async def _heal_and_persist_crashes(
        self,
        *,
        payload: FuzzingInput,
        target_workdir: Path,
        unique_crashes: list[TriagedCrashRef],
    ) -> list[tuple[str, TriagedCrashRef]]:
        """Drive autonomous repair (when enabled) and persist each crash.

        For every unique, net-new crash returned by ``triage_results``
        with ``defer_persistence=True`` we:

        1. (Optional, when ``payload.enable_self_healing == True``) call
           :func:`run_autonomous_repair_activity` with the ASAN log,
           reusing the workspace established by the adaptive build so
           the agent already has the source + instrumented binary on
           hand. The repair activity is bounded by the LangGraph
           agent's own ``healing_max_attempts`` and a 15-minute
           ``start_to_close_timeout`` so it cannot stall the workflow
           indefinitely.
        2. Persist the crash via :func:`persist_triaged_crash`, passing
           the verified ``.patch`` text (or empty string), the number of
           agent attempts, and the campaign's most recent ``run_id`` so
           the crash is linked to its producing fuzzing run.

        The method is total — it never raises. Per-crash failures are
        logged and the workflow continues so a single repair-blowup
        does not cost the entire campaign.

        Returns
        -------
        A list of ``(crash_uuid, crash_ref)`` tuples for every crash that
        was successfully persisted, so the caller can drive per-crash
        root-cause analysis against the real database UUID.
        """
        log = workflow.logger
        campaign_id = payload.campaign_id
        if campaign_id is None:
            return []

        persisted: list[tuple[str, TriagedCrashRef]] = []

        for crash_ref in unique_crashes:
            patch_text: str = ""
            patch_summary: str = ""
            healing_attempts: int = 0

            if payload.enable_self_healing:
                self._stage = WorkflowStage.HEALING_REPAIR
                log.info(
                    "main_workflow.healing.repair_start "
                    f"crash_id={crash_ref.crash_id} "
                    f"stack_hash={crash_ref.stack_hash} "
                    f"bug_type={crash_ref.bug_type} "
                    f"asan_chars={len(crash_ref.asan_log)}"
                )
                try:
                    repair_result: dict[str, Any] = await workflow.execute_activity(
                        run_autonomous_repair_activity,
                        args=[
                            crash_ref.crash_id,
                            crash_ref.asan_log,
                            str(target_workdir),
                            campaign_id,
                            payload.healing_max_attempts,
                            str(crash_ref.crash_file_path) if crash_ref.crash_file_path else None,
                            crash_ref.bug_type,
                            crash_ref.root_cause,
                        ],
                        start_to_close_timeout=_HEALING_REPAIR_TIMEOUT,
                        heartbeat_timeout=_HEALING_HEARTBEAT_TIMEOUT,
                        retry_policy=_HEALING_REPAIR_RETRY,
                    )
                    healing_attempts = int(repair_result.get("attempt_count", 0) or 0)
                    if bool(repair_result.get("success", False)):
                        patch_text = str(repair_result.get("patch", "") or "")
                        patch_summary = str(repair_result.get("summary", "") or "")
                        if patch_text:
                            self._total_patches_generated += 1
                            log.info(
                                "main_workflow.healing.repair_succeeded "
                                f"crash_id={crash_ref.crash_id} "
                                f"attempts={healing_attempts} "
                                f"patch_chars={len(patch_text)}"
                            )
                        else:
                            log.warning(
                                "main_workflow.healing.repair_no_patch "
                                f"crash_id={crash_ref.crash_id}"
                            )
                    else:
                        log.warning(
                            "main_workflow.healing.repair_failed "
                            f"crash_id={crash_ref.crash_id} "
                            f"attempts={healing_attempts} "
                            f"summary={str(repair_result.get('summary', ''))[:120]}"
                        )
                except Exception as exc:  # broad-except: never break loop
                    log.warning(
                        "main_workflow.healing.repair_error "
                        f"crash_id={crash_ref.crash_id} "
                        f"error={exc!s:.160}"
                    )

            # Always persist — with the verified patch when we got one,
            # without otherwise. The persistence activity itself does
            # the Redis dedup check, so duplicates are cheap.
            try:
                persist_out: PersistTriagedCrashOutput = await workflow.execute_activity(
                    "persist_triaged_crash",
                    PersistTriagedCrashInput(
                        campaign_id=campaign_id,
                        crash=crash_ref,
                        patch=patch_text,
                        patch_summary=patch_summary,
                        healing_attempts=healing_attempts,
                        run_id=self._last_run_id,
                    ),
                    result_type=PersistTriagedCrashOutput,
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=_PERSIST_RETRY,
                )
                if persist_out.persisted:
                    if persist_out.crash_uuid:
                        persisted.append((persist_out.crash_uuid, crash_ref))
                    log.info(
                        "main_workflow.healing.crash_persisted "
                        f"crash_id={crash_ref.crash_id} "
                        f"crash_uuid={persist_out.crash_uuid} "
                        f"with_patch={bool(patch_text)}"
                    )
                elif persist_out.duplicate:
                    log.debug(
                        "main_workflow.healing.crash_duplicate_skipped "
                        f"crash_id={crash_ref.crash_id}"
                    )
                else:
                    log.warning(
                        "main_workflow.healing.crash_persist_softfail "
                        f"crash_id={crash_ref.crash_id}"
                    )
            except Exception as exc:  # broad-except: never break loop
                log.warning(
                    "main_workflow.healing.crash_persist_error "
                    f"crash_id={crash_ref.crash_id} "
                    f"error={exc!s:.160}"
                )

        return persisted

    async def _run_evolution(
        self,
        *,
        payload: FuzzingInput,
        setup_out: SetupTargetOutput,
        harness_path: Path,
        campaign: FuzzingCampaignState,
    ) -> Path:
        """Phase 21 + Linux-Native: invoke harness evolution + hot-swap.

        Called by the main loop once the MAB has shown two consecutive
        pivots produced no coverage growth — implying a structural
        blocker (magic value, checksum, length guard) that no fuzzer
        configuration can cross unaided.

        T2 — the evolution branch now closes the **intelligence loop**:

        1. Run the ``analyze_coverage_activity`` over the target source
           tree to identify the single most-confident coverage blocker
           (magic value, length check, checksum, …) and the source line
           that gates it.
        2. Hand that blocker — *not* a ``BlockerType.UNKNOWN`` stub —
           to ``evolve_harness_activity``.  The LLM now receives a
           concrete, structured reason for why the fuzzer is stuck and
           the exact code location, dramatically improving the chance
           of producing a useful rewrite for targets like libjxl.
        3. Hot-swap the resulting binary.

        A ``max_evolution_count`` guard prevents the loop from spending
        the entire LLM budget on identical fallback templates.
        """
        log = workflow.logger

        # Bound: never run more than ``max_evolution_count`` evolutions
        # per campaign. Default 10 — defensive when ``payload`` is older.
        max_evolutions = getattr(payload, "max_evolution_count", 10) or 10
        if self._evolution_count >= max_evolutions:
            log.warning(
                "main_workflow.evolution.cap_reached "
                f"count={self._evolution_count} max={max_evolutions}"
            )
            return harness_path

        log.info(
            "main_workflow.evolution.start "
            f"iteration={campaign.iteration} "
            f"evolution={self._evolution_count}/{max_evolutions} "
            f"harness={harness_path}"
        )

        # ── 1. Identify the structural blocker via analyze_coverage. ──
        blocker, target_function = await self._identify_blocker(
            setup_out=setup_out,
            harness_path=harness_path,
            campaign=campaign,
        )

        # ── 2. Ask the LLM to rewrite the harness against the blocker. ─
        evolve_in = EvolveHarnessInput(
            current_harness_code=(
                "// placeholder; the evolution agent will re-read the\n"
                "// real harness source from the workdir.\n"
                'extern "C" int LLVMFuzzerTestOneInput('
                "const uint8_t *data, size_t size) { return 0; }\n"
            ),
            blocker=blocker,
            target_source_path=str(setup_out.workdir),
            target_function=target_function,
            iteration=self._evolution_count,
        )
        evolved: EvolveHarnessOutput = await workflow.execute_activity(
            "evolve_harness_activity",
            evolve_in,
            result_type=EvolveHarnessOutput,
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_EVOLVE_RETRY,
        )

        if not evolved.evolved_harness_code:
            log.warning("main_workflow.evolution.no_code")
            return harness_path

        log.info(
            "main_workflow.evolution.llm_response "
            f"blocker={blocker.blocker_type.value} "
            f"confidence={blocker.confidence:.2f} "
            f"line={blocker.line_number} "
            f"strategy={evolved.bypass_strategy[:80]!r}"
        )

        # ── 3. Compile + hot-swap the new binary. ────────────────────
        swap: HotSwapOutput = await workflow.execute_activity(
            "hot_swap_harness",
            HotSwapInput(
                job_id=(f"{payload.campaign_id or 'anon'}-iter{campaign.iteration}"),
                new_harness_code=evolved.evolved_harness_code,
                compilation_command=evolved.compilation_command,
                preserve_corpus=True,
            ),
            result_type=HotSwapOutput,
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_MUTATE_RETRY,
        )

        if swap.swapped and swap.binary_path is not None:
            self._evolution_count += 1
            harness_path = swap.binary_path
            log.info(f"main_workflow.evolution.success binary={swap.binary_path}")
        else:
            log.warning(f"main_workflow.evolution.failed notes={swap.notes[:80]}")

        # Return the (possibly updated) harness path so the main loop uses
        # the freshly compiled binary on the next iteration.
        return harness_path

    async def _identify_blocker(
        self,
        *,
        setup_out: SetupTargetOutput,
        harness_path: Path,
        campaign: FuzzingCampaignState,
    ) -> tuple[CoverageBlocker, str]:
        """Run ``analyze_coverage_activity`` and pick the best blocker.

        Returns
        -------
        ``(blocker, target_function)`` where ``target_function`` is the
        function-name extracted from the most-confident blocker. The
        blocker is guaranteed to have a concrete :class:`BlockerType`
        (never ``UNKNOWN``) when the analysis succeeded; on failure
        we fall back to a low-confidence ``UNKNOWN`` placeholder.
        """
        log = workflow.logger
        # Prefer the harness's parent directory as the source root —
        # it almost always co-locates with the target sources after
        # ``setup_target``.  Fall back to the workdir if the harness
        # path is unset.
        source_root = harness_path.parent if harness_path else setup_out.workdir

        # Load live coverage data collected by execute_fuzzing activity.
        coverage_data = ""
        if campaign.last_coverage_data_path is not None:
            try:
                _cov_path = campaign.last_coverage_data_path
                # Read coverage data in an activity to maintain determinism.
                coverage_data = await workflow.execute_activity(
                    "read_coverage_data",
                    {"path": str(_cov_path)},
                    result_type=str,
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=_COVERAGE_RETRY,
                )
            except Exception as exc:
                log.warning(f"main_workflow.evolution.coverage_data_read_failed error={exc!s:.120}")
                # Fall through — static analysis is still useful.

        try:
            analysis: CoverageAnalysis = await workflow.execute_activity(
                "analyze_coverage_activity",
                AnalyzeCoverageInput(
                    source_path=source_root,
                    coverage_data=coverage_data,
                ),
                result_type=CoverageAnalysis,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_COVERAGE_RETRY,
            )
        except Exception as exc:  # broad-except — never break the loop
            log.warning(f"main_workflow.evolution.analyze_coverage_failed error={exc!s:.120}")
            return (
                CoverageBlocker(
                    blocker_type=BlockerType.UNKNOWN,
                    confidence=0.4,
                    function_name="LLVMFuzzerTestOneInput",
                ),
                "LLVMFuzzerTestOneInput",
            )

        if not analysis.blockers:
            log.info("main_workflow.evolution.no_blocker_identified")
            return (
                CoverageBlocker(
                    blocker_type=BlockerType.UNKNOWN,
                    confidence=0.4,
                    function_name="LLVMFuzzerTestOneInput",
                ),
                "LLVMFuzzerTestOneInput",
            )

        best = analysis.blockers[0]
        log.info(
            "main_workflow.evolution.blocker_identified "
            f"type={best.blocker_type.value} "
            f"function={best.function_name} "
            f"line={best.line_number} "
            f"confidence={best.confidence:.2f}"
        )
        return best, best.function_name or "LLVMFuzzerTestOneInput"


__all__ = ["MainFuzzingWorkflow"]
