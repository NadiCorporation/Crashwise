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
        PivotStrategyInput,
        PivotStrategyOutput,
        SeedCorpusInput,
        SetupTargetInput,
        SetupTargetOutput,
        TriageInput,
        TriageOutput,
        WorkflowStage,
    )
    from crashwise.orchestration.activities.analyze_coverage import (
        AnalyzeCoverageInput,
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
            "main_workflow.force_pivot_signal "
            f"reason={reason[:80]} iteration={self._iteration}"
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
            self._operator_notes.append(
                f"[REJECTED] inject_seed: unsafe filename {filename!r}"
            )
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
        self._operator_notes.append(
            f"[ACK] pause_hunt: {action} at iteration {self._iteration}"
        )
        workflow.logger.warning(
            "main_workflow.pause_hunt_signal "
            f"paused={self._paused} iteration={self._iteration}"
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

        # ── 2. Setup target ─────────────────────────────────────────────────
        self._stage = WorkflowStage.SETUP
        setup_out: SetupTargetOutput = await workflow.execute_activity(
            "setup_target",
            SetupTargetInput(
                target_repo=payload.target_repo,
                target_branch=payload.target_branch,
                sanitizers=payload.sanitizers,
                synthesize_harness=payload.harness_path is None,
                fuzzer_type=payload.fuzzer_type.value,
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

        # ── 2b. Phase 21: initialise MAB if requested ───────────────────────
        # ``initialise_mab`` is pure (no I/O / no time-of-day) → safe to call
        # from inside the workflow without a sandbox violation.
        if payload.enable_mab and self._mab_state is None:
            self._mab_state = initialise_mab()
            self._mab_state.current_arm_id = (
                "afl_default"
                if payload.fuzzer_type == FuzzerType.AFLPP
                else "libfuzzer_custom"
            )
            log.info(
                "main_workflow.mab_initialised "
                f"arm={self._mab_state.current_arm_id}"
            )

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
                    "main_workflow.paused "
                    f"iteration={campaign.iteration} "
                    f"reason=operator_signal"
                )
                await workflow.wait_condition(lambda: not self._paused)
                log.warning(
                    "main_workflow.resumed "
                    f"iteration={campaign.iteration}"
                )

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
                                {"filename": fn, "data_b64": db}
                                for fn, db in seeds_to_inject
                            ],
                            "campaign_id": payload.campaign_id,
                        },
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=_SEED_RETRY,
                    )
                    log.info(
                        "main_workflow.seeds_injected "
                        f"count={len(seeds_to_inject)}"
                    )
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
                ),
                result_type=ExecuteFuzzingOutput,
                start_to_close_timeout=timedelta(seconds=payload.timeout_seconds)
                + timedelta(minutes=10),
                heartbeat_timeout=timedelta(minutes=5),
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

            # ── Phase 21: MAB pivot check (autonomous strategy switching) ─
            # God-Mode: a ``force_pivot`` signal short-circuits the
            # iteration-interval gate and evaluates the bandit immediately.
            interval_due = (
                campaign.iteration > 0
                and campaign.iteration
                % payload.pivot_check_interval_iterations
                == 0
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
                    elapsed_seconds=float(
                        campaign.iteration * payload.timeout_seconds
                    ),
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
                    if (
                        campaign.last_coverage.edges_hit
                        <= self._last_coverage_at_pivot
                    ):
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
                        await self._run_evolution(
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
                f"main_workflow.analyze_crash "
                f"crash_count={campaign.crash_count} "
                f"campaign_id={payload.campaign_id}"
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

        # Update campaign status to completed/failed.
        if payload.campaign_id:
            final_status = "completed" if result.crash_found else "completed"
            await workflow.execute_activity(
                "update_campaign_status",
                {
                    "campaign_id": payload.campaign_id,
                    "status": final_status,
                },
                start_to_close_timeout=timedelta(seconds=10),
            )

        return result


    async def _run_evolution(
        self,
        *,
        payload: FuzzingInput,
        setup_out: SetupTargetOutput,
        harness_path: Path,
        campaign: FuzzingCampaignState,
    ) -> None:
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
            return

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
                "extern \"C\" int LLVMFuzzerTestOneInput("
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
            return

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
                job_id=(
                    f"{payload.campaign_id or 'anon'}-iter{campaign.iteration}"
                ),
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
            log.info(
                "main_workflow.evolution.success "
                f"binary={swap.binary_path}"
            )
        else:
            log.warning(
                "main_workflow.evolution.failed "
                f"notes={swap.notes[:80]}"
            )

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
                log.warning(
                    "main_workflow.evolution.coverage_data_read_failed "
                    f"error={exc!s:.120}"
                )
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
            log.warning(
                "main_workflow.evolution.analyze_coverage_failed "
                f"error={exc!s:.120}"
            )
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
