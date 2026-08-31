# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""End-to-end workflow tests using Temporal's time-skipping environment.

These run entirely in-process — no Docker required — and exercise the
real workflow code path against the real activity stubs (with a tiny
heartbeat interval so the simulated fuzz loop completes in milliseconds).
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from crashwise.core.models import (
    CrashSeverity,
    ExecuteFuzzingInput,
    ExecuteFuzzingOutput,
    FuzzerType,
    FuzzingInput,
    FuzzingOutput,
    WorkflowStage,
)
from crashwise.orchestration.activities import ALL_ACTIVITIES
from crashwise.orchestration.activities import execute_fuzzing as ef_module
from crashwise.orchestration.data_converter import pydantic_data_converter
from crashwise.orchestration.workflows.main import MainFuzzingWorkflow

# The activity is decorated, so resolve the underlying module via its dunder.
_EF_MODULE = sys.modules[ef_module.__module__]


@pytest.fixture(autouse=True)
def _fast_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Compress the fuzz tick so workflows resolve in milliseconds."""
    monkeypatch.setattr(_EF_MODULE, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)


@pytest.fixture(autouse=True)
def _fast_simulator(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the wall-clock simulator with an instant stub.

    The legacy simulator drives its loop off ``time.monotonic()``, so even
    with a compressed heartbeat it would sleep for the full
    ``timeout_seconds`` (10s) per iteration. We stub it to return a
    zero-crash result immediately so the workflow resolves in milliseconds.
    """

    async def _fake_simulated_execute(
        payload: ExecuteFuzzingInput,
        logs_path: Path,
        crashes_dir: Path,
    ) -> ExecuteFuzzingOutput:
        return ExecuteFuzzingOutput(
            logs_path=logs_path,
            crashes_dir=crashes_dir,
            crash_count=0,
            executions=1_000,
            duration_seconds=0.001,
        )

    monkeypatch.setattr(_EF_MODULE, "_simulated_execute", _fake_simulated_execute)


@pytest.fixture(autouse=True)
def _mock_clone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Mock git clone so workflow tests don't need network access."""
    from crashwise.orchestration.activities.setup_target import setup_target  # noqa: F401

    st_module = sys.modules["crashwise.orchestration.activities.setup_target"]

    async def _fake_clone(
        repo_url: str,
        branch: str | None,
        workdir: Path,
        clone_depth: int = 1,
        *args: object,
        **kwargs: object,
    ) -> str:
        (workdir / "main.c").write_text("int main() { return 0; }\n")
        return "abc123deadbeef"

    monkeypatch.setattr(st_module, "_clone_repo", _fake_clone)


@pytest.fixture(autouse=True)
def _mock_build_and_harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Mock the healing build, sandbox container, and harness synthesis.

    The workflow's adaptive-build stage (and its legacy ``setup_target``
    fallback) would otherwise spawn a live Docker container and drive an
    LLM agent — both unavailable in the unit-test sandbox and the source
    of the suite hang. We short-circuit them so the workflow resolves in
    milliseconds:

    * ``OpenHandsSandbox.allocate`` raises ``openhands-sdk is not
      installed`` — the same permanent failure the activity maps to a
      non-retryable ``HealingBuildError``, forcing the workflow's legacy
      ``setup_target`` fallback.
    * ``setup_target._build_target`` becomes a no-op (no live shell build).
    * ``setup_target._run_harness_synthesis`` returns ``None`` (no LLM).
    """
    from crashwise.agents.healing.tools import OpenHandsSandbox

    async def _fake_allocate(**kwargs: object) -> object:
        raise RuntimeError("openhands-sdk is not installed")

    monkeypatch.setattr(OpenHandsSandbox, "allocate", staticmethod(_fake_allocate))

    st_module = sys.modules["crashwise.orchestration.activities.setup_target"]

    async def _fake_build(workdir: Path, sanitizers: str) -> None:
        return None

    async def _fake_run_harness_synthesis(**kwargs: object) -> Path | None:
        return None

    monkeypatch.setattr(st_module, "_build_target", _fake_build)
    monkeypatch.setattr(st_module, "_run_harness_synthesis", _fake_run_harness_synthesis)


async def _run_main(client: Client, task_queue: str, payload: FuzzingInput) -> FuzzingOutput:
    return await client.execute_workflow(
        MainFuzzingWorkflow.run,
        payload,
        id=f"test-{uuid.uuid4()}",
        task_queue=task_queue,
    )


@pytest.mark.asyncio
async def test_main_workflow_completes_with_no_crashes() -> None:
    async with await WorkflowEnvironment.start_time_skipping(
        data_converter=pydantic_data_converter,
    ) as env:
        task_queue = f"crashwise-test-{uuid.uuid4()}"
        async with Worker(
            env.client,
            task_queue=task_queue,
            workflows=[MainFuzzingWorkflow],
            activities=ALL_ACTIVITIES,
        ):
            payload = FuzzingInput(
                target_repo="https://github.com/example/target",  # type: ignore[arg-type]
                fuzzer_type=FuzzerType.LIBFUZZER,
                timeout_seconds=10,
                max_iterations=1,
            )
            result = await _run_main(env.client, task_queue, payload)

    # Phase-1 stub: never finds crashes.
    assert isinstance(result, FuzzingOutput)
    assert result.crash_found is False
    assert result.crash_count == 0
    assert result.severity is CrashSeverity.UNKNOWN
    assert result.finished_at >= result.started_at
    assert "No crash artefacts found" in result.summary


@pytest.mark.asyncio
async def test_main_workflow_query_reflects_completion() -> None:
    async with await WorkflowEnvironment.start_time_skipping(
        data_converter=pydantic_data_converter,
    ) as env:
        task_queue = f"crashwise-test-{uuid.uuid4()}"
        async with Worker(
            env.client,
            task_queue=task_queue,
            workflows=[MainFuzzingWorkflow],
            activities=ALL_ACTIVITIES,
        ):
            payload = FuzzingInput(
                target_repo="https://github.com/example/target",  # type: ignore[arg-type]
                timeout_seconds=10,
            )
            handle = await env.client.start_workflow(
                MainFuzzingWorkflow.run,
                payload,
                id=f"test-{uuid.uuid4()}",
                task_queue=task_queue,
            )
            await handle.result()
            stage = await handle.query("current_stage")
            assert stage == WorkflowStage.COMPLETED.value


# ── Phase 21: MAB + Evolution wiring ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_main_workflow_with_mab_enabled_completes_cleanly() -> None:
    """enable_mab=True must run pivot_strategy without breaking the loop.

    Because the simulator never grows coverage, plateau detection always
    yields ``False`` (first_cov == 0 short-circuit) — so no pivots fire.
    The test validates the wiring is exception-free, not that pivots fire.
    """
    async with await WorkflowEnvironment.start_time_skipping(
        data_converter=pydantic_data_converter,
    ) as env:
        task_queue = f"crashwise-test-{uuid.uuid4()}"
        async with Worker(
            env.client,
            task_queue=task_queue,
            workflows=[MainFuzzingWorkflow],
            activities=ALL_ACTIVITIES,
        ):
            payload = FuzzingInput(
                target_repo="https://github.com/example/target",  # type: ignore[arg-type]
                fuzzer_type=FuzzerType.LIBFUZZER,
                timeout_seconds=10,
                max_iterations=2,
                enable_mab=True,
            )
            handle = await env.client.start_workflow(
                MainFuzzingWorkflow.run,
                payload,
                id=f"test-mab-{uuid.uuid4()}",
                task_queue=task_queue,
            )
            result = await handle.result()
            stage = await handle.query("current_stage")
            pivots = await handle.query("pivot_count")
            assert stage == WorkflowStage.COMPLETED.value
            assert isinstance(pivots, int)
            assert result.crash_found is False
