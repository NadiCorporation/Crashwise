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

import pytest
from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from crashwise.core.models import (
    CrashSeverity,
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
