# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``synthesize_harness`` activity — runs autonomous LLM harness synthesis in a Temporal activity.

Decouples harness synthesis from workflow execution to preserve Temporal workflow
determinism and prevent WorkflowTaskTimedOut errors on long-running LLM calls.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from temporalio import activity
from temporalio.exceptions import ApplicationError

from crashwise.agents.harness_synth import synthesize_harness
from crashwise.core.logging import get_logger
from crashwise.core.models import (
    SynthesizeHarnessInput,
    SynthesizeHarnessOutput,
)

log = get_logger(__name__)

_HEARTBEAT_INTERVAL_SECONDS: Final[float] = 15.0


def _find_target_source_file(workspace_path: Path) -> Path | None:
    """Find the best C/C++ source file candidate in the workspace."""
    if not workspace_path.exists():
        return None

    # First pass: search for non-test, non-build C/C++ implementation files
    for ext in [".c", ".cpp", ".cc", ".cxx"]:
        candidates = list(workspace_path.rglob(f"*{ext}"))
        filtered = []
        for c in candidates:
            if any(k in str(c).lower() for k in ("test", "build", "example", "fuzz")):
                continue
            try:
                if "LLVMFuzzerTestOneInput" in c.read_text(encoding="utf-8", errors="ignore"):
                    continue
            except Exception:
                pass
            filtered.append(c)

        if filtered:
            return filtered[0]
        if candidates:
            # Fallback to any file with matching extension if all were filtered
            non_build = [c for c in candidates if "build" not in str(c).lower()]
            if non_build:
                return non_build[0]

    # Second pass: headers as last resort
    for ext in [".h", ".hpp"]:
        candidates = list(workspace_path.rglob(f"*{ext}"))
        filtered = [c for c in candidates if "build" not in str(c).lower()]
        if filtered:
            return filtered[0]

    return None


@activity.defn(name="synthesize_harness")
async def synthesize_harness_activity(
    payload: SynthesizeHarnessInput,
) -> SynthesizeHarnessOutput:
    """Synthesize an autonomous fuzzing harness for a workspace.

    Runs within a dedicated activity with periodic heartbeats to safely
    accommodate multi-turn LLM reasoning, Clang compilation, and GDB checks.
    """
    try:
        info = activity.info()
        workflow_id = info.workflow_id or "anonymous"
        attempt = info.attempt
    except Exception:
        workflow_id = "standalone"
        attempt = 1

    started_at = datetime.now(tz=UTC)

    log.info(
        "synthesize_harness.start",
        workflow_id=workflow_id,
        attempt=attempt,
        workspace=str(payload.workspace_path),
        fuzzer_type=payload.fuzzer_type,
        max_retries=payload.max_retries,
    )

    workspace = Path(payload.workspace_path)
    source_file = (
        Path(payload.source_file_path)
        if payload.source_file_path and Path(payload.source_file_path).exists()
        else _find_target_source_file(workspace)
    )

    if source_file is None or not source_file.exists():
        err_msg = f"No C/C++ source file found in workspace {workspace}"
        log.warning("synthesize_harness.no_source_file", workspace=str(workspace))
        return SynthesizeHarnessOutput(
            success=False,
            error_message=err_msg,
        )

    harness_workdir = workspace / "harness"
    harness_workdir.mkdir(parents=True, exist_ok=True)

    heartbeat_task: asyncio.Task[None] | None = None

    async def _heartbeat_loop() -> None:
        while True:
            await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
            with contextlib.suppress(Exception):
                activity.heartbeat(f"synthesizing harness for {source_file.name}")

    try:
        heartbeat_task = asyncio.create_task(_heartbeat_loop())

        result = await synthesize_harness(
            source_path=source_file,
            workdir=harness_workdir,
            max_retries=payload.max_retries,
            engine=payload.fuzzer_type,
        )

        log.info(
            "synthesize_harness.complete",
            workflow_id=workflow_id,
            success=result.success,
            harness_path=str(result.harness_path) if result.harness_path else None,
            binary_path=str(result.binary_path) if result.binary_path else None,
            retry_count=result.retry_count,
        )

        return SynthesizeHarnessOutput(
            success=result.success,
            harness_path=result.harness_path,
            binary_path=result.binary_path,
            source_file_used=source_file,
            retry_count=result.retry_count,
            error_message=result.last_stderr if not result.success else "",
        )

    except Exception as exc:
        log.error("synthesize_harness.error", error=str(exc))
        return SynthesizeHarnessOutput(
            success=False,
            source_file_used=source_file,
            error_message=str(exc),
        )
    finally:
        if heartbeat_task is not None:
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task


__all__ = ["synthesize_harness_activity"]
