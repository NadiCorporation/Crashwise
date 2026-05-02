# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``setup_target`` activity — clones the target repository and stages it.

Phase 1 ships a deterministic clone stub. Phase 2 extends it: when the
caller asks for autonomous harness generation (``synthesize_harness=True``)
we drive the LangGraph harness-synthesis agent on the supplied source file
and return its compiled binary path through ``SetupTargetOutput``.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import SetupTargetInput, SetupTargetOutput

log = get_logger(__name__)


@activity.defn(name="setup_target")
async def setup_target(payload: SetupTargetInput) -> SetupTargetOutput:
    """Prepare a clean working directory for the target project.

    The activity is idempotent within a single workflow attempt: re-running
    against the same workdir wipes and recreates it.
    """
    info = activity.info()
    workflow_id = info.workflow_id or "anonymous"
    workdir_root = Path("/tmp/crashwise") / workflow_id
    workdir = workdir_root / "target"

    log.info(
        "setup_target.start",
        workflow_id=workflow_id,
        attempt=info.attempt,
        target_repo=str(payload.target_repo),
        target_branch=payload.target_branch,
        sanitizers=payload.sanitizers,
        synthesize_harness=payload.synthesize_harness,
    )

    if workdir.exists():
        log.debug("setup_target.cleanup_existing", workdir=str(workdir))
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)

    seed = f"{payload.target_repo}|{payload.target_branch or 'HEAD'}".encode()
    fake_sha = hashlib.sha1(seed, usedforsecurity=False).hexdigest()

    marker = workdir / ".crashwise-setup"
    marker.write_text(
        f"crashwise-stub\nrepo={payload.target_repo}\nbranch={payload.target_branch}\n"
        f"sanitizers={payload.sanitizers}\nat={datetime.now(tz=UTC).isoformat()}\n",
        encoding="utf-8",
    )

    harness_path: Path | None = None
    if payload.synthesize_harness and payload.target_source_path:
        harness_path = await _run_harness_synthesis(
            workdir=workdir,
            target_source_path=payload.target_source_path,
            max_retries=payload.max_synth_retries,
            workflow_id=workflow_id,
        )

    output = SetupTargetOutput(
        workdir=workdir,
        commit_sha=fake_sha,
        harness_path=harness_path,
    )

    log.info(
        "setup_target.complete",
        workflow_id=workflow_id,
        workdir=str(output.workdir),
        commit_sha=output.commit_sha,
        harness_path=str(output.harness_path) if output.harness_path else None,
    )
    return output


async def _run_harness_synthesis(
    *,
    workdir: Path,
    target_source_path: str,
    max_retries: int,
    workflow_id: str,
) -> Path | None:
    """Drive the Phase-2 harness agent and return the compiled-binary path.

    Imported lazily so the workflow sandbox doesn't pull in LangGraph at
    workflow validation time.
    """
    # Lazy import: avoids loading langgraph/langchain in workflow contexts.
    from crashwise.agents.harness_synth import synthesize_harness

    source = Path(target_source_path)
    if not source.is_absolute():
        source = (workdir / target_source_path).resolve()

    if not source.exists():
        log.warning(
            "setup_target.synth.source_missing",
            workflow_id=workflow_id,
            target_source_path=target_source_path,
        )
        return None

    synth_workdir = workdir / "harness"
    result = await synthesize_harness(
        source_path=source,
        workdir=synth_workdir,
        max_retries=max_retries,
    )

    log.info(
        "setup_target.synth.done",
        workflow_id=workflow_id,
        success=result.success,
        simplified=result.simplified,
        retries=result.retry_count,
        binary=str(result.binary_path) if result.binary_path else None,
    )
    # Return the binary if compilation succeeded; otherwise return the
    # source path so downstream activities can still try (or report).
    return result.binary_path or result.harness_path
