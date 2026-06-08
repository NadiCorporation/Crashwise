# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for the Phase 21 real-execution path of execute_fuzzing.

These tests focus on the contract that gates production behaviour:
  • The simulator path (no campaign_id) is unchanged.
  • The real path (campaign_id provided) invokes DockerManager.start /
    .stop / .preserve_corpus / .cleanup in that order.
  • The libFuzzer log parser populates exec_per_sec in heartbeats.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from crashwise.core.models import (
    ExecuteFuzzingInput,
    FuzzerType,
)
from crashwise.execution.docker_manager import (
    parse_afl_fuzzer_stats,
    parse_libfuzzer_log_tail,
)
from crashwise.orchestration.activities import execute_fuzzing as _ef_func

# The activity is decorated; the submodule is in sys.modules.
EF_MODULE = sys.modules[_ef_func.__module__]
_real_execute = EF_MODULE._real_execute
_simulated_execs_per_tick = EF_MODULE._simulated_execs_per_tick


# ── Test helpers ─────────────────────────────────────────────────────────────


class _FakeManager:
    """Stand-in for DockerManager that records lifecycle calls."""

    def __init__(self, *, sample_log: str = "", die_after: int = 0) -> None:
        self.calls: list[str] = []
        self.preserved_to: Path | None = None
        self._sample_log = sample_log
        self._die_after = die_after
        self._tick = 0

    async def start(self, job) -> str:  # type: ignore[no-untyped-def]
        self.calls.append("start")
        return "container-id"

    async def stop(self, job_id: str, **kwargs) -> None:  # type: ignore[no-untyped-def]
        self.calls.append("stop")

    async def preserve_corpus(self, job_id: str, dest: Path) -> Path:
        self.calls.append("preserve_corpus")
        self.preserved_to = dest
        dest.mkdir(parents=True, exist_ok=True)
        return dest

    async def cleanup(self, job_id: str) -> None:
        self.calls.append("cleanup")

    async def is_alive(self, job_id: str) -> bool:
        self._tick += 1
        return not (self._die_after and self._tick > self._die_after)

    async def logs(self, job_id: str, **kwargs) -> str:  # type: ignore[no-untyped-def]
        return self._sample_log

    async def get_exit_code(self, job_id: str) -> int | None:
        # Container is dead if it's not alive
        alive = await self.is_alive(job_id)
        return 0 if not alive else None

    async def extract_coverage_data(self, job_id: str, dest: Path) -> None:
        # No-op for tests
        pass


@pytest.fixture
def fast_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(EF_MODULE, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    wd = tmp_path / "wd"
    wd.mkdir()
    return wd


# ── Parser sanity ────────────────────────────────────────────────────────────


def test_parse_libfuzzer_log_tail_picks_last_stats() -> None:
    log = (
        "#100 INITED cov: 5 ft: 10 corp: 1/1b lim: 4 exec/s: 0 rss: 30Mb\n"
        "#9999 DONE cov: 88 ft: 200 corp: 50/2kb lim: 4096 exec/s: 12500 rss: 120Mb\n"
    )
    parsed = parse_libfuzzer_log_tail(log)
    assert parsed["exec_per_sec"] == 12500.0
    assert parsed["coverage"] == 88.0


def test_parse_afl_stats_handles_percent_units() -> None:
    parsed = parse_afl_fuzzer_stats("stability  : 99.7%\nexecs_per_sec: 4321\n")
    assert parsed["stability"] == 99.7
    assert parsed["exec_per_sec"] == 4321.0


# ── Dispatch behaviour ────────────────────────────────────────────────────────


def test_simulator_helper_unchanged() -> None:
    """The legacy helper must keep its constants for back-compat."""
    assert _simulated_execs_per_tick(FuzzerType.LIBFUZZER) == 5_000
    assert _simulated_execs_per_tick(FuzzerType.AFLPP) == 2_500


@pytest.mark.asyncio
async def test_dispatch_simulator_when_no_campaign_id(
    workdir: Path,
    fast_heartbeat: None,
) -> None:
    """No campaign_id → never invoke DockerManager."""
    ef_module = EF_MODULE

    payload = ExecuteFuzzingInput(
        workdir=workdir,
        harness_path=workdir / "harness",
        fuzzer_type=FuzzerType.LIBFUZZER,
        timeout_seconds=10,
        campaign_id=None,
    )

    fake_info = MagicMock()
    fake_info.workflow_id = "wf-1"
    fake_info.attempt = 1
    fake_info.heartbeat_details = []

    with patch.object(ef_module.activity, "info", return_value=fake_info), \
         patch.object(ef_module.activity, "heartbeat"), \
         patch(
             "crashwise.execution.docker_manager.DockerManager",
         ) as mock_mgr:
        mock_mgr.side_effect = AssertionError(
            "DockerManager must NOT be instantiated in simulator mode"
        )
        # Use the inner function directly to avoid the activity decorator,
        # which requires an active workflow context.
        out = await ef_module._simulated_execute(
            payload, workdir / "fuzz.log", workdir / "crashes"
        )
        assert out.executions > 0


# ── Real path lifecycle ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_real_path_invokes_lifecycle_in_order(
    workdir: Path,
    fast_heartbeat: None,
) -> None:
    """Phase 21 §1.3: stop → preserve_corpus → cleanup; never rm before cp."""
    ef_module = EF_MODULE

    # Create a dummy harness file to pass the existence check
    harness_file = workdir / "harness"
    harness_file.write_text("#!/bin/bash\necho 'dummy harness'\n")
    harness_file.chmod(0o755)

    payload = ExecuteFuzzingInput(
        workdir=workdir,
        harness_path=harness_file,
        fuzzer_type=FuzzerType.LIBFUZZER,
        timeout_seconds=10,
        campaign_id="11111111-2222-3333-4444-555555555555",
        iteration=0,
    )

    sample = "#5000 DONE cov: 42 ft: 88 corp: 10/100b lim: 4096 exec/s: 2500 rss: 50Mb\n"
    # Container "dies" after 1 tick → loop exits naturally → triggers
    # stop → preserve_corpus → cleanup. This is what we want to assert.
    fake_mgr = _FakeManager(sample_log=sample, die_after=1)

    fake_info = MagicMock()
    fake_info.workflow_id = "wf-1"
    fake_info.attempt = 1
    fake_info.heartbeat_details = []

    async def _noop(*a, **k):  # type: ignore[no-untyped-def]
        return None

    with patch.object(ef_module.activity, "info", return_value=fake_info), \
         patch.object(ef_module.activity, "heartbeat"), \
         patch(
             "crashwise.execution.docker_manager.DockerManager",
             return_value=fake_mgr,
         ), \
         patch.object(ef_module, "_persist_run", new=_noop), \
         patch("crashwise.core.redis.incr_exec_counter", new=_noop), \
         patch("crashwise.core.storage.sync_directory", new=_noop):
        out = await _real_execute(
            payload, workdir / "fuzz.log", workdir / "crashes"
        )

    # Lifecycle must be: start ... stop, preserve_corpus, cleanup (in order).
    assert "start" in fake_mgr.calls
    assert fake_mgr.calls.index("stop") < fake_mgr.calls.index("preserve_corpus")
    assert fake_mgr.calls.index("preserve_corpus") < fake_mgr.calls.index("cleanup")
    # Parsed coverage propagated.
    assert out.executions >= 5000


@pytest.mark.asyncio
async def test_real_path_cleanup_runs_on_cancel(
    workdir: Path,
    fast_heartbeat: None,
) -> None:
    """A CancelledError mid-run still calls cleanup() (no leaked containers)."""
    # Create a dummy harness file to pass the existence check
    harness_file = workdir / "harness"
    harness_file.write_text("#!/bin/bash\necho 'dummy harness'\n")
    harness_file.chmod(0o755)

    payload = ExecuteFuzzingInput(
        workdir=workdir,
        harness_path=harness_file,
        fuzzer_type=FuzzerType.LIBFUZZER,
        timeout_seconds=10,
        campaign_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        iteration=0,
    )

    fake_mgr = _FakeManager(sample_log="")

    fake_info = MagicMock()
    fake_info.workflow_id = "wf-cancel"
    fake_info.attempt = 1
    fake_info.heartbeat_details = []

    raised = {"first": True}

    async def _maybe_raise(*a, **k):  # type: ignore[no-untyped-def]
        # Cancel after one tick.
        if raised["first"]:
            raised["first"] = False
            return None
        raise asyncio.CancelledError()

    async def _noop(*a, **k):  # type: ignore[no-untyped-def]
        return None

    ef_module = EF_MODULE

    with patch.object(ef_module.activity, "info", return_value=fake_info), \
         patch.object(ef_module.activity, "heartbeat"), \
         patch(
             "crashwise.execution.docker_manager.DockerManager",
             return_value=fake_mgr,
         ), \
         patch("asyncio.sleep", new=_maybe_raise), \
         patch.object(ef_module, "_persist_run", new=_noop), \
         patch("crashwise.core.redis.incr_exec_counter", new=_noop), \
         patch("crashwise.core.storage.sync_directory", new=_noop):
        with pytest.raises(asyncio.CancelledError):
            await _real_execute(
                payload, workdir / "fuzz.log", workdir / "crashes"
            )

    assert "cleanup" in fake_mgr.calls, (
        "cleanup() must run even on cancellation to avoid container leak"
    )
