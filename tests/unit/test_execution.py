# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the Phase-5 execution infrastructure.

Docker and QEMU managers are mocked at the subprocess boundary so these
tests run without root or KVM.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from crashwise.core.models import ExecutionBackend, FuzzJob
from crashwise.execution.docker_manager import DockerManager
from crashwise.execution.monitor import (
    DockerHealthChecker,
    HealthSnapshot,
    QEMUHealthChecker,
    ResourceMonitor,
)
from crashwise.execution.qemu_manager import QEMUManager


# ── Fixtures ───────────────────────────────────────────────────────────────
@pytest.fixture
def sample_job(tmp_path: Path) -> FuzzJob:
    harness = tmp_path / "harness.out"
    harness.write_text("fake binary")
    return FuzzJob(
        job_id="test-job-001",
        backend=ExecutionBackend.DOCKER,
        harness_path=harness,
        corpus_dir=tmp_path / "corpus",
        output_dir=tmp_path / "out",
        timeout_seconds=60,
        cpu_limit=1.0,
        memory_limit_mb=512,
    )


# ── DockerManager tests ──────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_docker_manager_start_success(sample_job: FuzzJob) -> None:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        # First call: docker images (returns empty → needs pull).
        # Second call: docker pull.
        # Third call: docker run (returns container ID).
        mock_exec.side_effect = [
            _fake_proc(stdout=b""),  # images check
            _fake_proc(stdout=b"", returncode=0),  # pull
            _fake_proc(stdout=b"abc123\n"),  # run
        ]

        mgr = DockerManager()
        cid = await mgr.start(sample_job)
        assert cid == "abc123"
        assert mgr._containers["test-job-001"] == "abc123"


@pytest.mark.asyncio
async def test_docker_manager_stop(sample_job: FuzzJob) -> None:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.side_effect = [
            _fake_proc(stdout=b""),
            _fake_proc(stdout=b"", returncode=0),
            _fake_proc(stdout=b"abc123\n"),
            _fake_proc(stdout=b"", returncode=0),  # stop
        ]

        mgr = DockerManager()
        await mgr.start(sample_job)
        await mgr.stop("test-job-001")
        assert "test-job-001" not in mgr._containers


@pytest.mark.asyncio
async def test_docker_manager_is_alive_true(sample_job: FuzzJob) -> None:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.side_effect = [
            _fake_proc(stdout=b""),
            _fake_proc(stdout=b"", returncode=0),
            _fake_proc(stdout=b"abc123\n"),
            _fake_proc(stdout=b"true\n"),  # inspect
        ]

        mgr = DockerManager()
        await mgr.start(sample_job)
        alive = await mgr.is_alive("test-job-001")
        assert alive is True


@pytest.mark.asyncio
async def test_docker_manager_logs(sample_job: FuzzJob) -> None:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.side_effect = [
            _fake_proc(stdout=b""),
            _fake_proc(stdout=b"", returncode=0),
            _fake_proc(stdout=b"abc123\n"),
            _fake_proc(stdout=b"fuzzing output line\n"),  # logs
        ]

        mgr = DockerManager()
        await mgr.start(sample_job)
        logs = await mgr.logs("test-job-001")
        assert "fuzzing output line" in logs


# ── QEMUManager tests ────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_qemu_manager_start_missing_kernel(sample_job: FuzzJob) -> None:
    mgr = QEMUManager()
    job = sample_job.model_copy(update={"backend": ExecutionBackend.QEMU})
    with pytest.raises(FileNotFoundError):
        await mgr.start(job)


@pytest.mark.asyncio
async def test_qemu_manager_is_alive(tmp_path: Path) -> None:
    mgr = QEMUManager()
    fake_proc = MagicMock()
    fake_proc.returncode = None
    fake_proc.pid = 1234
    mgr._processes["test-qemu"] = fake_proc
    assert await mgr.is_alive("test-qemu") is True

    fake_proc.returncode = 0
    assert await mgr.is_alive("test-qemu") is False


@pytest.mark.asyncio
async def test_qemu_manager_stop(tmp_path: Path) -> None:
    mgr = QEMUManager()
    fake_proc = MagicMock()
    fake_proc.pid = 1234
    fake_proc.terminate = MagicMock()
    fake_proc.kill = MagicMock()
    fake_proc.wait = AsyncMock(return_value=0)
    mgr._processes["test-qemu"] = fake_proc

    await mgr.stop("test-qemu")
    fake_proc.terminate.assert_called_once()
    assert "test-qemu" not in mgr._processes


# ── ResourceMonitor tests ────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_monitor_detects_hang() -> None:
    """If the check_fn returns identical output for > hang_timeout, fire hang_event."""
    hang_timeout = 0.2
    stall_interval = 0.1

    async def frozen_checker() -> HealthSnapshot:
        return HealthSnapshot(
            timestamp=asyncio.get_event_loop().time(),
            alive=True,
            last_output_line="same line",
        )

    monitor = ResourceMonitor(
        job_id="hang-test",
        check_fn=frozen_checker,
        hang_timeout=hang_timeout,
        stall_interval=stall_interval,
    )
    monitor.start()
    # Wait for hang detection.
    await asyncio.wait_for(monitor.hang_event.wait(), timeout=2.0)
    await monitor.stop()
    assert monitor.hang_event.is_set()


@pytest.mark.asyncio
async def test_monitor_detects_stall() -> None:
    """If exec_per_sec stays 0.0 across checks, fire stall_event."""

    async def stalled_checker() -> HealthSnapshot:
        return HealthSnapshot(
            timestamp=asyncio.get_event_loop().time(),
            alive=True,
            last_output_line="",
            exec_per_sec=0.0,
        )

    monitor = ResourceMonitor(
        job_id="stall-test",
        check_fn=stalled_checker,
        hang_timeout=10.0,  # Longer than stall detection.
        stall_interval=0.05,
    )
    monitor.start()
    await asyncio.wait_for(monitor.stall_event.wait(), timeout=2.0)
    await monitor.stop()
    assert monitor.stall_event.is_set()


@pytest.mark.asyncio
async def test_monitor_detects_oom() -> None:
    async def oom_checker() -> HealthSnapshot:
        return HealthSnapshot(
            timestamp=asyncio.get_event_loop().time(),
            alive=False,
            last_output_line="killed by oom-killer",
        )

    monitor = ResourceMonitor(
        job_id="oom-test",
        check_fn=oom_checker,
        hang_timeout=10.0,
        stall_interval=0.05,
    )
    monitor.start()
    await asyncio.wait_for(monitor.oom_event.wait(), timeout=2.0)
    await monitor.stop()
    assert monitor.oom_event.is_set()


@pytest.mark.asyncio
async def test_monitor_healthy_never_fires(tmp_path: Path) -> None:
    counter = 0

    async def healthy_checker() -> HealthSnapshot:
        nonlocal counter
        counter += 1
        return HealthSnapshot(
            timestamp=asyncio.get_event_loop().time(),
            alive=True,
            last_output_line=f"line {counter}",
            exec_per_sec=100.0 + counter,
        )

    monitor = ResourceMonitor(
        job_id="healthy-test",
        check_fn=healthy_checker,
        hang_timeout=0.5,
        stall_interval=0.1,
    )
    monitor.start()
    # Let it run for a few checks.
    await asyncio.sleep(0.35)
    await monitor.stop()
    assert not monitor.hang_event.is_set()
    assert not monitor.oom_event.is_set()
    assert not monitor.stall_event.is_set()


# ── HealthChecker adapter tests ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_docker_health_checker(sample_job: FuzzJob) -> None:
    mock_mgr = AsyncMock()
    mock_mgr.is_alive.return_value = True
    mock_mgr.stats.return_value = {
        "cpu_percent": "150.00%",
        "memory": "256MiB / 512MiB",
        "pids": "12",
    }
    mock_mgr.logs.return_value = "last log line\n"

    checker = DockerHealthChecker(mock_mgr, "test-job", sample_job.output_dir)
    snap = await checker()
    assert snap.alive is True
    assert snap.cpu_percent == "150.00%"
    assert snap.last_output_line == "last log line"


@pytest.mark.asyncio
async def test_qemu_health_checker(tmp_path: Path) -> None:
    serial = tmp_path / "serial.log"
    serial.write_text("booting...\nlast line\n")
    mock_mgr = AsyncMock()
    mock_mgr.is_alive.return_value = True

    checker = QEMUHealthChecker(mock_mgr, "test-qemu", serial)
    snap = await checker()
    assert snap.alive is True
    assert snap.last_output_line == "last line"


# ── Helpers ──────────────────────────────────────────────────────────────────
def _fake_proc(
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    returncode: int = 0,
) -> asyncio.subprocess.Process:
    """Build a mock asyncio Process."""
    proc = MagicMock(spec=asyncio.subprocess.Process)
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc
