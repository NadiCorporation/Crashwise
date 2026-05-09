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
from crashwise.execution.docker_manager import (
    DockerManager,
    parse_afl_fuzzer_stats,
    parse_libfuzzer_log_tail,
)
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
        # First call: docker rm -f (B13 pre-flight; no-op on first run).
        # Second call: docker images (returns empty → needs pull).
        # Third call: docker pull.
        # Fourth call: docker run (returns container ID).
        mock_exec.side_effect = [
            _fake_proc(stdout=b"", returncode=1),  # pre-flight rm -f (no such container)
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
    """Phase 21 §1.3: stop() retains the container so docker cp can run.

    Removal happens in cleanup(); stop alone must keep tracking the id.
    """
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.side_effect = [
            _fake_proc(stdout=b"", returncode=1),  # pre-flight rm -f
            _fake_proc(stdout=b""),
            _fake_proc(stdout=b"", returncode=0),
            _fake_proc(stdout=b"abc123\n"),
            _fake_proc(stdout=b"", returncode=0),  # stop
            _fake_proc(stdout=b"", returncode=0),  # cleanup -> docker rm -f
        ]

        mgr = DockerManager()
        await mgr.start(sample_job)
        await mgr.stop("test-job-001")
        # Container is stopped but NOT removed — corpus still recoverable.
        assert "test-job-001" in mgr._containers
        await mgr.cleanup("test-job-001")
        assert "test-job-001" not in mgr._containers


@pytest.mark.asyncio
async def test_docker_manager_is_alive_true(sample_job: FuzzJob) -> None:
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.side_effect = [
            _fake_proc(stdout=b"", returncode=1),  # pre-flight rm -f
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
            _fake_proc(stdout=b"", returncode=1),  # pre-flight rm -f
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


# ── Phase 21: --rm race fix + parser tests ───────────────────────────────────


@pytest.mark.asyncio
async def test_docker_run_does_not_use_rm_flag(sample_job: FuzzJob) -> None:
    """Phase 21 §1.3: --rm must be absent so docker cp can run after stop."""
    captured: list[list[str]] = []

    def _record(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(list(args))
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        # First call (images query) returns empty so we proceed to pull+run.
        if args[:2] == ("docker", "images"):
            proc.communicate = AsyncMock(return_value=(b"", b""))
        elif args[:2] == ("docker", "pull"):
            proc.communicate = AsyncMock(return_value=(b"", b""))
        else:
            proc.communicate = AsyncMock(return_value=(b"abc123\n", b""))
        return proc

    with patch("asyncio.create_subprocess_exec", side_effect=_record):
        mgr = DockerManager()
        await mgr.start(sample_job)

    # Find the docker run invocation among the calls.
    run_cmds = [c for c in captured if len(c) > 1 and c[1] == "run"]
    assert run_cmds, "docker run was not invoked"
    assert "--rm" not in run_cmds[0], (
        f"--rm flag must NOT be present (Phase 21 §1.3 fix). Got: {run_cmds[0]}"
    )


@pytest.mark.asyncio
async def test_docker_cleanup_invokes_rm_force(sample_job: FuzzJob) -> None:
    captured_argv: list[tuple[str, ...]] = []

    def _record(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured_argv.append(args)
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        if args[:2] == ("docker", "images"):
            proc.communicate = AsyncMock(return_value=(b"", b""))
        elif args[:2] == ("docker", "pull"):
            proc.communicate = AsyncMock(return_value=(b"", b""))
        else:
            proc.communicate = AsyncMock(return_value=(b"abc123\n", b""))
        return proc

    with patch("asyncio.create_subprocess_exec", side_effect=_record):
        mgr = DockerManager()
        await mgr.start(sample_job)
        await mgr.cleanup("test-job-001")

    rm_calls = [c for c in captured_argv if len(c) > 1 and c[1] == "rm"]
    assert rm_calls, "docker rm was not invoked"
    assert "-f" in rm_calls[0]
    assert "test-job-001" not in mgr._containers


@pytest.mark.asyncio
async def test_docker_corpus_preservation_order(sample_job: FuzzJob, tmp_path: Path) -> None:
    """The harvest sequence must be: stop → cp → cleanup. Never rm before cp."""
    order: list[str] = []

    def _record(*args, **kwargs):  # type: ignore[no-untyped-def]
        op = args[1] if len(args) > 1 else "?"
        order.append(op)
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.returncode = 0
        if op == "images":
            proc.communicate = AsyncMock(return_value=(b"", b""))
        elif op == "pull":
            proc.communicate = AsyncMock(return_value=(b"", b""))
        elif op == "run":
            proc.communicate = AsyncMock(return_value=(b"abc123\n", b""))
        elif op == "cp":
            proc.communicate = AsyncMock(return_value=(b"", b""))
        else:
            proc.communicate = AsyncMock(return_value=(b"", b""))
        return proc

    with patch("asyncio.create_subprocess_exec", side_effect=_record):
        mgr = DockerManager()
        await mgr.start(sample_job)
        await mgr.stop("test-job-001")
        await mgr.preserve_corpus("test-job-001", tmp_path / "preserved")
        await mgr.cleanup("test-job-001")

    # B13: ``start`` now invokes a pre-flight ``docker rm -f`` against the
    # name to clear any stale container before launching. We must look at
    # only the lifecycle events that happen *after* ``run``.
    try:
        run_idx = order.index("run")
    except ValueError:
        run_idx = 0
    post_run = order[run_idx + 1:]
    lifecycle = [op for op in post_run if op in {"stop", "cp", "rm"}]
    # First a stop, at least one cp, then exactly one rm.
    assert lifecycle[0] == "stop"
    assert "cp" in lifecycle
    assert lifecycle[-1] == "rm"
    # Critical: cp must precede rm (the §1.3 race condition fix).
    cp_idx = lifecycle.index("cp")
    rm_idx = lifecycle.index("rm")
    assert cp_idx < rm_idx, "docker cp must run before docker rm"


def test_parse_libfuzzer_log_tail_basic() -> None:
    log = (
        "INFO: Seed: 1234\n"
        "#1\tINITED cov: 5 ft: 8 corp: 1/1b lim: 4 exec/s: 0 rss: 30Mb\n"
        "#10000\tDONE  cov: 42 ft: 88 corp: 12/345b lim: 4096 exec/s: 2500 rss: 50Mb\n"
    )
    parsed = parse_libfuzzer_log_tail(log)
    assert parsed["coverage"] == 42.0
    assert parsed["features"] == 88.0
    assert parsed["exec_per_sec"] == 2500.0
    assert parsed["executions"] == 10000.0


def test_parse_libfuzzer_log_tail_no_match() -> None:
    assert parse_libfuzzer_log_tail("nothing here\n") == {}
    assert parse_libfuzzer_log_tail("") == {}


def test_parse_afl_fuzzer_stats_basic() -> None:
    text = (
        "execs_done        : 123456\n"
        "execs_per_sec     : 4321.5\n"
        "edges_found       : 87\n"
        "stability         : 99.5%\n"
        "saved_crashes     : 2\n"
    )
    parsed = parse_afl_fuzzer_stats(text)
    assert parsed["executions"] == 123456.0
    assert parsed["exec_per_sec"] == 4321.5
    assert parsed["coverage"] == 87.0
    assert parsed["stability"] == 99.5
    assert parsed["crashes"] == 2.0


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
