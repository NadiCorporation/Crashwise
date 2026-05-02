# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Docker orchestrator for fuzzing workers.

Manages the lifecycle of AFL++/libFuzzer containers:
    pull image → create volume mounts → start with resource limits →
    stream logs → stop on signal / timeout.

Requires the Docker daemon to be running and the user to be in the
``docker`` group (or root).
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

from crashwise.core.logging import get_logger
from crashwise.core.models import FuzzJob

log = get_logger(__name__)

# Well-known fuzzer images.
_AFL_IMAGE = "aflplusplus/aflplusplus:latest"
_LIBFUZZER_IMAGE = "gcr.io/oss-fuzz-base/libfuzzer-runner:latest"


def _resolve_image(harness_path: Path) -> str:
    """Pick a base image based on the harness binary type."""
    # Heuristic: if the harness filename contains "afl", use AFL++.
    name = harness_path.name.lower()
    if "afl" in name:
        return _AFL_IMAGE
    return _LIBFUZZER_IMAGE


class DockerManager:
    """Async Docker container manager for fuzzing jobs.

    Uses the ``docker`` CLI via subprocess rather than the heavy Python SDK
    to keep dependencies minimal and startup fast.
    """

    def __init__(self) -> None:
        self._containers: dict[str, str] = {}  # job_id → container_id

    # ── Lifecycle ────────────────────────────────────────────────────────────
    async def start(self, job: FuzzJob) -> str:
        """Start a fuzzing container and return the container ID."""
        if not await self._docker_available():
            raise RuntimeError("docker daemon not reachable")

        image = _resolve_image(job.harness_path)
        await self._ensure_image(image)

        # Prepare host paths.
        job.output_dir.mkdir(parents=True, exist_ok=True)
        job.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Build docker run command.
        cmd: list[str] = [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            f"crashwise-{job.job_id}",
            "--cpus",
            str(job.cpu_limit),
            "--memory",
            f"{job.memory_limit_mb}m",
            "--pids-limit",
            "1024",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "SYS_PTRACE",  # Required for AFL forkserver.
            "-v",
            f"{job.harness_path.parent}:/work:ro",
            "-v",
            f"{job.corpus_dir}:/corpus:rw",
            "-v",
            f"{job.output_dir}:/out:rw",
        ]
        for key, val in job.env_vars.items():
            cmd.extend(["-e", f"{key}={val}"])

        # Entrypoint: run the harness.
        harness_in_container = f"/work/{job.harness_path.name}"
        if "afl" in image.lower():
            cmd.extend(
                [
                    image,
                    "afl-fuzz",
                    "-i",
                    "/corpus",
                    "-o",
                    "/out",
                    "--",
                    harness_in_container,
                ]
            )
        else:
            cmd.extend(
                [
                    image,
                    harness_in_container,
                    "/corpus",
                    "-max_total_time=0",
                    "-max_len=4096",
                ]
            )

        log.info(
            "docker.start",
            job_id=job.job_id,
            image=image,
            harness=harness_in_container,
            cpus=job.cpu_limit,
            memory_mb=job.memory_limit_mb,
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"docker run failed: {stderr.decode('utf-8', errors='replace')}")

        container_id = stdout.decode("utf-8", errors="replace").strip()
        self._containers[job.job_id] = container_id
        log.info("docker.started", job_id=job.job_id, container_id=container_id[:12])
        return container_id

    async def stop(self, job_id: str, *, timeout: float = 30.0) -> None:
        """Gracefully stop a container."""
        container_id = self._containers.pop(job_id, None)
        if not container_id:
            log.warning("docker.stop.unknown_job", job_id=job_id)
            return

        log.info("docker.stop", job_id=job_id, container_id=container_id[:12])
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "stop",
            "-t",
            str(int(timeout)),
            container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            log.warning(
                "docker.stop_error",
                job_id=job_id,
                error=stderr.decode("utf-8", errors="replace"),
            )
            # Force kill.
            await asyncio.create_subprocess_exec(
                "docker",
                "kill",
                container_id,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

    async def logs(self, job_id: str, *, tail: int = 100) -> str:
        """Fetch the last N lines of container stdout+stderr."""
        container_id = self._containers.get(job_id)
        if not container_id:
            return ""
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "logs",
            "--tail",
            str(tail),
            container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode("utf-8", errors="replace")

    async def is_alive(self, job_id: str) -> bool:
        """Check whether the container is still running."""
        container_id = self._containers.get(job_id)
        if not container_id:
            return False
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode("utf-8", errors="replace").strip() == "true"

    async def stats(self, job_id: str) -> dict[str, Any]:
        """Return container CPU / memory stats (best-effort)."""
        container_id = self._containers.get(job_id)
        if not container_id:
            return {}
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}",
            container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        parts = stdout.decode("utf-8", errors="replace").strip().split("|")
        return {
            "cpu_percent": parts[0] if len(parts) > 0 else "N/A",
            "memory": parts[1] if len(parts) > 1 else "N/A",
            "pids": parts[2] if len(parts) > 2 else "N/A",
        }

    # ── Internals ────────────────────────────────────────────────────────────
    async def _docker_available(self) -> bool:
        return shutil.which("docker") is not None

    async def _ensure_image(self, image: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "images",
            "-q",
            image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if stdout.decode("utf-8", errors="replace").strip():
            return  # Already present.
        log.info("docker.pull", image=image)
        pull_proc = await asyncio.create_subprocess_exec(
            "docker",
            "pull",
            image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await pull_proc.communicate()
        if pull_proc.returncode != 0:
            raise RuntimeError(
                f"docker pull failed for {image}: {stderr.decode('utf-8', errors='replace')}"
            )


__all__ = ["DockerManager"]
