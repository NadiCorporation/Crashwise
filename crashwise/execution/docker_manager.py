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
import contextlib
import re
import shutil
from pathlib import Path
from typing import Any

from crashwise.core.logging import get_logger
from crashwise.core.models import FuzzJob

log = get_logger(__name__)

# Well-known fuzzer images.
_AFL_IMAGE = "aflplusplus/aflplusplus:latest"
_LIBFUZZER_IMAGE = "gcr.io/oss-fuzz-base/libfuzzer-runner:latest"


# ── libFuzzer / AFL stdout parser (Phase 21) ────────────────────────────────

# libFuzzer stats line:
#   #12345  DONE  cov: 42 ft: 88 corp: 12/345b lim: 4096 exec/s: 2500 rss: 12Mb
_LIBFUZZER_STATS_RE = re.compile(
    r"#(?P<execs>\d+).*?cov:\s+(?P<cov>\d+).*?ft:\s+(?P<ft>\d+).*?exec/s:\s+(?P<rate>[\d.]+k?)"
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Remove ANSI colour / cursor escape sequences from ``text``."""
    return _ANSI_ESCAPE_RE.sub("", text)


def _parse_rate(raw: str) -> float:
    """Parse libFuzzer's ``exec/s`` field, which may be int, float, or
    ``Nk`` for thousands.
    """
    raw = raw.strip()
    if not raw:
        return 0.0
    if raw.endswith("k"):
        try:
            return float(raw[:-1]) * 1000.0
        except ValueError:
            return 0.0
    try:
        return float(raw)
    except ValueError:
        return 0.0


def parse_libfuzzer_log_tail(text: str) -> dict[str, float]:
    """Parse the most recent libFuzzer stats line in ``text``.

    Returns a dict with keys ``executions``, ``coverage``, ``features`` and
    ``exec_per_sec``. Returns ``{}`` when no stats line is present.
    """
    if not text:
        return {}
    cleaned = _strip_ansi(text)
    for line in reversed(cleaned.splitlines()):
        m = _LIBFUZZER_STATS_RE.search(line)
        if m:
            return {
                "executions": float(m["execs"]),
                "coverage": float(m["cov"]),
                "features": float(m["ft"]),
                "exec_per_sec": _parse_rate(m["rate"]),
            }
    return {}


def parse_afl_fuzzer_stats(stats_text: str) -> dict[str, float]:
    """Parse AFL++ ``fuzzer_stats`` ``key : value`` text.

    Returns a dict with the keys CrashWise consumes: ``executions``,
    ``exec_per_sec``, ``coverage`` (edges_found), ``stability``, ``crashes``.
    Missing fields are simply absent from the result (no exceptions).
    """
    out: dict[str, float] = {}
    for line in _strip_ansi(stats_text).splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        key = k.strip()
        val = v.strip().split()[0] if v.strip() else ""
        try:
            num = float(val.rstrip("%").replace(",", ""))
        except ValueError:
            continue
        if key == "execs_done":
            out["executions"] = num
        elif key == "execs_per_sec":
            out["exec_per_sec"] = num
        elif key == "edges_found":
            out["coverage"] = num
        elif key == "stability":
            out["stability"] = num
        elif key in {"saved_crashes", "unique_crashes"}:
            out["crashes"] = max(out.get("crashes", 0.0), num)
    return out


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
        """Start a fuzzing container and return the container ID.

        Hardened by the Vanguard audit (B3):

        * ``--network none``   — fuzzer cannot reach the host or the public
          internet.  Untrusted harnesses + attacker-controlled corpora must
          never have egress.
        * ``--read-only``      — container rootfs is immutable.  All writable
          surfaces are explicit (``/tmp``, ``/dev/shm``, ``/corpus``, ``/out``).
        * ``--tmpfs`` mounts   — give the fuzzer a fast, size-capped scratch
          area without giving it the rootfs.
        * ``SYS_PTRACE``       — granted ONLY to AFL forkserver containers;
          libFuzzer doesn't need it.
        * Pre-flight ``docker rm -f``  — kills any stale container with the
          same name so an activity retry never collides with a zombie from
          a previous worker crash (B13).
        """
        if not await self._docker_available():
            raise RuntimeError("docker daemon not reachable")

        image = _resolve_image(job.harness_path)
        await self._ensure_image(image)

        # Prepare host paths.
        job.output_dir.mkdir(parents=True, exist_ok=True)
        job.corpus_dir.mkdir(parents=True, exist_ok=True)

        # B13: defensively remove any stale container with the same name
        # before starting (Temporal activity retries reuse job_id; a worker
        # crash between start() and cleanup() leaves the prior container
        # around and ``docker run`` would otherwise fail with "name in use").
        container_name = f"crashwise-{job.job_id}"
        await self._force_remove_by_name(container_name)

        is_afl = "afl" in image.lower()

        # Build docker run command.
        # Phase 21 §1.3 fix: ``--rm`` is REMOVED. The container must outlive
        # ``docker stop`` so we can ``docker cp`` the corpus and crash
        # artefacts before issuing ``docker rm`` via ``cleanup()``.
        cmd: list[str] = [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            # B3 — sandbox hardening.
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=512m,mode=1777",
            "--tmpfs",
            "/dev/shm:rw,size=512m,mode=1777",
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
        ]
        # AFL forkserver needs SYS_PTRACE; libFuzzer does not.
        if is_afl:
            cmd.extend(["--cap-add", "SYS_PTRACE"])
        cmd.extend(
            [
                "-v",
                f"{job.harness_path.parent}:/work:ro",
                "-v",
                f"{job.corpus_dir}:/corpus:rw",
                "-v",
                f"{job.output_dir}:/out:rw",
            ]
        )
        for key, val in job.env_vars.items():
            cmd.extend(["-e", f"{key}={val}"])

        # Entrypoint: run the harness.
        harness_in_container = f"/work/{job.harness_path.name}"
        if is_afl:
            # AFL emits ANSI colour by default; disable so log parsers don't
            # have to strip escape sequences. Insert before the image so it
            # is interpreted as a docker run flag, not an afl-fuzz arg.
            cmd.extend(["-e", "AFL_NO_UI=1", "-e", "AFL_SKIP_BIN_CHECK=1"])
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
        """Gracefully stop a container WITHOUT removing it.

        Phase 21 §1.3: stop must not pop ``self._containers`` because
        callers (e.g. :meth:`preserve_corpus`) need to address the same
        container after it has stopped but before it is removed. Use
        :meth:`cleanup` to finally delete the container.
        """
        container_id = self._containers.get(job_id)
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
            # Force kill — but still keep the container around for cleanup().
            await asyncio.create_subprocess_exec(
                "docker",
                "kill",
                container_id,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

    async def wait(self, job_id: str, *, timeout: float | None = None) -> int:
        """Block until the container exits; return its exit code.

        Returns ``-1`` on timeout or when the job is unknown. Used by the
        execution path to detect whether the fuzzer terminated naturally
        (e.g. found a crash) vs being externally stopped.
        """
        container_id = self._containers.get(job_id)
        if not container_id:
            return -1
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "wait",
            container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            if timeout is not None:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            else:
                stdout, _ = await proc.communicate()
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            return -1
        try:
            return int(stdout.decode("utf-8", errors="replace").strip())
        except ValueError:
            return -1

    async def cleanup(self, job_id: str) -> None:
        """Remove the container; idempotent.

        Phase 21 §1.3: this MUST be called AFTER any
        :meth:`preserve_corpus` / ``docker cp`` operations. Calling cleanup
        before harvesting the corpus loses every seed the fuzzer found.
        """
        container_id = self._containers.pop(job_id, None)
        if not container_id:
            return
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "rm",
            "-f",
            container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        log.info(
            "docker.cleanup",
            job_id=job_id,
            container_id=container_id[:12],
        )

    # ── Phase 17: MAB pivot support ──────────────────────────────────────────

    async def preserve_corpus(self, job_id: str, preserve_dir: Path) -> Path:
        """Copy the fuzzer's corpus/seeds from a running container to ``preserve_dir``.

        Returns the path to the preserved corpus directory.
        """
        container_id = self._containers.get(job_id)
        if not container_id:
            log.warning("docker.preserve_corpus.unknown_job", job_id=job_id)
            return preserve_dir

        preserve_dir.mkdir(parents=True, exist_ok=True)

        # Try common corpus locations inside the container.
        corpus_paths = ["/corpus", "/out/queue", "/out/corpus", "/tmp/corpus"]
        for src in corpus_paths:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "cp",
                f"{container_id}:{src}",
                str(preserve_dir),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                log.info(
                    "docker.preserve_corpus.copied",
                    job_id=job_id,
                    src=src,
                    dest=str(preserve_dir),
                )
                return preserve_dir

        log.warning("docker.preserve_corpus.failed", job_id=job_id)
        return preserve_dir

    async def update_resource_limits(
        self,
        job_id: str,
        *,
        cpu_limit: float | None = None,
        memory_limit_mb: int | None = None,
    ) -> bool:
        """Hot-update resource limits for a running container.

        Docker does not support true hot-swap of CPU/memory limits for
        running containers.  This method attempts ``docker update``; if it
        fails, the caller should stop and restart the container.

        Returns ``True`` if the update succeeded.
        """
        container_id = self._containers.get(job_id)
        if not container_id:
            log.warning("docker.update_limits.unknown_job", job_id=job_id)
            return False

        cmd: list[str] = ["docker", "update"]
        if cpu_limit is not None:
            cmd.extend(["--cpus", str(cpu_limit)])
        if memory_limit_mb is not None:
            cmd.extend(["--memory", f"{memory_limit_mb}m"])
        cmd.append(container_id)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode == 0:
            log.info(
                "docker.update_limits.success",
                job_id=job_id,
                cpu=cpu_limit,
                memory_mb=memory_limit_mb,
            )
            return True

        log.warning(
            "docker.update_limits.failed",
            job_id=job_id,
            error=stderr.decode("utf-8", errors="replace")[:200],
        )
        return False

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

    async def _force_remove_by_name(self, container_name: str) -> None:
        """Remove a container by name; swallow errors when none exists.

        Used as a pre-flight before ``docker run`` so that a Temporal
        activity retry (which reuses ``job_id`` and therefore the
        container name) cannot collide with a zombie left by a prior
        worker crash.
        """
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "rm",
            "-f",
            container_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()

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


__all__ = [
    "DockerManager",
    "parse_libfuzzer_log_tail",
    "parse_afl_fuzzer_stats",
]
