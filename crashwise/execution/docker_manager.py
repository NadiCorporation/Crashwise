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

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger
from crashwise.core.models import FuzzJob, FuzzerType

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


def _resolve_image(harness_path: Path, fuzzer_type: FuzzerType = FuzzerType.LIBFUZZER) -> str:
    """Pick a base image based on the fuzzer type."""
    if fuzzer_type == FuzzerType.AFLPP:
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

        image = _resolve_image(job.harness_path, job.fuzzer_type)
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
            # Disk protection: limit individual file sizes to 10 GB.
            # Prevents a runaway corpus or crash dump from filling the host.
            "--ulimit",
            "fsize=10737418240:10737418240",
            # OOM handling: disable OOM kill so we can detect OOM state
            # and log it cleanly rather than having the container vanish.
            "--oom-kill-disable=false",
        ]

        # Disk quota: --storage-opt requires overlay2 on xfs with pquota.
        # Try with it; if Docker rejects it, retry without.
        _storage_opt_args = ["--storage-opt", f"size={get_settings().docker_disk_quota}"]
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

        # Try with --storage-opt first; retry without if unsupported.
        for attempt_with_quota in (True, False):
            run_cmd = cmd.copy()
            if attempt_with_quota:
                # Insert storage-opt before the image argument.
                run_cmd = cmd[:2] + _storage_opt_args + cmd[2:]
            else:
                run_cmd = cmd

            proc = await asyncio.create_subprocess_exec(
                *run_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            err_text = stderr.decode("utf-8", errors="replace")

            if proc.returncode == 0:
                break

            # If storage-opt caused the failure, retry without it.
            if attempt_with_quota and "storage-opt" in err_text.lower():
                log.warning(
                    "docker.storage_opt_unsupported",
                    detail="Filesystem does not support --storage-opt; retrying without disk quota.",
                )
                await self._force_remove_by_name(container_name)
                continue

            raise RuntimeError(f"docker run failed: {err_text}")

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

        Exit code interpretation:
          * 0: normal exit (fuzzer completed or found nothing)
          * 1: fuzzer error (crash found, invalid args, etc.)
          * 137: OOM kill (SIGKILL from kernel OOM killer) or docker stop -t exceeded
          * 139: SIGSEGV (crash in the fuzzer itself)
          * -1: timeout or unknown job

        Returns ``-1`` on timeout or when the job is unknown.
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
            exit_code = int(stdout.decode("utf-8", errors="replace").strip())
        except ValueError:
            return -1

        # Detect OOM kill (exit 137 = 128 + SIGKILL).
        if exit_code == 137:
            log.warning(
                "docker.oom_or_killed",
                job_id=job_id,
                exit_code=exit_code,
                detail="Container was killed (likely OOM). Consider increasing "
                       "--memory or reducing parallel corpus size.",
            )
        elif exit_code == 139:
            log.warning(
                "docker.segfault",
                job_id=job_id,
                exit_code=exit_code,
                detail="Container crashed with SIGSEGV (fuzzer or harness bug).",
            )

        return exit_code

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

    async def extract_coverage_data(self, job_id: str, dest_dir: Path) -> Path | None:
        """Extract llvm-cov/sancov coverage data from a stopped container.

        Looks for:
          1. .sancov files (SanitizerCoverage raw bitmaps)
          2. default.profraw (llvm source-based coverage)

        Returns the path to the extracted coverage directory, or None.
        """
        container_id = self._containers.get(job_id)
        if not container_id:
            return None

        dest_dir.mkdir(parents=True, exist_ok=True)
        coverage_sources = ["/tmp/*.sancov", "/tmp/default.profraw", "/out/*.sancov"]

        for pattern in coverage_sources:
            # Use docker exec + find to locate files matching the pattern.
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", container_id,
                "sh", "-c", f"ls {pattern} 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0 or not stdout.strip():
                continue
            for fpath in stdout.decode("utf-8", errors="replace").strip().splitlines():
                fpath = fpath.strip()
                if not fpath:
                    continue
                cp_proc = await asyncio.create_subprocess_exec(
                    "docker", "cp", f"{container_id}:{fpath}", str(dest_dir),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await cp_proc.communicate()

        # Check if we got anything.
        extracted = list(dest_dir.iterdir())
        if extracted:
            log.info("docker.extract_coverage", job_id=job_id, files=len(extracted))
            return dest_dir
        return None

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
    @staticmethod
    async def check_disk_quota_support() -> tuple[bool, str]:
        """Check if the Docker storage driver supports per-container quotas.

        Returns (supported, message) for use by ``crashwise doctor``.
        Requires overlay2 on xfs with project quotas (pquota mount option).
        """
        proc = await asyncio.create_subprocess_exec(
            "docker", "info", "--format", "{{.Driver}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        driver = stdout.decode("utf-8", errors="replace").strip()
        if driver != "overlay2":
            return False, (
                f"Storage driver is '{driver}', not overlay2. "
                "--storage-opt size= requires overlay2 on xfs with pquota."
            )
        # Check if Docker's data-root is on xfs with pquota.
        proc2 = await asyncio.create_subprocess_exec(
            "docker", "info", "--format", "{{.DockerRootDir}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout2, _ = await proc2.communicate()
        root_dir = stdout2.decode("utf-8", errors="replace").strip()
        # Read /proc/mounts to find the filesystem type and options.
        try:
            mounts = Path("/proc/mounts").read_text()
            for line in mounts.splitlines():
                parts = line.split()
                if len(parts) >= 4 and root_dir.startswith(parts[1]):
                    fs_type = parts[2]
                    opts = parts[3]
                    if fs_type != "xfs":
                        return False, (
                            f"Docker root '{root_dir}' is on {fs_type}, not xfs. "
                            "--storage-opt size= requires xfs with pquota."
                        )
                    if "pquota" not in opts and "prjquota" not in opts:
                        return False, (
                            f"xfs at '{root_dir}' lacks pquota mount option. "
                            "Remount with '-o pquota' or add to /etc/fstab."
                        )
                    return True, "Disk quotas supported (overlay2 + xfs + pquota)."
        except OSError:
            pass
        return False, "Could not verify quota support. --storage-opt size= may fail at runtime."

    async def _docker_available(self) -> bool:
        """Verify Docker daemon is installed AND responsive.

        Checks both binary presence and daemon responsiveness via
        'docker info'. A hanging daemon is detected by a 10-second timeout.
        """
        if not shutil.which("docker"):
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10.0)
            return proc.returncode == 0
        except asyncio.TimeoutError:
            log.error("docker.daemon_timeout", detail="docker info timed out after 10s")
            return False
        except Exception:
            return False

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
        """Ensure a Docker image is available locally; pull if missing.

        Timeout: image pulls are capped at 5 minutes. Network issues or
        massive images beyond this timeout trigger a clear error rather
        than blocking the worker indefinitely.
        """
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
        try:
            _, stderr = await asyncio.wait_for(
                pull_proc.communicate(), timeout=300.0  # 5-minute pull timeout.
            )
        except asyncio.TimeoutError:
            # Kill the stuck pull process.
            with contextlib.suppress(ProcessLookupError):
                pull_proc.kill()
            raise RuntimeError(
                f"docker pull timed out after 300s for {image}. "
                "Check network connectivity or pre-pull the image."
            )
        if pull_proc.returncode != 0:
            raise RuntimeError(
                f"docker pull failed for {image}: {stderr.decode('utf-8', errors='replace')}"
            )


__all__ = [
    "DockerManager",
    "parse_libfuzzer_log_tail",
    "parse_afl_fuzzer_stats",
]
