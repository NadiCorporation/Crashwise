# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""System Sentinel — diagnostic engine for CrashWise host provisioning.

Checks hardware, runtime dependencies, build tools, and service connectivity.
Produces structured results for ``crashwise doctor`` and ``crashwise setup``.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import httpx

from crashwise.core.logging import get_logger

logger = get_logger(__name__)


class CheckStatus(str, Enum):
    """Result of a single sentinel check."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one sentinel check."""

    name: str
    status: CheckStatus
    message: str
    detail: str = ""
    remediation: str = ""


@dataclass
class SentinelReport:
    """Aggregated report from all sentinel checks."""

    host: str = ""
    platform: str = ""
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.OK)

    @property
    def warn_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.WARN)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def healthy(self) -> bool:
        return self.fail_count == 0

    def by_category(self) -> dict[str, list[CheckResult]]:
        """Group checks by category prefix (e.g. 'hardware.ram')."""
        groups: dict[str, list[CheckResult]] = {}
        for check in self.checks:
            cat = check.name.split(".")[0] if "." in check.name else "misc"
            groups.setdefault(cat, []).append(check)
        return groups


# ── Helpers ──────────────────────────────────────────────────────────────────


def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Run a shell command and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"


def _which(name: str) -> str | None:
    """Find executable path or None."""
    return shutil.which(name)


def _parse_meminfo_kb(key: str) -> int | None:
    """Parse /proc/meminfo for a key (e.g. 'MemTotal')."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith(key):
                    val = line.split(":")[1].strip().split()[0]
                    return int(val)
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return None


def _get_total_ram_gb() -> float | None:
    """Return total RAM in GB (Linux only)."""
    kb = _parse_meminfo_kb("MemTotal")
    if kb is not None:
        return round(kb / (1024 * 1024), 2)
    return None


def _get_cpu_cores() -> int | None:
    """Return logical CPU core count."""
    try:
        return os.cpu_count()
    except Exception:
        return None


def _get_free_disk_gb(path: Path = Path("/")) -> float | None:
    """Return free disk space in GB."""
    try:
        st = os.statvfs(path)
        return round((st.f_bavail * st.f_frsize) / (1024 ** 3), 2)
    except OSError:
        return None


# ── Check Functions ──────────────────────────────────────────────────────────


def check_hardware_ram(min_gb: float = 8.0) -> CheckResult:
    """Check total system RAM."""
    total = _get_total_ram_gb()
    if total is None:
        return CheckResult(
            name="hardware.ram",
            status=CheckStatus.SKIP,
            message="Could not detect RAM (non-Linux?).",
            remediation="Ensure at least 8 GB RAM for fuzzing.",
        )
    if total >= min_gb:
        return CheckResult(
            name="hardware.ram",
            status=CheckStatus.OK,
            message=f"{total:.1f} GB RAM detected.",
        )
    return CheckResult(
        name="hardware.ram",
        status=CheckStatus.WARN,
        message=f"Only {total:.1f} GB RAM detected (recommended: {min_gb:.0f} GB).",
        remediation="Add more RAM or reduce parallel fuzzing jobs.",
    )


def check_hardware_cpu(min_cores: int = 4) -> CheckResult:
    """Check CPU core count."""
    cores = _get_cpu_cores()
    if cores is None:
        return CheckResult(
            name="hardware.cpu",
            status=CheckStatus.SKIP,
            message="Could not detect CPU cores.",
        )
    if cores >= min_cores:
        return CheckResult(
            name="hardware.cpu",
            status=CheckStatus.OK,
            message=f"{cores} logical cores detected.",
        )
    return CheckResult(
        name="hardware.cpu",
        status=CheckStatus.WARN,
        message=f"Only {cores} cores detected (recommended: {min_cores}).",
        remediation="Reduce worker concurrency or use a machine with more cores.",
    )


def check_hardware_disk(min_free_gb: float = 50.0) -> CheckResult:
    """Check available disk space."""
    free = _get_free_disk_gb()
    if free is None:
        return CheckResult(
            name="hardware.disk",
            status=CheckStatus.SKIP,
            message="Could not detect disk space.",
        )
    if free >= min_free_gb:
        return CheckResult(
            name="hardware.disk",
            status=CheckStatus.OK,
            message=f"{free:.1f} GB free disk space.",
        )
    return CheckResult(
        name="hardware.disk",
        status=CheckStatus.WARN,
        message=f"Only {free:.1f} GB free (recommended: {min_free_gb:.0f} GB).",
        remediation="Free up disk space or mount a larger volume.",
    )


def check_runtime_docker() -> CheckResult:
    """Check Docker daemon availability."""
    rc, out, err = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if rc == 0 and out:
        return CheckResult(
            name="runtime.docker",
            status=CheckStatus.OK,
            message=f"Docker {out} is running.",
        )
    if _which("docker"):
        return CheckResult(
            name="runtime.docker",
            status=CheckStatus.FAIL,
            message="Docker CLI found but daemon is not responding.",
            detail=err or out,
            remediation="Start Docker:  sudo systemctl start docker",
        )
    return CheckResult(
        name="runtime.docker",
        status=CheckStatus.FAIL,
        message="Docker is not installed.",
        remediation="Install Docker:  sudo apt-get install docker.io docker-compose",
    )


def check_runtime_docker_compose() -> CheckResult:
    """Check Docker Compose availability."""
    # Try plugin first (docker compose), then standalone
    for cmd in [["docker", "compose", "version"], ["docker-compose", "--version"]]:
        rc, out, _ = _run(cmd)
        if rc == 0:
            return CheckResult(
                name="runtime.docker-compose",
                status=CheckStatus.OK,
                message=f"Docker Compose available ({out.splitlines()[0]}).",
            )
    return CheckResult(
        name="runtime.docker-compose",
        status=CheckStatus.FAIL,
        message="Docker Compose not found.",
        remediation="Install:  sudo apt-get install docker-compose-plugin",
    )


def check_runtime_python(min_major: int = 3, min_minor: int = 11) -> CheckResult:
    """Check Python version."""
    major, minor, *_ = platform.python_version_tuple()
    ver = f"{major}.{minor}"
    if int(major) > min_major or (int(major) == min_major and int(minor) >= min_minor):
        return CheckResult(
            name="runtime.python",
            status=CheckStatus.OK,
            message=f"Python {ver} (>= {min_major}.{min_minor}).",
        )
    return CheckResult(
        name="runtime.python",
        status=CheckStatus.FAIL,
        message=f"Python {ver} is too old (need >= {min_major}.{min_minor}).",
        remediation="Install Python 3.11+ via pyenv or apt.",
    )


def check_build_cmake() -> CheckResult:
    """Check CMake availability."""
    rc, out, _ = _run(["cmake", "--version"])
    if rc == 0:
        ver = out.splitlines()[0] if out else "unknown"
        return CheckResult(
            name="build.cmake",
            status=CheckStatus.OK,
            message=f"CMake found ({ver}).",
        )
    return CheckResult(
        name="build.cmake",
        status=CheckStatus.FAIL,
        message="CMake not found.",
        remediation="Install:  sudo apt-get install cmake",
    )


def check_build_clang() -> CheckResult:
    """Check Clang availability."""
    rc, out, _ = _run(["clang", "--version"])
    if rc == 0:
        ver = out.splitlines()[0] if out else "unknown"
        return CheckResult(
            name="build.clang",
            status=CheckStatus.OK,
            message=f"Clang found ({ver}).",
        )
    return CheckResult(
        name="build.clang",
        status=CheckStatus.FAIL,
        message="Clang not found.",
        remediation="Install:  sudo apt-get install clang",
    )


def check_build_gcc() -> CheckResult:
    """Check GCC availability."""
    rc, out, _ = _run(["gcc", "--version"])
    if rc == 0:
        ver = out.splitlines()[0] if out else "unknown"
        return CheckResult(
            name="build.gcc",
            status=CheckStatus.OK,
            message=f"GCC found ({ver}).",
        )
    return CheckResult(
        name="build.gcc",
        status=CheckStatus.FAIL,
        message="GCC not found.",
        remediation="Install:  sudo apt-get install gcc",
    )


def check_build_llvm() -> CheckResult:
    """Check LLVM development tools (llvm-config)."""
    rc, out, _ = _run(["llvm-config", "--version"])
    if rc == 0:
        return CheckResult(
            name="build.llvm",
            status=CheckStatus.OK,
            message=f"LLVM {out.strip()} found.",
        )
    # Try llvm-config with version suffix
    for suffix in ["-18", "-17", "-16", "-15"]:
        rc2, out2, _ = _run([f"llvm-config{suffix}", "--version"])
        if rc2 == 0:
            return CheckResult(
                name="build.llvm",
                status=CheckStatus.OK,
                message=f"LLVM {out2.strip()} found (via llvm-config{suffix}).",
            )
    return CheckResult(
        name="build.llvm",
        status=CheckStatus.FAIL,
        message="LLVM development tools not found.",
        remediation="Install:  sudo apt-get install llvm-dev",
    )


def check_build_afl() -> CheckResult:
    """Check AFL++ availability."""
    rc, out, _ = _run(["afl-fuzz", "-V"])
    if rc == 0:
        return CheckResult(
            name="build.afl++",
            status=CheckStatus.OK,
            message="AFL++ found.",
        )
    return CheckResult(
        name="build.afl++",
        status=CheckStatus.WARN,
        message="AFL++ not found on host.",
        remediation="Will use Docker worker image with AFL++ pre-installed.",
    )


def check_build_libfuzzer() -> CheckResult:
    """Check LibFuzzer availability (via clang -fsanitize=fuzzer)."""
    rc, out, err = _run([
        "clang", "-fsanitize=fuzzer", "-x", "c", "-",
    ], timeout=3.0)
    # clang will fail because stdin is empty, but we just check it recognises the flag
    if "unrecognized" in (err + out).lower() or "unknown" in (err + out).lower():
        return CheckResult(
            name="build.libfuzzer",
            status=CheckStatus.WARN,
            message="LibFuzzer support not detected in Clang.",
            remediation="Install clang with fuzzer support or use Docker worker.",
        )
    return CheckResult(
        name="build.libfuzzer",
        status=CheckStatus.OK,
        message="LibFuzzer support detected in Clang.",
    )


async def check_service_temporal(
    host: str = "localhost",
    port: int = 7233,
    timeout: float = 3.0,
) -> CheckResult:
    """Check Temporal server connectivity."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Temporal gRPC health check isn't HTTP; try the Web UI port as proxy
            resp = await client.get(f"http://{host}:8233")
            if resp.status_code < 500:
                return CheckResult(
                    name="service.temporal",
                    status=CheckStatus.OK,
                    message=f"Temporal Web UI reachable at {host}:8233.",
                )
    except Exception as exc:
        pass
    return CheckResult(
        name="service.temporal",
        status=CheckStatus.WARN,
        message=f"Temporal server not reachable at {host}:{port}.",
        remediation="Start Temporal:  docker compose up temporal",
    )


async def check_service_redis(
    host: str = "localhost",
    port: int = 6379,
    timeout: float = 3.0,
) -> CheckResult:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as redis_mod
        r = redis_mod.Redis(host=host, port=port, socket_connect_timeout=timeout)
        await r.ping()
        await r.close()
        return CheckResult(
            name="service.redis",
            status=CheckStatus.OK,
            message=f"Redis reachable at {host}:{port}.",
        )
    except Exception as exc:
        return CheckResult(
            name="service.redis",
            status=CheckStatus.WARN,
            message=f"Redis not reachable at {host}:{port}: {exc}",
            remediation="Start Redis:  docker compose up redis",
        )


async def check_service_llm(
    base_url: str = "http://localhost:11434",
    timeout: float = 3.0,
) -> CheckResult:
    """Check LLM API (Ollama) connectivity."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{base_url}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "?") for m in data.get("models", [])]
                model_list = ", ".join(models[:3]) if models else "no models"
                return CheckResult(
                    name="service.llm",
                    status=CheckStatus.OK,
                    message=f"Ollama reachable. Models: {model_list}",
                )
    except Exception as exc:
        pass
    return CheckResult(
        name="service.llm",
        status=CheckStatus.WARN,
        message=f"LLM API not reachable at {base_url}.",
        remediation="Start Ollama:  ollama serve  (or configure a remote provider)",
    )


# ── Orchestrator ───────────────────────────────────────────────────────────────


async def run_all_checks(
    *,
    temporal_host: str = "localhost",
    temporal_port: int = 7233,
    redis_host: str = "localhost",
    redis_port: int = 6379,
    llm_base_url: str = "http://localhost:11434",
) -> SentinelReport:
    """Run every sentinel check and return an aggregated report."""
    report = SentinelReport(
        host=platform.node(),
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
    )

    # Hardware (sync)
    report.checks.extend([
        check_hardware_ram(),
        check_hardware_cpu(),
        check_hardware_disk(),
    ])

    # Runtime (sync)
    report.checks.extend([
        check_runtime_docker(),
        check_runtime_docker_compose(),
        check_runtime_python(),
    ])

    # Build tools (sync)
    report.checks.extend([
        check_build_cmake(),
        check_build_clang(),
        check_build_gcc(),
        check_build_llvm(),
        check_build_afl(),
        check_build_libfuzzer(),
    ])

    # Services (async)
    service_checks = await asyncio.gather(
        check_service_temporal(temporal_host, temporal_port),
        check_service_redis(redis_host, redis_port),
        check_service_llm(llm_base_url),
    )
    report.checks.extend(service_checks)

    return report


# ── Provisioner ──────────────────────────────────────────────────────────────


# Debian/Ubuntu packages required by each check
_CHECK_PACKAGES: dict[str, list[str]] = {
    "runtime.docker": ["docker.io", "docker-compose-plugin"],
    "runtime.docker-compose": ["docker-compose-plugin"],
    "build.cmake": ["cmake"],
    "build.clang": ["clang"],
    "build.gcc": ["gcc", "g++"],
    "build.llvm": ["llvm-dev", "lld"],
    "build.afl++": ["afl++"],
}


def get_missing_packages(report: SentinelReport) -> list[str]:
    """Return a deduplicated list of packages to install for failed checks."""
    packages: set[str] = set()
    for check in report.checks:
        if check.status == CheckStatus.FAIL:
            for pkg in _CHECK_PACKAGES.get(check.name, []):
                packages.add(pkg)
    return sorted(packages)


def generate_setup_script(packages: list[str]) -> str:
    """Generate a bash script to install missing packages on Debian/Ubuntu."""
    if not packages:
        return "# All required packages are already installed.\n"
    lines = [
        "#!/usr/bin/env bash",
        "# CrashWise System Provisioner",
        "# Generated automatically by crashwise setup",
        "",
        "set -euo pipefail",
        "",
        'echo "[CrashWise] Updating package lists..."',
        "sudo apt-get update -qq",
        "",
        'echo "[CrashWise] Installing packages..."',
        f"sudo apt-get install -y {' '.join(packages)}",
        "",
        'echo "[CrashWise] Setup complete."',
    ]
    return "\n".join(lines) + "\n"
