# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Heuristic Dispatcher — selects execution parameters based on TargetProfile.

The dispatcher bridges the profiler's static-analysis output with the
execution layer.  It maps a :class:`TargetProfile` to concrete choices:

* Docker base image (AFL++ vs libFuzzer vs custom)
* Compiler flags (sanitizer selection, optimisation level)
* Fuzzer type (AFL++ for coverage, libFuzzer for in-process speed)
* Resource limits (CPU, memory) based on complexity
* Timeout scaling based on domain and code size

This ensures every fuzzing campaign starts with a bespoke configuration
tailored to the specific target, rather than using generic defaults.
"""

from __future__ import annotations

from crashwise.core.logging import get_logger
from crashwise.core.models import (
    ExecutionBackend,
    FuzzerType,
    FuzzJob,
    TargetDomain,
    TargetProfile,
)

log = get_logger(__name__)


class ExecutionConfig:
    """Resolved execution parameters for a fuzzing job."""

    def __init__(
        self,
        fuzzer_type: FuzzerType,
        backend: ExecutionBackend,
        image: str,
        compiler_flags: list[str],
        cpu_limit: float,
        memory_limit_mb: int,
        timeout_seconds: int,
        env_vars: dict[str, str],
    ) -> None:
        self.fuzzer_type = fuzzer_type
        self.backend = backend
        self.image = image
        self.compiler_flags = compiler_flags
        self.cpu_limit = cpu_limit
        self.memory_limit_mb = memory_limit_mb
        self.timeout_seconds = timeout_seconds
        self.env_vars = env_vars

    def to_dict(self) -> dict[str, object]:
        return {
            "fuzzer_type": self.fuzzer_type.value,
            "backend": self.backend.value,
            "image": self.image,
            "compiler_flags": self.compiler_flags,
            "cpu_limit": self.cpu_limit,
            "memory_limit_mb": self.memory_limit_mb,
            "timeout_seconds": self.timeout_seconds,
            "env_vars": self.env_vars,
        }


# ── Image registry ─────────────────────────────────────────────────────────────

_IMAGES: dict[str, str] = {
    "aflplusplus": "aflplusplus/aflplusplus:latest",
    "libfuzzer": "gcr.io/oss-fuzz-base/libfuzzer-runner:latest",
    "honggfuzz": "honggfuzz/honggfuzz:latest",
    "kernel": "aflplusplus/aflplusplus:latest",  # kernel builds need full toolchain
}


# ── Dispatch logic ─────────────────────────────────────────────────────────

def dispatch(profile: TargetProfile) -> ExecutionConfig:
    """Resolve execution parameters from a target profile.

    Parameters
    ----------
    profile:
        The :class:`TargetProfile` produced by the profiler agent.

    Returns
    -------
    ExecutionConfig with tailored fuzzer, image, flags, and resource limits.
    """
    log.info(
        "dispatcher.resolve",
        domain=profile.domain.value,
        complexity=profile.complexity_score,
        strategy=profile.recommended_strategy,
        loc=profile.lines_of_code,
    )

    # 1. Select fuzzer type.
    fuzzer = _select_fuzzer(profile)

    # 2. Select backend.
    backend = _select_backend(profile)

    # 3. Select Docker image.
    image = _select_image(fuzzer, profile)

    # 4. Build compiler flags.
    flags = _build_compiler_flags(profile)

    # 5. Scale resources.
    cpu, memory, timeout = _scale_resources(profile)

    # 6. Environment variables.
    env = _build_env(profile)

    return ExecutionConfig(
        fuzzer_type=fuzzer,
        backend=backend,
        image=image,
        compiler_flags=flags,
        cpu_limit=cpu,
        memory_limit_mb=memory,
        timeout_seconds=timeout,
        env_vars=env,
    )


def _select_fuzzer(profile: TargetProfile) -> FuzzerType:
    """Pick the best fuzzer for the target domain and strategy."""
    strategy = profile.recommended_strategy
    domain = profile.domain

    # Aggressive strategy with many dangerous functions → AFL++ for coverage depth.
    if strategy == "aggressive" and len(profile.dangerous_functions) >= 5:
        return FuzzerType.AFLPP

    # Kernel targets → AFL++ (forkserver works better with kernel modules).
    if domain == TargetDomain.KERNEL or profile.has_syscall_handlers:
        return FuzzerType.AFLPP

    # Network parsers → AFL++ (network packet mutation is AFL's strength).
    if domain == TargetDomain.NETWORK_PROTOCOL:
        return FuzzerType.AFLPP

    # Image / compression / parser → libFuzzer (in-process speed).
    if domain in (TargetDomain.IMAGE_PROCESSING, TargetDomain.COMPRESSION, TargetDomain.PARSER):
        return FuzzerType.LIBFUZZER

    # Default: libFuzzer for simplicity and speed.
    return FuzzerType.LIBFUZZER


def _select_backend(profile: TargetProfile) -> ExecutionBackend:
    """Pick execution backend based on target characteristics."""
    if profile.domain == TargetDomain.KERNEL:
        return ExecutionBackend.QEMU
    if profile.has_syscall_handlers:
        return ExecutionBackend.QEMU
    return ExecutionBackend.DOCKER


def _select_image(fuzzer: FuzzerType, profile: TargetProfile) -> str:
    """Pick Docker image based on fuzzer and domain."""
    if profile.domain == TargetDomain.KERNEL:
        return _IMAGES["kernel"]
    if fuzzer == FuzzerType.AFLPP:
        return _IMAGES["aflplusplus"]
    if fuzzer == FuzzerType.HONGGFUZZ:
        return _IMAGES["honggfuzz"]
    return _IMAGES["libfuzzer"]


def _build_compiler_flags(profile: TargetProfile) -> list[str]:
    """Construct compiler flags tailored to the target."""
    flags: list[str] = ["-O1", "-g", "-fno-omit-frame-pointer"]

    # Sanitizers from profile.
    sanitizers = profile.recommended_sanitizers
    if sanitizers:
        flags.append(f"-fsanitize={sanitizers}")

    # Domain-specific hardening.
    if profile.domain == TargetDomain.KERNEL:
        flags.extend(["-DKASAN", "-DCONFIG_KASAN"])
    elif profile.domain == TargetDomain.NETWORK_PROTOCOL:
        flags.append("-D_FORTIFY_SOURCE=2")

    # Custom allocator → add pointer sanitizer checks and disable ASAN hooks.
    if profile.has_custom_allocator:
        flags.append("-fsanitize=pointer-compare")
        flags.append("-fsanitize=pointer-subtract")
        flags.append("-fno-sanitize-address-use-after-scope")

    return flags


def _scale_resources(profile: TargetProfile) -> tuple[float, int, int]:
    """Return (cpu_limit, memory_mb, timeout_seconds) based on complexity."""
    complexity = profile.complexity_score
    loc = profile.lines_of_code

    # Base resources.
    cpu = 2.0
    memory = 2048
    timeout = 300

    # Scale by complexity.
    if complexity >= 7.0:
        cpu = 4.0
        memory = 4096
        timeout = 600
    elif complexity >= 4.0:
        cpu = 3.0
        memory = 3072
        timeout = 450

    # Scale by codebase size.
    if loc > 100_000:
        timeout += 300
        memory += 2048
    elif loc > 50_000:
        timeout += 150
        memory += 1024

    # Domain-specific overrides.
    if profile.domain == TargetDomain.KERNEL:
        cpu = 4.0
        memory = 8192
        timeout = 900
    elif profile.domain == TargetDomain.IMAGE_PROCESSING:
        memory += 2048  # Large image buffers.

    return cpu, memory, timeout


def _build_env(profile: TargetProfile) -> dict[str, str]:
    """Build environment variables for the fuzzing container."""
    env: dict[str, str] = {}

    if profile.domain == TargetDomain.KERNEL:
        env["KERNEL_FUZZING"] = "1"
        env["KASAN"] = "1"

    if profile.recommended_strategy == "aggressive":
        env["AFL_FAST_CAL"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"

    if profile.has_custom_allocator:
        env["ASAN_OPTIONS"] = "detect_stack_use_after_return=1:allocator_may_return_null=1"

    return env


# ── Convenience: apply dispatch to a FuzzJob ───────────────────────────────

def apply_profile_to_job(job: FuzzJob, profile: TargetProfile) -> FuzzJob:
    """Mutate an existing ``FuzzJob`` in-place with profile-aware settings.

    Returns the same instance (modified) for fluent chaining.
    """
    config = dispatch(profile)

    job.backend = config.backend
    job.cpu_limit = config.cpu_limit
    job.memory_limit_mb = config.memory_limit_mb
    job.timeout_seconds = config.timeout_seconds
    job.env_vars.update(config.env_vars)

    # Inject compiler flags into env so the build script can pick them up.
    if config.compiler_flags:
        job.env_vars["CRASHWISE_CFLAGS"] = " ".join(config.compiler_flags)
        job.env_vars["CRASHWISE_SANITIZERS"] = profile.recommended_sanitizers

    log.info(
        "dispatcher.applied",
        job_id=job.job_id,
        fuzzer=config.fuzzer_type.value,
        backend=config.backend.value,
        cpu=config.cpu_limit,
        memory_mb=config.memory_limit_mb,
        timeout=config.timeout_seconds,
    )
    return job


__all__ = ["ExecutionConfig", "apply_profile_to_job", "dispatch"]
