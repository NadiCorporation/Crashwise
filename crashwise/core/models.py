# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Shared Pydantic data models for the CrashWise control plane.

These models form the **type-safe boundary** between Temporal workflows,
activities, and downstream LangGraph agents. Every cross-component payload
in the system MUST be a model defined here (or extending one of these
base models). Doing so keeps the multi-LLM build coherent: every author
codes against the same contracts.

Models are intentionally narrow and immutable-by-convention; mutation is
discouraged. New fields must be additive and default-valued so existing
serialised workflow histories remain replayable.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# ── Enums ────────────────────────────────────────────────────────────────────
class FuzzerType(StrEnum):
    """Supported fuzzing back-ends."""

    AFLPP = "afl++"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"


class CrashSeverity(StrEnum):
    """Coarse severity classification used by the triage engine."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SeedSource(StrEnum):
    """Origin of a fuzzing seed."""

    GITHUB = "github"
    CVE = "cve"
    MANUAL = "manual"


class WorkflowStage(StrEnum):
    """Lifecycle stages for the main fuzzing workflow."""

    PENDING = "pending"
    SEEDING = "seeding"
    SETUP = "setup"
    HEALING_BUILD = "healing_build"
    EXECUTING = "executing"
    TRIAGE = "triage"
    HEALING_REPAIR = "healing_repair"
    COMPLETED = "completed"
    FAILED = "failed"
    FAILED_COMPILATION = "failed_compilation"


# ── Base ─────────────────────────────────────────────────────────────────────
class _StrictModel(BaseModel):
    """Project-wide base: strict validation, JSON-friendly serialisation."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )


# ── Top-level workflow I/O ───────────────────────────────────────────────────
class FuzzingInput(_StrictModel):
    """Input payload for :class:`MainFuzzingWorkflow`.

    Attributes
    ----------
    target_repo:
        Git URL of the C/C++/Rust project to fuzz.
    fuzzer_type:
        Which fuzzing engine to deploy.
    timeout_seconds:
        Hard wall-clock cap for the ``ExecuteFuzzing`` activity.
    target_branch:
        Optional branch / tag / commit SHA to check out. Defaults to HEAD.
    harness_path:
        Path *inside the cloned repo* to a pre-existing harness. If
        ``None``, Phase 2's harness-synthesis agent will produce one.
    sanitizers:
        Comma-separated sanitizer list (``address,undefined`` etc.).
    campaign_id:
        Optional UUID of a pre-created campaign record.  When present,
        activities will log their results to the persistence layer.
    """

    target_repo: str = Field(..., min_length=1, max_length=1024, description="Git URL or directory path of target project")
    fuzzer_type: FuzzerType = Field(default=FuzzerType.LIBFUZZER)
    timeout_seconds: int = Field(default=600, ge=10, le=86_400)

    target_branch: str | None = Field(default=None, max_length=255)
    harness_path: str | None = Field(default=None, max_length=512)
    sanitizers: str = Field(default="address,undefined")
    max_iterations: int = Field(default=5, ge=1, le=20)
    campaign_id: str | None = Field(default=None, max_length=36)

    # Phase 21 — opt-in autonomous strategy switching and harness evolution.
    # Both default False so existing tests / smoke runs are unaffected.
    enable_mab: bool = Field(
        default=False,
        description="Phase 17 strategy switcher (MAB) — opt-in",
    )
    enable_evolution: bool = Field(
        default=False,
        description="Phase 18 harness evolution — implies enable_mab",
    )
    pivot_check_interval_iterations: int = Field(
        default=1,
        ge=1,
        le=20,
        description="Run pivot_strategy every N iterations",
    )
    max_evolution_count: int = Field(
        default=10,
        ge=1,
        le=50,
    )

    # Phase 22 — CrashWise Healing Engine (openhands-sdk + LangGraph).
    # When enabled, the workflow drives the adaptive build loop in place
    # of the legacy ``setup_target`` activity and routes every unique
    # crash through the autonomous repair agent before persistence.
    enable_self_healing: bool = Field(
        default=False,
        description=(
            "Phase 22 self-healing toggle — when True the workflow uses "
            "``run_autonomous_repair_activity`` to attempt an automated "
            "patch for each unique crash before persisting it."
        ),
    )
    healing_max_attempts: int = Field(
        default=10,
        ge=1,
        le=50,
        description=(
            "Per-mission cap on LangGraph agent iterations inside the "
            "healing engine. Mirrors ``DEFAULT_MAX_ATTEMPTS`` and bounds "
            "API spend on stuck repairs."
        ),
    )


class FuzzingOutput(_StrictModel):
    """Final output payload of :class:`MainFuzzingWorkflow`.

    Attributes
    ----------
    crash_found:
        Whether at least one crash was triggered during execution.
    logs_path:
        Filesystem path (worker-local) to the captured fuzzer logs / artefacts.
    crash_count:
        Total distinct crashes observed.
    severity:
        Coarse severity, derived by the triage engine.
    started_at / finished_at:
        UTC timestamps bounding the run.
    summary:
        Human-readable rollup populated by the triage stage.
    """

    crash_found: bool
    logs_path: Path

    crash_count: int = Field(default=0, ge=0)
    severity: CrashSeverity = Field(default=CrashSeverity.UNKNOWN)
    started_at: datetime
    finished_at: datetime
    summary: str = Field(default="")

    # Phase 22 — CrashWise Healing Engine telemetry.
    total_patches_generated: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of unique crashes for which the autonomous repair "
            "agent produced a verified patch during this campaign."
        ),
    )
    build_attempts: int = Field(
        default=0,
        ge=0,
        description=(
            "LangGraph agent iterations consumed by the adaptive build "
            "stage. Useful for tracking LLM spend across campaigns."
        ),
    )
    build_succeeded: bool = Field(
        default=True,
        description=(
            "False when the adaptive build activity returned "
            "``is_successful=False`` and the campaign exited via "
            "``WorkflowStage.FAILED_COMPILATION``."
        ),
    )
    healing_workspace_path: str = Field(
        default="",
        description=(
            "Absolute path of the openhands-sdk workspace that hosted "
            "the build (and any subsequent repair) for this campaign. "
            "Empty string when self-healing was disabled."
        ),
    )

    @classmethod
    def now(cls) -> datetime:
        """Helper for callers wanting a coherent UTC timestamp."""
        return datetime.now(tz=UTC)


# ── Per-activity I/O ─────────────────────────────────────────────────────────
class SetupTargetInput(_StrictModel):
    """Input to the ``setup_target`` activity."""

    target_repo: str = Field(..., min_length=1, max_length=1024, description="Git URL or directory path of target project")
    target_branch: str | None = None
    sanitizers: str = "address,undefined"
    target_source_path: str | None = None
    synthesize_harness: bool = False
    max_synth_retries: int = Field(default=4, ge=0, le=10)
    fuzzer_type: str = "libfuzzer"


class SetupTargetOutput(_StrictModel):
    """Result of cloning + preparing the target."""

    workdir: Path = Field(..., description="Local checkout directory")
    commit_sha: str = Field(..., min_length=7, max_length=64)
    harness_path: Path | None = None


class SynthesizeHarnessInput(_StrictModel):
    """Input to the ``synthesize_harness`` activity."""

    workspace_path: Path = Field(..., description="Root directory of target repository")
    source_file_path: Path | None = Field(default=None, description="Explicit source file if specified")
    fuzzer_type: str = Field(default="libfuzzer", description="Fuzzer engine format")
    max_retries: int = Field(default=4, ge=0, le=10)
    campaign_id: str | None = None


class SynthesizeHarnessOutput(_StrictModel):
    """Result of the ``synthesize_harness`` activity."""

    success: bool = Field(default=False)
    harness_path: Path | None = None
    binary_path: Path | None = None
    source_file_used: Path | None = None
    retry_count: int = Field(default=0, ge=0)
    error_message: str = ""


class ExecuteFuzzingInput(_StrictModel):
    """Input to the ``execute_fuzzing`` activity."""

    workdir: Path
    harness_path: Path | None
    fuzzer_type: FuzzerType
    timeout_seconds: int = Field(..., ge=10, le=86_400)
    sanitizers: str = "address,undefined"
    corpus_dir: Path | None = None
    campaign_id: str | None = Field(default=None, max_length=36)
    iteration: int = Field(default=0, ge=0)


class ExecuteFuzzingOutput(_StrictModel):
    """Result of an execution campaign."""

    logs_path: Path
    crashes_dir: Path
    crash_count: int = Field(default=0, ge=0)
    executions: int = Field(default=0, ge=0, description="Total fuzzer iterations")
    duration_seconds: float = Field(default=0.0, ge=0.0)
    coverage_edges: int = Field(
        default=0, ge=0, description="Edges discovered during this iteration"
    )
    coverage_data_path: Path | None = Field(
        default=None,
        description="Path to raw coverage data file (AFL plot_data or sancov output)",
    )
    peak_cpu_percent: float = Field(
        default=0.0, ge=0.0, description="Peak CPU usage percentage during fuzzing"
    )
    peak_memory_mb: float = Field(
        default=0.0, ge=0.0, description="Peak memory usage in MB during fuzzing"
    )
    run_id: str | None = Field(
        default=None,
        max_length=36,
        description="UUID of the FuzzingRun row persisted for this iteration.",
    )


class SeedCorpusInput(_StrictModel):
    """Input to the ``seed_corpus`` activity."""

    target_name: str = Field(..., min_length=1, max_length=128)
    workdir: Path
    max_seeds: int = Field(default=10, ge=1, le=100)
    campaign_id: str | None = Field(default=None, max_length=36)


class AnalyzeProgressInput(_StrictModel):
    """Input to the ``analyze_progress`` activity."""

    fuzz_output: ExecuteFuzzingOutput
    campaign: FuzzingCampaignState


class TriageInput(_StrictModel):
    """Input to the ``triage_results`` activity."""

    logs_path: Path
    crashes_dir: Path
    crash_count: int = Field(default=0, ge=0)
    campaign_id: str | None = Field(default=None, max_length=36)
    defer_persistence: bool = Field(
        default=False,
        description=(
            "When True the activity classifies + deduplicates crashes "
            "but skips its inline DB write. The workflow takes over "
            "persistence so it can interleave the autonomous repair "
            "step (Phase 22 healing engine) on each unique crash."
        ),
    )


class TriagedCrashRef(_StrictModel):
    """Workflow-visible reference for a unique, triaged crash.

    Returned by ``triage_results`` (in :attr:`TriageOutput.unique_crashes`)
    so the workflow can iterate over each net-new crash and call the
    autonomous repair activity *before* persistence. Carries everything
    the repair agent and the persistence activity need — there is no
    second activity round-trip required to fetch the ASAN log or stack
    trace.
    """

    crash_id: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Stable identifier (typically the fuzzer's crash filename).",
    )
    stack_hash: str = Field(
        default="",
        max_length=128,
        description="Truncated SHA256 over the normalised stack-frame names.",
    )
    asan_log: str = Field(
        default="",
        max_length=65_536,
        description=(
            "Full ASAN/KASAN block (or raw fuzzer stderr when ASAN is "
            "absent). Fed to ``run_autonomous_repair_activity`` as the "
            "crash_context."
        ),
    )
    crash_file_path: str = Field(
        default="",
        max_length=512,
        description="Absolute path to the on-disk crasher seed.",
    )
    bug_type: str = Field(
        default="unknown",
        max_length=64,
        description="Classified bug class (heap-buffer-overflow, UAF, ...).",
    )
    severity: CrashSeverity = Field(default=CrashSeverity.UNKNOWN)
    signal: str = Field(default="", max_length=32)
    stack_trace: str = Field(default="", max_length=8_192)
    root_cause: str = Field(default="", max_length=4_096)


class TriageOutput(_StrictModel):
    """Result of the triage pass."""

    severity: CrashSeverity = CrashSeverity.UNKNOWN
    summary: str = ""
    triaged_crash_count: int = Field(default=0, ge=0)
    unique_crashes: list[TriagedCrashRef] = Field(
        default_factory=list,
        description=(
            "Deduplicated, ready-for-repair crash references. Populated "
            "regardless of ``defer_persistence`` so callers can always "
            "see what the activity decided was unique."
        ),
    )


class PersistTriagedCrashInput(_StrictModel):
    """Input to the ``persist_triaged_crash`` activity (Phase 22).

    Carries a single triaged crash plus the optional verified patch the
    healing engine produced, so the activity can perform Redis dedup
    and the SQL write in one atomic call.
    """

    campaign_id: str = Field(..., min_length=1, max_length=36)
    crash: TriagedCrashRef
    patch: str = Field(default="", max_length=16_384)
    patch_summary: str = Field(default="", max_length=4_096)
    healing_attempts: int = Field(default=0, ge=0)
    run_id: str | None = Field(
        default=None,
        max_length=36,
        description="UUID of the FuzzingRun row to link this crash to.",
    )


class PersistTriagedCrashOutput(_StrictModel):
    """Result of a single :func:`persist_triaged_crash` invocation."""

    persisted: bool = Field(
        default=False,
        description=(
            "True when a new Crash row was committed. False when the "
            "stack hash was already known to Redis (duplicate skip)."
        ),
    )
    crash_uuid: str | None = Field(
        default=None,
        description="DB-assigned UUID of the new Crash row (None when skipped).",
    )
    duplicate: bool = Field(
        default=False,
        description="True when Redis fast-path dedup short-circuited the write.",
    )


class ExecutionBackend(StrEnum):
    """Supported execution backends for fuzzing jobs."""

    DOCKER = "docker"
    QEMU = "qemu"
    LOCAL = "local"


class FuzzJob(_StrictModel):
    """Input to the ``execute_job`` activity.

    Attributes
    ----------
    job_id:
        Unique identifier for this fuzzing run.
    backend:
        Whether to run in Docker, QEMU, or locally.
    harness_path:
        Path to the compiled fuzzer binary.
    corpus_dir:
        Seed corpus directory.
    output_dir:
        Where crashes and logs will be written.
    timeout_seconds:
        Wall-clock cap for the job.
    cpu_limit:
        CPU cores to allocate (Docker only).
    memory_limit_mb:
        RAM cap in MiB (Docker only).
    qemu_kernel:
        Path to kernel image (QEMU only).
    qemu_initrd:
        Path to initrd (QEMU only).
    qemu_append:
        Additional kernel cmdline args (QEMU only).
    env_vars:
        Extra environment variables injected into the container/VM.
    """

    job_id: str
    backend: ExecutionBackend = ExecutionBackend.DOCKER
    fuzzer_type: FuzzerType = FuzzerType.LIBFUZZER
    harness_path: Path
    corpus_dir: Path
    output_dir: Path
    crashes_dir: Path | None = None
    timeout_seconds: int = Field(default=600, ge=10, le=86_400)
    cpu_limit: float = Field(default=2.0, ge=0.1)
    memory_limit_mb: int = Field(default=2048, ge=256)
    qemu_kernel: Path | None = None
    qemu_initrd: Path | None = None
    qemu_append: str = ""
    env_vars: dict[str, str] = Field(default_factory=dict)


# ── Coverage & Campaign State ────────────────────────────────────────────────
class CoverageReport(_StrictModel):
    """Snapshot of fuzzer coverage metrics.

    Attributes
    ----------
    edges_hit:
        Number of control-flow edges discovered.
    blocks_hit:
        Basic blocks reached.
    functions_hit:
        Distinct functions exercised.
    exec_per_sec:
        Current executions per second.
    total_execs:
        Cumulative fuzzer iterations.
    stability:
        AFL stability percentage (0-100).
    map_density:
        Bitmap utilisation percentage.
    pending_favs:
        AFL pending favourite seeds.
    corpus_count:
        Total seeds in corpus.
    """

    edges_hit: int = Field(default=0, ge=0)
    blocks_hit: int = Field(default=0, ge=0)
    functions_hit: int = Field(default=0, ge=0)
    exec_per_sec: float = Field(default=0.0, ge=0.0)
    total_execs: int = Field(default=0, ge=0)
    stability: float = Field(default=0.0, ge=0.0, le=100.0)
    map_density: float = Field(default=0.0, ge=0.0, le=100.0)
    pending_favs: int = Field(default=0, ge=0)
    corpus_count: int = Field(default=0, ge=0)


class CampaignStatus(StrEnum):
    """Lifecycle states for a fuzzing campaign."""

    RUNNING = "running"
    STALLED = "stalled"
    CRASHED = "crashed"
    COMPLETE = "complete"
    MUTATING = "mutating"


class VerificationStatus(StrEnum):
    """Lifecycle states for patch verification."""

    PENDING = "pending"
    FIXED = "fixed"
    FAILED_VERIFICATION = "failed_verification"
    BUILD_FAILED = "build_failed"
    ERROR = "error"


class VerifyPatchInput(_StrictModel):
    """Input to the ``VerifyPatchWorkflow``."""

    crash_id: str = Field(..., min_length=1, max_length=36)
    campaign_id: str = Field(..., min_length=1, max_length=36)
    repo_url: str = Field(..., min_length=1, max_length=512)
    patch: str = Field(..., min_length=1, max_length=16384)
    seed_path: Path = Field(...)
    harness_path: Path | None = None
    fuzzer_type: FuzzerType = Field(default=FuzzerType.LIBFUZZER)
    timeout_seconds: int = Field(default=60, ge=10, le=600)


class VerifyPatchOutput(_StrictModel):
    """Result of patch verification."""

    status: VerificationStatus = Field(default=VerificationStatus.PENDING)
    patch_applied: bool = False
    build_success: bool = False
    crash_reproduced: bool | None = None
    stdout: str = Field(default="", max_length=8192)
    stderr: str = Field(default="", max_length=8192)


class FuzzingCampaignState(_StrictModel):
    """Mutable state that tracks a multi-iteration fuzzing campaign.

    Attributes
    ----------
    iteration:
        Current loop iteration (0-indexed).
    max_iterations:
        Hard cap on iterations before forced exit.
    best_coverage:
        Highest ``edges_hit`` seen so far.
    last_coverage:
        Coverage from the most recent iteration.
    harness_path:
        Path to the harness used in the current iteration.
    status:
        Current campaign phase.
    should_continue:
        ``True`` when the workflow loop should schedule another iteration.
    mutation_hint:
        Structured feedback from the analyzer to the harness synth agent.
    crash_count:
        Total distinct crashes observed across all iterations.
    """

    iteration: int = Field(default=0, ge=0)
    max_iterations: int = Field(default=5, ge=1, le=20)
    best_coverage: CoverageReport = Field(default_factory=CoverageReport)
    last_coverage: CoverageReport = Field(default_factory=CoverageReport)
    harness_path: Path | None = None
    status: CampaignStatus = CampaignStatus.RUNNING
    should_continue: bool = True
    mutation_hint: str = ""
    crash_count: int = Field(default=0, ge=0)
    consecutive_plateau_count: int = Field(
        default=0,
        ge=0,
        description="Consecutive iterations with < 1% edge growth. Stall triggers at threshold.",
    )
    last_coverage_data_path: Path | None = Field(
        default=None,
        description="Path to the most recent raw coverage data (AFL plot_data/showmap output).",
    )
    last_stall_reasons: list[str] = Field(
        default_factory=list,
        description="Stall reasons from the most recent analyze_campaign call. Consumed by agentic_enrich.",
    )
    iteration_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Historical metrics per iteration for the agentic feedback analyzer.",
    )


class SeedMetadata(_StrictModel):
    """Metadata for a single fuzzing seed.

    Attributes
    ----------
    seed_id:
        Unique identifier (e.g., CVE-2023-1234 or GitHub issue URL hash).
    source:
        Where the seed was discovered.
    target_name:
        Human-readable target (e.g., ``openssl``, ``libpng``).
    url:
        Original URL of the PoC / advisory.
    description:
        Short summary of the vulnerability.
    language:
        Programming language of the PoC (``c``, ``python``, ``binary``, etc.).
    tags:
        Free-form labels for filtering (``heap-overflow``, ``use-after-free``).
    created_at:
        UTC timestamp when the seed record was created.
    downloaded_path:
        Local filesystem path to the original PoC file.
    seed_path:
        Local filesystem path to the transformed binary seed ready for the fuzzer.
    """

    seed_id: str = Field(..., min_length=1, max_length=256)
    source: SeedSource = Field(default=SeedSource.MANUAL)
    target_name: str = Field(..., min_length=1, max_length=128)
    url: HttpUrl | None = None
    description: str = Field(default="", max_length=1024)
    language: str = Field(default="", max_length=32)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    downloaded_path: Path | None = None
    seed_path: Path | None = None


# ── Exploit Generation ───────────────────────────────────────────────────────
class ExploitabilityScore(StrEnum):
    """Reachability / exploitability rating for a vulnerability."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ExploitGenInput(_StrictModel):
    """Input to the exploit-generation agent.

    Attributes
    ----------
    crash_id:
        Database UUID of the crash to generate a PoC for.
    crash_context:
        Concatenated crash report (ASAN + GDB + stack trace + registers).
    bug_type:
        Classified bug category (e.g. ``heap-buffer-overflow``).
    target_repo:
        Git URL of the vulnerable project.
    target_source_path:
        Path within the repo to the vulnerable source file.
    vulnerable_function:
        Name of the function containing the bug.
    """

    crash_id: str = Field(..., min_length=1, max_length=36)
    crash_context: str = Field(..., min_length=1, max_length=32768)
    bug_type: str = Field(default="unknown", max_length=64)
    target_repo: str = Field(default="", max_length=512)
    target_source_path: str = Field(default="", max_length=512)
    vulnerable_function: str = Field(default="", max_length=256)


class ExploitGenOutput(_StrictModel):
    """Result of the exploit-generation agent.

    Attributes
    ----------
    poc_code:
        Standalone C exploit script ready to compile and run.
    primitive:
        Detected memory-safety primitive (e.g. ``out-of-bounds-write``).
    reachability:
        How easily the bug is triggered from untrusted input.
    reachability_score:
        Numeric 0.0-10.0 score for reachability.
    confidence:
        0.0-1.0 confidence in the generated PoC.
    compilation_command:
        Suggested ``gcc`` / ``clang`` invocation.
    notes:
        Human-readable notes from the architect agent.
    """

    poc_code: str = Field(default="", max_length=65536)
    primitive: str = Field(default="unknown", max_length=128)
    reachability: ExploitabilityScore = Field(default=ExploitabilityScore.UNKNOWN)
    reachability_score: float = Field(default=0.0, ge=0.0, le=10.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    compilation_command: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)


class PocVerifyInput(_StrictModel):
    """Input to the ``verify_poc`` activity.

    Attributes
    ----------
    crash_id:
        Database UUID of the crash being verified.
    poc_code:
        C source code of the generated PoC.
    compilation_command:
        Suggested compiler invocation (fallback to auto-detect).
    target_repo:
        Git URL to clone for headers / libraries.
    expected_signal:
        The signal the PoC should trigger (e.g. ``SIGSEGV``).
    expected_asan_pattern:
        Substring expected in ASAN output (e.g. ``heap-buffer-overflow``).
    timeout_seconds:
        Wall-clock cap for compilation + execution.
    """

    crash_id: str = Field(..., min_length=1, max_length=36)
    poc_code: str = Field(..., min_length=1, max_length=65536)
    compilation_command: str = Field(default="", max_length=1024)
    target_repo: str = Field(default="", max_length=512)
    expected_signal: str = Field(default="SIGSEGV", max_length=32)
    expected_asan_pattern: str = Field(default="", max_length=128)
    timeout_seconds: int = Field(default=60, ge=10, le=600)


class PocVerifyOutput(_StrictModel):
    """Result of PoC verification.

    Attributes
    ----------
    compiled:
        Whether the PoC compiled successfully.
    binary_path:
        Path to the compiled binary (if compilation succeeded).
    crash_reproduced:
        Whether running the PoC triggered the expected crash.
    stdout:
        Captured stdout from compilation + execution.
    stderr:
        Captured stderr (contains ASAN / GDB output).
    signal_received:
        The signal that actually terminated the process.
    notes:
        Human-readable summary of the verification.
    """

    compiled: bool = False
    binary_path: Path | None = None
    crash_reproduced: bool = False
    stdout: str = Field(default="", max_length=8192)
    stderr: str = Field(default="", max_length=8192)
    signal_received: str = Field(default="", max_length=32)
    notes: str = Field(default="", max_length=4096)


# ── Target Profiling ─────────────────────────────────────────────────────────
class TargetDomain(StrEnum):
    """High-level domain classification for a fuzzing target."""

    IMAGE_PROCESSING = "image_processing"
    NETWORK_PROTOCOL = "network_protocol"
    FILESYSTEM = "filesystem"
    CRYPTOGRAPHY = "cryptography"
    COMPRESSION = "compression"
    PARSER = "parser"
    DATABASE = "database"
    MULTIMEDIA = "multimedia"
    KERNEL = "kernel"
    GENERAL = "general"


class DangerousFunction(StrEnum):
    """Known dangerous functions that are common vulnerability sources."""

    MEMCPY = "memcpy"
    STRCPY = "strcpy"
    STRCAT = "strcat"
    STRNCPY = "strncpy"
    MEMMOVE = "memmove"
    MEMSET = "memset"
    MALLOC = "malloc"
    REALLOC = "realloc"
    FREE = "free"
    KMALLOC = "kmalloc"
    VMALLOC = "vmalloc"
    SPRINTF = "sprintf"
    GETS = "gets"
    READ = "read"
    RECV = "recv"
    COPY_FROM_USER = "copy_from_user"
    COPY_TO_USER = "copy_to_user"


class TargetProfile(_StrictModel):
    """Structured profile of a fuzzing target produced by the profiler agent.

    Attributes
    ----------
    domain:
        High-level domain classification (e.g. ``image_processing``).
    complexity_score:
        Cyclomatic-complexity-derived score 0.0-10.0.
    call_graph_depth:
        Maximum depth of the call graph from public entry points.
    attack_surface:
        Public functions reachable from untrusted input.
    dangerous_functions:
        Dangerous libc/kernel functions found in the codebase.
    language:
        Primary language: ``c``, ``cpp``, ``rust``, ``go``.
    lines_of_code:
        Total lines of code (from ``cloc``).
    file_count:
        Number of source files.
    has_custom_allocator:
        Whether the project defines its own memory allocator.
    has_syscall_handlers:
        Whether syscall/ioctl handlers were detected.
    has_network_parsers:
        Whether network packet / protocol parsers were detected.
    recommended_sanitizers:
        Sanitizer flags tailored to the target (e.g. ``address,undefined``).
    recommended_strategy:
        High-level fuzzing strategy hint for the orchestrator.
    notes:
        Human-readable summary from the profiler.
    """

    domain: TargetDomain = Field(default=TargetDomain.GENERAL)
    complexity_score: float = Field(default=0.0, ge=0.0, le=10.0)
    call_graph_depth: int = Field(default=0, ge=0)
    attack_surface: list[str] = Field(default_factory=list)
    dangerous_functions: list[DangerousFunction] = Field(default_factory=list)
    language: str = Field(default="c", max_length=16)
    lines_of_code: int = Field(default=0, ge=0)
    file_count: int = Field(default=0, ge=0)
    has_custom_allocator: bool = False
    has_syscall_handlers: bool = False
    has_network_parsers: bool = False
    recommended_sanitizers: str = Field(default="address,undefined", max_length=128)
    recommended_strategy: str = Field(
        default="standard",
        max_length=64,
        description="One of: standard, aggressive, kernel, network, minimal",
    )
    notes: str = Field(default="", max_length=4096)


class ProfileTargetInput(_StrictModel):
    """Input to the ``profile_target`` activity."""

    workdir: Path = Field(..., description="Path to the cloned target repository")
    source_paths: list[Path] = Field(default_factory=list, description="Specific files to analyse")
    max_files: int = Field(default=50, ge=1, le=500, description="Cap on files to scan")
    enable_semantic_profiling: bool = Field(
        default=True,
        description="Enable LLM-powered semantic analysis to enrich the regex-based profile",
    )


class ProfileTargetOutput(_StrictModel):
    """Result of the ``profile_target`` activity."""

    profile: TargetProfile = Field(default_factory=TargetProfile)
    duration_seconds: float = Field(default=0.0, ge=0.0)
    files_scanned: int = Field(default=0, ge=0)


# ── Multi-Armed Bandit Strategy Switcher ────────────────────────────────────
class StrategyArm(_StrictModel):
    """A single fuzzing strategy configuration (one "arm" of the MAB).

    Attributes
    ----------
    arm_id:
        Unique identifier (e.g. ``afl_default``, ``libfuzzer_custom``).
    name:
        Human-readable label.
    fuzzer_type:
        Which fuzzer engine this arm uses.
    compiler_flags:
        Extra CFLAGS / CXXFLAGS for this strategy.
    env_vars:
        Environment variables (e.g. ``AFL_FAST_CAL=1``).
    cpu_limit:
        CPU cores allocated when this arm is active.
    memory_limit_mb:
        RAM cap when this arm is active.
    mutation_mode:
        Description of the mutation strategy (e.g. ``aggressive``, ``havoc``).
    """

    arm_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(default="", max_length=128)
    fuzzer_type: FuzzerType = Field(default=FuzzerType.LIBFUZZER)
    compiler_flags: list[str] = Field(default_factory=list)
    env_vars: dict[str, str] = Field(default_factory=dict)
    cpu_limit: float = Field(default=2.0, ge=0.1)
    memory_limit_mb: int = Field(default=2048, ge=256)
    mutation_mode: str = Field(default="default", max_length=64)


class MabState(_StrictModel):
    """State of the Multi-Armed Bandit for a single campaign.

    Attributes
    ----------
    arms:
        All strategy arms available.
    successes:
        Per-arm success count (new coverage found).
    failures:
        Per-arm failure count (no new coverage).
    trials:
        Per-arm total pulls.
    current_arm_id:
        Which arm is currently running.
    last_pivot_at:
        UTC timestamp of the last strategy switch.
    pivot_count:
        How many times we've switched strategies.
    coverage_history:
        List of (timestamp, edges_hit) tuples for plateau detection.
    """

    arms: list[StrategyArm] = Field(default_factory=list)
    successes: dict[str, int] = Field(default_factory=dict)
    failures: dict[str, int] = Field(default_factory=dict)
    trials: dict[str, int] = Field(default_factory=dict)
    current_arm_id: str = ""
    last_pivot_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    pivot_count: int = Field(default=0, ge=0)
    coverage_history: list[tuple[float, int]] = Field(default_factory=list)

    def record_trial(self, arm_id: str, new_coverage_found: bool) -> None:
        """Record the outcome of one trial for ``arm_id``."""
        self.trials[arm_id] = self.trials.get(arm_id, 0) + 1
        if new_coverage_found:
            self.successes[arm_id] = self.successes.get(arm_id, 0) + 1
        else:
            self.failures[arm_id] = self.failures.get(arm_id, 0) + 1

    def is_plateaued(self, *, window_minutes: float = 30.0, threshold: float = 0.01) -> bool:
        """Return True if coverage growth < ``threshold`` over ``window_minutes``."""
        if len(self.coverage_history) < 2:
            return False
        cutoff = time.time() - window_minutes * 60
        recent = [(t, c) for t, c in self.coverage_history if t >= cutoff]
        if len(recent) < 2:
            return False
        first_cov = recent[0][1]
        last_cov = recent[-1][1]
        if first_cov == 0:
            return False
        growth = (last_cov - first_cov) / first_cov
        return growth < threshold

    def is_global_plateau(
        self,
        *,
        window_minutes: float = 60.0,
        threshold: float = 0.01,
    ) -> bool:
        """Return True when ALL arms have plateaued (no arm found new coverage).

        A global plateau triggers harness re-synthesis (Phase 18).
        """
        if not self.coverage_history:
            return False
        # Check if any arm has succeeded recently.
        cutoff = time.time() - window_minutes * 60
        recent_history = [(t, c) for t, c in self.coverage_history if t >= cutoff]
        if len(recent_history) < 2:
            return False
        first_cov = recent_history[0][1]
        last_cov = recent_history[-1][1]
        if first_cov == 0:
            return False
        growth = (last_cov - first_cov) / first_cov
        global_plateau = growth < threshold
        # Also check: every arm must have at least one trial in this window.
        total_trials_recent = sum(self.trials.get(a.arm_id, 0) for a in self.arms)
        return global_plateau and total_trials_recent > 0


class PivotStrategyInput(_StrictModel):
    """Input to the ``pivot_strategy`` activity."""

    campaign_id: str = Field(..., min_length=1, max_length=36)
    mab_state: MabState = Field(default_factory=MabState)
    current_coverage: int = Field(default=0, ge=0)
    current_exec_rate: float = Field(default=0.0, ge=0.0)
    elapsed_seconds: float = Field(default=0.0, ge=0.0)


class PivotStrategyOutput(_StrictModel):
    """Result of the ``pivot_strategy`` activity."""

    should_pivot: bool = False
    new_arm_id: str = Field(default="", max_length=64)
    new_arm: StrategyArm | None = None
    reason: str = Field(default="", max_length=512)
    mab_state: MabState = Field(default_factory=MabState)


# ── Coverage-Guided Harness Evolution ─────────────────────────────────────────
class BlockerType(StrEnum):
    """Classification of coverage blockers."""

    MAGIC_VALUE = "magic_value"
    LENGTH_CHECK = "length_check"
    NULL_CHECK = "null_check"
    FORMAT_CHECK = "format_check"
    CHECKSUM = "checksum"
    STATE_MACHINE = "state_machine"
    INITIALIZATION = "initialization"
    UNKNOWN = "unknown"


class CoverageBlocker(_StrictModel):
    """A single coverage blocker identified by the analysis agent.

    Attributes
    ----------
    blocker_type:
        What kind of check is blocking coverage (magic value, length, etc.).
    line_number:
        Source line of the blocking condition.
    function_name:
        Function containing the blocker.
    condition_text:
        The actual condition expression (e.g. ``if (header.magic != 0x89PNG)``).
    expected_value:
        The value needed to pass the check (if known).
    distance_from_entry:
        Number of basic blocks from the entry point to this blocker.
    confidence:
        0.0-1.0 confidence that this is the actual blocker.
    """

    blocker_type: BlockerType = Field(default=BlockerType.UNKNOWN)
    line_number: int = Field(default=0, ge=0)
    function_name: str = Field(default="", max_length=256)
    condition_text: str = Field(default="", max_length=1024)
    expected_value: str = Field(default="", max_length=256)
    distance_from_entry: int = Field(default=0, ge=0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class CoverageAnalysis(_StrictModel):
    """Result of coverage analysis for a single campaign iteration.

    Attributes
    ----------
    total_edges:
        Total control-flow edges in the target.
    edges_hit:
        Edges actually reached by the fuzzer.
    edges_missed:
        Edges never reached.
    hit_rate:
        Fraction of edges reached (0.0-1.0).
    blockers:
        Ordered list of suspected coverage blockers, best-first.
    unreachable_functions:
        Functions never called by any seed.
    notes:
        Human-readable summary.
    """

    total_edges: int = Field(default=0, ge=0)
    edges_hit: int = Field(default=0, ge=0)
    edges_missed: int = Field(default=0, ge=0)
    hit_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    blockers: list[CoverageBlocker] = Field(default_factory=list)
    unreachable_functions: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=4096)


class EvolveHarnessInput(_StrictModel):
    """Input to the harness evolution agent.

    Attributes
    ----------
    current_harness_code:
        The harness that produced the plateaued coverage.
    blocker:
        The coverage blocker to bypass.
    target_source_path:
        Path to the source file containing the blocker.
    target_function:
        Function being fuzzed.
    iteration:
        Evolution iteration count (0 = first attempt).
    max_iterations:
        Hard cap on evolution attempts.
    """

    current_harness_code: str = Field(..., min_length=1, max_length=65536)
    blocker: CoverageBlocker = Field(default_factory=CoverageBlocker)
    target_source_path: str = Field(default="", max_length=512)
    target_function: str = Field(default="", max_length=256)
    iteration: int = Field(default=0, ge=0)
    max_iterations: int = Field(default=3, ge=1, le=10)


class EvolveHarnessOutput(_StrictModel):
    """Result of harness evolution.

    Attributes
    ----------
    evolved_harness_code:
        The rewritten harness that attempts to bypass the blocker.
    bypass_strategy:
        Description of how the evolution tries to bypass the blocker.
    confidence:
        0.0-1.0 confidence in the evolved harness.
    compilation_command:
        Suggested compiler invocation.
    notes:
        Human-readable explanation.
    """

    evolved_harness_code: str = Field(default="", max_length=65536)
    bypass_strategy: str = Field(default="", max_length=512)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    compilation_command: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)


class HotSwapInput(_StrictModel):
    """Input to the ``hot_swap_harness`` activity.

    Attributes
    ----------
    job_id:
        Running fuzzing job to hot-swap.
    new_harness_code:
        Evolved harness source code.
    compilation_command:
        Compiler invocation for the new harness.
    preserve_corpus:
        Whether to copy the existing corpus before swap.
    """

    job_id: str = Field(..., min_length=1, max_length=64)
    new_harness_code: str = Field(..., min_length=1, max_length=65536)
    compilation_command: str = Field(default="", max_length=1024)
    preserve_corpus: bool = True


class HotSwapOutput(_StrictModel):
    """Result of hot-swapping a harness.

    Attributes
    ----------
    swapped:
        Whether the swap succeeded.
    binary_path:
        Path to the newly compiled binary.
    preserved_corpus_path:
        Where the old corpus was saved (if preserved).
    stdout:
        Compilation output.
    stderr:
        Compilation errors.
    notes:
        Human-readable summary.
    """

    swapped: bool = False
    binary_path: Path | None = None
    preserved_corpus_path: Path | None = None
    stdout: str = Field(default="", max_length=8192)
    stderr: str = Field(default="", max_length=8192)
    notes: str = Field(default="", max_length=4096)
