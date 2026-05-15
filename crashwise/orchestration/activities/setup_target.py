# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``setup_target`` activity — clones the target repository, builds it
with sanitizer instrumentation, and optionally synthesizes a harness.

This activity performs the real work of onboarding ANY C/C++ project:

  1. ``git clone`` (with optional branch/tag/commit checkout)
  2. Detect build system via :mod:`crashwise.core.discovery`
  3. Build the target with ``-fsanitize=address,undefined`` and
     ``-fsanitize-coverage=trace-pc-guard,trace-cmp`` for coverage feedback
  4. Detect or synthesize a fuzz harness
  5. Compile the harness linked against the instrumented target

The activity is idempotent: re-running against the same workdir wipes
and recreates it (safe for Temporal activity retries).
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from temporalio import activity
from temporalio.exceptions import ApplicationError

from crashwise.core.logging import get_logger
from crashwise.core.models import SetupTargetInput, SetupTargetOutput

log = get_logger(__name__)

# Maximum time for git clone (large repos like chromium can be slow).
_CLONE_TIMEOUT_SECONDS: float = 600.0
# Maximum time for build step.
_BUILD_TIMEOUT_SECONDS: float = 900.0


@activity.defn(name="setup_target")
async def setup_target(payload: SetupTargetInput) -> SetupTargetOutput:
    """Clone, build, and prepare a target for fuzzing.

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

    # ── 1. Clone the repository ──────────────────────────────────────────
    commit_sha = await _clone_repo(
        repo_url=str(payload.target_repo),
        branch=payload.target_branch,
        workdir=workdir,
    )

    # ── 2. Detect build system and build ─────────────────────────────────
    await _build_target(
        workdir=workdir,
        sanitizers=payload.sanitizers,
    )

    # ── 3. Detect existing harness or synthesize one ─────────────────────
    harness_path: Path | None = None

    # First: check if the target already has a fuzz harness.
    existing_harness = _detect_existing_harness(workdir)
    if existing_harness:
        log.info(
            "setup_target.existing_harness_found",
            path=str(existing_harness),
        )
        # Compile the existing harness with sanitizer instrumentation.
        compiled = await _compile_harness(
            harness_source=existing_harness,
            workdir=workdir,
            sanitizers=payload.sanitizers,
        )
        if compiled:
            harness_path = compiled

    # Second: if no existing harness (or it failed to compile), synthesize.
    if harness_path is None and payload.synthesize_harness:
        # Find the best source file to target for synthesis.
        source_path = payload.target_source_path
        if not source_path:
            source_path = _find_best_source_for_synthesis(workdir)
        if source_path:
            harness_path = await _run_harness_synthesis(
                workdir=workdir,
                target_source_path=source_path,
                max_retries=payload.max_synth_retries,
                workflow_id=workflow_id,
            )

    output = SetupTargetOutput(
        workdir=workdir,
        commit_sha=commit_sha,
        harness_path=harness_path,
    )

    log.info(
        "setup_target.complete",
        workflow_id=workflow_id,
        workdir=str(output.workdir),
        commit_sha=output.commit_sha[:12],
        harness_path=str(output.harness_path) if output.harness_path else None,
    )
    return output


# ── Git Clone ────────────────────────────────────────────────────────────────


async def _clone_repo(
    repo_url: str,
    branch: str | None,
    workdir: Path,
) -> str:
    """Clone the target repository and return the HEAD commit SHA.

    Uses --depth 1 for speed on initial clone; recursive for submodules.
    Falls back to full clone if shallow clone fails (some hosts reject it).
    """
    cmd = ["git", "clone", "--recursive", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([repo_url, str(workdir)])

    log.info("setup_target.clone.start", repo=repo_url, branch=branch)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_CLONE_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        proc.kill()
        raise ApplicationError(
            f"git clone timed out after {_CLONE_TIMEOUT_SECONDS}s for {repo_url}",
            type="CloneTimeout",
            non_retryable=False,
        )

    if proc.returncode != 0:
        err_text = stderr.decode("utf-8", errors="replace")[:500]
        # Retry without --depth 1 (some repos reject shallow clones).
        if "--depth" in " ".join(cmd):
            log.warning("setup_target.clone.shallow_failed", error=err_text[:200])
            cmd_full = ["git", "clone", "--recursive"]
            if branch:
                cmd_full.extend(["--branch", branch])
            cmd_full.extend([repo_url, str(workdir)])
            shutil.rmtree(workdir, ignore_errors=True)
            workdir.mkdir(parents=True, exist_ok=True)
            proc2 = await asyncio.create_subprocess_exec(
                *cmd_full,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr2 = await asyncio.wait_for(
                    proc2.communicate(), timeout=_CLONE_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                proc2.kill()
                raise ApplicationError(
                    f"git clone (full) timed out for {repo_url}",
                    type="CloneTimeout",
                    non_retryable=False,
                )
            if proc2.returncode != 0:
                raise ApplicationError(
                    f"git clone failed: {stderr2.decode('utf-8', errors='replace')[:300]}",
                    type="CloneFailed",
                    non_retryable=True,
                )

    # Get the actual commit SHA.
    sha_proc = await asyncio.create_subprocess_exec(
        "git", "-C", str(workdir), "rev-parse", "HEAD",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await sha_proc.communicate()
    commit_sha = stdout.decode("utf-8", errors="replace").strip()
    if not commit_sha or len(commit_sha) < 7:
        commit_sha = "unknown"

    log.info("setup_target.clone.complete", sha=commit_sha[:12])
    return commit_sha


# ── Build ────────────────────────────────────────────────────────────────────


async def _build_target(workdir: Path, sanitizers: str) -> None:
    """Detect build system and compile the target with instrumentation.

    Sets CC/CXX/CFLAGS/CXXFLAGS to inject sanitizer and coverage
    instrumentation into the build, regardless of the build system.
    """
    from crashwise.core.discovery import discover_project

    profile = discover_project(workdir)
    if profile is None:
        log.warning("setup_target.build.no_build_system_detected", workdir=str(workdir))
        return

    # Construct sanitizer flags.
    san_flags = f"-fsanitize={sanitizers}" if sanitizers else ""
    cov_flags = "-fsanitize-coverage=trace-pc-guard,trace-cmp"
    common_flags = f"-g -O1 {san_flags} {cov_flags} -fno-omit-frame-pointer"

    # Environment: inject instrumentation into whatever build system runs.
    env = {
        "CC": "clang",
        "CXX": "clang++",
        "CFLAGS": common_flags,
        "CXXFLAGS": common_flags,
        "LDFLAGS": san_flags,
        # AFL++ compatibility.
        "AFL_CC": "clang",
        "AFL_CXX": "clang++",
    }

    build_cmd = profile.build_command
    log.info(
        "setup_target.build.start",
        system=profile.build_system,
        command=build_cmd[:200],
        language=profile.language,
    )

    # Run the build command.
    import os
    full_env = {**os.environ, **env}

    proc = await asyncio.create_subprocess_shell(
        build_cmd,
        cwd=str(workdir),
        env=full_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_BUILD_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        proc.kill()
        log.warning(
            "setup_target.build.timeout",
            command=build_cmd[:100],
            timeout=_BUILD_TIMEOUT_SECONDS,
        )
        return

    if proc.returncode != 0:
        err_text = stderr.decode("utf-8", errors="replace")
        log.warning(
            "setup_target.build.failed",
            returncode=proc.returncode,
            stderr=err_text[:500],
        )
        # Build failure is NOT fatal — harness synthesis can still work
        # by #including the source directly.
    else:
        log.info("setup_target.build.success", system=profile.build_system)


# ── Harness Detection ────────────────────────────────────────────────────────

import re

_HARNESS_PATTERNS = re.compile(
    r"(fuzz|harness|LLVMFuzzerTestOneInput)",
    re.IGNORECASE,
)


def _detect_existing_harness(workdir: Path) -> Path | None:
    """Search for an existing fuzz harness in the cloned repository.

    Many open-source projects (libjxl, libpng, openssl) ship their own
    fuzz targets. Using these is always better than LLM-generated ones.
    """
    candidates: list[tuple[Path, int]] = []
    for p in workdir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".c", ".cpp", ".cc", ".cxx"):
            continue
        # Score by how "fuzzy" the filename/content looks.
        name_lower = p.name.lower()
        if "fuzz" in name_lower or "harness" in name_lower:
            # Check content for LLVMFuzzerTestOneInput.
            try:
                content = p.read_text(encoding="utf-8", errors="replace")[:4000]
                if "LLVMFuzzerTestOneInput" in content:
                    # Perfect: this IS a libFuzzer harness.
                    depth = len(p.relative_to(workdir).parts)
                    candidates.append((p, depth))
            except OSError:
                pass

    if not candidates:
        return None

    # Pick the shallowest (closest to root) harness.
    candidates.sort(key=lambda x: x[1])
    return candidates[0][0]


def _find_best_source_for_synthesis(workdir: Path) -> str | None:
    """Find the most promising source file for harness synthesis.

    Strategy (Operation Hydra):
    1. First, scan PUBLIC HEADERS to find the real API surface.
       If a high-scoring header API is found, locate its implementation .c file.
    2. Fall back to scanning .c files directly if no headers found.
    """
    from crashwise.agents.harness_synth.analyzer import find_entry_points, find_public_api

    # ── Strategy 1: Header-aware API discovery ───────────────────────────
    api_entries = find_public_api(workdir, max_results=5)
    if api_entries and api_entries[0].score >= 0.5:
        best_api = api_entries[0]
        log.info(
            "setup_target.api_discovery",
            function=best_api.name,
            score=best_api.score,
            strategy="header_scan",
        )
        # Find the .c file that implements this function.
        source_exts = {".c", ".cpp", ".cc", ".cxx"}
        for p in workdir.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in source_exts:
                continue
            if ".git" in str(p) or "test" in p.parts:
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")[:16000]
            except OSError:
                continue
            # Look for the function definition (not just declaration).
            if re.search(rf"\b{re.escape(best_api.name)}\s*\(", content):
                return str(p)

    # ── Strategy 2: Fallback — scan .c files directly ────────────────────
    best_path: Path | None = None
    best_score: float = 0.0

    source_exts = {".c", ".cpp", ".cc", ".cxx"}
    skip_dirs = {"test", "tests", "examples", "docs", "third_party", "vendor", ".git"}

    _HIGH_VALUE_NAMES = {
        "inflate", "deflate", "decompress", "compress", "decode", "parse",
        "read", "unpack", "deserialize", "load", "import", "extract",
        "process", "handle", "dispatch", "recv", "input",
    }

    for p in workdir.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in source_exts:
            continue
        if any(part in skip_dirs for part in p.relative_to(workdir).parts):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")[:8000]
        except OSError:
            continue
        eps = find_entry_points(content)
        if not eps:
            continue
        score = eps[0].score
        stem = p.stem.lower()
        if any(name in stem for name in _HIGH_VALUE_NAMES):
            score += 0.5
        if len(eps) >= 3:
            score += 0.2
        if score > best_score:
            best_score = score
            best_path = p

    if best_path:
        return str(best_path)
    return None


# ── Harness Compilation ──────────────────────────────────────────────────────


async def _compile_harness(
    harness_source: Path,
    workdir: Path,
    sanitizers: str,
) -> Path | None:
    """Compile an existing harness source with sanitizer instrumentation.

    Automatically discovers built static libraries (.a) and object files
    in the workdir to link against the target.

    Returns the binary path on success, None on failure.
    """
    binary_path = workdir / "harness_binary"
    san_flags = f"-fsanitize=fuzzer,{sanitizers}" if sanitizers else "-fsanitize=fuzzer"

    # Discover include paths: add common subdirectories.
    include_dirs = {harness_source.parent, workdir}
    for subdir in ("include", "src", "lib", "build"):
        candidate = workdir / subdir
        if candidate.is_dir():
            include_dirs.add(candidate)

    # Discover static libraries (.a) and object files to link against.
    link_libs: list[str] = []
    for lib_file in workdir.rglob("*.a"):
        # Skip test/example libraries.
        if any(skip in str(lib_file) for skip in ("test", "example", "CMakeFiles")):
            continue
        link_libs.append(str(lib_file))
    # If no .a found, try linking .o files from build directory.
    if not link_libs:
        build_dir = workdir / "build"
        if build_dir.exists():
            obj_files = list(build_dir.rglob("*.o"))
            # Only link if reasonable number of objects (not hundreds).
            if 0 < len(obj_files) <= 50:
                link_libs.extend(str(o) for o in obj_files)

    cmd = [
        "clang++",
        san_flags,
        "-g", "-O1",
        "-fno-omit-frame-pointer",
    ]
    for inc in include_dirs:
        cmd.append(f"-I{inc}")
    cmd.extend(["-o", str(binary_path), str(harness_source)])
    cmd.extend(link_libs)
    # Common system libs that targets often need.
    cmd.extend(["-lm", "-lz", "-lpthread"])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(workdir),
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
    except asyncio.TimeoutError:
        proc.kill()
        return None

    if proc.returncode == 0 and binary_path.exists():
        log.info("setup_target.compile_harness.success", binary=str(binary_path))
        return binary_path

    log.warning(
        "setup_target.compile_harness.failed",
        returncode=proc.returncode,
        stderr=stderr.decode("utf-8", errors="replace")[:300],
    )
    return None


# ── Harness Synthesis ────────────────────────────────────────────────────────


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
