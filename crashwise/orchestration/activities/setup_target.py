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
import re
import shutil
from contextlib import suppress
from pathlib import Path

from temporalio import activity
from temporalio.exceptions import ApplicationError

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger
from crashwise.core.models import SetupTargetInput, SetupTargetOutput

log = get_logger(__name__)

# Maximum time for git clone (large repos like chromium can be slow).
_CLONE_TIMEOUT_SECONDS: float = 600.0


def _get_build_timeout() -> float:
    """Return configured target build timeout in seconds."""
    try:
        return float(get_settings().crashwise_build_timeout)
    except Exception:
        return 900.0


@activity.defn(name="setup_target")
async def setup_target(payload: SetupTargetInput) -> SetupTargetOutput:
    """Clone, build, and prepare a target for fuzzing.

    The activity is idempotent within a single workflow attempt: re-running
    against the same workdir wipes and recreates it.
    """
    try:
        info = activity.info()
        workflow_id = info.workflow_id or "anonymous"
        attempt = info.attempt
    except Exception:
        workflow_id = "anonymous"
        attempt = 1

    settings = get_settings()
    workdir_root = settings.crashwise_workdir / workflow_id
    workdir = workdir_root / "target"

    log.info(
        "setup_target.start",
        workflow_id=workflow_id,
        attempt=attempt,
        target_repo=str(payload.target_repo),
        target_name=payload.target_name,
        target_subdir=payload.target_subdir,
        target_clone_depth=payload.target_clone_depth,
        target_branch=payload.target_branch,
        sanitizers=payload.sanitizers,
        synthesize_harness=payload.synthesize_harness,
    )

    # Enforce path traversal protection on target_subdir upfront
    if payload.target_subdir:
        candidate_dir = (workdir / payload.target_subdir).resolve()
        if not candidate_dir.is_relative_to(workdir.resolve()):
            raise ApplicationError(
                f"Path traversal detected in target_subdir: {payload.target_subdir}",
                type="InvalidSubdirectory",
                non_retryable=True,
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
        clone_depth=payload.target_clone_depth,
    )

    # Resolve component directory within monorepo
    if payload.target_subdir:
        component_dir = (workdir / payload.target_subdir).resolve()
        if not component_dir.is_relative_to(workdir.resolve()):
            raise ApplicationError(
                f"Path traversal detected in target_subdir: {payload.target_subdir}",
                type="InvalidSubdirectory",
                non_retryable=True,
            )
        if not component_dir.is_dir():
            raise ApplicationError(
                f"Target subdirectory does not exist: {payload.target_subdir}",
                type="DirectoryNotFound",
                non_retryable=True,
            )
    else:
        component_dir = workdir

    # ── 2. Detect build system and build ─────────────────────────────────
    await _build_target(
        workdir=component_dir,
        sanitizers=payload.sanitizers,
    )

    # ── 3. Detect existing harness or synthesize one ─────────────────────
    harness_path: Path | None = None

    # First: check if the target already has a fuzz harness.
    existing_harness = _detect_existing_harness(component_dir)
    if existing_harness:
        log.info(
            "setup_target.existing_harness_found",
            path=str(existing_harness),
        )
        # Compile the existing harness with sanitizer instrumentation.
        compiled = await _compile_harness(
            harness_source=existing_harness,
            workdir=component_dir,
            sanitizers=payload.sanitizers,
            target_name=payload.target_name,
        )
        if compiled:
            harness_path = compiled

    # Second: if no existing harness (or it failed to compile), synthesize.
    if harness_path is None and payload.synthesize_harness:
        # Find the best source file to target for synthesis.
        source_path = payload.target_source_path
        if not source_path:
            source_path = _find_best_source_for_synthesis(component_dir)
        if source_path:
            harness_path = await _run_harness_synthesis(
                workdir=component_dir,
                target_source_path=source_path,
                max_retries=payload.max_synth_retries,
                workflow_id=workflow_id,
                fuzzer_type=payload.fuzzer_type,
            )

    output = SetupTargetOutput(
        workdir=component_dir,
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
    clone_depth: int = 1,
) -> str:
    """Clone or copy the target repository and return the HEAD commit SHA.

    Uses --depth <depth> if clone_depth > 0 for speed; full clone if 0.
    Falls back to full clone if shallow clone fails (some hosts reject it).
    Supports local filesystem paths and file:// URIs directly.
    """
    local_path = None
    if repo_url.startswith("file://"):
        local_path = Path(repo_url[7:])
    elif Path(repo_url).exists() and Path(repo_url).is_dir():
        local_path = Path(repo_url)

    if local_path and local_path.exists():
        log.info("setup_target.clone.local_path", path=str(local_path))
        if (local_path / ".git").exists():
            repo_url = str(local_path.resolve())
        else:
            shutil.rmtree(workdir, ignore_errors=True)
            shutil.copytree(local_path, workdir, symlinks=True, ignore_dangling_symlinks=True)
            init_proc = await asyncio.create_subprocess_exec(
                "git", "init", str(workdir),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await init_proc.communicate()
            return "local-snapshot"

    cmd = ["git", "clone", "--recursive"]
    if clone_depth > 0:
        cmd.extend(["--depth", str(clone_depth)])
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
    except TimeoutError as err:
        proc.kill()
        raise ApplicationError(
            f"git clone timed out after {_CLONE_TIMEOUT_SECONDS}s for {repo_url}",
            type="CloneTimeout",
            non_retryable=False,
        ) from err

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
            except TimeoutError as err2:
                proc2.kill()
                raise ApplicationError(
                    f"git clone (full) timed out for {repo_url}",
                    type="CloneTimeout",
                    non_retryable=False,
                ) from err2
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
    # Use -fsanitize=fuzzer-no-link for coverage instrumentation during build.
    # The actual fuzzer runtime (-fsanitize=fuzzer) is linked only in the harness.
    # Note: -fsanitize-coverage=trace-pc-guard is deprecated by modern libFuzzer.
    cov_flags = "-fsanitize=fuzzer-no-link"
    # Source-based coverage: produces default.profraw at runtime so llvm-cov
    # can generate line-level hit/miss data for ALL fuzzer types (including
    # AFL++). This closes the gap where AFL++ campaigns were permanently
    # stuck using the low-confidence static regex fallback.
    source_cov_flags = "-fprofile-instr-generate -fcoverage-mapping"
    common_flags = f"-g -O1 {san_flags} {cov_flags} {source_cov_flags} -fno-omit-frame-pointer -Wno-error"

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
        # Source-based coverage output path (consumed by _collect_coverage_data).
        "LLVM_PROFILE_FILE": "default.profraw",
    }

    build_cmd = profile.build_command

    # For CMake projects, disable -Werror and inject our instrumentation flags.
    if profile.build_system == "cmake":
        cmake_flags = common_flags.replace('"', '\\"')
        build_cmd = (
            # Strip -Werror from CMakeLists.txt to prevent warnings-as-errors.
            "find . -name CMakeLists.txt -exec sed -i 's/-Werror//g' {} + && "
            + build_cmd.replace(
                "cmake -B",
                f'cmake -DCMAKE_C_FLAGS="{cmake_flags}" -DCMAKE_CXX_FLAGS="{cmake_flags}" -B',
            )
        )
    elif profile.build_system == "bazel":
        san_val = sanitizers if sanitizers else "address,undefined"
        build_cmd = (
            f"bazel build --action_env=CC=clang --action_env=CXX=clang++ "
            f"--copt=-g --copt=-O1 --copt=-fsanitize={san_val} --copt=-fsanitize=fuzzer-no-link "
            f"--copt=-fprofile-instr-generate --copt=-fcoverage-mapping "
            f"--linkopt=-fsanitize={san_val} --linkopt=-fprofile-instr-generate //..."
        )
    elif profile.build_system == "meson":
        output_dir = profile.output_dir or "build"
        reconf_flag = " --reconfigure" if (workdir / output_dir).exists() else ""
        build_cmd = (
            f"meson setup {output_dir}{reconf_flag} --wrap-mode=nofallback && "
            f"meson compile -C {output_dir}"
        )
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
    build_timeout = _get_build_timeout()
    try:
        _stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=build_timeout
        )
    except TimeoutError:
        proc.kill()
        log.warning(
            "setup_target.build.timeout",
            command=build_cmd[:100],
            timeout=build_timeout,
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

    if profile.build_system == "bazel":
        _extract_bazel_artifacts(workdir)


def _extract_bazel_artifacts(workdir: Path) -> None:
    """Harvest .a and .so build artifacts from bazel-bin symlink/cache and copy to workdir/lib."""
    candidate_dirs: list[Path] = []
    bazel_bin = workdir / "bazel-bin"
    if bazel_bin.exists() or bazel_bin.is_symlink():
        candidate_dirs.append(bazel_bin)
        with suppress(Exception):
            candidate_dirs.append(bazel_bin.resolve())
    for p in workdir.glob("bazel-bin*"):
        if p not in candidate_dirs:
            candidate_dirs.append(p)
            with suppress(Exception):
                candidate_dirs.append(p.resolve())

    lib_dir = workdir / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    seen: set[str] = set()
    for bdir in candidate_dirs:
        if not bdir.exists():
            continue
        for ext in ("*.a", "*.so", "*.so.*"):
            for artifact in bdir.rglob(ext):
                if not artifact.is_file():
                    continue
                if artifact.name in seen:
                    continue
                try:
                    dest = lib_dir / artifact.name
                    shutil.copy2(artifact.resolve(), dest)
                    seen.add(artifact.name)
                    copied += 1
                except Exception as exc:
                    log.warning("setup_target.bazel.copy_failed", artifact=str(artifact), error=str(exc))

    log.info("setup_target.bazel.artifacts_extracted", count=copied, dest=str(lib_dir))


# ── Harness Detection ────────────────────────────────────────────────────────

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
        skip_dirs = {
            "test", "tests", "fuzz", "fuzzing", "examples", "example",
            "docs", "doc", "sample", "samples", "third_party", "vendor",
            ".git", "build", "CMakeFiles",
        }
        # Prioritize files whose name matches the function (compress→compress.c).
        candidates_by_name: list[Path] = []
        candidates_by_def: list[Path] = []
        for p in workdir.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in source_exts:
                continue
            try:
                rel_parts = [part.lower() for part in p.relative_to(workdir).parts[:-1]]
            except ValueError:
                rel_parts = [part.lower() for part in p.parts[:-1]]
            if any(part.startswith(".") or part in skip_dirs for part in rel_parts):
                continue
            if best_api.name.lower() in p.stem.lower() or p.stem.lower() in best_api.name.lower():
                candidates_by_name.append(p)
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")[:32000]
            except OSError:
                continue
            # Match function DEFINITION (function name followed by arguments and opening brace).
            pattern = rf"\b{re.escape(best_api.name)}\s*\([^;{{]*\)\s*\{{"
            if re.search(pattern, content, re.DOTALL | re.MULTILINE):
                candidates_by_def.append(p)
        # Prefer name-matched file, then definition-matched.
        best_candidates = candidates_by_name or candidates_by_def
        if best_candidates:
            return str(best_candidates[0])

    # ── Strategy 2: Fallback — scan .c files directly ────────────────────
    best_path: Path | None = None
    best_score: float = 0.0

    source_exts = {".c", ".cpp", ".cc", ".cxx"}
    skip_dirs = {"test", "tests", "examples", "docs", "third_party", "vendor", ".git"}

    high_value_names = {
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
        if any(name in stem for name in high_value_names):
            score += 0.5
        if len(eps) >= 3:
            score += 0.2
        if score > best_score:
            best_score = score
            best_path = p

    if best_path:
        return str(best_path)
    return None


def _rank_and_select_libraries(
    target_dir: Path,
    target_name: str | None = None,
) -> tuple[list[str], set[Path]]:
    """Enumerate and rank built libraries (.a and .so) for harness linking.

    Scores candidate libraries based on:
    - Exact match against target_name stem (e.g. libfoo.a or foo.a for target 'foo') -> +100
    - Substring match with target_name -> +50
    - Library file size (larger libraries generally contain the main codebase)

    Returns:
        tuple of (ordered list of library file paths as strings, set of directory Paths containing .so files for RPATH).
    """
    candidates: list[Path] = []
    skip_keywords = ("test", "tests", "example", "examples", "cmakefiles", "fuzz", "benchmark", "benchmarks")

    for ext in ("*.a", "*.so", "*.so.*"):
        for lib_file in target_dir.rglob(ext):
            if not lib_file.is_file():
                continue
            try:
                rel_parts = [part.lower() for part in lib_file.relative_to(target_dir).parts]
                rel_str = "/".join(rel_parts)
            except ValueError:
                rel_parts = [part.lower() for part in lib_file.parts]
                rel_str = lib_file.name.lower()
            if any(skip in rel_str for skip in skip_keywords):
                continue
            if lib_file not in candidates:
                candidates.append(lib_file)

    if not candidates:
        return [], set()

    scored: list[tuple[float, int, Path]] = []
    norm_target = target_name.lower().strip() if target_name else ""
    norm_target_clean = norm_target.removeprefix("lib").removesuffix(".git") if norm_target else ""

    for lib in candidates:
        score = 0.0
        try:
            size = lib.stat().st_size
        except OSError:
            size = 0

        stem = lib.stem.lower()
        stem_clean = stem.removeprefix("lib")

        if norm_target_clean:
            if stem == norm_target or stem_clean == norm_target_clean or stem == f"lib{norm_target_clean}":
                score += 100.0
            elif norm_target_clean in stem or stem_clean in norm_target_clean:
                score += 50.0

        size_mb = size / (1024 * 1024)
        score += min(20.0, size_mb)

        scored.append((score, size, lib))

    # Sort descending by score, then by size descending
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)

    ranked_libs = [item[2] for item in scored]
    rpath_dirs: set[Path] = {
        lib.parent.resolve()
        for lib in ranked_libs
        if ".so" in lib.name
    }

    return [str(p) for p in ranked_libs], rpath_dirs


async def _compile_harness(
    harness_source: Path,
    workdir: Path,
    sanitizers: str,
    target_name: str | None = None,
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
    # Auto-discover directories containing headers.
    for h in workdir.glob("*/*.h"):
        hdir = h.parent
        if "CMakeFiles" not in str(hdir):
            include_dirs.add(hdir)

    # Discover static libraries (.a) and shared libraries (.so) to link against.
    link_libs, rpath_dirs = _rank_and_select_libraries(workdir, target_name)

    # If no libraries found, try linking non-test .o files from build directory.
    if not link_libs:
        build_dir = workdir / "build"
        if build_dir.exists():
            obj_files = [
                o for o in build_dir.rglob("*.o")
                if not any(skip in str(o).lower() for skip in ("test", "example", "main", "unity", "fuzz"))
            ]
            if 0 < len(obj_files) <= 50:
                link_libs.extend(str(o) for o in obj_files)
    # If still no object files or static libs, link source files directly
    if not link_libs:
        src_files = [
            str(f)
            for f in list(workdir.rglob("*.c")) + list(workdir.rglob("*.cpp")) + list(workdir.rglob("*.cc"))
            if f.resolve() != harness_source.resolve()
            and "test" not in str(f).lower()
            and "fuzz" not in str(f).lower()
            and "example" not in str(f).lower()
            and "build" not in str(f).lower()
        ]
        if src_files:
            link_libs.extend(src_files)

    cmd = [
        "clang++",
        san_flags,
        "-g", "-O1",
        "-fno-omit-frame-pointer",
    ]
    # Define HAVE_CONFIG_H if config.h exists (needed by libarchive, etc).
    if (workdir / "build" / "config.h").exists() or (workdir / "config.h").exists():
        cmd.append("-DHAVE_CONFIG_H")
    for inc in include_dirs:
        cmd.append(f"-I{inc}")
    for rd in sorted(rpath_dirs):
        cmd.append(f"-Wl,-rpath,{rd.resolve()}")
    cmd.extend(["-o", str(binary_path), str(harness_source)])
    cmd.extend(link_libs)
    # Common system libs that targets often need (after .a files for link order).
    cmd.extend(["-lm", "-lz", "-lbz2", "-llzma", "-lssl", "-lcrypto", "-lxml2", "-lpthread"])
    # Common system libs that targets often need (after .a files for link order).
    cmd.extend(["-lm", "-lz", "-lbz2", "-llzma", "-lssl", "-lcrypto", "-lxml2", "-lpthread"])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(workdir),
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
    except TimeoutError:
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
    fuzzer_type: str = "libfuzzer",
) -> Path | None:
    """Drive the Phase-2 harness agent and return the compiled-binary path."""
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

    # Map fuzzer_type to engine name for harness synthesis.
    engine = "aflpp" if "afl" in fuzzer_type.lower() else "libfuzzer"

    # Operation Hydra Phase 2: Mine usage examples from tests/examples.
    usage_example = _find_usage_example(workdir, source)

    synth_workdir = workdir / "harness"
    result = await synthesize_harness(
        source_path=source,
        workdir=synth_workdir,
        max_retries=max_retries,
        usage_example=usage_example,
        engine=engine,
    )

    log.info(
        "setup_target.synth.done",
        workflow_id=workflow_id,
        success=result.success,
        simplified=result.simplified,
        retries=result.retry_count,
        binary=str(result.binary_path) if result.binary_path else None,
    )
    return result.binary_path


def _find_usage_example(workdir: Path, source_path: Path) -> str:
    """Mine tests/examples for a code snippet showing how the target API is called.

    Operation Hydra Phase 2: Context Enrichment.
    Scans test/example directories for files that call functions defined in
    the target source, extracts a relevant snippet as a reference pattern.
    """
    import re as _re

    # Find function names defined in the target source.
    try:
        source_content = source_path.read_text(encoding="utf-8", errors="replace")[:8000]
    except OSError:
        return ""

    target_funcs: set[str] = set()
    for m in _re.finditer(r"^\w[\w\s\*]*\s+(\w+)\s*\([^)]*\)\s*\{", source_content, _re.MULTILINE):
        name = m.group(1)
        if name not in ("main", "if", "for", "while", "switch", "static"):
            target_funcs.add(name)

    if not target_funcs:
        return ""

    # Search in test/example directories.
    search_dirs = []
    for name in ("test", "tests", "example", "examples", "contrib"):
        candidate = workdir / name
        if candidate.is_dir():
            search_dirs.append(candidate)
    # Also check root-level test files.
    search_dirs.append(workdir)

    source_exts = {".c", ".cpp", ".cc", ".cxx", ".h"}

    for search_dir in search_dirs:
        for p in search_dir.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in source_exts:
                continue
            if p == source_path:
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")[:12000]
            except OSError:
                continue

            # Find a function call to any of our target functions.
            for func_name in target_funcs:
                pattern = rf"\b{_re.escape(func_name)}\s*\("
                match = _re.search(pattern, content)
                if match:
                    # Extract surrounding context (10 lines before, 15 after).
                    lines = content.splitlines()
                    match_line = content[:match.start()].count("\n")
                    start = max(0, match_line - 10)
                    end = min(len(lines), match_line + 15)
                    snippet = "\n".join(lines[start:end])

                    log.info(
                        "setup_target.usage_example_found",
                        function=func_name,
                        file=str(p.relative_to(workdir)),
                        line=match_line + 1,
                    )
                    return (
                        f"// Reference: how '{func_name}' is called in {p.name}:\n"
                        f"{snippet}"
                    )

    return ""


__all__ = ["setup_target"]
