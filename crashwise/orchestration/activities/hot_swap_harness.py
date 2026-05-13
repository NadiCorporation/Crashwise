# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``hot_swap_harness`` activity — compiles and deploys an evolved harness
without stopping the fuzzing campaign.

The activity:

  1. Writes the LLM-generated harness source to a temp directory.
  2. Compiles it with a hardened, *non-shell* invocation (B6).
  3. Moves the resulting binary to a permanent ``build_cache/`` so the
     caller can keep a stable path after the temp directory is cleaned
     up (B5).
  4. Copies the surviving corpus out of any still-running fuzzer
     container that matches ``job_id``, so the new harness inherits the
     coverage frontier instead of starting cold (B5).

Hardening posture
-----------------

* **No shell.** ``compilation_command`` is parsed with :func:`shlex.split`
  and executed via ``asyncio.create_subprocess_exec``.  Shell metacharacters
  in an LLM response no longer translate into RCE on the worker host.
* **Compiler allowlist.** The first token must be one of a small set of
  known compiler binaries (``cc``, ``gcc``, ``clang``, ``clang++``, etc.).
  Anything else aborts with ``swapped=False``.
* **Persistent binary.** The compiled artefact is moved to
  ``$CRASHWISE_BUILD_CACHE`` (default ``/var/cache/crashwise/build``) under
  a deterministic ``{job_id}/{iteration}`` path, then returned.  The
  ``TemporaryDirectory`` is allowed to disappear without orphaning the
  binary path.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import shutil
import tempfile
from pathlib import Path

from temporalio import activity

from crashwise.core.logging import get_logger
from crashwise.core.models import HotSwapInput, HotSwapOutput

log = get_logger(__name__)


# Compilers we are willing to invoke on LLM-generated source. Anything
# else is treated as a prompt-injection attempt.
_ALLOWED_COMPILERS: frozenset[str] = frozenset(
    {
        "cc",
        "gcc",
        "g++",
        "clang",
        "clang++",
        "clang-15",
        "clang-16",
        "clang-17",
        "clang-18",
        "afl-gcc",
        "afl-gcc-fast",
        "afl-clang",
        "afl-clang-fast",
        "afl-clang++",
        "afl-clang-fast++",
    }
)


def _build_cache_root() -> Path:
    """Return the persistent build-cache root.

    Honours ``$CRASHWISE_BUILD_CACHE`` for tests / sandboxed deployments;
    otherwise falls back to a host-writable system path. Creates the
    directory on first use.
    """
    override = os.environ.get("CRASHWISE_BUILD_CACHE")
    if override:
        root = Path(override)
    else:
        # Prefer /var/cache when writable (Linux servers); otherwise fall
        # back to ~/.cache/crashwise/build for dev workstations.
        candidate = Path("/var/cache/crashwise/build")
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # Probe writability.
            probe = candidate / ".write-probe"
            probe.touch()
            probe.unlink()
            root = candidate
        except (OSError, PermissionError):
            root = Path.home() / ".cache" / "crashwise" / "build"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _validate_compile_argv(argv: list[str]) -> tuple[bool, str]:
    """Reject obviously hostile compile commands.

    Returns ``(ok, reason)``. A failed validation must abort the swap;
    we never want to ``exec`` an LLM-supplied program that is not a
    compiler from the allowlist.
    """
    if not argv:
        return False, "empty compile argv"
    compiler = Path(argv[0]).name  # tolerate absolute paths like /usr/bin/clang
    if compiler not in _ALLOWED_COMPILERS:
        return False, f"compiler {compiler!r} not in allowlist"
    # Any token containing a shell metachar is suspicious; we use exec()
    # so it is not interpreted, but reject anyway to surface the attempt.
    forbidden = {";", "&&", "||", "|", "$(", "`", ">", "<"}
    for tok in argv[1:]:
        if any(seq in tok for seq in forbidden):
            return False, f"forbidden shell metachar in arg {tok!r}"
    return True, ""


def _materialise_compile_argv(
    template: str,
    src_path: Path,
    binary_path: Path,
) -> list[str]:
    """Turn an LLM-supplied compile-command string into an exec argv.

    The template may include the literal placeholders ``harness.cpp``
    (replaced with ``src_path``) and a ``-o harness`` pair (replaced with
    ``-o {binary_path}``). The result is split with :func:`shlex.split`
    so quoting is honoured but no subshell is invoked.
    """
    if not template.strip():
        # Safe default for the bare-bones generic harness.
        return [
            "clang++",
            "-fsanitize=address,undefined",
            "-g",
            "-O1",
            "-fno-omit-frame-pointer",
            "-o",
            str(binary_path),
            str(src_path),
        ]

    # Replace the literal source placeholder.
    cmd = template.replace("harness.cpp", str(src_path))
    argv = shlex.split(cmd)

    # Replace ``-o harness`` with ``-o <binary_path>``.
    for i, tok in enumerate(argv):
        if tok == "harness" and i > 0 and argv[i - 1] == "-o":
            argv[i] = str(binary_path)
            break
    else:
        # No explicit -o; append one.
        argv.extend(["-o", str(binary_path)])
    return argv


async def _preserve_corpus_from_container(
    job_id: str, dest_dir: Path
) -> Path | None:
    """Best-effort: pull the live corpus out of a container named after ``job_id``.

    Uses a singleton-style ``DockerManager`` lookup; if the manager has no
    record of this job (e.g. fuzzing is happening on a different worker),
    fall back to a no-op and let the caller continue with a cold corpus.
    """
    try:
        from crashwise.execution.docker_manager import DockerManager

        mgr = DockerManager()
        # The DockerManager state is per-instance; absent persistent state
        # we attempt an unconditional ``docker cp`` against the conventional
        # container name. Errors are swallowed.
        container_name = f"crashwise-{job_id}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "cp",
            f"{container_name}:/corpus",
            str(dest_dir),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, _ = await proc.communicate()
        if proc.returncode == 0:
            return dest_dir
        # Manager-level fallback (only useful on the same worker process).
        if job_id in mgr._containers:  # pragma: no cover - defensive
            return await mgr.preserve_corpus(job_id, dest_dir)
    except Exception as exc:  # broad-except
        log.debug("hot_swap.preserve_corpus_skipped", error=str(exc))
    return None


@activity.defn(name="hot_swap_harness")
async def hot_swap_harness(payload: HotSwapInput) -> HotSwapOutput:
    """Compile and hot-swap an evolved harness.

    Parameters
    ----------
    payload:
        job_id, new harness code, compilation command, and corpus
        preservation flag.

    Returns
    -------
    :class:`HotSwapOutput` with swap status, persistent binary path, and
    preserved corpus path.
    """
    info = activity.info()
    log.info(
        "hot_swap.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        job_id=payload.job_id,
        preserve=payload.preserve_corpus,
    )

    # Build cache slot — survives the temp dir.
    cache_root = _build_cache_root()
    job_cache = cache_root / payload.job_id
    job_cache.mkdir(parents=True, exist_ok=True)
    persistent_binary = job_cache / "harness"
    persistent_corpus = job_cache / "corpus_preserved"

    with tempfile.TemporaryDirectory(prefix="crashwise-swap-") as tmpdir:
        workdir = Path(tmpdir)

        # 1. Write evolved harness source.
        src_path = workdir / "harness.cpp"
        src_path.write_text(payload.new_harness_code, encoding="utf-8")

        # 2. Build a safe argv for compilation.
        tmp_binary = workdir / "harness"
        argv = _materialise_compile_argv(
            payload.compilation_command, src_path, tmp_binary
        )
        ok, reason = _validate_compile_argv(argv)
        if not ok:
            log.warning(
                "hot_swap.compile_rejected",
                job_id=payload.job_id,
                reason=reason,
                argv0=argv[0] if argv else "",
            )
            return HotSwapOutput(
                swapped=False,
                stdout="",
                stderr=f"compile-command validation failed: {reason}",
                notes=(
                    "Refused to invoke LLM-supplied compile command "
                    f"({reason}). Keeping current binary."
                ),
            )

        # 3. Compile WITHOUT a shell. ``shell=False`` is implicit in
        # ``create_subprocess_exec``; metacharacters in ``argv`` cannot
        # spawn subshells.
        # Timeout: 5 minutes max for compilation. Pathological headers or
        # template metaprogramming can hang clang indefinitely without this.
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workdir),
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=300.0  # 5-minute compile timeout.
            )
        except asyncio.TimeoutError:
            # Kill the stuck compiler.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            log.warning(
                "hot_swap.compile_timeout",
                job_id=payload.job_id,
                timeout_seconds=300,
            )
            return HotSwapOutput(
                swapped=False,
                stdout="",
                stderr="Compilation timed out after 300 seconds.",
                notes=(
                    "Compilation of evolved harness exceeded 5-minute limit. "
                    "Likely pathological template expansion or infinite loop "
                    "in preprocessor. Keeping current binary."
                ),
            )
        # HotSwapOutput caps stdout/stderr at 8192 chars (see models.py).
        stdout = stdout_b.decode("utf-8", errors="replace")[:8000]
        stderr = stderr_b.decode("utf-8", errors="replace")[:8000]
        compile_ok = proc.returncode == 0

        if not compile_ok or not tmp_binary.exists():
            log.warning(
                "hot_swap.compile_failed",
                job_id=payload.job_id,
                rc=proc.returncode,
                stderr=stderr[:500],
            )
            return HotSwapOutput(
                swapped=False,
                stdout=stdout,
                stderr=stderr,
                notes="Compilation of evolved harness failed. Keeping current binary.",
            )

        # 4. Persist binary OUT of the temp directory (B5).
        try:
            shutil.copy2(tmp_binary, persistent_binary)
            os.chmod(persistent_binary, 0o755)
        except OSError as exc:
            log.warning(
                "hot_swap.persist_failed",
                job_id=payload.job_id,
                error=str(exc),
            )
            return HotSwapOutput(
                swapped=False,
                stdout=stdout,
                stderr=f"failed to persist binary: {exc}",
                notes="Compilation succeeded but persistent copy failed.",
            )

        log.info(
            "hot_swap.compiled",
            job_id=payload.job_id,
            binary=str(persistent_binary),
        )

        # 5. Preserve corpus from the live container, if requested.
        preserved_path: Path | None = None
        if payload.preserve_corpus:
            preserved_path = await _preserve_corpus_from_container(
                payload.job_id, persistent_corpus
            )
            if preserved_path is None:
                # Still create the directory so downstream callers can
                # treat the path as a stable corpus seed root even when
                # no live container existed (cold-start path).
                persistent_corpus.mkdir(parents=True, exist_ok=True)
                preserved_path = persistent_corpus
            log.info(
                "hot_swap.corpus_preserved",
                job_id=payload.job_id,
                path=str(preserved_path),
            )

    log.info(
        "hot_swap.complete",
        job_id=payload.job_id,
        swapped=True,
        binary=str(persistent_binary),
    )

    return HotSwapOutput(
        swapped=True,
        binary_path=persistent_binary,
        preserved_corpus_path=preserved_path,
        stdout=stdout,
        stderr=stderr,
        notes="Evolved harness compiled and ready for deployment.",
    )


__all__ = ["hot_swap_harness"]
