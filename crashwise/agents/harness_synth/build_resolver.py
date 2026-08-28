# SPDX-License-Identifier: MIT
"""Automated build path discovery for harness compilation.

Operation Hydra Phase 3: The Linker Hand.
When compilation fails, this module discovers library paths, include
directories, and pkg-config flags from the build tree so the agent
can fix its own compilation command.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from crashwise.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class BuildPaths:
    """Discovered build artifacts for linking."""

    include_dirs: list[Path] = field(default_factory=list)
    lib_files: list[Path] = field(default_factory=list)
    lib_dirs: list[Path] = field(default_factory=list)

    def to_compile_args(self) -> list[str]:
        """Convert to clang/gcc command-line arguments."""
        args: list[str] = []
        for inc in self.include_dirs:
            args.append(f"-I{inc}")
        for lib in self.lib_files:
            args.append(str(lib))
        for ld in self.lib_dirs:
            args.append(f"-L{ld}")
            args.append(f"-Wl,-rpath,{ld.resolve()}")
        return args


def resolve_build_paths(workdir: Path) -> BuildPaths:
    """Scan the build tree for libraries and include directories.

    Searches common build output locations for .a/.so files and
    include directories. Returns a BuildPaths with everything found.
    """
    paths = BuildPaths()
    skip_patterns = {"CMakeFiles", ".git", "test", "tests", "__pycache__"}

    # Discover include directories.
    for candidate in [workdir, workdir / "include", workdir / "src",
                      workdir / "build", workdir / "build" / "include"]:
        if candidate.is_dir():
            paths.include_dirs.append(candidate)

    # Scan for generated headers in build tree.
    build_dir = workdir / "build"
    if build_dir.is_dir():
        for h in build_dir.rglob("*.h"):
            if not any(skip in str(h) for skip in skip_patterns):
                parent = h.parent
                if parent not in paths.include_dirs:
                    paths.include_dirs.append(parent)

    # Discover static libraries (.a).
    for lib in workdir.rglob("*.a"):
        if not any(skip in str(lib) for skip in skip_patterns):
            paths.lib_files.append(lib)
            if lib.parent not in paths.lib_dirs:
                paths.lib_dirs.append(lib.parent)

    # Discover shared libraries (.so).
    for lib in workdir.rglob("*.so*"):
        if not any(skip in str(lib) for skip in skip_patterns) and lib.parent not in paths.lib_dirs:
            paths.lib_dirs.append(lib.parent)

    log.info(
        "build_resolver.resolved",
        includes=len(paths.include_dirs),
        libs=len(paths.lib_files),
    )
    return paths


def find_missing_header(workdir: Path, header_name: str) -> Path | None:
    """Search the build tree for a specific header file."""
    for h in workdir.rglob(header_name):
        if ".git" not in str(h):
            return h.parent
    return None


def diagnose_compile_error(stderr: str, workdir: Path) -> list[str]:
    """Parse compile errors and return additional flags to fix them.

    Handles:
    - 'file not found' → search for the header and add -I
    - 'undefined reference' → search for .a files and add them
    - 'cannot find -l...' → search for the library
    """
    import re

    fixes: list[str] = []

    # Missing headers: "fatal error: 'zlib.h' file not found"
    for m in re.finditer(r"['\"]([^'\"]+\.h)['\"].*(?:file not found|No such file)", stderr):
        header = m.group(1)
        # Try just the filename.
        found = find_missing_header(workdir, Path(header).name)
        if found and f"-I{found}" not in fixes:
            fixes.append(f"-I{found}")

    # Undefined references: "undefined reference to `compress'"
    for _m in re.finditer(r"undefined reference to [`'](\w+)'", stderr):
        # Search for .a files that might contain this symbol.
        for lib in workdir.rglob("*.a"):
            if "CMakeFiles" not in str(lib) and str(lib) not in fixes:
                fixes.append(str(lib))
                break

    # Cannot find library: "cannot find -lz"
    for m in re.finditer(r"cannot find -l(\w+)", stderr):
        lib_name = m.group(1)
        for lib in workdir.rglob(f"lib{lib_name}.*"):
            if lib.parent not in [Path(f) for f in fixes]:
                fixes.append(f"-L{lib.parent}")
                break

    if fixes:
        log.info("build_resolver.diagnosed", fixes=len(fixes))

    return fixes


__all__ = ["BuildPaths", "diagnose_compile_error", "find_missing_header", "resolve_build_paths"]
