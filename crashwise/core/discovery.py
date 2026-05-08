# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Autodiscovery Engine — detects project type, build system, and language
automatically so CrashWise can generate a ``crashwise.yaml`` with zero
manual configuration.

The engine walks the target directory looking for:
  • Build-system files (CMakeLists.txt, Makefile, meson.build, Cargo.toml, etc.)
  • Source files (.c, .cpp, .rs, .go) to determine primary language
  • Existing fuzzer harnesses (files named *fuzz*, *harness*, *test*)
  • Version information (from package.json, Cargo.toml, git tags)

Usage::

    from crashwise.core.discovery import discover_project

    profile = discover_project(Path("/path/to/repo"))
    manifest = profile.to_manifest()
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path

from crashwise.core.logging import get_logger
from crashwise.core.manifest import (
    AiSection,
    BuildSection,
    CrashwiseManifest,
    FuzzingSection,
    ProjectSection,
    ReportingSection,
)

log = get_logger(__name__)

# ── Detection heuristics ─────────────────────────────────────────────────────

_BUILD_SYSTEMS: dict[str, tuple[str, str]] = {
    "CMakeLists.txt": ("cmake", 'cmake -B {output_dir} -S . && cmake --build {output_dir}'),
    "Makefile": ("make", "make -j$(nproc)"),
    "meson.build": ("meson", "meson setup {output_dir} && meson compile -C {output_dir}"),
    "BUILD.bazel": ("bazel", "bazel build //..."),
    "Cargo.toml": ("cargo", "cargo build --release"),
    "go.mod": ("go", "go build ./..."),
    "setup.py": ("custom", "python setup.py build"),
    "pyproject.toml": ("custom", "pip install -e ."),
}

_LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".go": "go",
    ".py": "python",
}

_HARNESS_HINTS = re.compile(r"(fuzz|harness|test.*one|llvmfuzzer)", re.IGNORECASE)


# ── Public API ───────────────────────────────────────────────────────────────

class DiscoveredProfile:
    """Intermediate representation of a discovered project."""

    def __init__(
        self,
        name: str,
        language: str,
        build_system: str,
        build_command: str,
        output_dir: str,
        harness_path: str = "",
        version: str = "",
        description: str = "",
    ) -> None:
        self.name = name
        self.language = language
        self.build_system = build_system
        self.build_command = build_command
        self.output_dir = output_dir
        self.harness_path = harness_path
        self.version = version
        self.description = description

    def to_manifest(self) -> CrashwiseManifest:
        """Convert discovery results into a full CrashwiseManifest."""
        return CrashwiseManifest(
            project=ProjectSection(
                name=self.name,
                language=self.language,
                version=self.version,
                description=self.description,
            ),
            build=BuildSection(
                system=self.build_system,
                command=self.build_command,
                output_dir=self.output_dir,
                harness_path=self.harness_path,
            ),
            fuzzing=FuzzingSection(
                fuzzer="libfuzzer" if self.language in ("c", "cpp") else "afl++",
                sanitizers="address,undefined" if self.language in ("c", "cpp", "rust") else "",
            ),
            ai=AiSection(),
            reporting=ReportingSection(),
        )


def discover_project(root: Path) -> DiscoveredProfile | None:
    """Analyse ``root`` directory and return a discovery profile.

    Returns ``None`` if the directory does not look like a software project.
    """
    if not root.exists() or not root.is_dir():
        log.warning("discovery.not_a_directory", path=str(root))
        return None

    # 1. Detect build system.
    build_system, build_cmd, output_dir = _detect_build_system(root)

    # 2. Detect primary language.
    language = _detect_language(root)

    # 3. Detect project name.
    name = _detect_name(root)

    # 4. Detect version.
    version = _detect_version(root)

    # 5. Detect existing harness.
    harness = _detect_harness(root)

    # 6. Description from README if available.
    description = _detect_description(root)

    log.info(
        "discovery.complete",
        name=name,
        language=language,
        build_system=build_system,
        harness_found=bool(harness),
    )

    return DiscoveredProfile(
        name=name,
        language=language,
        build_system=build_system,
        build_command=build_cmd.format(output_dir=output_dir),
        output_dir=output_dir,
        harness_path=harness,
        version=version,
        description=description,
    )


# ── Detection helpers ────────────────────────────────────────────────────────

def _detect_build_system(root: Path) -> tuple[str, str, str]:
    """Return (system, command_template, output_dir)."""
    for filename, (system, cmd_template) in _BUILD_SYSTEMS.items():
        if (root / filename).exists():
            output_dir = "build" if system != "cargo" else "target"
            return system, cmd_template, output_dir
    return "custom", "make", "build"


def _detect_language(root: Path) -> str:
    """Determine the dominant programming language by file count."""
    counts: Counter[str] = Counter()
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in _LANGUAGE_EXTENSIONS:
            counts[_LANGUAGE_EXTENSIONS[p.suffix.lower()]] += 1
    if not counts:
        return "c"
    return counts.most_common(1)[0][0]


def _detect_name(root: Path) -> str:
    """Guess project name from directory or git remote."""
    # Directory name.
    name = root.name
    # Try git remote.
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            # Extract repo name from URL.
            if "/" in url:
                name = url.rstrip(".git").split("/")[-1]
    except Exception:
        pass
    return name


def _detect_version(root: Path) -> str:
    """Try to find a version string from git tags or files."""
    # Try git describe.
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "describe", "--tags", "--always"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if result.returncode == 0:
            return result.stdout.strip().lstrip("v")
    except Exception:
        pass

    # Try common version files.
    for pattern in ("VERSION", "version.txt", "VERSION.txt"):
        vf = root / pattern
        if vf.exists():
            return vf.read_text(encoding="utf-8").strip()[:64]

    return ""


def _detect_harness(root: Path) -> str:
    """Search for an existing fuzzer harness."""
    candidates: list[tuple[Path, int]] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if _HARNESS_HINTS.search(p.name):
            # Score: shorter path = higher priority.
            depth = len(p.relative_to(root).parts)
            candidates.append((p, depth))
    if not candidates:
        return ""
    candidates.sort(key=lambda x: x[1])
    return str(candidates[0][0].relative_to(root))


def _detect_description(root: Path) -> str:
    """Extract first sentence from README if available."""
    for readme_name in ("README.md", "README.rst", "README.txt", "README"):
        readme = root / readme_name
        if readme.exists():
            text = readme.read_text(encoding="utf-8", errors="replace")
            # First non-empty line that's not a heading.
            for line in text.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and len(stripped) > 10:
                    return stripped[:256]
    return ""


__all__ = ["DiscoveredProfile", "discover_project"]
