# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""CrashWise Manifest — unified YAML configuration for fuzzing targets.

A ``crashwise.yaml`` file sits at the root of a target repository and
describes everything CrashWise needs to know: how to build the project,
which fuzzer to use, what sanitizers to enable, and which AI provider
to call for root-cause analysis.

When ``crashwise run`` is invoked with no arguments, it looks for
``crashwise.yaml`` in the current directory and uses it as the source
of truth.  This enables zero-config onboarding: ``cd my-project &&
crashwise run`` just works.

Example ``crashwise.yaml``::

    project:
      name: libpng
      language: c
      version: "1.6.40"

    build:
      system: cmake
      command: "cmake -B build -S . && cmake --build build"
      output_dir: build
      harness_path: tests/fuzz/harness.c

    fuzzing:
      fuzzer: libfuzzer
      timeout_seconds: 600
      sanitizers: address,undefined
      corpus_dir: corpus
      max_iterations: 5

    ai:
      provider: ollama
      model: codellama
      enabled: true
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from crashwise.core.logging import get_logger

log = get_logger(__name__)

MANIFEST_FILENAME = "crashwise.yaml"


# ── Sub-models ───────────────────────────────────────────────────────────────

class ProjectSection(BaseModel):
    """Project metadata."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=128)
    language: str = Field(default="c", pattern=r"^(c|cpp|rust|go|python)$")
    version: str = Field(default="", max_length=64)
    description: str = Field(default="", max_length=1024)
    repo_url: HttpUrl | None = None


class BuildSection(BaseModel):
    """Build system configuration."""

    model_config = ConfigDict(extra="forbid")

    system: str = Field(
        default="auto",
        pattern=r"^(auto|cmake|make|meson|bazel|cargo|go|custom)$",
    )
    command: str = Field(default="", max_length=2048)
    output_dir: str = Field(default="build", max_length=512)
    harness_path: str = Field(default="", max_length=512)
    extra_cflags: str = Field(default="", max_length=1024)
    extra_ldflags: str = Field(default="", max_length=1024)
    clean_before_build: bool = True


class FuzzingSection(BaseModel):
    """Fuzzing strategy and runtime parameters."""

    model_config = ConfigDict(extra="forbid")

    fuzzer: str = Field(
        default="libfuzzer",
        pattern=r"^(libfuzzer|afl\+\+|honggfuzz)$",
    )
    timeout_seconds: int = Field(default=300, ge=10, le=86_400)
    sanitizers: str = Field(default="address,undefined", max_length=256)
    corpus_dir: str = Field(default="corpus", max_length=512)
    max_iterations: int = Field(default=5, ge=1, le=50)
    cpu_limit: float = Field(default=2.0, ge=0.5)
    memory_limit_mb: int = Field(default=2048, ge=256)
    mutation_mode: str = Field(default="default", max_length=64)


class AiSection(BaseModel):
    """AI provider configuration for RCA and harness synthesis."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(
        default="null",
        pattern=r"^(ollama|venice|openai|anthropic|null)$",
    )
    model: str = Field(default="codellama", max_length=128)
    api_key: str = Field(default="", max_length=512)
    base_url: str = Field(default="", max_length=512)
    enabled: bool = True
    max_retries: int = Field(default=3, ge=0, le=10)
    timeout_seconds: int = Field(default=60, ge=5, le=600)


class ReportingSection(BaseModel):
    """Auto-disclosure and notification settings."""

    model_config = ConfigDict(extra="forbid")

    cvss_threshold: float = Field(default=7.0, ge=0.0, le=10.0)
    webhook_url: str = Field(default="", max_length=1024)
    webhook_format: str = Field(default="slack", pattern=r"^(slack|discord|generic)$")
    email_enabled: bool = False
    notifications_enabled: bool = False


# ── Top-level manifest ───────────────────────────────────────────────────────

class CrashwiseManifest(BaseModel):
    """Root model for ``crashwise.yaml``."""

    model_config = ConfigDict(extra="forbid")

    project: ProjectSection
    build: BuildSection = Field(default_factory=BuildSection)
    fuzzing: FuzzingSection = Field(default_factory=FuzzingSection)
    ai: AiSection = Field(default_factory=AiSection)
    reporting: ReportingSection = Field(default_factory=ReportingSection)

    @classmethod
    def from_file(cls, path: Path) -> "CrashwiseManifest":
        """Load and validate a manifest from a YAML file."""
        if not path.exists():
            raise FileNotFoundError(f"Manifest not found: {path}")
        text = path.read_text(encoding="utf-8")
        data: dict[str, object] = yaml.safe_load(text) or {}
        return cls.model_validate(data)

    def to_file(self, path: Path) -> None:
        """Serialize the manifest to a YAML file."""
        path.write_text(
            yaml.safe_dump(self.model_dump(exclude_none=True), sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )

    def to_fuzzing_input(self) -> dict[str, object]:
        """Convert manifest to FuzzingInput-compatible dict."""
        return {
            "target_repo": str(self.project.repo_url) if self.project.repo_url else "",
            "fuzzer_type": self.fuzzing.fuzzer,
            "timeout_seconds": self.fuzzing.timeout_seconds,
            "harness_path": self.build.harness_path or None,
            "sanitizers": self.fuzzing.sanitizers,
            "max_iterations": self.fuzzing.max_iterations,
        }


def find_manifest(start_dir: Path | None = None) -> Path | None:
    """Search for ``crashwise.yaml`` starting from ``start_dir`` upwards."""
    if start_dir is None:
        start_dir = Path.cwd()
    current = start_dir.resolve()
    for _ in range(10):  # search up 10 levels max
        candidate = current / MANIFEST_FILENAME
        if candidate.exists():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def load_manifest_or_none(path: Path | None = None) -> CrashwiseManifest | None:
    """Load manifest from ``path`` or auto-discover. Returns None if not found."""
    if path is None:
        path = find_manifest()
    if path is None:
        return None
    try:
        return CrashwiseManifest.from_file(path)
    except Exception as exc:
        log.warning("manifest.load_failed", path=str(path), error=str(exc))
        return None


__all__ = [
    "AiSection",
    "BuildSection",
    "CrashwiseManifest",
    "FuzzingSection",
    "ProjectSection",
    "ReportingSection",
    "find_manifest",
    "load_manifest_or_none",
]
