# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Phase 19 — Unified Manifest & Zero-Config Onboarding."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml
from unittest.mock import patch

from crashwise.core.discovery import (
    DiscoveredProfile,
    _detect_build_system,
    _detect_description,
    _detect_harness,
    _detect_language,
    _detect_name,
    _detect_version,
    discover_project,
)
from crashwise.core.manifest import (
    AiSection,
    BuildSection,
    CrashwiseManifest,
    FuzzingSection,
    ProjectSection,
    ReportingSection,
    find_manifest,
    load_manifest_or_none,
)


# ── Manifest Model ─────────────────────────────────────────────────────────────


def test_manifest_round_trip() -> None:
    manifest = CrashwiseManifest(
        project=ProjectSection(name="libpng", language="c", version="1.6.40"),
        build=BuildSection(system="cmake", command="cmake -B build && cmake --build build"),
        fuzzing=FuzzingSection(fuzzer="libfuzzer", timeout_seconds=600),
        ai=AiSection(provider="ollama", model="codellama"),
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "crashwise.yaml"
        manifest.to_file(path)
        loaded = CrashwiseManifest.from_file(path)
    assert loaded.project.name == "libpng"
    assert loaded.project.language == "c"
    assert loaded.build.system == "cmake"
    assert loaded.fuzzing.timeout_seconds == 600
    assert loaded.ai.provider == "ollama"


def test_manifest_to_fuzzing_input() -> None:
    manifest = CrashwiseManifest(
        project=ProjectSection(
            name="test",
            language="cpp",
            repo_url="https://github.com/example/test",
        ),
        build=BuildSection(harness_path="tests/fuzz.cpp"),
        fuzzing=FuzzingSection(fuzzer="afl++", timeout_seconds=300, sanitizers="address"),
    )
    data = manifest.to_fuzzing_input()
    assert data["target_repo"] == "https://github.com/example/test"
    assert data["fuzzer_type"] == "afl++"
    assert data["timeout_seconds"] == 300
    assert data["harness_path"] == "tests/fuzz.cpp"
    assert data["sanitizers"] == "address"


def test_manifest_validation_language() -> None:
    with pytest.raises(ValueError):
        CrashwiseManifest(
            project=ProjectSection(name="test", language="java"),
        )


def test_manifest_validation_fuzzer() -> None:
    with pytest.raises(ValueError):
        CrashwiseManifest(
            project=ProjectSection(name="test"),
            fuzzing=FuzzingSection(fuzzer="invalid"),
        )


def test_manifest_validation_ai_provider() -> None:
    with pytest.raises(ValueError):
        CrashwiseManifest(
            project=ProjectSection(name="test"),
            ai=AiSection(provider="unknown"),
        )


def test_find_manifest_found() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest_path = Path(tmpdir) / "crashwise.yaml"
        manifest_path.write_text("project:\n  name: test\n  language: c\n")
        found = find_manifest(Path(tmpdir))
        assert found == manifest_path


def test_find_manifest_not_found() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        found = find_manifest(Path(tmpdir))
        assert found is None


def test_load_manifest_or_none_found() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest_path = Path(tmpdir) / "crashwise.yaml"
        manifest_path.write_text("project:\n  name: found\n  language: c\n")
        loaded = load_manifest_or_none(manifest_path)
        assert loaded is not None
        assert loaded.project.name == "found"


def test_load_manifest_or_none_not_found() -> None:
    loaded = load_manifest_or_none(Path("/does/not/exist/crashwise.yaml"))
    assert loaded is None


def test_load_manifest_or_none_auto_discover() -> None:
    with patch("crashwise.core.manifest.find_manifest", return_value=None):
        loaded = load_manifest_or_none()
        assert loaded is None


# ── Autodiscovery ──────────────────────────────────────────────────────────────


def test_detect_build_system_cmake() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
        system, cmd, out = _detect_build_system(Path(tmpdir))
        assert system == "cmake"
        assert "cmake" in cmd


def test_detect_build_system_make() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "Makefile").write_text("all:\n\techo ok")
        system, cmd, out = _detect_build_system(Path(tmpdir))
        assert system == "make"


def test_detect_build_system_cargo() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "Cargo.toml").write_text("[package]\nname = \"foo\"")
        system, cmd, out = _detect_build_system(Path(tmpdir))
        assert system == "cargo"


def test_detect_language_c() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "src").mkdir()
        (Path(tmpdir) / "src" / "main.c").write_text("int main() {}")
        (Path(tmpdir) / "src" / "helper.c").write_text("void helper() {}")
        lang = _detect_language(Path(tmpdir))
        assert lang == "c"


def test_detect_language_cpp() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.cpp").write_text("int main() {}")
        (Path(tmpdir) / "helper.cpp").write_text("void helper() {}")
        lang = _detect_language(Path(tmpdir))
        assert lang == "cpp"


def test_detect_language_rust() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.rs").write_text("fn main() {}")
        lang = _detect_language(Path(tmpdir))
        assert lang == "rust"


def test_detect_name_from_dir() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        name = _detect_name(Path(tmpdir))
        assert name == Path(tmpdir).name


def test_detect_version_from_file() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "VERSION").write_text("1.2.3")
        version = _detect_version(Path(tmpdir))
        assert version == "1.2.3"


def test_detect_harness_found() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "tests").mkdir()
        (Path(tmpdir) / "tests" / "fuzz_parser.c").write_text("int main() {}")
        harness = _detect_harness(Path(tmpdir))
        assert "fuzz" in harness.lower()


def test_detect_harness_not_found() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        harness = _detect_harness(Path(tmpdir))
        assert harness == ""


def test_detect_description_from_readme() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "README.md").write_text("# My Project\n\nThis is a great library.\n")
        desc = _detect_description(Path(tmpdir))
        assert "great library" in desc


def test_detect_description_no_readme() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        desc = _detect_description(Path(tmpdir))
        assert desc == ""


# ── Full Discovery ─────────────────────────────────────────────────────────────


def test_discover_project_cmake_cpp() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
        (Path(tmpdir) / "src").mkdir()
        (Path(tmpdir) / "src" / "main.cpp").write_text("int main() {}")
        profile = discover_project(Path(tmpdir))
        assert profile is not None
        assert profile.language == "cpp"
        assert profile.build_system == "cmake"
        assert "cmake" in profile.build_command


def test_discover_project_cargo_rust() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "Cargo.toml").write_text("[package]\nname = \"my-crate\"")
        (Path(tmpdir) / "src").mkdir()
        (Path(tmpdir) / "src" / "main.rs").write_text("fn main() {}")
        profile = discover_project(Path(tmpdir))
        assert profile is not None
        assert profile.language == "rust"
        assert profile.build_system == "cargo"


def test_discover_project_not_a_dir() -> None:
    profile = discover_project(Path("/does/not/exist"))
    assert profile is None


# ── DiscoveredProfile to Manifest ────────────────────────────────────────────


def test_profile_to_manifest() -> None:
    profile = DiscoveredProfile(
        name="libpng",
        language="c",
        build_system="cmake",
        build_command="cmake -B build && cmake --build build",
        output_dir="build",
        harness_path="tests/fuzz.c",
        version="1.6.40",
    )
    manifest = profile.to_manifest()
    assert manifest.project.name == "libpng"
    assert manifest.project.language == "c"
    assert manifest.build.system == "cmake"
    assert manifest.build.harness_path == "tests/fuzz.c"
    assert manifest.fuzzing.fuzzer == "libfuzzer"
    assert manifest.fuzzing.sanitizers == "address,undefined"


def test_profile_to_manifest_rust() -> None:
    profile = DiscoveredProfile(
        name="my-crate",
        language="rust",
        build_system="cargo",
        build_command="cargo build --release",
        output_dir="target",
    )
    manifest = profile.to_manifest()
    assert manifest.fuzzing.fuzzer == "afl++"
    assert manifest.fuzzing.sanitizers == "address,undefined"
