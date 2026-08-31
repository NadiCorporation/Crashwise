# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Phase 16 — Target Profiling & Adaptive Heuristics."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from crashwise.agents.research.profiler import (
    _collect_source_files,
    _estimate_call_depth,
    _estimate_complexity,
    _is_public_entry_point,
    _manual_loc_count,
    _recommend_config,
    profile_target,
)
from crashwise.core.models import (
    DangerousFunction,
    ExecutionBackend,
    FuzzerType,
    FuzzJob,
    ProfileTargetInput,
    ProfileTargetOutput,
    TargetDomain,
    TargetProfile,
)
from crashwise.execution.dispatcher import (
    apply_profile_to_job,
    dispatch,
)

# ── File Collection ──────────────────────────────────────────────────────────


def test_collect_source_files_with_explicit_paths() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        p1 = Path(tmpdir) / "foo.c"
        p2 = Path(tmpdir) / "bar.txt"
        p1.write_text("int main() {}")
        p2.write_text("not source")
        result = _collect_source_files(Path(tmpdir), [p1, p2], 10)
        assert len(result) == 1
        assert result[0] == p1


def test_collect_source_files_rglob() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "src").mkdir()
        (Path(tmpdir) / "src" / "main.c").write_text("int main() {}")
        (Path(tmpdir) / "src" / "helper.cpp").write_text("void helper() {}")
        (Path(tmpdir) / "tests").mkdir(parents=True)
        (Path(tmpdir) / "tests" / "test.c").write_text("void test() {}")
        result = _collect_source_files(Path(tmpdir), [], 100)
        # Should exclude tests/ directory.
        assert len(result) == 2
        names = {p.name for p in result}
        assert "main.c" in names
        assert "helper.cpp" in names


# ── Complexity & Depth Heuristics ──────────────────────────────────────────────


def test_estimate_complexity() -> None:
    code = """
void foo(int x) {
    if (x > 0) {
        for (int i = 0; i < x; i++) {
            while (i < 10) {
                if (i == 5) break;
                i++;
            }
        }
    }
}
"""
    score = _estimate_complexity(code)
    assert score >= 4  # if, for, while, if, break etc.


def test_estimate_call_depth() -> None:
    code = "foo(bar(baz(1)))"
    depth = _estimate_call_depth(code)
    assert depth == 3


# ── Public Entry Point Detection ─────────────────────────────────────────────


def test_is_public_entry_point_known_prefix() -> None:
    assert _is_public_entry_point("parse_packet", "") is True
    assert _is_public_entry_point("handle_request", "") is True
    assert _is_public_entry_point("main", "") is True


def test_is_public_entry_point_static() -> None:
    text = "static void internal_func() {}"
    assert _is_public_entry_point("internal_func", text) is False


def test_is_public_entry_point_unknown() -> None:
    text = "void helper_func() {}"
    assert _is_public_entry_point("helper_func", text) is True


# ── Manual LoC Count ───────────────────────────────────────────────────────────


def test_manual_loc_count() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "a.c").write_text("int main() { return 0; }\n")
        (Path(tmpdir) / "b.cpp").write_text("void foo() {}\n// comment\n")
        result = _manual_loc_count(Path(tmpdir))
        assert result["loc"] >= 2  # at least main + foo (comment excluded)
        assert result["language"] in ("c", "cpp")  # depends on line counts


# ── Config Recommendation ──────────────────────────────────────────────────────


def test_recommend_config_kernel() -> None:
    sanitizers, strategy = _recommend_config(
        TargetDomain.KERNEL,
        [DangerousFunction.COPY_FROM_USER],
        has_custom_allocator=False,
        has_syscall=True,
    )
    assert "bounds" in sanitizers
    assert "alignment" in sanitizers
    assert strategy == "kernel"


def test_recommend_config_network() -> None:
    sanitizers, strategy = _recommend_config(
        TargetDomain.NETWORK_PROTOCOL,
        [DangerousFunction.MEMCPY],
        has_custom_allocator=False,
        has_syscall=False,
    )
    assert "cfi" in sanitizers
    assert strategy == "network"


def test_recommend_config_aggressive() -> None:
    dangers = [DangerousFunction.MEMCPY, DangerousFunction.STRCPY, DangerousFunction.MALLOC,
               DangerousFunction.REALLOC, DangerousFunction.FREE, DangerousFunction.SPRINTF]
    _sanitizers, strategy = _recommend_config(
        TargetDomain.IMAGE_PROCESSING,
        dangers,
        has_custom_allocator=False,
        has_syscall=False,
    )
    assert strategy == "aggressive"


def test_recommend_config_standard() -> None:
    sanitizers, strategy = _recommend_config(
        TargetDomain.GENERAL,
        [DangerousFunction.MALLOC],
        has_custom_allocator=False,
        has_syscall=False,
    )
    assert "address" in sanitizers
    assert "undefined" in sanitizers
    assert strategy == "standard"


# ── Profile Target Integration ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_profile_target_image_processing() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "png_decoder.c"
        src.write_text("""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void decode_png(const uint8_t *data, size_t len) {
    memcpy(buffer, data, len);
    strcpy(name, "png");
    malloc(1024);
}

int main(int argc, char **argv) {
    return 0;
}
""")
        result = await profile_target(
            ProfileTargetInput(workdir=Path(tmpdir), max_files=10)
        )

    assert isinstance(result, ProfileTargetOutput)
    assert result.files_scanned >= 1
    assert result.profile.domain == TargetDomain.IMAGE_PROCESSING
    assert result.profile.lines_of_code > 0
    assert DangerousFunction.MEMCPY in result.profile.dangerous_functions
    assert DangerousFunction.STRCPY in result.profile.dangerous_functions
    assert DangerousFunction.MALLOC in result.profile.dangerous_functions
    assert "decode_png" in result.profile.attack_surface
    assert result.profile.complexity_score >= 0


@pytest.mark.asyncio
async def test_profile_target_network_protocol() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "tcp_handler.c"
        src.write_text("""
#include <sys/socket.h>

void handle_packet(const char *buf, size_t len) {
    recv(sock, buffer, len, 0);
    parse_header(buf);
}

void parse_header(const char *data) {
    memcpy(header, data, 16);
}
""")
        result = await profile_target(
            ProfileTargetInput(workdir=Path(tmpdir), max_files=10)
        )

    assert result.profile.domain == TargetDomain.NETWORK_PROTOCOL
    assert DangerousFunction.RECV in result.profile.dangerous_functions
    assert DangerousFunction.MEMCPY in result.profile.dangerous_functions
    assert result.profile.has_network_parsers is True


@pytest.mark.asyncio
async def test_profile_target_kernel() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "driver.c"
        src.write_text("""
#include <linux/module.h>

SYSCALL_DEFINE1(my_ioctl, int, cmd) {
    copy_from_user(buffer, user_ptr, size);
    kmalloc(1024, GFP_KERNEL);
    return 0;
}
""")
        result = await profile_target(
            ProfileTargetInput(workdir=Path(tmpdir), max_files=10)
        )

    assert result.profile.domain == TargetDomain.KERNEL
    assert DangerousFunction.COPY_FROM_USER in result.profile.dangerous_functions
    assert DangerousFunction.KMALLOC in result.profile.dangerous_functions
    assert result.profile.has_syscall_handlers is True


@pytest.mark.asyncio
async def test_profile_target_empty_workdir() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        result = await profile_target(
            ProfileTargetInput(workdir=Path(tmpdir), max_files=10)
        )
    assert result.files_scanned == 0
    assert result.profile.domain == TargetDomain.GENERAL


@pytest.mark.asyncio
async def test_profile_target_missing_workdir() -> None:
    result = await profile_target(
        ProfileTargetInput(workdir=Path("/does/not/exist"), max_files=10)
    )
    assert result.files_scanned == 0
    assert "does not exist" in result.profile.notes


# ── Dispatcher ───────────────────────────────────────────────────────────────


def test_dispatch_kernel() -> None:
    profile = TargetProfile(
        domain=TargetDomain.KERNEL,
        complexity_score=8.0,
        has_syscall_handlers=True,
    )
    config = dispatch(profile)
    assert config.fuzzer_type == FuzzerType.AFLPP
    assert config.backend == ExecutionBackend.QEMU
    assert config.memory_limit_mb >= 4096
    assert config.timeout_seconds >= 600
    assert "-DKASAN" in config.compiler_flags


def test_dispatch_network() -> None:
    profile = TargetProfile(
        domain=TargetDomain.NETWORK_PROTOCOL,
        complexity_score=5.0,
        has_network_parsers=True,
    )
    config = dispatch(profile)
    assert config.fuzzer_type == FuzzerType.AFLPP
    assert config.backend == ExecutionBackend.DOCKER
    assert "-D_FORTIFY_SOURCE=2" in config.compiler_flags


def test_dispatch_image_processing() -> None:
    profile = TargetProfile(
        domain=TargetDomain.IMAGE_PROCESSING,
        complexity_score=4.0,
    )
    config = dispatch(profile)
    assert config.fuzzer_type == FuzzerType.LIBFUZZER
    assert config.backend == ExecutionBackend.DOCKER


def test_dispatch_aggressive() -> None:
    profile = TargetProfile(
        domain=TargetDomain.PARSER,
        complexity_score=7.5,
        dangerous_functions=[
            DangerousFunction.MEMCPY, DangerousFunction.STRCPY,
            DangerousFunction.MALLOC, DangerousFunction.REALLOC,
            DangerousFunction.FREE, DangerousFunction.SPRINTF,
        ],
        recommended_strategy="aggressive",
    )
    config = dispatch(profile)
    assert config.fuzzer_type == FuzzerType.AFLPP
    assert config.cpu_limit >= 3.0


def test_dispatch_custom_allocator() -> None:
    profile = TargetProfile(
        domain=TargetDomain.GENERAL,
        complexity_score=3.0,
        has_custom_allocator=True,
    )
    config = dispatch(profile)
    assert "-fsanitize=pointer-compare" in config.compiler_flags
    assert "-fsanitize=pointer-subtract" in config.compiler_flags
    assert "allocator_may_return_null" in config.env_vars.get("ASAN_OPTIONS", "")


def test_dispatch_scale_by_loc() -> None:
    profile = TargetProfile(
        domain=TargetDomain.GENERAL,
        complexity_score=2.0,
        lines_of_code=200_000,
    )
    config = dispatch(profile)
    assert config.memory_limit_mb >= 4096
    assert config.timeout_seconds >= 600


def test_dispatch_small_project() -> None:
    profile = TargetProfile(
        domain=TargetDomain.GENERAL,
        complexity_score=1.0,
        lines_of_code=1000,
    )
    config = dispatch(profile)
    assert config.memory_limit_mb == 2048
    assert config.timeout_seconds == 300


# ── Apply Profile to FuzzJob ─────────────────────────────────────────────────


def test_apply_profile_to_job() -> None:
    profile = TargetProfile(
        domain=TargetDomain.PARSER,
        complexity_score=5.0,
        recommended_sanitizers="address,undefined",
    )
    job = FuzzJob(
        job_id="test-1",
        harness_path=Path("/tmp/harness"),
        corpus_dir=Path("/tmp/corpus"),
        output_dir=Path("/tmp/out"),
    )
    result = apply_profile_to_job(job, profile)
    assert result is job  # same instance
    assert result.env_vars.get("CRASHWISE_CFLAGS") is not None
    assert result.env_vars.get("CRASHWISE_SANITIZERS") == "address,undefined"


# ── Activity Integration ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_profile_target_activity() -> None:
    """Integration test: profile_target activity end-to-end."""
    from crashwise.orchestration.activities.profile_target import profile_target as activity_profile

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "parser.c"
        src.write_text("""
// JSON parser implementation
void parse_json(const char *input) {
    strcpy(buffer, input);
    malloc(256);
}
""")
        with patch("crashwise.orchestration.activities.profile_target.activity.info") as mock_info:
            mock_info.return_value.workflow_id = "test-wf"
            mock_info.return_value.attempt = 1
            result = await activity_profile(
                ProfileTargetInput(workdir=Path(tmpdir), max_files=10)
            )

    assert isinstance(result, ProfileTargetOutput)
    assert result.profile.domain == TargetDomain.PARSER
    assert DangerousFunction.STRCPY in result.profile.dangerous_functions
    assert DangerousFunction.MALLOC in result.profile.dangerous_functions
    assert "parse_json" in result.profile.attack_surface
