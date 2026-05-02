# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Phase 12 — Autonomous Patch Verification & Regression Testing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from crashwise.agents.feedback.verifier import (
    VerificationResult,
    _apply_patch,
    _discover_harness,
    _run_regression,
    verify_patch,
)
from crashwise.core.models import FuzzerType, VerificationStatus


# ── Verifier unit tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apply_patch_git_apply(tmp_path: Path) -> None:
    """git apply successfully patches a file."""
    # Create a dummy file to patch.
    target_file = tmp_path / "main.c"
    target_file.write_text("int main() { return 0; }\n")

    # Create a unified diff patch.
    patch_text = f"""\
--- a/main.c
+++ b/main.c
@@ -1 +1 @@
-int main() {{ return 0; }}
+int main() {{ return 1; }}
"""

    ok, stderr = await _apply_patch(tmp_path, patch_text)
    assert ok is True
    assert "return 1" in target_file.read_text()


@pytest.mark.asyncio
async def test_apply_patch_invalid_patch(tmp_path: Path) -> None:
    """Invalid patch returns failure."""
    patch_text = "this is not a valid patch"
    ok, stderr = await _apply_patch(tmp_path, patch_text)
    assert ok is False


def test_discover_harness_found(tmp_path: Path) -> None:
    """Harness discovery finds *fuzz*.cpp files."""
    (tmp_path / "src").mkdir()
    harness = tmp_path / "src" / "parser_fuzz.cpp"
    harness.write_text("int main() {}")
    found = _discover_harness(tmp_path)
    assert found == harness


def test_discover_harness_not_found(tmp_path: Path) -> None:
    """Harness discovery returns None when no match."""
    found = _discover_harness(tmp_path)
    assert found is None


@pytest.mark.asyncio
async def test_run_regression_crash_reproduced(tmp_path: Path) -> None:
    """Regression detects ASAN error in stderr."""
    # Create a fake binary that prints ASAN error.
    binary = tmp_path / "harness.out"
    script = tmp_path / "fake_harness.sh"
    script.write_text("#!/bin/bash\necho 'ERROR: AddressSanitizer: heap-buffer-overflow' >&2\n")
    script.chmod(0o755)

    seed = tmp_path / "crash.seed"
    seed.write_bytes(b"A")

    crash_reproduced, stdout, stderr = await _run_regression(
        binary_path=script,
        seed_path=seed,
        workdir=tmp_path,
        fuzzer_type=FuzzerType.LIBFUZZER,
        timeout_seconds=10,
    )
    assert crash_reproduced is True
    assert "AddressSanitizer" in stderr


@pytest.mark.asyncio
async def test_run_regression_no_crash(tmp_path: Path) -> None:
    """Regression passes when no ASAN error."""
    binary = tmp_path / "harness.out"
    script = tmp_path / "fake_harness.sh"
    script.write_text("#!/bin/bash\necho 'OK'\n")
    script.chmod(0o755)

    seed = tmp_path / "crash.seed"
    seed.write_bytes(b"A")

    crash_reproduced, stdout, stderr = await _run_regression(
        binary_path=script,
        seed_path=seed,
        workdir=tmp_path,
        fuzzer_type=FuzzerType.LIBFUZZER,
        timeout_seconds=10,
    )
    assert crash_reproduced is False


# ── Integration: verify_patch end-to-end ─────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_patch_fixed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end: patch applies, builds, and regression passes."""
    c_file = tmp_path / "fuzz.c"
    c_file.write_text("int main() { return 0; }")

    patch_text = "dummy patch"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"A")

    # Mock compile to succeed.
    mock_compile = AsyncMock(return_value=MagicMock(
        success=True,
        binary_path=tmp_path / "harness.out",
        stdout="",
        stderr="",
        returncode=0,
    ))

    # Mock regression to NOT reproduce crash.
    mock_regression = AsyncMock(return_value=(False, "FIXED", ""))

    # Mock apply patch to succeed.
    mock_apply = AsyncMock(return_value=(True, ""))

    with patch("crashwise.agents.feedback.verifier.compile_harness", mock_compile):
        with patch("crashwise.agents.feedback.verifier._run_regression", mock_regression):
            with patch("crashwise.agents.feedback.verifier._apply_patch", mock_apply):
                result = await verify_patch(
                    repo_url="",
                    patch=patch_text,
                    seed_path=seed,
                    workdir=tmp_path,
                    harness_path=c_file,
                    fuzzer_type=FuzzerType.LIBFUZZER,
                    timeout_seconds=10,
                )

    assert result.status == "fixed"
    assert result.patch_applied is True
    assert result.build_success is True
    assert result.crash_reproduced is False


@pytest.mark.asyncio
async def test_verify_patch_build_failed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end: patch applies but build fails."""
    c_file = tmp_path / "fuzz.c"
    c_file.write_text("int main() { return 0; }")

    patch_text = "dummy patch"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"A")

    mock_compile = AsyncMock(return_value=MagicMock(
        success=False,
        binary_path=None,
        stdout="",
        stderr="syntax error",
        returncode=1,
    ))

    mock_apply = AsyncMock(return_value=(True, ""))

    with patch("crashwise.agents.feedback.verifier.compile_harness", mock_compile):
        with patch("crashwise.agents.feedback.verifier._apply_patch", mock_apply):
            result = await verify_patch(
                repo_url="",
                patch=patch_text,
                seed_path=seed,
                workdir=tmp_path,
                harness_path=c_file,
                fuzzer_type=FuzzerType.LIBFUZZER,
                timeout_seconds=10,
            )

    assert result.status == "build_failed"
    assert result.patch_applied is True
    assert result.build_success is False


@pytest.mark.asyncio
async def test_verify_patch_crash_still_reproduces(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end: patch applies and builds, but crash still reproduces."""
    c_file = tmp_path / "fuzz.c"
    c_file.write_text("int main() { return 0; }")

    patch_text = "dummy patch"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"A")

    mock_compile = AsyncMock(return_value=MagicMock(
        success=True,
        binary_path=tmp_path / "harness.out",
        stdout="",
        stderr="",
        returncode=0,
    ))

    mock_regression = AsyncMock(return_value=(True, "", "ERROR: AddressSanitizer"))
    mock_apply = AsyncMock(return_value=(True, ""))

    with patch("crashwise.agents.feedback.verifier.compile_harness", mock_compile):
        with patch("crashwise.agents.feedback.verifier._run_regression", mock_regression):
            with patch("crashwise.agents.feedback.verifier._apply_patch", mock_apply):
                result = await verify_patch(
                    repo_url="",
                    patch=patch_text,
                    seed_path=seed,
                    workdir=tmp_path,
                    harness_path=c_file,
                    fuzzer_type=FuzzerType.LIBFUZZER,
                    timeout_seconds=10,
                )

    assert result.status == "failed_verification"
    assert result.patch_applied is True
    assert result.build_success is True
    assert result.crash_reproduced is True


# ── VerificationResult model ───────────────────────────────────────────────


def test_verification_result_to_dict() -> None:
    result = VerificationResult(
        status="fixed",
        patch_applied=True,
        build_success=True,
        crash_reproduced=False,
        stdout="OK",
        stderr="",
        details={"duration": 1.5},
    )
    d = result.to_dict()
    assert d["status"] == "fixed"
    assert d["patch_applied"] is True
    assert d["crash_reproduced"] is False
    assert d["details"]["duration"] == 1.5


# ── DB activity: update_verification_status ─────────────────────────────────


@pytest.mark.asyncio
async def test_update_verification_status_persists() -> None:
    """The DB activity updates the crash record."""
    from crashwise.core.database import Crash, close_db, get_session, init_db
    from crashwise.orchestration.activities.verify_patch import update_verification_status

    await init_db(drop=True)

    # Create a crash record.
    async with get_session() as session:
        crash = Crash(
            crash_type="heap-buffer-overflow",
            severity="critical",
            stack_hash="abc123",
        )
        session.add(crash)
        await session.commit()
        crash_id = str(crash.id)

    # Mock activity.info().
    mock_info = MagicMock()
    mock_info.workflow_id = "test"
    mock_info.attempt = 1

    with patch("crashwise.orchestration.activities.verify_patch.activity.info", return_value=mock_info):
        await update_verification_status(
            crash_id=crash_id,
            status="fixed",
            stdout="Regression passed",
            stderr="",
        )

    # Verify DB update.
    async with get_session() as session:
        updated = await session.get(Crash, crash.id)
        assert updated is not None
        assert updated.verification_status == "fixed"
        assert updated.verification_stdout == "Regression passed"
        assert updated.verified_at is not None

    await close_db()
