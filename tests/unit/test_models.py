# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for :mod:`crashwise.core.models`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from crashwise.core.models import (
    CrashSeverity,
    FuzzerType,
    FuzzingInput,
    FuzzingOutput,
)


def test_fuzzing_input_defaults() -> None:
    payload = FuzzingInput(target_repo="https://github.com/example/x")  # type: ignore[arg-type]
    assert payload.fuzzer_type is FuzzerType.LIBFUZZER
    assert payload.timeout_seconds == 600
    assert payload.sanitizers == "address,undefined"


def test_fuzzing_input_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        FuzzingInput(  # type: ignore[call-arg]
            target_repo="https://github.com/example/x",  # type: ignore[arg-type]
            unknown_field="boom",
        )


def test_fuzzing_input_timeout_bounds() -> None:
    with pytest.raises(ValidationError):
        FuzzingInput(target_repo="https://x.example", timeout_seconds=0)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        FuzzingInput(target_repo="https://x.example", timeout_seconds=10**9)  # type: ignore[arg-type]


def test_fuzzing_output_roundtrip() -> None:
    now = datetime.now(tz=UTC)
    out = FuzzingOutput(
        crash_found=True,
        logs_path="/tmp/x.log",  # type: ignore[arg-type]
        crash_count=3,
        severity=CrashSeverity.MEDIUM,
        started_at=now,
        finished_at=now,
        summary="ok",
    )
    js = out.model_dump_json()
    restored = FuzzingOutput.model_validate_json(js)
    assert restored == out
