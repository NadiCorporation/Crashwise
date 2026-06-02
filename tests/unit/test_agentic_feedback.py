# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Tests for the agentic feedback analyzer."""

from __future__ import annotations

import json

import pytest

from crashwise.agents.feedback.agentic_analyzer import (
    AgenticFeedbackResult,
    FeedbackState,
    IterationSnapshot,
    _build_rule_based_hint,
    _extract_text,
    _format_history,
    _parse_json_response,
    agentic_analyze,
)
from crashwise.agents.feedback.analyzer import agentic_enrich
from crashwise.core.models import (
    CampaignStatus,
    CoverageReport,
    FuzzingCampaignState,
)


# ── JSON parser ──────────────────────────────────────────────────────────────
def test_parse_json_response_clean() -> None:
    raw = json.dumps({
        "diagnosis": "magic bytes",
        "root_cause_category": "magic_bytes",
        "strategy": "prefix magic",
        "harness_modifications": "add prefix",
        "seed_suggestions": "add seed",
        "confidence": 0.85,
    })
    result = _parse_json_response(raw)
    assert result is not None
    assert result["diagnosis"] == "magic bytes"
    assert result["confidence"] == 0.85


def test_parse_json_response_fenced() -> None:
    raw = '```json\n{"diagnosis": "stuck", "confidence": 0.7}\n```'
    result = _parse_json_response(raw)
    assert result is not None
    assert result["diagnosis"] == "stuck"


def test_parse_json_response_with_prose() -> None:
    raw = 'Here is my analysis:\n{"diagnosis": "stuck", "confidence": 0.6}\nDone.'
    result = _parse_json_response(raw)
    assert result is not None
    assert result["diagnosis"] == "stuck"


def test_parse_json_response_invalid() -> None:
    assert _parse_json_response("not json at all") is None
    assert _parse_json_response("") is None


# ── History formatter ────────────────────────────────────────────────────────
def test_format_history_empty() -> None:
    assert "no history" in _format_history([])


def test_format_history_with_data() -> None:
    history = [
        IterationSnapshot(iteration=0, edges_hit=100, exec_per_sec=5000),
        IterationSnapshot(iteration=1, edges_hit=150, exec_per_sec=4800),
        IterationSnapshot(iteration=2, edges_hit=150, exec_per_sec=4500),
    ]
    text = _format_history(history)
    assert "100" in text
    assert "150" in text
    assert "5000" in text


def test_format_history_truncates_to_10() -> None:
    history = [
        IterationSnapshot(iteration=i, edges_hit=i * 10)
        for i in range(20)
    ]
    text = _format_history(history)
    lines = [line for line in text.splitlines() if line.strip().startswith(("0", "1", "2"))]
    assert len(lines) <= 10


# ── Text extractor ───────────────────────────────────────────────────────────
def test_extract_text_string_content() -> None:
    class FakeResponse:
        content = "hello world"
    assert _extract_text(FakeResponse()) == "hello world"


def test_extract_text_list_content() -> None:
    from typing import ClassVar

    class FakeResponse:
        content: ClassVar[list[dict[str, str]]] = [{"text": "part1"}, {"text": "part2"}]
    assert "part1" in _extract_text(FakeResponse())


def test_extract_text_plain_string() -> None:
    assert _extract_text("raw string") == "raw string"


# ── Rule-based hint builder ──────────────────────────────────────────────────
def test_build_rule_based_hint_exec_rate() -> None:
    reasons = ["Execution rate collapsed to 5.0 exec/s"]
    hint = _build_rule_based_hint(reasons, 3)
    assert "FEEDBACK FROM ITERATION 3" in hint
    assert "Remove expensive setup" in hint


def test_build_rule_based_hint_coverage_plateau() -> None:
    reasons = ["Coverage plateaued at 200 edges for 5 consecutive iterations"]
    hint = _build_rule_based_hint(reasons, 7)
    assert "magic-value check" in hint


def test_build_rule_based_hint_zero_coverage() -> None:
    reasons = ["Zero coverage edges observed after warm-up"]
    hint = _build_rule_based_hint(reasons, 2)
    assert "fsanitize" in hint


def test_build_rule_based_hint_stability() -> None:
    reasons = ["Stability degraded to 40.0%"]
    hint = _build_rule_based_hint(reasons, 4)
    assert "non-determinism" in hint


def test_build_rule_based_hint_multiple() -> None:
    reasons = [
        "Execution rate collapsed to 5.0 exec/s",
        "Coverage plateaued at 200 edges for 3 consecutive iterations",
    ]
    hint = _build_rule_based_hint(reasons, 5)
    assert "Remove expensive setup" in hint
    assert "magic-value check" in hint


# ── AgenticFeedbackResult ────────────────────────────────────────────────────
def test_result_to_mutation_hint_full() -> None:
    result = AgenticFeedbackResult(
        diagnosis="Fuzzer stuck at magic byte check",
        root_cause_category="magic_bytes",
        strategy="Prefix input with 0x89504E47",
        harness_modifications="Add 4-byte prefix before target call",
        seed_suggestions="Add valid PNG header to corpus",
        confidence=0.9,
        used_llm=True,
    )
    hint = result.to_mutation_hint()
    assert "DIAGNOSIS" in hint
    assert "magic_bytes" in hint
    assert "MUTATION STRATEGY" in hint
    assert "REQUIRED HARNESS CHANGES" in hint
    assert "SEED CORPUS SUGGESTIONS" in hint


def test_result_to_mutation_hint_empty() -> None:
    result = AgenticFeedbackResult()
    assert result.to_mutation_hint() == ""


# ── agentic_analyze (no stall) ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_agentic_analyze_no_stall() -> None:
    result = await agentic_analyze(
        coverage=CoverageReport(edges_hit=100),
        best_coverage=CoverageReport(edges_hit=90),
        harness_code="int main() {}",
        stall_reasons=[],
    )
    assert result.used_llm is False
    assert result.confidence == 1.0
    assert "healthy" in result.diagnosis.lower()


# ── agentic_analyze (LLM unavailable → fallback) ────────────────────────────
@pytest.mark.asyncio
async def test_agentic_analyze_llm_unavailable() -> None:
    from crashwise.agents.harness_synth.llm import set_chat_model_override

    class FailingModel:
        async def ainvoke(self, *args, **kwargs):
            raise RuntimeError("API unavailable")

    set_chat_model_override(FailingModel())
    try:
        result = await agentic_analyze(
            coverage=CoverageReport(edges_hit=100, exec_per_sec=5.0),
            best_coverage=CoverageReport(edges_hit=100),
            harness_code='extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }',
            stall_reasons=["Execution rate collapsed to 5.0 exec/s"],
            current_iteration=3,
        )
        assert result.used_llm is False
        assert result.confidence == 0.3
        assert "FEEDBACK FROM ITERATION 3" in result.mutation_hint
    finally:
        set_chat_model_override(None)


# ── agentic_analyze (LLM success) ────────────────────────────────────────────
@pytest.mark.asyncio
async def test_agentic_analyze_llm_success() -> None:
    from crashwise.agents.harness_synth.llm import set_chat_model_override

    llm_response = json.dumps({
        "diagnosis": "The harness calls parse_image() but never provides the PNG magic bytes 0x89504E47, so the parser exits at line 42 before reaching the decompression logic.",
        "root_cause_category": "magic_bytes",
        "strategy": "Prefix the fuzzer input with the 4-byte PNG signature before passing to parse_image().",
        "harness_modifications": "Add: if (size < 4) return 0; uint8_t buf[size]; memcpy(buf, data, size); buf[0]=0x89; buf[1]=0x50; buf[2]=0x4E; buf[3]=0x47; parse_image(buf, size);",
        "seed_suggestions": "Add a minimal valid PNG file (8-byte signature + IHDR chunk) to the seed corpus.",
        "confidence": 0.88,
    })

    class SuccessModel:
        async def ainvoke(self, *args, **kwargs):
            class Response:
                content = llm_response
            return Response()

    set_chat_model_override(SuccessModel())
    try:
        result = await agentic_analyze(
            coverage=CoverageReport(edges_hit=42, exec_per_sec=3000),
            best_coverage=CoverageReport(edges_hit=42),
            harness_code='extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { parse_image(d, s); return 0; }',
            stall_reasons=["Coverage plateaued at 42 edges for 4 consecutive iterations"],
            current_iteration=5,
            target_name="libpng",
            target_domain="image",
        )
        assert result.used_llm is True
        assert result.confidence == 0.88
        assert result.root_cause_category == "magic_bytes"
        assert "PNG" in result.strategy or "magic" in result.strategy.lower()
        assert "DIAGNOSIS" in result.mutation_hint
    finally:
        set_chat_model_override(None)


# ── agentic_analyze (LLM returns bad JSON → fallback) ────────────────────────
@pytest.mark.asyncio
async def test_agentic_analyze_llm_bad_json() -> None:
    from crashwise.agents.harness_synth.llm import set_chat_model_override

    class BadJsonModel:
        async def ainvoke(self, *args, **kwargs):
            class Response:
                content = "This is not JSON at all, just prose."
            return Response()

    set_chat_model_override(BadJsonModel())
    try:
        result = await agentic_analyze(
            coverage=CoverageReport(edges_hit=50),
            best_coverage=CoverageReport(edges_hit=50),
            harness_code="void fuzz() {}",
            stall_reasons=["Coverage plateaued at 50 edges"],
            current_iteration=4,
        )
        assert result.used_llm is False
        assert result.confidence == 0.3
    finally:
        set_chat_model_override(None)


# ── agentic_enrich integration ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_agentic_enrich_skips_non_stalled() -> None:
    state = FuzzingCampaignState(status=CampaignStatus.RUNNING)
    result = await agentic_enrich(state)
    assert result.status == CampaignStatus.RUNNING
    assert result.mutation_hint == ""


@pytest.mark.asyncio
async def test_agentic_enrich_with_stall() -> None:
    from crashwise.agents.harness_synth.llm import set_chat_model_override

    llm_response = json.dumps({
        "diagnosis": "Entry point is guarded by length check",
        "root_cause_category": "input_format",
        "strategy": "Ensure input is at least 64 bytes",
        "harness_modifications": "Add length guard",
        "seed_suggestions": "",
        "confidence": 0.75,
    })

    class SuccessModel:
        async def ainvoke(self, *args, **kwargs):
            class Response:
                content = llm_response
            return Response()

    set_chat_model_override(SuccessModel())
    try:
        state = FuzzingCampaignState(
            status=CampaignStatus.STALLED,
            last_stall_reasons=["Coverage plateaued at 100 edges for 3 consecutive iterations"],
            mutation_hint="old rule-based hint",
            iteration=3,
        )
        result = await agentic_enrich(
            state,
            harness_code='extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { target(d, s); return 0; }',
            fuzzer_type="libfuzzer",
            target_name="testlib",
        )
        assert result.mutation_hint != "old rule-based hint"
        assert "DIAGNOSIS" in result.mutation_hint
        assert "input_format" in result.mutation_hint
    finally:
        set_chat_model_override(None)


# ── IterationSnapshot model ──────────────────────────────────────────────────
def test_iteration_snapshot_defaults() -> None:
    snap = IterationSnapshot()
    assert snap.iteration == 0
    assert snap.edges_hit == 0
    assert snap.exec_per_sec == 0.0


def test_iteration_snapshot_values() -> None:
    snap = IterationSnapshot(
        iteration=5,
        edges_hit=200,
        exec_per_sec=3500.0,
        corpus_count=50,
        stability=98.5,
        crash_count=1,
    )
    assert snap.iteration == 5
    assert snap.edges_hit == 200
    assert snap.crash_count == 1


# ── FeedbackState model ──────────────────────────────────────────────────────
def test_feedback_state_defaults() -> None:
    state = FeedbackState()
    assert state.done is False
    assert state.confidence == 0.0
    assert state.analysis == ""
    assert state.stall_reasons == []
