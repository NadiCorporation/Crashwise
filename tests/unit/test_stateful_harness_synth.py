# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Comprehensive unit tests for Stateful Multi-API Harness Synthesis (R2).

Validates API lifecycle sequence detection (init -> configure -> process -> cleanup),
context pointer propagation, call graph reachability scoring, FuzzedDataProvider
input partitioning, guaranteed resource teardown (ASan leak prevention), clang++
compilation verification, validator compliance, and deterministic fallback synthesis.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, BaseMessage
from pydantic import ValidationError

from crashwise.agents.harness_synth.llm import set_chat_model_override
from crashwise.agents.harness_synth.models import (
    ApiFunction,
    ApiParam,
    ApiSequence,
)
from crashwise.agents.harness_synth.nodes import _apply_fallback, analyze_code
from crashwise.agents.harness_synth.prompts import SEQUENCE_SECTION_TEMPLATE, SYSTEM_PROMPT
from crashwise.agents.harness_synth.sequence_builder import (
    build_api_sequences,
    classify_function_role,
    generate_stateful_harness,
    parse_function_signature,
    parse_param,
)
from crashwise.agents.harness_synth.state import HarnessState
from crashwise.agents.harness_synth.synth import synthesize_harness
from crashwise.agents.harness_synth.validator import validate_harness

_HAS_CLANGXX = shutil.which("clang++") is not None


# ── Sample C/C++ Header/Source Snippets ──────────────────────────────────────

_MOCK_TARGET_C_SRC = """\
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct TargetCtx {
    int mode;
    int flag;
    uint32_t max_len;
} TargetCtx;

TargetCtx *target_init(void) {
    TargetCtx *ctx = (TargetCtx *)malloc(sizeof(TargetCtx));
    if (ctx) {
        ctx->mode = 0;
        ctx->flag = 0;
        ctx->max_len = 1024;
    }
    return ctx;
}

int target_set_mode(TargetCtx *ctx, int mode) {
    if (!ctx) return -1;
    ctx->mode = mode;
    return 0;
}

int target_set_flag(TargetCtx *ctx, int flag) {
    if (!ctx) return -1;
    ctx->flag = flag;
    return 0;
}

int target_process_data(TargetCtx *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size == 0) return 0;
    int acc = 0;
    for (size_t i = 0; i < size; ++i) {
        acc ^= (data[i] + ctx->mode + ctx->flag);
    }
    return acc;
}

void target_cleanup(TargetCtx *ctx) {
    if (ctx) {
        free(ctx);
    }
}
"""

_MOCK_OUT_PARAM_C_SRC = """\
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

typedef struct StreamParser StreamParser;

int parser_create(StreamParser **out_parser);
int parser_set_option(StreamParser *parser, int opt, int enable);
int parser_feed(StreamParser *parser, const uint8_t *buf, size_t len);
void parser_destroy(StreamParser *parser);
"""


# ── Unit Tests ───────────────────────────────────────────────────────────────


def test_parse_api_param_types() -> None:
    """Test parameter extraction and classification across C/C++ types."""
    p_buf = parse_param("const uint8_t *data")
    assert p_buf.name == "data"
    assert p_buf.is_pointer is True
    assert p_buf.is_buffer is True
    assert p_buf.is_size is False

    p_size = parse_param("size_t size")
    assert p_size.name == "size"
    assert p_size.is_pointer is False
    assert p_size.is_size is True

    p_ctx = parse_param("TargetCtx *ctx")
    assert p_ctx.name == "ctx"
    assert p_ctx.is_pointer is True
    assert p_ctx.is_context is True
    assert p_ctx.is_buffer is False

    p_bool = parse_param("bool enable_fast_mode")
    assert p_bool.name == "enable_fast_mode"
    assert p_bool.is_bool is True

    p_enum = parse_param("int mode")
    assert p_enum.is_enum is True

    p_integral = parse_param("uint32_t max_depth")
    assert p_integral.is_integral is True


def test_classify_function_roles() -> None:
    """Test role assignment (init, configure, process, cleanup) based on names & signatures."""
    assert classify_function_role("target_init", return_type="TargetCtx*") == "init"
    assert classify_function_role("target_new", return_type="void*") == "init"
    assert classify_function_role("target_create", return_type="TargetCtx*") == "init"
    assert classify_function_role("target_alloc", return_type="TargetCtx*") == "init"

    assert classify_function_role("target_set_option") == "configure"
    assert classify_function_role("target_config") == "configure"
    assert classify_function_role("target_add_filter") == "configure"

    assert classify_function_role("target_process_data") == "process"
    assert classify_function_role("target_parse_packet") == "process"
    assert classify_function_role("target_decode_frame") == "process"
    assert classify_function_role("target_decompress") == "process"

    assert classify_function_role("target_cleanup") == "cleanup"
    assert classify_function_role("target_free") == "cleanup"
    assert classify_function_role("target_destroy") == "cleanup"
    assert classify_function_role("target_close") == "cleanup"


def test_stateful_sequence_detection_full_lifecycle() -> None:
    """Detect full init -> configure -> process -> cleanup lifecycle sequence from C source."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) >= 1

    top_seq = sequences[0]
    assert top_seq.init_function is not None
    assert top_seq.init_function.name == "target_init"
    assert top_seq.init_function.role == "init"

    assert len(top_seq.configure_functions) >= 1
    config_names = [c.name for c in top_seq.configure_functions]
    assert "target_set_mode" in config_names or "target_set_flag" in config_names

    assert top_seq.process_function.name == "target_process_data"
    assert top_seq.process_function.role == "process"

    assert top_seq.cleanup_function is not None
    assert top_seq.cleanup_function.name == "target_cleanup"
    assert top_seq.cleanup_function.role == "cleanup"

    assert "TargetCtx" in top_seq.context_type


def test_stateful_sequence_context_pointer_propagation() -> None:
    """Verify that context struct pointer type propagates consistently across lifecycle calls."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    seq = sequences[0]

    assert seq.context_type == "TargetCtx"
    assert seq.context_var_name == "ctx"

    # Verify that configure and process params reference the context pointer
    assert any(p.is_context for p in seq.process_function.params)
    for cfg in seq.configure_functions:
        assert any(p.is_context for p in cfg.params)


def test_stateful_sequence_reachability_scoring() -> None:
    """Verify call graph reachability depth directly increases sequence score."""
    call_graph_shallow = {
        "target_process_data": ["internal_leaf"],
    }
    call_graph_deep = {
        "target_process_data": ["decode_l1"],
        "decode_l1": ["decode_l2"],
        "decode_l2": ["decode_l3"],
        "decode_l3": ["inflate_deep_core"],
    }
    reachability_deep = {
        "target_process_data": 4,
    }

    seqs_shallow = build_api_sequences(_MOCK_TARGET_C_SRC, call_graph=call_graph_shallow)
    seqs_deep = build_api_sequences(
        _MOCK_TARGET_C_SRC,
        call_graph=call_graph_deep,
        reachability_depths=reachability_deep,
    )

    assert len(seqs_shallow) > 0 and len(seqs_deep) > 0
    assert seqs_deep[0].reachability_depth >= seqs_shallow[0].reachability_depth
    assert seqs_deep[0].score >= seqs_shallow[0].score


def test_fuzzed_data_provider_harness_generation() -> None:
    """Verify generated C++ harness uses <fuzzer/FuzzedDataProvider.h> and partitions data."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness = generate_stateful_harness(sequences[0], header_include="target.h")

    assert "#include <fuzzer/FuzzedDataProvider.h>" in harness
    assert 'extern "C" int LLVMFuzzerTestOneInput' in harness
    assert "FuzzedDataProvider fdp(data, size);" in harness
    assert "target_init(" in harness
    assert "target_cleanup(ctx);" in harness
    assert "ConsumeRemainingBytes" in harness


def test_fuzzed_data_provider_integral_partitioning() -> None:
    """Verify FuzzedDataProvider consumes integral and range arguments for configure functions."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness = generate_stateful_harness(sequences[0], header_include="target.h")

    assert "ConsumeIntegral" in harness or "ConsumeIntegralInRange" in harness


def test_fuzzed_data_provider_bool_partitioning() -> None:
    """Verify FuzzedDataProvider consumes boolean flags for boolean/flag parameters."""
    fn_sig = "int target_set_verbose(TargetCtx *ctx, bool verbose, int debug_level);"
    seq = ApiSequence(
        init_function=ApiFunction(
            name="target_init",
            signature="TargetCtx *target_init(void)",
            return_type="TargetCtx*",
            role="init",
            context_type="TargetCtx",
        ),
        configure_functions=[
            parse_function_signature(fn_sig),
        ],
        process_function=ApiFunction(
            name="target_process",
            signature="int target_process(TargetCtx *ctx, const uint8_t *data, size_t size)",
            return_type="int",
            params=[
                ApiParam(name="ctx", type_name="TargetCtx*", is_context=True),
                ApiParam(name="data", type_name="const uint8_t*", is_buffer=True),
                ApiParam(name="size", type_name="size_t", is_size=True),
            ],
            role="process",
            context_type="TargetCtx",
        ),
        cleanup_function=ApiFunction(
            name="target_cleanup",
            signature="void target_cleanup(TargetCtx *ctx)",
            return_type="void",
            role="cleanup",
            context_type="TargetCtx",
        ),
        context_type="TargetCtx",
        score=0.9,
    )
    harness = generate_stateful_harness(seq, header_include="target.h")

    assert "ConsumeBool()" in harness
    assert "target_set_verbose" in harness


def test_fuzzed_data_provider_bytes_partitioning() -> None:
    """Verify FuzzedDataProvider passes remaining payload buffer to process function."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness = generate_stateful_harness(sequences[0], header_include="target.h")

    assert "std::vector<uint8_t> payload = fdp.ConsumeRemainingBytes<uint8_t>();" in harness
    assert "target_process_data(ctx, payload.data(), payload.size());" in harness


def test_stateful_harness_cleanup_matching() -> None:
    """Verify balanced cleanup teardown matching every init/alloc call to prevent ASan leaks."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness = generate_stateful_harness(sequences[0], header_include="target.h")

    # Ensure target_cleanup is called
    assert "target_cleanup(ctx);" in harness
    # Ensure cleanup is before return 0;
    cleanup_pos = harness.find("target_cleanup(ctx);")
    return_pos = harness.rfind("return 0;")
    assert cleanup_pos < return_pos
    assert cleanup_pos != -1


@pytest.mark.skipif(not _HAS_CLANGXX, reason="clang++ not installed")
def test_stateful_harness_clang_compilation(tmp_path: Path) -> None:
    """Compile generated stateful FuzzedDataProvider harness with clang++ and verify zero errors."""
    src_file = tmp_path / "target.h"
    src_file.write_text(_MOCK_TARGET_C_SRC, encoding="utf-8")

    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness_code = generate_stateful_harness(sequences[0], header_include="target.h")

    harness_file = tmp_path / "harness.cpp"
    harness_file.write_text(harness_code, encoding="utf-8")

    cmd = [
        "clang++",
        "-O1",
        "-g",
        "-fsyntax-only",
        "-I",
        str(tmp_path),
        str(harness_file),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"clang++ syntax check failed:\n{proc.stderr}"


def test_stateful_harness_fallback_synthesis(tmp_path: Path) -> None:
    """Verify _apply_fallback synthesizes a working multi-API harness with FuzzedDataProvider."""
    src_file = tmp_path / "target.h"
    src_file.write_text(_MOCK_TARGET_C_SRC, encoding="utf-8")

    state = HarnessState(
        source_path=src_file,
        source_code=_MOCK_TARGET_C_SRC,
        workdir=tmp_path / "out",
    )
    # Run analysis first
    import asyncio
    state = asyncio.run(analyze_code(state))
    assert state.selected_sequence is not None

    state = asyncio.run(_apply_fallback(state, reason="test fallback"))
    assert state.simplified is True
    assert state.harness_code != ""
    assert "FuzzedDataProvider" in state.harness_code
    assert "target_init" in state.harness_code
    assert "target_cleanup" in state.harness_code


def test_stateful_validator_permits_fuzzed_data_provider() -> None:
    """Verify semantic validator permits FuzzedDataProvider and safe constructs without blocking."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness_code = generate_stateful_harness(sequences[0], header_include="target.h")

    result = validate_harness(harness_code)
    assert result.passed is True
    assert len(result.blocking_issues) == 0


def test_stateful_sequence_handles_empty_input() -> None:
    """Verify generated harness guards against 0-byte fuzz input gracefully."""
    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness = generate_stateful_harness(sequences[0], header_include="target.h")

    assert "if (size == 0)" in harness
    assert "return 0;" in harness


def test_stateful_sequence_pydantic_serialization() -> None:
    """Verify Pydantic models validate strictly with ConfigDict(extra='forbid')."""
    param = ApiParam(name="len", type_name="size_t", is_size=True)
    fn = ApiFunction(
        name="test_fn",
        signature="void test_fn(size_t len)",
        params=[param],
        role="process",
    )
    seq = ApiSequence(
        process_function=fn,
        context_type="MyCtx",
        reachability_depth=2,
        score=0.85,
    )
    dumped = seq.model_dump()
    reloaded = ApiSequence.model_validate(dumped)
    assert reloaded.process_function.name == "test_fn"
    assert reloaded.reachability_depth == 2

    # Extra field must raise ValidationError due to extra='forbid'
    with pytest.raises(ValidationError):
        ApiParam(name="x", type_name="int", unexpected_field="invalid")  # type: ignore[call-arg]


def test_stateful_sequence_out_param_init() -> None:
    """Verify out-parameter init (e.g. parser_create(&parser)) is handled properly."""
    sequences = build_api_sequences(_MOCK_OUT_PARAM_C_SRC)
    assert len(sequences) > 0
    top_seq = sequences[0]

    assert top_seq.init_function is not None
    assert top_seq.init_function.name == "parser_create"
    assert top_seq.cleanup_function is not None
    assert top_seq.cleanup_function.name == "parser_destroy"

    harness = generate_stateful_harness(top_seq, header_include="parser.h")
    assert "StreamParser *ctx = nullptr;" in harness
    assert "parser_create(&ctx)" in harness
    assert "parser_destroy(ctx);" in harness


def test_prompt_templates_include_fuzzed_data_provider_and_sequence() -> None:
    """Verify SYSTEM_PROMPT and SEQUENCE_SECTION_TEMPLATE guide stateful lifecycle synthesis."""
    assert "FuzzedDataProvider" in SYSTEM_PROMPT
    assert "ConsumeRemainingBytes" in SYSTEM_PROMPT
    assert "GUARANTEE RESOURCE CLEANUP" in SYSTEM_PROMPT

    seq_section = SEQUENCE_SECTION_TEMPLATE.format(
        context_type="TargetCtx",
        init_signature="TargetCtx *target_init(void)",
        config_signatures="int target_set_mode(TargetCtx *ctx, int mode)",
        process_signature="int target_process_data(TargetCtx *ctx, const uint8_t *data, size_t size)",
        cleanup_signature="void target_cleanup(TargetCtx *ctx)",
        init_name="target_init",
        process_name="target_process_data",
        cleanup_name="target_cleanup",
    )
    assert "## DETECTED API LIFECYCLE SEQUENCE" in seq_section
    assert "target_init" in seq_section
    assert "target_cleanup" in seq_section


def test_stateful_sequence_multiple_clusters() -> None:
    """Verify multiple distinct API clusters (e.g. Client vs Server) are separated."""
    multi_cluster_src = """
    typedef struct ClientCtx ClientCtx;
    typedef struct ServerCtx ServerCtx;

    ClientCtx *client_init(void);
    int client_process(ClientCtx *c, const uint8_t *data, size_t len);
    void client_free(ClientCtx *c);

    ServerCtx *server_init(void);
    int server_process(ServerCtx *s, const uint8_t *data, size_t len);
    void server_free(ServerCtx *s);
    """
    sequences = build_api_sequences(multi_cluster_src)
    assert len(sequences) >= 2
    ctx_types = {s.context_type for s in sequences}
    assert "ClientCtx" in ctx_types
    assert "ServerCtx" in ctx_types


def test_stateful_sequence_single_api_standalone() -> None:
    """Verify standalone single function is wrapped into a valid ApiSequence."""
    single_fn_src = """
    int parse_standalone_buffer(const uint8_t *buf, size_t size);
    """
    sequences = build_api_sequences(single_fn_src)
    assert len(sequences) >= 1
    seq = sequences[0]
    assert seq.process_function.name == "parse_standalone_buffer"
    assert seq.init_function is None
    assert seq.cleanup_function is None

    harness = generate_stateful_harness(seq, header_include="standalone.h")
    assert "parse_standalone_buffer" in harness
    assert "ConsumeRemainingBytes" in harness


class _StatefulStubChatModel:
    """Stub LLM returning a valid multi-API FuzzedDataProvider harness."""

    def __init__(self, response: str) -> None:
        self._response = response

    async def ainvoke(self, _messages: list[BaseMessage]) -> AIMessage:
        return AIMessage(content=self._response)


@pytest.fixture(autouse=True)
def _restore_chat_override() -> Iterator[None]:
    yield
    set_chat_model_override(None)


@pytest.mark.asyncio
async def test_stateful_harness_full_langgraph_synthesis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify full end-to-end synthesize_harness pipeline with stateful multi-API target."""
    from crashwise.agents.harness_synth import nodes
    from crashwise.agents.harness_synth.compiler import SanityResult

    async def _mock_sanity_check(binary_path: Path, *, timeout: float = 5.0, corpus_dir: Path | None = None) -> SanityResult:
        return SanityResult(passed=True, edges_hit=5)

    monkeypatch.setattr(nodes, "sanity_check", _mock_sanity_check)

    src_file = tmp_path / "target.h"
    src_file.write_text(_MOCK_TARGET_C_SRC, encoding="utf-8")

    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    generated_code = generate_stateful_harness(sequences[0], header_include="target.h")
    llm_response = f"```cpp\n{generated_code}\n```"

    set_chat_model_override(_StatefulStubChatModel(llm_response))

    result = await synthesize_harness(
        source_path=src_file,
        workdir=tmp_path / "out",
        max_retries=2,
    )

    assert result.success is True
    assert result.selected_sequence is not None
    assert result.selected_sequence.process_function.name == "target_process_data"
    assert result.selected_sequence.init_function is not None
    assert result.selected_sequence.init_function.name == "target_init"
    assert result.selected_sequence.cleanup_function is not None
    assert result.selected_sequence.cleanup_function.name == "target_cleanup"


@pytest.mark.asyncio
@pytest.mark.skipif(not _HAS_CLANGXX, reason="clang++ not installed")
async def test_stateful_harness_validator_syntax_check(tmp_path: Path) -> None:
    """Verify validator syntax_check_harness passes on generated stateful harness."""
    from crashwise.agents.harness_synth.validator import syntax_check_harness

    sequences = build_api_sequences(_MOCK_TARGET_C_SRC)
    assert len(sequences) > 0
    harness = generate_stateful_harness(sequences[0], header_include="target.h")

    # Prefix with target header content so clang syntax check resolves all symbols
    full_source = _MOCK_TARGET_C_SRC + "\n" + harness.replace('#include "target.h"', "")

    result = await syntax_check_harness(full_source)
    assert result.passed is True

