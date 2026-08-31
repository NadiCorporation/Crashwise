# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Comprehensive unit tests for the AST-based code analysis engine (Tree-sitter C/C++)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from crashwise.agents.harness_synth.analyzer import (
    analyze_source,
    detect_language,
    find_entry_points,
    find_public_api,
)
from crashwise.agents.harness_synth.models import AnalysisResult, EntryPoint
from crashwise.agents.harness_synth.type_extractor import (
    extract_all_types,
    extract_type_definition,
    extract_types_for_signature,
)

# ── 1. C++ Templates ──────────────────────────────────────────────────────────


def test_ast_cpp_template_free_function() -> None:
    src = """\
template<typename T>
int parse_template(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    return (int)data[0];
}
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "parse_template"
    assert top.is_template is True
    assert top.takes_buffer is True
    assert top.score == 1.0


def test_ast_cpp_template_class_method() -> None:
    src = """\
template<typename T, size_t N>
class DataHandler {
public:
    int process(const uint8_t *buf, size_t len) {
        return (int)len;
    }
};
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "process"
    assert top.is_template is True
    assert "DataHandler" in top.namespace
    assert top.takes_buffer is True
    assert top.score == 1.0


def test_ast_cpp_template_specialization() -> None:
    src = """\
template<typename T>
int decode(const uint8_t *d, size_t s);

template<>
int decode(const uint8_t *d, size_t s) {
    return (int)s;
}
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "decode"
    assert top.takes_buffer is True
    assert top.score >= 0.85


# ── 2. Preprocessor Macros ────────────────────────────────────────────────────


def test_ast_macro_api_export_declaration() -> None:
    src = """\
#define API_EXPORT __attribute__((visibility("default")))

API_EXPORT int parse_packet(const uint8_t *data, size_t size);
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "parse_packet"
    assert top.takes_buffer is True
    assert top.score == 1.0


def test_ast_macro_zexport_calling_convention() -> None:
    src = """\
typedef unsigned char Bytef;
typedef unsigned long uLong;
typedef unsigned long uLongf;

ZEXPORT int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = next(ep for ep in eps if ep.name == "uncompress")
    assert top.takes_buffer is True
    assert top.score >= 0.9


def test_ast_macro_png_export_wrapper() -> None:
    src = """\
typedef struct png_struct_def png_struct;
typedef png_struct * png_structrp;
typedef unsigned char ** png_bytepp;

PNG_EXPORT(1, void, png_read_image, (png_structrp png_ptr, png_bytepp image));
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = next(ep for ep in eps if ep.name == "png_read_image")
    assert top.name == "png_read_image"
    assert top.score >= 0.6


def test_ast_macro_custom_define_expansion() -> None:
    src = """\
#define DECLARE_FUZZ_TARGET(name) int fuzz_##name(const uint8_t *data, size_t size)

DECLARE_FUZZ_TARGET(json);
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = next(ep for ep in eps if ep.name == "fuzz_json")
    assert top.name == "fuzz_json"
    assert top.takes_buffer is True
    assert top.score == 1.0


def test_ast_macro_windows_calling_convention() -> None:
    src = """\
int WINAPI WinProcessBuffer(const uint8_t *data, size_t len);
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "WinProcessBuffer"
    assert top.takes_buffer is True
    assert top.score == 1.0


# ── 3. Namespaces ─────────────────────────────────────────────────────────────


def test_ast_nested_namespaces_single_and_deep() -> None:
    src = """\
namespace A {
    namespace B {
        namespace C {
            int decode_msg(const char *input) {
                return (int)input[0];
            }
        }
    }
}
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "decode_msg"
    assert top.namespace == "A::B::C"
    assert top.takes_buffer is True
    assert top.score >= 0.7


def test_ast_cpp17_nested_namespace_syntax() -> None:
    src = """\
namespace Net::Protocol::V2 {
    int parse_frame(const uint8_t *d, size_t s) {
        return (int)s;
    }
}
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "parse_frame"
    assert top.namespace == "Net::Protocol::V2"
    assert top.takes_buffer is True
    assert top.score == 1.0


# ── 4. Call Graph & Transitive Reachability ───────────────────────────────────


def test_ast_call_graph_direct_edge() -> None:
    src = """\
int internal_parse(const uint8_t *d, size_t s) {
    return d[0];
}

int handle_input(const uint8_t *d, size_t s) {
    return internal_parse(d, s);
}
"""
    res = analyze_source(src)
    assert "handle_input" in res.call_graph
    assert "internal_parse" in res.call_graph["handle_input"]


def test_ast_call_graph_transitive_reachability_bfs() -> None:
    src = """\
int step_d(const uint8_t *d, size_t s) { return 42; }
int step_c(const uint8_t *d, size_t s) { return step_d(d, s); }
int step_b(const uint8_t *d, size_t s) { return step_c(d, s); }

int step_a(const uint8_t *d, size_t s) {
    return step_b(d, s);
}
"""
    res = analyze_source(src)
    ep_a = next(ep for ep in res.entry_points if ep.name == "step_a")
    assert ep_a.call_depth == 3
    assert set(ep_a.callees) == {"step_b", "step_c", "step_d"}


def test_ast_call_graph_cycle_handling() -> None:
    src = """\
int func_a(const uint8_t *d, size_t s);
int func_b(const uint8_t *d, size_t s);

int func_a(const uint8_t *d, size_t s) {
    if (s > 0) return func_b(d + 1, s - 1);
    return 0;
}

int func_b(const uint8_t *d, size_t s) {
    if (s > 0) return func_a(d + 1, s - 1);
    return 0;
}
"""
    res = analyze_source(src)
    # BFS cycle termination: must not hang
    assert "func_a" in res.call_graph
    assert "func_b" in res.call_graph
    ep_a = next(ep for ep in res.entry_points if ep.name == "func_a")
    assert ep_a.call_depth >= 1


def test_ast_reachability_scoring_boost_for_deep_parser() -> None:
    src = """\
int log_message(const char *msg) { return 0; }

int inflate_block(const uint8_t *d, size_t s) {
    return (int)s;
}

int internal_decoder(const uint8_t *d, size_t s) {
    return inflate_block(d, s);
}

int shallow_wrapper(const uint8_t *d, size_t s) {
    log_message("shallow");
    return 0;
}

int deep_wrapper(const uint8_t *d, size_t s) {
    return internal_decoder(d, s);
}
"""
    eps = find_entry_points(src)
    deep_ep = next(ep for ep in eps if ep.name == "deep_wrapper")
    shallow_ep = next(ep for ep in eps if ep.name == "shallow_wrapper")

    assert deep_ep.call_depth >= 2
    assert "inflate_block" in deep_ep.callees
    assert deep_ep.score >= shallow_ep.score


# ── 5. Type Extraction & Field Layouts ─────────────────────────────────────────


def test_ast_type_extractor_nested_named_struct() -> None:
    src = """\
struct Outer {
    int id;
    struct Inner {
        char tag[16];
        int code;
    } in;
};
"""
    types = extract_all_types(src)
    assert "Outer" in types
    outer = types["Outer"]
    assert outer.kind == "struct"
    assert len(outer.fields) >= 2
    id_field = next(f for f in outer.fields if f.name == "id")
    assert id_field.type_name == "int"
    in_field = next(f for f in outer.fields if f.name == "in")
    assert in_field.is_nested_struct is True


def test_ast_type_extractor_anonymous_struct_typedef() -> None:
    src = """\
typedef struct {
    uint32_t magic;
    struct {
        uint16_t id;
    } meta;
} Packet_t;
"""
    types = extract_all_types(src)
    assert "Packet_t" in types
    pkt = types["Packet_t"]
    assert pkt.kind == "struct"
    magic_field = next(f for f in pkt.fields if f.name == "magic")
    assert magic_field.type_name == "uint32_t"


def test_ast_type_extractor_enum_and_typedef_alias() -> None:
    src = """\
typedef unsigned char Bytef;
enum State { IDLE = 0, RUNNING = 1, STOPPED = 2 };
"""
    types = extract_all_types(src)
    assert "Bytef" in types
    assert types["Bytef"].kind == "typedef"
    assert types["Bytef"].alias_for == "unsigned char"

    assert "State" in types
    assert types["State"].kind == "enum"
    assert "IDLE" in types["State"].enum_values
    assert "RUNNING" in types["State"].enum_values


def test_ast_type_extractor_transitive_signature_extraction(tmp_path: Path) -> None:
    header = tmp_path / "packet.h"
    header.write_text("""\
typedef unsigned char Bytef;

typedef struct Payload {
    Bytef *data;
    size_t size;
} Payload_t;

typedef struct Packet {
    uint32_t id;
    Payload_t payload;
} Packet_t;
""")
    res = extract_types_for_signature(tmp_path, "int parse_pkt(Packet_t *pkt)")
    assert "Packet" in res
    assert "Payload" in res
    assert "Bytef" in res


def test_ast_type_extractor_file_lookup(tmp_path: Path) -> None:
    header = tmp_path / "my_types.h"
    header.write_text("""\
struct Config {
    int port;
    char *host;
};
""")
    defn = extract_type_definition(tmp_path, "Config")
    assert defn is not None
    assert "struct Config" in defn
    assert "int port" in defn


# ── 6. Model Contract & Backward Compatibility ────────────────────────────────


def test_ast_models_strict_contract_and_forbid_extra() -> None:
    ep = EntryPoint(
        name="test_func",
        signature="int test_func(const uint8_t *d, size_t s)",
        line=10,
        takes_buffer=True,
        score=1.0,
        call_depth=2,
        callees=["internal_call"],
        namespace="test_ns",
        is_template=False,
    )
    assert ep.name == "test_func"
    assert ep.call_depth == 2

    # Extra field rejected
    with pytest.raises(ValidationError):
        EntryPoint(
            name="invalid",
            signature="void invalid()",
            line=1,
            invalid_extra_field=123,  # type: ignore[call-arg]
        )


def test_ast_analysis_result_model_contract() -> None:
    res = AnalysisResult(
        entry_points=[],
        call_graph={"foo": ["bar"]},
        reachability_depths={"foo": 1},
        type_definitions={"MyType": "typedef int MyType;"},
        structured_types={},
        language="cpp",
    )
    assert res.call_graph["foo"] == ["bar"]
    assert res.reachability_depths["foo"] == 1


# ── 7. Edge Cases & Integration ───────────────────────────────────────────────


def test_ast_edge_case_empty_source() -> None:
    eps = find_entry_points("")
    assert eps == []
    res = analyze_source("")
    assert res.entry_points == []
    assert res.call_graph == {}


def test_ast_edge_case_syntax_error_resilience() -> None:
    src = """\
this is completely broken syntax !!! %%% ;;;
int valid_parser(const uint8_t *d, size_t s) {
    return (int)s;
}
more broken syntax %%% ;;;
"""
    eps = find_entry_points(src)
    assert len(eps) >= 1
    assert any(ep.name == "valid_parser" for ep in eps)


def test_ast_find_public_api_multi_header_directory(tmp_path: Path) -> None:
    inc = tmp_path / "include"
    inc.mkdir()
    (inc / "api.h").write_text("""\
int public_parse(const uint8_t *data, size_t len);
void unrelated_noop();
""")

    src = tmp_path / "src"
    src.mkdir()
    (src / "core.h").write_text("""\
int decode_stream(const char *input);
""")

    eps = find_public_api(tmp_path)
    names = {ep.name for ep in eps}
    assert "public_parse" in names
    assert "decode_stream" in names
    top = eps[0]
    assert top.name == "public_parse"
    assert top.takes_buffer is True


def test_ast_language_detection(tmp_path: Path) -> None:
    assert detect_language(tmp_path / "core.c") == "c"
    assert detect_language(tmp_path / "header.h") == "c"
    assert detect_language(tmp_path / "main.cpp") == "cpp"
    assert detect_language(tmp_path / "util.cc") == "cpp"
    assert detect_language(tmp_path / "mod.cxx") == "cpp"
    assert detect_language(tmp_path / "types.hpp") == "cpp"


# ── 8. Adversarial Stress & Regression Coverage ──────────────────────────────


def test_ast_multiline_macro_and_token_pasting() -> None:
    """Verify multiline macros with backslash continuations and token concatenation."""
    src = """\
#define DECLARE_PARSER(prefix, name) \\
    int parse_##prefix##_##name(const uint8_t *data, size_t size); \\
    struct chunk_##prefix##_t { \\
        int id; \\
        char tag[4]; \\
    };

DECLARE_PARSER(png, header)
DECLARE_PARSER(png, body)
"""
    res = analyze_source(src)
    names = {ep.name for ep in res.entry_points}
    assert "parse_png_header" in names
    assert "parse_png_body" in names
    assert any(ep.takes_buffer is True for ep in res.entry_points)
    assert "chunk_png_t" in res.type_definitions


def test_ast_call_graph_scaling_cyclic_diamond() -> None:
    """Verify BFS reachability does not suffer exponential explosion on diamond/cyclic graphs."""
    import time

    lines = []
    # Create a 40-node diamond DAG with mutual recursion loops
    for i in range(40):
        callees = [f"node_{i+1}", f"node_{i+2}"] if i < 38 else ["target_sink"]
        if i % 3 == 0 and i > 0:
            callees.append(f"node_{i-1}")  # cycle
        callee_str = ", ".join(f"{c}()" for c in callees)
        lines.append(f"""\
void node_{i}() {{
    {callee_str};
}}
""")
    lines.append("""\
void target_sink() {}
int entry_parser(const uint8_t *data, size_t size) {
    node_0();
    return (int)size;
}
""")
    src = "\n".join(lines)
    t0 = time.perf_counter()
    res = analyze_source(src)
    dur_ms = (time.perf_counter() - t0) * 1000

    assert dur_ms < 100, f"BFS reachability took {dur_ms:.2f}ms (>100ms)"
    assert len(res.entry_points) >= 1
    top = res.entry_points[0]
    assert top.name == "entry_parser"
    assert "node_0" in top.callees or "target_sink" in res.call_graph.get("entry_parser", [])


def test_ast_interspersed_syntax_errors_recovery() -> None:
    """Verify recovery when valid function definitions are interspersed with broken syntax."""
    src = """\
void broken_fn( {
    invalid syntax +++ === ;;;
}

int first_valid_parser(const uint8_t *buf, size_t len) {
    if (len > 0) return (int)buf[0];
    return 0;
}

struct { broken struct without tag

int second_valid_parser(const uint8_t *data, size_t size) {
    first_valid_parser(data, size);
    return (int)size;
}
"""
    res = analyze_source(src)
    names = {ep.name for ep in res.entry_points}
    assert "first_valid_parser" in names
    assert "second_valid_parser" in names


def test_ast_large_file_stress_and_memory_safety() -> None:
    """Verify large scale (1,000 functions, 1,000 structs) AST analysis is memory-safe."""
    lines = []
    for i in range(1000):
        lines.append(f"""\
struct Type_{i} {{
    int field_a_{i};
    char buf_{i}[32];
}};

int parser_func_{i}(const uint8_t *data, size_t size) {{
    if (size > {i}) return {i};
    return 0;
}}
""")
    large_src = "\n".join(lines)
    res = analyze_source(large_src)
    assert len(res.entry_points) >= 100
    assert len(res.type_definitions) >= 100

