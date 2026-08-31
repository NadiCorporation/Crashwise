# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Stateful multi-API sequence detection and harness generation.

Identifies API lifecycle patterns (init -> configure -> process -> cleanup),
correlates functions sharing context pointers, computes reachability depth scores
from call graphs, and synthesizes structured FuzzedDataProvider harnesses with
guaranteed resource cleanup.
"""

from __future__ import annotations

import re
from collections import deque

from crashwise.agents.harness_synth.models import (
    ApiFunction,
    ApiParam,
    ApiSequence,
    EntryPoint,
)
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# ── Lifecycle Role Regexes ───────────────────────────────────────────────────

_INIT_NAME_RE = re.compile(
    r"(?:^|_|[a-z])(init(?:ialize|2)?|new|create|open|alloc(?:ate)?|begin|setup|start)(?:[_0-9A-Z]|$)",
    re.IGNORECASE,
)
_CLEANUP_NAME_RE = re.compile(
    r"(?:^|_|[a-z])(free|destroy|close|end|cleanup|release|delete|finish|uninit|teardown)(?:[_0-9A-Z]|$)",
    re.IGNORECASE,
)
_CONFIG_NAME_RE = re.compile(
    r"(?:^|_|[a-z])(set(?:opt)?|config(?:ure)?|add|option|opt|enable|disable|load|register|param|tune|format)(?:[_0-9A-Z]|$)",
    re.IGNORECASE,
)
_PROCESS_NAME_RE = re.compile(
    r"(?:^|_|[a-z])(process|parse|read|decode|decompress|handle|write|eval|execute|run|feed|update|deflate|inflate|consume|transform|search|scan)(?:[_0-9A-Z]|$)",
    re.IGNORECASE,
)

# ── Parameter Shape Regexes ──────────────────────────────────────────────────

_BYTE_BUFFER_RE = re.compile(
    r"(?:const\s+)?(?:unsigned\s+char|uint8_t|u8|Bytef|Byte|uChar|char|void)\s*\*",
    re.IGNORECASE,
)
_SIZE_RE = re.compile(
    r"^(?:const\s+)?(?:size_t|ssize_t|unsigned\s+(?:int|long)|int|long|u?int(?:8|16|32|64)_t|uLong|uLongf|uInt)$",
    re.IGNORECASE,
)
_SIZE_NAME_RE = re.compile(
    r"^(?:size|len|length|count|nbytes|bytes|buflen|buf_size|data_len|datalen|sz)$",
    re.IGNORECASE,
)
_BOOL_NAME_RE = re.compile(
    r"^(?:flag|enable|disable|verbose|debug|is_\w+|has_\w+|use_\w+|opt_\w+)$",
    re.IGNORECASE,
)
_ENUM_NAME_RE = re.compile(
    r"^(?:mode|type|kind|action|cmd|command|format|encoding|level|algorithm|algo|method|strategy|opt)$",
    re.IGNORECASE,
)
_CONTEXT_HINT_RE = re.compile(
    r"(?:ctx|context|handle|state|strm|stream|session|parser|decoder|encoder|engine|inst|instance|obj|client|server|env)",
    re.IGNORECASE,
)


# ── Parameter Parsing ────────────────────────────────────────────────────────


def parse_param(param_str: str) -> ApiParam:
    """Parse a C/C++ parameter declaration into structured ApiParam."""
    raw = param_str.strip()
    if not raw or raw == "void":
        return ApiParam(name="", type_name="void")

    # Split into type part and parameter identifier name
    parts = raw.split()
    if len(parts) == 1:
        type_name = parts[0]
        name = ""
    else:
        # Check if last token is an identifier name
        last_tok = parts[-1].lstrip("*&")
        if last_tok.isidentifier() and last_tok not in ("const", "unsigned", "struct", "enum"):
            name = last_tok
            type_name = raw[: raw.rfind(last_tok)].strip()
        else:
            name = ""
            type_name = raw

    type_name = re.sub(r"\s+", " ", type_name).strip()
    is_pointer = "*" in raw or "*" in type_name or any(
        t in type_name for t in ("_ptr", "pcre2_code", "z_streamp", "png_structp", "handle_t")
    )

    # Detect buffer
    is_buffer = bool(_BYTE_BUFFER_RE.search(type_name)) and not (
        "**" in raw or _CONTEXT_HINT_RE.search(name)
    )

    # Detect size
    is_size = bool(_SIZE_RE.match(type_name)) and bool(_SIZE_NAME_RE.match(name))
    if not is_size and bool(_SIZE_RE.match(type_name)) and name in ("len", "length", "size", "count", "n"):
        is_size = True

    # Detect boolean
    is_bool = (
        type_name in ("bool", "_Bool", "boolean")
        or (type_name in ("int", "int32_t", "uint8_t") and bool(_BOOL_NAME_RE.match(name)))
    )

    # Detect enum
    is_enum = (
        type_name.startswith("enum ")
        or "enum" in type_name
        or (type_name in ("int", "uint32_t", "unsigned int") and bool(_ENUM_NAME_RE.match(name)))
    )

    # Detect integral
    is_integral = (
        not is_pointer
        and any(
            t in type_name
            for t in (
                "int",
                "char",
                "short",
                "long",
                "uint8_t",
                "uint16_t",
                "uint32_t",
                "uint64_t",
                "int8_t",
                "int16_t",
                "int32_t",
                "int64_t",
                "size_t",
                "uInt",
                "uLong",
            )
        )
        and not is_bool
        and not is_size
    )

    # Detect context pointer
    is_context = False
    if is_pointer and (
        bool(_CONTEXT_HINT_RE.search(type_name))
        or bool(_CONTEXT_HINT_RE.search(name))
        or "struct" in type_name
        or (not is_buffer and not is_size and type_name.endswith("*"))
    ):
        is_context = True

    return ApiParam(
        name=name,
        type_name=type_name,
        is_pointer=is_pointer,
        is_buffer=is_buffer,
        is_size=is_size,
        is_context=is_context,
        is_enum=is_enum,
        is_integral=is_integral,
        is_bool=is_bool,
    )


# ── Function Parsing & Role Classification ───────────────────────────────────


def parse_function_signature(
    signature: str,
    name: str = "",
    line: int = 1,
    call_depth: int = 0,
    score: float = 0.0,
) -> ApiFunction:
    """Parse a full function signature into an ApiFunction model with classified role."""
    clean_sig = signature.strip().rstrip(";")
    clean_sig = re.sub(r"\s+", " ", clean_sig)

    # Extract function name and arguments
    args_match = re.search(r"\((.*?)\)", clean_sig)
    args_str = args_match.group(1).strip() if args_match else ""

    ret_type = "void"
    if args_match:
        before_paren = clean_sig[: args_match.start()].strip()
        if name:
            m_name = re.search(rf"\b{re.escape(name)}\s*$", before_paren)
            if m_name:
                ret_type = before_paren[: m_name.start()].strip() or "void"
            else:
                ret_type = before_paren or "void"
        else:
            m_name = re.search(r"(\w+)\s*$", before_paren)
            if m_name:
                name = m_name.group(1)
                ret_type = before_paren[: m_name.start()].strip() or "void"
            else:
                name = "unknown"
                ret_type = before_paren or "void"
    elif not name:
        m_name = re.search(r"(\w+)\s*$", clean_sig)
        name = m_name.group(1) if m_name else "unknown"

    # Parse parameters
    params: list[ApiParam] = []
    if args_str and args_str != "void":
        raw_params = [p.strip() for p in args_str.split(",") if p.strip()]
        params = [parse_param(p) for p in raw_params]

    # Context type identification
    context_type = ""
    # 1. From parameters
    for p in params:
        if p.is_context:
            context_type = p.type_name.replace("const", "").replace("*", "").replace("struct", "").strip()
            break
    # 2. From return type if pointer
    if not context_type and ("*" in ret_type or any(h in ret_type.lower() for h in ("ctx", "handle", "stream", "parser"))):
        context_type = ret_type.replace("const", "").replace("*", "").replace("struct", "").strip()

    # Role classification
    role = classify_function_role(name=name, return_type=ret_type, params=params)

    # If score not provided, compute baseline
    if score == 0.0:
        has_buf = any(p.is_buffer for p in params)
        has_size = any(p.is_size for p in params)
        if has_buf and has_size:
            score = 0.9
        elif has_buf:
            score = 0.75
        elif role == "process":
            score = 0.6
        elif role in ("init", "cleanup"):
            score = 0.5
        else:
            score = 0.4

    return ApiFunction(
        name=name,
        signature=clean_sig,
        return_type=ret_type,
        params=params,
        role=role,
        context_type=context_type,
        call_depth=call_depth,
        score=score,
        line=line,
    )


def classify_function_role(
    name: str,
    return_type: str = "void",
    params: list[ApiParam] | None = None,
) -> str:
    """Classify API function lifecycle role: 'init', 'configure', 'process', or 'cleanup'."""
    params = params or []
    name_clean = name.strip()

    # 1. Check cleanup first
    if _CLEANUP_NAME_RE.search(name_clean):
        return "cleanup"

    # 2. Check init
    if _INIT_NAME_RE.search(name_clean):
        return "init"

    # Check if return type allocates context or 1st arg is out-pointer (e.g. ctx_t **out)
    if any(p.type_name.endswith("**") for p in params) and not _PROCESS_NAME_RE.search(name_clean):
        return "init"
    if ("*" in return_type or "handle" in return_type.lower()) and not params and not _PROCESS_NAME_RE.search(name_clean):
        return "init"

    # 3. Check configure
    if _CONFIG_NAME_RE.search(name_clean):
        return "configure"

    # 4. Check process
    if _PROCESS_NAME_RE.search(name_clean):
        return "process"

    # Signature shape heuristics:
    has_buffer = any(p.is_buffer for p in params)
    has_size = any(p.is_size for p in params)
    has_context = any(p.is_context for p in params)

    if has_buffer and has_size:
        return "process"
    if has_buffer:
        return "process"
    if has_context and len(params) > 1:
        return "configure"

    return "process"


# ── Context Type Correlation & Reachability Scoring ──────────────────────────


def _extract_prefix(name: str) -> str:
    """Extract library or subsystem prefix (e.g. 'zlib_' or 'target_') from function name."""
    parts = name.split("_")
    if len(parts) > 1:
        return parts[0].lower()
    return ""


def _compute_bfs_reachability(
    start_fn: str,
    call_graph: dict[str, list[str]],
) -> int:
    """Compute maximum transitive depth reachable from a function in the call graph."""
    if not call_graph or start_fn not in call_graph:
        leaf = start_fn.split("::")[-1]
        if leaf not in call_graph:
            return 0
        start_fn = leaf

    visited: set[str] = {start_fn}
    queue: deque[tuple[str, int]] = deque([(start_fn, 0)])
    max_depth = 0

    while queue:
        curr, depth = queue.popleft()
        if depth > max_depth:
            max_depth = depth
        for callee in call_graph.get(curr, []):
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, depth + 1))

    return max_depth


def build_api_sequences(
    source_code: str,
    entry_points: list[EntryPoint] | None = None,
    call_graph: dict[str, list[str]] | None = None,
    reachability_depths: dict[str, int] | None = None,
) -> list[ApiSequence]:
    """Detect stateful API sequences (init -> configure -> process -> cleanup).

    Correlates functions sharing context pointer types or naming prefixes,
    scores sequences using call-graph reachability depth, and prioritizes
    chains that reach deep processing logic.
    """
    call_graph = call_graph or {}
    reachability_depths = reachability_depths or {}

    functions: list[ApiFunction] = []

    # 1. Convert any EntryPoint objects
    if entry_points:
        for ep in entry_points:
            depth = reachability_depths.get(ep.name, ep.call_depth)
            if depth == 0 and ep.name in call_graph:
                depth = _compute_bfs_reachability(ep.name, call_graph)
            fn = parse_function_signature(
                signature=ep.signature,
                name=ep.name,
                line=ep.line,
                call_depth=depth,
                score=ep.score,
            )
            functions.append(fn)

    # 2. Extract function signatures directly from source code
    func_pattern = re.compile(
        r"^(?:[\w\s\*&:]+?)\b(\w+)\s*\(([^)]*)\)\s*(?:;|\{)",
        re.MULTILINE,
    )
    existing_names = {f.name for f in functions}

    for m in func_pattern.finditer(source_code):
        fn_name = m.group(1).strip()
        if fn_name in ("if", "for", "while", "switch", "return", "sizeof", "main"):
            continue
        if fn_name in existing_names:
            continue

        raw_match = m.group(0).rstrip("{;").strip()
        line = source_code[: m.start()].count("\n") + 1
        depth = reachability_depths.get(fn_name, 0)
        if depth == 0 and fn_name in call_graph:
            depth = _compute_bfs_reachability(fn_name, call_graph)

        fn = parse_function_signature(
            signature=raw_match,
            name=fn_name,
            line=line,
            call_depth=depth,
        )
        functions.append(fn)
        existing_names.add(fn_name)

    if not functions:
        return []

    # Group functions by context type or prefix
    clusters: dict[str, list[ApiFunction]] = {}
    for fn in functions:
        key = fn.context_type.lower() if fn.context_type else _extract_prefix(fn.name)
        if not key:
            key = "__default__"
        clusters.setdefault(key, []).append(fn)

    sequences: list[ApiSequence] = []

    for _cluster_key, group in clusters.items():
        inits = [f for f in group if f.role == "init"]
        configs = [f for f in group if f.role == "configure"]
        processes = [f for f in group if f.role == "process"]
        cleanups = [f for f in group if f.role == "cleanup"]

        # If no explicit process, pick the highest-depth/score function not init/cleanup
        if not processes:
            candidates = [f for f in group if f.role not in ("init", "cleanup")]
            if candidates:
                processes = [max(candidates, key=lambda f: (f.call_depth, f.score))]

        # If still no process, pick best non-cleanup function
        if not processes:
            candidates = [f for f in group if f.role != "cleanup"]
            if candidates:
                processes = [candidates[0]]

        # For each process candidate, assemble a sequence
        for proc in processes:
            # Pick best init
            best_init = inits[0] if inits else None
            # Pick best cleanup
            best_cleanup = cleanups[0] if cleanups else None
            # Pick relevant configs (up to 4)
            chosen_configs = configs[:4]

            # Determine context type and var name
            ctx_type = (
                proc.context_type
                or (best_init.context_type if best_init else "")
                or (best_cleanup.context_type if best_cleanup else "")
            )
            if not ctx_type:
                ctx_type = "Context"

            var_name = "ctx"

            # Compute reachability depth across chain
            chain_funcs = [f for f in [best_init, *chosen_configs, proc, best_cleanup] if f is not None]
            chain_depth = max((f.call_depth for f in chain_funcs), default=1)
            chain_depth = max(chain_depth, 1)

            # Compute sequence heuristic score
            score = proc.score
            if best_init:
                score += 0.2
            if best_cleanup:
                score += 0.15
            if chosen_configs:
                score += 0.05 * min(len(chosen_configs), 3)
            if chain_depth > 1:
                score += 0.05 * min(chain_depth, 4)

            score = min(1.0, round(score, 3))

            seq = ApiSequence(
                init_function=best_init,
                configure_functions=chosen_configs,
                process_function=proc,
                cleanup_function=best_cleanup,
                context_type=ctx_type,
                context_var_name=var_name,
                reachability_depth=chain_depth,
                score=score,
            )
            sequences.append(seq)

    # Sort sequences best-first
    sequences.sort(key=lambda s: (-s.score, -s.reachability_depth))

    log.info(
        "harness_synth.sequence_builder.complete",
        functions_parsed=len(functions),
        sequences_built=len(sequences),
        top_sequence_score=sequences[0].score if sequences else 0.0,
    )
    return sequences


# ── Stateful FuzzedDataProvider Harness Generation ───────────────────────────


def generate_stateful_harness(
    sequence: ApiSequence,
    header_include: str = "target.h",
    language: str = "cpp",
) -> str:
    """Generate a production-ready C++ libFuzzer harness using FuzzedDataProvider.

    Partitions input bytes into structured fields, invokes the full
    `init -> configure -> process -> cleanup` lifecycle, and guarantees
    matched resource teardown on all exit paths.
    """
    ctx_var = sequence.context_var_name or "ctx"
    ctx_type = sequence.context_type or "void"

    code_lines: list[str] = [
        "// SPDX-License-Identifier: MIT",
        "// CrashWise auto-generated stateful multi-API fuzz harness.",
        "#include <fuzzer/FuzzedDataProvider.h>",
        "#include <cstddef>",
        "#include <cstdint>",
        "#include <cstdlib>",
        "#include <cstring>",
        "#include <string>",
        "#include <vector>",
        f'#include "{header_include}"',
        "",
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {',
        "    if (size == 0) {",
        "        return 0;",
        "    }",
        "",
        "    FuzzedDataProvider fdp(data, size);",
    ]

    has_ctx = False

    # 1. Initialization Step
    if sequence.init_function:
        init_fn = sequence.init_function
        # Parse init args from FuzzedDataProvider if any
        init_args: list[str] = []
        for i, param in enumerate(init_fn.params):
            if param.is_bool:
                code_lines.append(f"    bool init_flag_{i} = fdp.ConsumeBool();")
                init_args.append(f"init_flag_{i}")
            elif param.is_integral:
                code_lines.append(f"    int init_val_{i} = fdp.ConsumeIntegral<int>();")
                init_args.append(f"init_val_{i}")
            elif param.is_pointer and "char" in param.type_name:
                code_lines.append(f"    std::string init_str_{i} = fdp.ConsumeRandomLengthString(32);")
                init_args.append(f"init_str_{i}.c_str()")
            elif param.type_name.endswith("**"):
                # Out-parameter initialization
                pass

        init_args_str = ", ".join(init_args)

        if any(p.type_name.endswith("**") for p in init_fn.params):
            # Out pointer pattern: target_init(&ctx)
            code_lines.append(f"    {ctx_type} *{ctx_var} = nullptr;")
            code_lines.append(f"    if ({init_fn.name}(&{ctx_var}) != 0 || !{ctx_var}) {{")
            code_lines.append("        return 0;")
            code_lines.append("    }")
            has_ctx = True
        elif "*" in init_fn.return_type or init_fn.return_type.strip() == ctx_type:
            # Pointer return: ctx = target_init(...)
            code_lines.append(f"    auto {ctx_var} = {init_fn.name}({init_args_str});")
            code_lines.append(f"    if (!{ctx_var}) {{")
            code_lines.append("        return 0;")
            code_lines.append("    }")
            has_ctx = True
        else:
            # Value or void return
            code_lines.append(f"    (void){init_fn.name}({init_args_str});")

    # 2. Configuration Step
    if sequence.configure_functions:
        for idx, cfg in enumerate(sequence.configure_functions):
            cfg_args: list[str] = []
            for p_idx, param in enumerate(cfg.params):
                if param.is_context and has_ctx:
                    cfg_args.append(ctx_var)
                elif param.is_bool:
                    code_lines.append(f"    bool cfg_bool_{idx}_{p_idx} = fdp.ConsumeBool();")
                    cfg_args.append(f"cfg_bool_{idx}_{p_idx}")
                elif param.is_enum:
                    code_lines.append(
                        f"    int cfg_enum_{idx}_{p_idx} = fdp.ConsumeIntegralInRange<int>(0, 10);"
                    )
                    cfg_args.append(f"cfg_enum_{idx}_{p_idx}")
                elif param.is_integral:
                    code_lines.append(
                        f"    int cfg_int_{idx}_{p_idx} = fdp.ConsumeIntegral<int>();"
                    )
                    cfg_args.append(f"cfg_int_{idx}_{p_idx}")
                elif param.is_pointer and "char" in param.type_name:
                    code_lines.append(
                        f"    std::string cfg_str_{idx}_{p_idx} = fdp.ConsumeRandomLengthString(32);"
                    )
                    cfg_args.append(f"cfg_str_{idx}_{p_idx}.c_str()")
                else:
                    if param.is_pointer:
                        cfg_args.append("nullptr")
                    else:
                        cfg_args.append("0")

            cfg_args_str = ", ".join(cfg_args)
            code_lines.append(f"    (void){cfg.name}({cfg_args_str});")

    # 3. Process Step
    proc = sequence.process_function
    proc_args: list[str] = []
    buffer_var = "payload"
    size_var = "payload.size()"

    has_proc_buffer = False
    for p_idx, param in enumerate(proc.params):
        if param.is_context and has_ctx:
            proc_args.append(ctx_var)
        elif param.is_buffer:
            has_proc_buffer = True
            proc_args.append(f"{buffer_var}.data()")
        elif param.is_size:
            proc_args.append(size_var)
        elif param.is_bool:
            code_lines.append(f"    bool proc_bool_{p_idx} = fdp.ConsumeBool();")
            proc_args.append(f"proc_bool_{p_idx}")
        elif param.is_integral:
            code_lines.append(f"    int proc_val_{p_idx} = fdp.ConsumeIntegral<int>();")
            proc_args.append(f"proc_val_{p_idx}")
        else:
            if param.is_pointer:
                proc_args.append("nullptr")
            else:
                proc_args.append("0")

    if not proc_args and not proc.params:
        # Single-call with remaining bytes
        code_lines.append("    std::vector<uint8_t> payload = fdp.ConsumeRemainingBytes<uint8_t>();")
        code_lines.append(f"    (void){proc.name}();")
    elif has_proc_buffer:
        code_lines.append("    std::vector<uint8_t> payload = fdp.ConsumeRemainingBytes<uint8_t>();")
        code_lines.append("    if (!payload.empty()) {")
        proc_args_str = ", ".join(proc_args)
        code_lines.append(f"        (void){proc.name}({proc_args_str});")
        code_lines.append("    }")
    else:
        proc_args_str = ", ".join(proc_args)
        code_lines.append(f"    (void){proc.name}({proc_args_str});")

    # 4. Cleanup Step (Guaranteed Teardown)
    if sequence.cleanup_function:
        cleanup_fn = sequence.cleanup_function
        cleanup_args = [ctx_var] if has_ctx else []
        cleanup_args_str = ", ".join(cleanup_args)
        code_lines.append(f"    {cleanup_fn.name}({cleanup_args_str});")

    code_lines.append("    return 0;")
    code_lines.append("}")
    code_lines.append("")

    return "\n".join(code_lines)


__all__ = [
    "build_api_sequences",
    "classify_function_role",
    "generate_stateful_harness",
    "parse_function_signature",
    "parse_param",
]
