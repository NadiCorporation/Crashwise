# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""AST-based static analysis pass — find fuzzable entry points, build call graphs,
and compute transitive reachability depth in C/C++ source code.

Replaces regex heuristics with a production Tree-sitter C/C++ AST parser
supporting templates, namespaces, macro wrappers, nested types, and call graph analysis.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import tree_sitter
import tree_sitter_c
import tree_sitter_cpp

from crashwise.agents.harness_synth.models import AnalysisResult, EntryPoint
from crashwise.agents.harness_synth.type_extractor import (
    _normalize_macros,
    extract_all_types,
)
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Tree-sitter Language & Parser singletons
_C_LANGUAGE = tree_sitter.Language(tree_sitter_c.language())
_CPP_LANGUAGE = tree_sitter.Language(tree_sitter_cpp.language())

_BUFFER_HINTS: tuple[str, ...] = (
    "parse",
    "decode",
    "read",
    "deserialize",
    "process",
    "consume",
    "load",
    "unpack",
    "extract",
)

# High-value function name patterns for security-critical targets.
_HIGH_VALUE_NAMES: tuple[str, ...] = (
    "inflate",
    "deflate",
    "decompress",
    "compress",
    "uncompress",
    "decode",
    "parse",
    "read",
    "unpack",
    "deserialize",
    "load",
    "extract",
    "process",
    "handle",
    "dispatch",
    "recv",
    "input",
    "decrypt",
    "verify",
    "authenticate",
    "open",
    "accept",
    "memcpy",
    "memmove",
    "malloc",
    "realloc",
    "free",
    "reallocarray",
)

# Common typedefs in C libraries that resolve to buffer-like or high-value types.
_TYPEDEF_MAP: dict[str, str] = {
    "Bytef": "unsigned char",
    "Byte": "unsigned char",
    "uChar": "unsigned char",
    "Byte*": "unsigned char*",
    "Bytef*": "unsigned char*",
    "pcre2_code": "struct*",
    "z_streamp": "struct*",
    "z_stream*": "struct*",
    "png_structp": "struct*",
    "png_infop": "struct*",
    "SSL*": "struct*",
    "SSL_CTX*": "struct*",
    "EVP_MD_CTX*": "struct*",
    "BIO*": "struct*",
    "FILE*": "struct*",
    "gzFile": "struct*",
    "uLong": "unsigned long",
    "uLongf": "unsigned long",
    "uInt": "unsigned int",
    "voidp": "void*",
    "voidpf": "void*",
    "voidpc": "const void*",
}

_BYTE_BUFFER_RE = re.compile(
    r"^(?:const\s+)?(?:unsigned\s+char|uint8_t|u8|Bytef|Byte|uChar)\s*\*\s*\w*$"
)
_C_STRING_RE = re.compile(r"^(?:const\s+)?char\s*\*\s*\w*$")
_VOID_PTR_RE = re.compile(r"^(?:const\s+)?void\s*\*\s*\w*$")
_INT_SIZE_RE = re.compile(
    r"^(?:const\s+)?(?:size_t|ssize_t|unsigned\s+(?:int|long)|int|long|"
    r"u?int(?:8|16|32|64)_t|uLong|uLongf|uInt)\s*\w*$"
)


def detect_language(path: Path) -> str:
    """Return ``"c"`` or ``"cpp"`` based on the file extension."""
    return "c" if path.suffix.lower() in {".c", ".h"} else "cpp"


def _get_parser(language: str = "cpp") -> tree_sitter.Parser:
    """Return a configured Tree-sitter parser for C or C++."""
    lang = _C_LANGUAGE if language == "c" else _CPP_LANGUAGE
    return tree_sitter.Parser(lang)


def _node_text(node: tree_sitter.Node | None, source_bytes: bytes) -> str:
    """Safely decode node text to a string using direct byte slicing."""
    if node is None:
        return ""
    start = node.start_byte
    end = node.end_byte
    return source_bytes[start:end].decode("utf-8", "replace")


def _get_children(node: tree_sitter.Node | None) -> Iterator[tree_sitter.Node]:
    """Safely yield children of a node one by one."""
    if node is None:
        return
    for i in range(node.child_count):
        c = node.child(i)
        if c is not None:
            yield c


# ── Signature Normalization & Argument Splitting ──────────────────────────────


def _split_args(args_raw: str) -> list[str]:
    """Split a comma-separated argument list into trimmed individual argument strings."""
    return [a.strip() for a in args_raw.split(",") if a.strip()]


def _resolve_typedef(arg: str) -> str:
    """Resolve known typedefs to canonical types for scoring."""
    stripped = arg.strip()
    for typedef, resolved in _TYPEDEF_MAP.items():
        if typedef in stripped:
            return resolved
    return stripped


def _is_byte_buffer(arg: str) -> bool:
    return bool(_BYTE_BUFFER_RE.match(arg.strip()))


def _is_c_string(arg: str) -> bool:
    return bool(_C_STRING_RE.match(arg.strip()))


def _is_void_ptr(arg: str) -> bool:
    return bool(_VOID_PTR_RE.match(arg.strip()))


def _is_integer_size(arg: str) -> bool:
    return bool(_INT_SIZE_RE.match(arg.strip()))


def _score_arguments(name: str, args_raw: str) -> tuple[float, bool]:
    """Compute base heuristic score and takes_buffer flag for a function signature."""
    args = _split_args(args_raw)
    if not args:
        # Check if function name matches strong hint
        lname = name.lower()
        if any(h in lname for h in _BUFFER_HINTS):
            return (0.3, False)
        return (0.0, False)

    resolved_args = [_resolve_typedef(a) for a in args]
    first = resolved_args[0]
    second = resolved_args[1] if len(resolved_args) > 1 else ""

    lname = name.lower()

    # 1) Perfect libFuzzer shape: (const? uint8_t* / unsigned char*, size_t)
    if _is_byte_buffer(first) and _is_integer_size(second):
        return (1.0, True)

    # Typedef'd buffer (e.g. Bytef* + uLong)
    if "unsigned char" in first and (
        "unsigned long" in second or _is_integer_size(second)
    ):
        return (0.95, True)

    # Multi-buffer destination/source pattern: (dest, destLen, src, srcLen)
    if len(args) >= 4 and "unsigned char" in resolved_args[2]:
        return (0.95, True)

    # 2) Single (const) char* parser or (const char*, size_t)
    if _is_c_string(args[0]) and len(args) == 1:
        return (0.7, True)
    if _is_c_string(args[0]) and _is_integer_size(args[1] if len(args) > 1 else ""):
        return (0.85, True)

    # 3) (void*, size_t)
    if _is_void_ptr(args[0]) and _is_integer_size(args[1] if len(args) > 1 else ""):
        return (0.5, True)

    # 4) Struct-pointer API (e.g. z_streamp, png_structp)
    if "struct*" in first:
        if any(h in lname for h in _HIGH_VALUE_NAMES):
            return (0.85, False)
        return (0.6, False)

    # 5) High-value name hints
    if any(h in lname for h in _HIGH_VALUE_NAMES):
        return (0.7, False)

    # 6) Generic name hints
    if any(h in lname for h in _BUFFER_HINTS):
        return (0.3, False)

    return (0.0, False)


def _dedupe(eps: Iterable[EntryPoint]) -> list[EntryPoint]:
    """Deduplicate entry points by name preserving first/best candidate."""
    seen: set[str] = set()
    out: list[EntryPoint] = []
    for ep in eps:
        if ep.name in seen:
            continue
        seen.add(ep.name)
        out.append(ep)
    return out


# ── AST Traversal & Call Graph Construction ───────────────────────────────────


class _ASTFunctionInfo:
    """Intermediate function metadata extracted from Tree-sitter AST."""

    def __init__(
        self,
        name: str,
        signature: str,
        line: int,
        args_raw: str,
        scope: str = "",
        is_template: bool = False,
        callees: list[str] | None = None,
    ) -> None:
        self.name = name
        self.signature = signature
        self.line = line
        self.args_raw = args_raw
        self.scope = scope
        self.is_template = is_template
        self.callees = callees or []


class _ASTAnalyzerVisitor:
    """Tree-sitter AST visitor extracting functions, templates, scopes, and calls."""

    def __init__(self, source_bytes: bytes) -> None:
        self.source_bytes = source_bytes
        self.functions: list[_ASTFunctionInfo] = []
        self.call_graph: dict[str, list[str]] = {}

    def visit(
        self,
        node: tree_sitter.Node,
        scope: str = "",
        is_template: bool = False,
    ) -> None:
        """Recursively traverse AST nodes."""
        if node.type == "namespace_definition":
            ns_name = ""
            for child in _get_children(node):
                if child.type in (
                    "namespace_identifier",
                    "nested_namespace_specifier",
                    "identifier",
                ):
                    ns_name = _node_text(child, self.source_bytes)
                elif child.type == "declaration_list":
                    new_scope = (
                        f"{scope}::{ns_name}" if scope and ns_name else (ns_name or scope)
                    )
                    for decl in _get_children(child):
                        self.visit(decl, new_scope, is_template)
            return

        if node.type in ("class_specifier", "struct_specifier"):
            cls_name = ""
            for child in _get_children(node):
                if child.type == "type_identifier":
                    cls_name = _node_text(child, self.source_bytes)
                elif child.type in ("field_declaration_list", "member_specification"):
                    new_scope = (
                        f"{scope}::{cls_name}" if scope and cls_name else (cls_name or scope)
                    )
                    for member in _get_children(child):
                        self.visit(member, new_scope, is_template)
            return

        if node.type == "template_declaration":
            for child in _get_children(node):
                if child.type in ("function_definition", "declaration"):
                    self._handle_function_node(child, scope, is_template=True)
                elif child.type in ("class_specifier", "struct_specifier"):
                    self.visit(child, scope, is_template=True)
            return

        if node.type == "linkage_specification":
            # extern "C" { ... }
            for child in _get_children(node):
                if child.type == "declaration_list":
                    for decl in _get_children(child):
                        self.visit(decl, scope, is_template)
                elif child.type in ("function_definition", "declaration"):
                    self.visit(child, scope, is_template)
            return

        if node.type in ("function_definition", "declaration", "parameter_declaration"):
            self._handle_function_node(node, scope, is_template=is_template)
            if node.type != "parameter_declaration":
                return

        if node.type == "compound_statement":
            # Handle orphaned function bodies following syntax error recovery
            prev = node.prev_sibling
            if prev is not None and prev.type in ("ERROR", "expression_statement"):
                def _find_recovered_call(n: tree_sitter.Node) -> tree_sitter.Node | None:
                    if n.type == "call_expression":
                        return n
                    for c in _get_children(n):
                        res = _find_recovered_call(c)
                        if res is not None:
                            return res
                    return None

                call_node = _find_recovered_call(prev)
                if call_node is not None and call_node.child_count >= 2:
                    fn_child = call_node.child(0)
                    args_child = call_node.child(1)
                    fn_name = _node_text(fn_child, self.source_bytes).strip()
                    args_text = _node_text(args_child, self.source_bytes).strip()
                    if args_text.startswith("(") and args_text.endswith(")"):
                        args_text = args_text[1:-1].strip()
                    if fn_name and fn_name not in ("if", "for", "while", "switch", "return", "sizeof"):
                        callees = self._extract_callees(node)
                        self.call_graph[fn_name] = list(callees)
                        if scope:
                            self.call_graph[f"{scope}::{fn_name}"] = list(callees)
                        fn_info = _ASTFunctionInfo(
                            name=fn_name,
                            signature=f"int {fn_name}({args_text})",
                            line=self.source_bytes[:node.start_byte].count(b"\n") + 1,
                            args_raw=args_text,
                            scope=scope,
                            is_template=is_template,
                            callees=callees,
                        )
                        self.functions.append(fn_info)

        for child in _get_children(node):
            self.visit(child, scope, is_template)

    def _extract_callees(self, body_node: tree_sitter.Node) -> list[str]:
        """Extract callee identifiers from a function's compound_statement body."""
        callees: list[str] = []

        def walk_calls(n: tree_sitter.Node) -> None:
            if n.type == "call_expression":
                fn_child = n.child_by_field_name("function") or n.child(0)
                if fn_child is not None:
                    raw_callee = _node_text(fn_child, self.source_bytes).strip()
                    # Clean up method or namespace call expressions (e.g. obj.method, ns::func)
                    clean_leaf = (
                        raw_callee.split("->")[-1].split(".")[-1].split("::")[-1].strip()
                    )
                    if clean_leaf and clean_leaf not in callees:
                        callees.append(clean_leaf)
            for ch in _get_children(n):
                walk_calls(ch)

        walk_calls(body_node)
        return callees

    def _find_function_declarator(
        self, node: tree_sitter.Node
    ) -> tree_sitter.Node | None:
        """Find the function_declarator node inside a declaration or pointer_declarator."""
        if node.type == "function_declarator":
            return node
        for child in _get_children(node):
            if child.type in (
                "function_declarator",
                "pointer_declarator",
                "template_function",
                "reference_declarator",
            ):
                res = self._find_function_declarator(child)
                if res is not None:
                    return res
        return None

    def _handle_function_node(
        self,
        node: tree_sitter.Node,
        scope: str,
        is_template: bool,
    ) -> None:
        """Process a function_definition or declaration node."""
        ret_parts: list[str] = []
        func_decl: tree_sitter.Node | None = None
        body_node: tree_sitter.Node | None = None

        for child in _get_children(node):
            if child.type in (
                "primitive_type",
                "type_identifier",
                "sized_type_specifier",
                "type_qualifier",
                "auto",
                "placeholder_type_specifier",
                "struct_specifier",
                "enum_specifier",
            ):
                ret_parts.append(_node_text(child, self.source_bytes))
            elif child.type in (
                "function_declarator",
                "pointer_declarator",
                "template_function",
                "reference_declarator",
            ):
                func_decl = self._find_function_declarator(child)
            elif child.type == "compound_statement":
                body_node = child

        if func_decl is None:
            return

        # Check if this is a function pointer variable (e.g. void (*cb)(int)) rather than a function
        first_child = func_decl.child(0)
        if first_child is not None and first_child.type == "parenthesized_declarator":
            return

        name = ""
        args_raw = ""
        for child in _get_children(func_decl):
            if child.type in (
                "identifier",
                "field_identifier",
                "destructor_name",
                "qualified_identifier",
            ):
                name = _node_text(child, self.source_bytes)
            elif child.type == "parameter_list":
                param_text = _node_text(child, self.source_bytes)
                # Remove surrounding parens for args_raw
                if param_text.startswith("(") and param_text.endswith(")"):
                    args_raw = param_text[1:-1].strip()
                else:
                    args_raw = param_text.strip()

        if not name or name in ("if", "for", "while", "switch", "return", "sizeof"):
            return

        ret_type = " ".join(ret_parts).strip() or "void"
        signature = f"{ret_type} {name}({args_raw})"
        line = self.source_bytes[:node.start_byte].count(b"\n") + 1

        callees: list[str] = []
        if body_node is not None:
            callees = self._extract_callees(body_node)
            self.call_graph[name] = list(callees)
            if scope:
                self.call_graph[f"{scope}::{name}"] = list(callees)

        fn_info = _ASTFunctionInfo(
            name=name,
            signature=signature,
            line=line,
            args_raw=args_raw,
            scope=scope,
            is_template=is_template,
            callees=callees,
        )
        self.functions.append(fn_info)


# ── Transitive Reachability & BFS Scoring ─────────────────────────────────────


def _compute_reachability(
    entry_point_name: str,
    call_graph: dict[str, list[str]],
) -> tuple[int, set[str], bool]:
    """Compute maximum call depth and transitive callees reached from an entry point via BFS.

    Returns (max_depth, reached_callees_set, reaches_deep_logic).
    """
    if entry_point_name not in call_graph:
        leaf_name = entry_point_name.split("::")[-1]
        if leaf_name not in call_graph:
            return 0, set(), False
        entry_point_name = leaf_name

    visited: set[str] = {entry_point_name}
    queue: deque[tuple[str, int]] = deque([(entry_point_name, 0)])
    max_depth = 0
    reaches_deep = False

    while queue:
        curr, depth = queue.popleft()
        if curr != entry_point_name:
            if depth > max_depth:
                max_depth = depth
            curr_lower = curr.lower()
            if any(h in curr_lower for h in _HIGH_VALUE_NAMES):
                reaches_deep = True

        for callee in call_graph.get(curr, []):
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, depth + 1))

    callees_reached = {c for c in visited if c != entry_point_name}
    return max_depth, callees_reached, reaches_deep


def _score_and_build_entry_points(
    functions: list[_ASTFunctionInfo],
    call_graph: dict[str, list[str]],
) -> tuple[list[EntryPoint], dict[str, int]]:
    """Score candidate functions using parameter shapes and transitive reachability depth."""
    entry_points: list[EntryPoint] = []
    reachability_depths: dict[str, int] = {}

    for fn in functions:
        base_score, takes_buffer = _score_arguments(fn.name, fn.args_raw)
        if base_score == 0.0:
            continue

        call_depth, reachable_callees, reaches_deep = _compute_reachability(
            fn.name, call_graph
        )
        reachability_depths[fn.name] = call_depth

        # Score adjustments based on reachability and deep logic
        score = base_score
        if reaches_deep:
            score = min(1.0, score + 0.15)
        if call_depth > 0:
            score = min(1.0, score + 0.05 * min(call_depth, 3))

        ep = EntryPoint(
            name=fn.name,
            signature=fn.signature,
            line=fn.line,
            takes_buffer=takes_buffer,
            score=round(score, 3),
            call_depth=call_depth,
            callees=list(reachable_callees or fn.callees),
            namespace=fn.scope,
            is_template=fn.is_template,
        )
        entry_points.append(ep)

    return entry_points, reachability_depths


# ── Public API Functions ───────────────────────────────────────────────────────


def analyze_source(
    source_code: str,
    workdir: Path | None = None,
    source_path: Path | None = None,
) -> AnalysisResult:
    """Run full AST analysis on C/C++ source code.

    Extracts entry points, constructs call graph, computes reachability depth,
    and extracts type definitions.
    """
    if not source_code.strip():
        return AnalysisResult(source_path=source_path)

    language = "cpp"
    if source_path is not None:
        language = detect_language(source_path)

    normalized_code = _normalize_macros(source_code)
    source_bytes = normalized_code.encode("utf-8", errors="replace")

    parser = _get_parser(language)
    tree = parser.parse(source_bytes)

    visitor = _ASTAnalyzerVisitor(source_bytes)
    visitor.visit(tree.root_node)

    # If workdir is provided, merge call graphs from other files in workdir
    call_graph = dict(visitor.call_graph)
    if workdir is not None and workdir.is_dir():
        for f in workdir.rglob("*"):
            if not f.is_file() or f.suffix.lower() not in {".c", ".cpp", ".cc"}:
                continue
            if any(part.startswith(".") for part in f.parts):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                other_norm = _normalize_macros(content)
                other_bytes = other_norm.encode("utf-8", errors="replace")
                other_tree = parser.parse(other_bytes)
                other_vis = _ASTAnalyzerVisitor(other_bytes)
                other_vis.visit(other_tree.root_node)
                for k, v in other_vis.call_graph.items():
                    if k not in call_graph:
                        call_graph[k] = v
            except OSError:
                continue

    entry_points, reachability_depths = _score_and_build_entry_points(
        visitor.functions, call_graph
    )
    entry_points.sort(key=lambda ep: (-ep.score, ep.line))
    deduped_eps = _dedupe(entry_points)

    # Extract type definitions
    type_definitions: dict[str, str] = {}
    structured_types: dict[str, Any] = {}
    extracted = extract_all_types(
        source_code, language=language, tree=tree, source_bytes=source_bytes
    )
    for name, tdef in extracted.items():
        type_definitions[name] = tdef.raw_definition
        structured_types[name] = tdef.model_dump()

    return AnalysisResult(
        entry_points=deduped_eps,
        call_graph=call_graph,
        reachability_depths=reachability_depths,
        type_definitions=type_definitions,
        structured_types=structured_types,
        source_path=source_path,
        language=language,
    )


def find_entry_points(source_code: str, *, max_results: int = 10) -> list[EntryPoint]:
    """Return entry-point candidates ordered by descending heuristic score."""
    result = analyze_source(source_code)
    log.info(
        "harness_synth.analyzer.found",
        candidates=len(result.entry_points),
        deduped=len(result.entry_points),
    )
    return result.entry_points[:max_results]


def _detect_init_cleanup(
    name: str, all_names: set[str]
) -> tuple[str | None, str | None]:
    """Detect likely init/cleanup functions for a given API function."""
    base = name.lower()
    init_fn = None
    cleanup_fn = None

    for candidate in all_names:
        cl = candidate.lower()
        if cl in (f"{base}init", f"{base}_init", f"{base}init2") or (
            cl.replace("_", "") == base.replace("_", "") + "init"
        ):
            init_fn = candidate
        if cl in (
            f"{base}end",
            f"{base}_end",
            f"{base}_free",
            f"{base}_close",
            f"{base}End",
            f"{base}_destroy",
        ):
            cleanup_fn = candidate

    return init_fn, cleanup_fn


def find_public_api(workdir: Path, *, max_results: int = 10) -> list[EntryPoint]:
    """Scan public header files using AST analysis to discover the real API surface.

    Understands typedef'd types, struct-pointer APIs, macro wrappers, and
    lifecycle patterns.
    """
    header_dirs = [workdir]
    for subdir in ("include", "src", "lib"):
        candidate = workdir / subdir
        if candidate.is_dir():
            header_dirs.append(candidate)

    candidates: list[EntryPoint] = []
    all_function_names: set[str] = set()

    header_files: list[Path] = []
    for d in header_dirs:
        for h in d.rglob("*.h"):
            try:
                rel_parts = h.relative_to(d).parts[:-1]
            except ValueError:
                rel_parts = h.parts[:-1]
            if any(part.startswith(".") for part in rel_parts):
                continue
            header_files.append(h)

    # First pass: collect all declared functions across headers
    for h in header_files:
        try:
            content = h.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        res = analyze_source(content, source_path=h)
        for ep in res.entry_points:
            all_function_names.add(ep.name)
            candidates.append(ep)

    # Second pass: annotate lifecycle hints and sort
    for ep in candidates:
        _init_fn, _cleanup_fn = _detect_init_cleanup(ep.name, all_function_names)

    candidates.sort(key=lambda ep: (-ep.score, ep.name))
    deduped = _dedupe(candidates)
    log.info(
        "harness_synth.analyzer.public_api_found",
        header_count=len(header_files),
        candidates=len(deduped),
    )
    return deduped[:max_results]


__all__ = [
    "analyze_source",
    "detect_language",
    "find_entry_points",
    "find_public_api",
]
