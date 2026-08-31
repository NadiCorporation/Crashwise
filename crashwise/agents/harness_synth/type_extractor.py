# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""AST-based type extraction from C/C++ headers and sources.

Operation Hydra Phase 3: AST Type Extraction Engine.
Extracts complete struct, union, enum, and typedef definitions with field layouts,
nested types, and namespace-qualified symbols using Tree-sitter.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Iterator
from pathlib import Path

import tree_sitter
import tree_sitter_c
import tree_sitter_cpp

from crashwise.agents.harness_synth.models import FieldLayout, TypeDefinition
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Tree-sitter Language & Parser singletons
_C_LANGUAGE = tree_sitter.Language(tree_sitter_c.language())
_CPP_LANGUAGE = tree_sitter.Language(tree_sitter_cpp.language())

_PRIMITIVE_TYPES: frozenset[str] = frozenset(
    {
        "void",
        "int",
        "char",
        "short",
        "long",
        "float",
        "double",
        "unsigned",
        "signed",
        "const",
        "size_t",
        "ssize_t",
        "bool",
        "_Bool",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uintptr_t",
        "intptr_t",
        "ptrdiff_t",
        "auto",
        "inline",
        "static",
        "extern",
        "volatile",
        "register",
        "restrict",
        "__restrict",
        "__restrict__",
    }
)


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


def _unwrap_declarator(
    node: tree_sitter.Node,
    source_bytes: bytes,
) -> tuple[str, bool, bool, int | None]:
    """Unwrap pointer, array, or parenthesized declarators.

    Returns (field_name, is_pointer, is_array, array_size).
    """
    is_pointer = False
    is_array = False
    array_size: int | None = None
    curr: tree_sitter.Node | None = node

    while curr is not None:
        if curr.type in ("field_identifier", "identifier", "type_identifier"):
            return _node_text(curr, source_bytes), is_pointer, is_array, array_size
        if curr.type == "pointer_declarator":
            is_pointer = True
            curr = curr.child_by_field_name("declarator") or curr.child(1)
        elif curr.type == "array_declarator":
            is_array = True
            for child in _get_children(curr):
                if child.type in ("number_literal", "identifier"):
                    with contextlib.suppress(ValueError):
                        array_size = int(_node_text(child, source_bytes))
            curr = curr.child_by_field_name("declarator") or curr.child(0)
        elif curr.type == "parenthesized_declarator":
            curr = curr.child_by_field_name("declarator") or curr.child(1)
        elif curr.type == "function_declarator":
            # Function pointer field, e.g. int (*cb)(void*)
            is_pointer = True
            curr = curr.child_by_field_name("declarator") or curr.child(0)
        elif curr.type == "bitfield_clause":
            curr = curr.prev_sibling
        else:
            found_name = ""
            for child in _get_children(curr):
                if child.type in ("field_identifier", "identifier"):
                    found_name = _node_text(child, source_bytes)
                    break
            if found_name:
                return found_name, is_pointer, is_array, array_size
            curr = curr.child(0)

    return "", is_pointer, is_array, array_size


def _extract_field_layout(
    node: tree_sitter.Node, source_bytes: bytes
) -> FieldLayout | None:
    """Extract a FieldLayout from a Tree-sitter field_declaration node."""
    if node.type != "field_declaration":
        return None

    type_parts: list[str] = []
    field_name = ""
    is_pointer = False
    is_array = False
    array_size: int | None = None
    is_nested_struct = False
    nested_type_name: str | None = None

    for child in _get_children(node):
        if child.type in (
            "primitive_type",
            "type_identifier",
            "type_qualifier",
            "sized_type_specifier",
        ):
            type_parts.append(_node_text(child, source_bytes))
        elif child.type in ("struct_specifier", "union_specifier", "class_specifier"):
            is_nested_struct = True
            type_kind = child.type.split("_")[0]
            type_parts.append(type_kind)
            for sub in _get_children(child):
                if sub.type == "type_identifier":
                    nested_type_name = _node_text(sub, source_bytes)
                    type_parts.append(nested_type_name)
                    break
        elif child.type == "enum_specifier":
            is_nested_struct = True
            type_parts.append("enum")
            for sub in _get_children(child):
                if sub.type == "type_identifier":
                    nested_type_name = _node_text(sub, source_bytes)
                    type_parts.append(nested_type_name)
                    break
        elif child.type in (
            "field_identifier",
            "identifier",
            "pointer_declarator",
            "array_declarator",
            "function_declarator",
        ):
            name, ptr, arr, size = _unwrap_declarator(child, source_bytes)
            if name:
                field_name = name
            if ptr:
                is_pointer = True
            if arr:
                is_array = True
                array_size = size
        elif child.type == "bitfield_clause":
            pass

    if not field_name:
        for child in _get_children(node):
            if child.type == "field_identifier":
                field_name = _node_text(child, source_bytes)
                break

    if not field_name:
        return None

    type_str = " ".join(type_parts).strip() if type_parts else "void"
    if is_pointer and not type_str.endswith("*"):
        type_str = f"{type_str}*"

    return FieldLayout(
        name=field_name,
        type_name=type_str,
        is_pointer=is_pointer,
        is_array=is_array,
        array_size=array_size,
        is_nested_struct=is_nested_struct,
        nested_type_name=nested_type_name,
    )


def _get_raw_definition(node: tree_sitter.Node, source_bytes: bytes) -> str:
    """Extract raw definition string including trailing semicolon if present."""
    start = node.start_byte
    end = node.end_byte

    # Look ahead for a trailing semicolon
    tail = source_bytes[end : end + 10]
    semi_idx = tail.find(b";")
    if semi_idx != -1 and tail[:semi_idx].strip() == b"":
        end = end + semi_idx + 1

    raw = source_bytes[start:end].decode("utf-8", "replace").strip()
    if not raw.endswith(";"):
        raw = f"{raw};"
    return raw


def _extract_enum_values(
    enum_node: tree_sitter.Node, source_bytes: bytes
) -> list[str]:
    """Extract enumerator variant names from an enum_specifier."""
    values: list[str] = []
    for child in _get_children(enum_node):
        if child.type == "enumerator_list":
            for enum_item in _get_children(child):
                if enum_item.type == "enumerator":
                    for sub in _get_children(enum_item):
                        if sub.type == "identifier":
                            values.append(_node_text(sub, source_bytes))
                            break
    return values


def _normalize_macros(code: str) -> str:
    """Preprocess common API export, calling conventions, and multiline macros for clean AST parsing."""
    # 0. Unfold line continuations with backslash (\ + newline)
    code = re.sub(r"[ \t]*\\(?:[ \t]*)\r?\n", " ", code)

    # 1. Expand PNG_EXPORT(ordinal, return_type, name, args) -> return_type name args;
    code = re.sub(
        r"PNG_EXPORT\s*\(\s*\d+\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*(\([^;]+?\))\s*\)\s*;?",
        r"\1 \2\3;",
        code,
    )
    code = re.sub(
        r"PNG_EXPORTA\s*\(\s*\d+\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*(\([^;]+?\))\s*,\s*[^)]+\s*\)\s*;?",
        r"\1 \2\3;",
        code,
    )

    # 2. Expand custom function/struct declaration macros like #define DECLARE_PARSER(name) ...
    defines = re.findall(
        r"#define\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s+([^\n]+)", code
    )
    for macro_name, params_raw, body in defines:
        params = [p.strip() for p in params_raw.split(",") if p.strip()]
        if params:
            pattern = rf"(?<!#define\s)\b{macro_name}\s*\(([^)]*)\)"

            def make_repl(
                p_list: list[str], b_body: str
            ) -> Callable[[re.Match[str]], str]:
                def repl(m: re.Match[str]) -> str:
                    args = [a.strip() for a in m.group(1).split(",")]
                    if len(args) != len(p_list):
                        return m.group(0)
                    expanded = b_body
                    for p_name, arg_val in zip(p_list, args, strict=False):
                        expanded = re.sub(
                            rf"##\s*{re.escape(p_name)}\s*##", arg_val, expanded
                        )
                        expanded = re.sub(
                            rf"##\s*{re.escape(p_name)}\b", arg_val, expanded
                        )
                        expanded = re.sub(
                            rf"\b{re.escape(p_name)}\s*##", arg_val, expanded
                        )
                        expanded = re.sub(
                            rf"\b{re.escape(p_name)}\b", arg_val, expanded
                        )
                    expanded = re.sub(r"##", "", expanded)
                    return expanded

                return repl

            code = re.sub(pattern, make_repl(params, body), code)
        else:
            pattern = rf"(?<!#define\s)\b{macro_name}\s*\(\s*\)"
            code = re.sub(pattern, body, code)

    # 3. Strip __attribute__ and __declspec annotations with balanced parens
    code = re.sub(r"__attribute__\s*\(\([^)]*\)\)", " ", code)
    code = re.sub(r"__declspec\s*\([^)]*\)", " ", code)

    # 4. Strip common calling conventions and visibility macros
    calling_convs = (
        r"\bZEXPORT\b",
        r"\bZEXTERN\b",
        r"\bAPI_EXPORT\b",
        r"\bC_EXPORT\b",
        r"\bWINAPI\b",
        r"\b__cdecl\b",
        r"\b__stdcall\b",
        r"\b__fastcall\b",
        r"\bEXPORT\b",
        r"\bPUBLIC_API\b",
        r"\bDLL_EXPORT\b",
        r"\bDLL_IMPORT\b",
    )
    for pat in calling_convs:
        code = re.sub(pat, " ", code)

    return code


class _TypeVisitor:
    """AST visitor that collects TypeDefinition models from Tree-sitter syntax trees."""

    def __init__(self, source_bytes: bytes) -> None:
        self.source_bytes = source_bytes
        self.types_by_name: dict[str, TypeDefinition] = {}

    def visit(self, node: tree_sitter.Node, scope: str = "") -> None:
        """Recursively traverse AST node."""
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
                        self.visit(decl, new_scope)
            return

        if node.type == "linkage_specification":
            # extern "C" { ... }
            for child in _get_children(node):
                if child.type == "declaration_list":
                    for decl in _get_children(child):
                        self.visit(decl, scope)
                elif child.type in (
                    "type_definition",
                    "struct_specifier",
                    "class_specifier",
                    "union_specifier",
                    "enum_specifier",
                ):
                    self.visit(child, scope)
            return

        if node.type == "type_definition":
            self._handle_type_definition(node, scope)
            return

        if node.type in ("struct_specifier", "class_specifier", "union_specifier"):
            self._handle_struct_or_class(node, scope)
            return

        if node.type == "enum_specifier":
            self._handle_enum(node, scope)
            return

        for child in _get_children(node):
            self.visit(child, scope)

    def _handle_type_definition(self, node: tree_sitter.Node, scope: str) -> None:
        """Handle typedef statements."""
        # Find alias name(s) (type_identifier at the end)
        alias_names: list[str] = []
        underlying_type_parts: list[str] = []
        struct_node: tree_sitter.Node | None = None
        enum_node: tree_sitter.Node | None = None

        for child in _get_children(node):
            if child.type == "type_identifier":
                alias_names.append(_node_text(child, self.source_bytes))
            elif child.type in ("struct_specifier", "union_specifier", "class_specifier"):
                struct_node = child
            elif child.type == "enum_specifier":
                enum_node = child
            elif child.type in (
                "primitive_type",
                "sized_type_specifier",
                "type_qualifier",
            ):
                underlying_type_parts.append(_node_text(child, self.source_bytes))

        raw_def = _get_raw_definition(node, self.source_bytes)

        if struct_node is not None:
            # typedef struct [Name] { ... } Alias;
            kind = struct_node.type.split("_")[0]
            struct_tag = ""
            fields: list[FieldLayout] = []
            nested: list[TypeDefinition] = []

            for child in _get_children(struct_node):
                if child.type == "type_identifier":
                    struct_tag = _node_text(child, self.source_bytes)
                elif child.type == "field_declaration_list":
                    for field in _get_children(child):
                        if field.type == "field_declaration":
                            fl = _extract_field_layout(field, self.source_bytes)
                            if fl:
                                fields.append(fl)
                            # Check for nested struct/enum
                            for fc in _get_children(field):
                                if fc.type in (
                                    "struct_specifier",
                                    "union_specifier",
                                    "enum_specifier",
                                ):
                                    sub_visitor = _TypeVisitor(self.source_bytes)
                                    sub_visitor.visit(fc, scope)
                                    nested.extend(sub_visitor.types_by_name.values())

            names_to_register = list(alias_names)
            if struct_tag:
                names_to_register.append(struct_tag)

            for name in names_to_register:
                full_name = f"{scope}::{name}" if scope else name
                tdef = TypeDefinition(
                    name=name,
                    kind=kind,
                    raw_definition=raw_def,
                    fields=fields,
                    nested_types=nested,
                )
                self.types_by_name[name] = tdef
                if scope:
                    self.types_by_name[full_name] = tdef

        elif enum_node is not None:
            # typedef enum [Name] { ... } Alias;
            enum_tag = ""
            for child in _get_children(enum_node):
                if child.type == "type_identifier":
                    enum_tag = _node_text(child, self.source_bytes)
                    break
            enum_values = _extract_enum_values(enum_node, self.source_bytes)

            names_to_register = list(alias_names)
            if enum_tag:
                names_to_register.append(enum_tag)

            for name in names_to_register:
                full_name = f"{scope}::{name}" if scope else name
                tdef = TypeDefinition(
                    name=name,
                    kind="enum",
                    raw_definition=raw_def,
                    enum_values=enum_values,
                )
                self.types_by_name[name] = tdef
                if scope:
                    self.types_by_name[full_name] = tdef

        else:
            # Simple typedef alias, e.g. typedef unsigned char Bytef;
            alias_name = alias_names[-1] if alias_names else ""
            underlying = " ".join(underlying_type_parts).strip()
            if alias_name:
                full_name = f"{scope}::{alias_name}" if scope else alias_name
                tdef = TypeDefinition(
                    name=alias_name,
                    kind="typedef",
                    raw_definition=raw_def,
                    alias_for=underlying,
                )
                self.types_by_name[alias_name] = tdef
                if scope:
                    self.types_by_name[full_name] = tdef

    def _handle_struct_or_class(self, node: tree_sitter.Node, scope: str) -> None:
        """Handle standalone struct, class, or union specifier."""
        tag_name = ""
        fields: list[FieldLayout] = []
        nested: list[TypeDefinition] = []
        kind = node.type.split("_")[0]

        has_body = False
        for child in _get_children(node):
            if child.type == "type_identifier":
                tag_name = _node_text(child, self.source_bytes)
            elif child.type in ("field_declaration_list", "member_specification"):
                has_body = True
                for field in _get_children(child):
                    if field.type == "field_declaration":
                        fl = _extract_field_layout(field, self.source_bytes)
                        if fl:
                            fields.append(fl)
                        for fc in _get_children(field):
                            if fc.type in (
                                "struct_specifier",
                                "union_specifier",
                                "enum_specifier",
                                "class_specifier",
                            ):
                                sub_scope = (
                                    f"{scope}::{tag_name}"
                                    if (scope and tag_name)
                                    else (tag_name or scope)
                                )
                                sub_visitor = _TypeVisitor(self.source_bytes)
                                sub_visitor.visit(fc, sub_scope)
                                nested.extend(sub_visitor.types_by_name.values())
                    elif field.type in (
                        "struct_specifier",
                        "union_specifier",
                        "enum_specifier",
                        "class_specifier",
                    ):
                        sub_scope = (
                            f"{scope}::{tag_name}"
                            if (scope and tag_name)
                            else (tag_name or scope)
                        )
                        sub_visitor = _TypeVisitor(self.source_bytes)
                        sub_visitor.visit(field, sub_scope)
                        nested.extend(sub_visitor.types_by_name.values())

        if not has_body:
            # Forward declaration (e.g. struct Foo;)
            return

        if not tag_name:
            # Anonymous struct without typedef
            return

        raw_def = _get_raw_definition(node, self.source_bytes)
        full_name = f"{scope}::{tag_name}" if scope else tag_name
        tdef = TypeDefinition(
            name=tag_name,
            kind=kind,
            raw_definition=raw_def,
            fields=fields,
            nested_types=nested,
        )
        self.types_by_name[tag_name] = tdef
        if scope:
            self.types_by_name[full_name] = tdef

    def _handle_enum(self, node: tree_sitter.Node, scope: str) -> None:
        """Handle standalone enum specifier."""
        tag_name = ""
        has_body = False
        for child in _get_children(node):
            if child.type == "type_identifier":
                tag_name = _node_text(child, self.source_bytes)
            elif child.type == "enumerator_list":
                has_body = True

        if not has_body or not tag_name:
            return

        raw_def = _get_raw_definition(node, self.source_bytes)
        enum_values = _extract_enum_values(node, self.source_bytes)
        full_name = f"{scope}::{tag_name}" if scope else tag_name
        tdef = TypeDefinition(
            name=tag_name,
            kind="enum",
            raw_definition=raw_def,
            enum_values=enum_values,
        )
        self.types_by_name[tag_name] = tdef
        if scope:
            self.types_by_name[full_name] = tdef


def extract_all_types(
    source_code: str,
    language: str = "cpp",
    tree: tree_sitter.Tree | None = None,
    source_bytes: bytes | None = None,
) -> dict[str, TypeDefinition]:
    """Parse source code with Tree-sitter and return all declared types."""
    if not source_code.strip():
        return {}

    if tree is None or source_bytes is None:
        normalized_code = _normalize_macros(source_code)
        source_bytes = normalized_code.encode("utf-8", errors="replace")
        parser = _get_parser(language)
        tree = parser.parse(source_bytes)

    visitor = _TypeVisitor(source_bytes)
    visitor.visit(tree.root_node)
    return visitor.types_by_name


def extract_types_from_file(file_path: Path) -> dict[str, TypeDefinition]:
    """Extract all types declared in a C/C++ file."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    lang = "c" if file_path.suffix.lower() in {".c", ".h"} else "cpp"
    return extract_all_types(content, language=lang)


def extract_type_structure(workdir: Path, type_name: str) -> TypeDefinition | None:
    """Find and return structured TypeDefinition for a given type name."""
    clean_name = type_name.strip().removeprefix("struct ").removeprefix("enum ").removeprefix("union ")
    if not clean_name:
        return None

    # Fast path: if workdir is a single file
    if workdir.is_file():
        types = extract_types_from_file(workdir)
        if clean_name in types:
            return types[clean_name]
        return None

    header_dirs = [workdir]
    for subdir in ("include", "src", "lib"):
        candidate = workdir / subdir
        if candidate.is_dir():
            header_dirs.append(candidate)

    for d in header_dirs:
        for h in d.rglob("*"):
            if not h.is_file() or h.suffix.lower() not in {".h", ".hpp", ".hxx", ".c", ".cpp", ".cc"}:
                continue
            try:
                rel_parts = h.relative_to(d).parts[:-1]
            except ValueError:
                rel_parts = h.parts[:-1]
            if any(part.startswith(".") or part in {"build", "cmake-build"} for part in rel_parts):
                continue
            types = extract_types_from_file(h)
            if clean_name in types:
                return types[clean_name]
            # Match suffix for namespaced types (e.g. net::Packet matches Packet)
            for k, v in types.items():
                if k == clean_name or k.endswith(f"::{clean_name}"):
                    return v

    return None


def extract_type_definition(workdir: Path, type_name: str) -> str | None:
    """Find and return the full C/C++ definition of a type from project headers/sources.

    Searches for struct definitions, typedefs, enums, unions, and nested types.
    Returns the complete C/C++ definition string, or None if not found.
    """
    tdef = extract_type_structure(workdir, type_name)
    if tdef is not None:
        return tdef.raw_definition
    return None


def extract_types_for_signature(workdir: Path, signature: str) -> str:
    """Extract all custom type definitions referenced in a function signature.

    Parses the signature for non-primitive type names and recursively looks up
    definitions and their transitively referenced nested types.
    Returns a concatenated string of all found definitions separated by double newlines.
    """
    cleaned = re.sub(r"[*&\[\](),;]", " ", signature)
    # Extract identifiers (including qualified names like net::Packet)
    raw_tokens = re.findall(r"\b([A-Za-z_][\w:]*)\b", cleaned)

    types_found: list[str] = []
    seen_names: set[str] = set()
    queue: list[str] = []

    for tok in raw_tokens:
        tok_leaf = tok.split("::")[-1]
        if tok_leaf in _PRIMITIVE_TYPES or tok in _PRIMITIVE_TYPES:
            continue
        if tok_leaf[0].islower() and len(tok_leaf) < 4:
            continue
        if tok not in seen_names:
            seen_names.add(tok)
            queue.append(tok)

    # Transitive type resolution BFS (up to 5 levels)
    depth = 0
    while queue and depth < 5:
        next_queue: list[str] = []
        for type_name in queue:
            tdef = extract_type_structure(workdir, type_name)
            if tdef and tdef.raw_definition:
                if tdef.raw_definition not in types_found:
                    types_found.append(tdef.raw_definition)
                # Enqueue referenced field types
                for field in tdef.fields:
                    f_clean = re.sub(r"[*&\[\](),;]", " ", field.type_name)
                    for f_tok in re.findall(r"\b([A-Za-z_][\w:]*)\b", f_clean):
                        f_leaf = f_tok.split("::")[-1]
                        if f_leaf in _PRIMITIVE_TYPES or f_tok in seen_names:
                            continue
                        if f_leaf[0].islower() and len(f_leaf) < 4:
                            continue
                        seen_names.add(f_tok)
                        next_queue.append(f_tok)
        queue = next_queue
        depth += 1

    if types_found:
        log.info("type_extractor.found", count=len(types_found))

    return "\n\n".join(types_found)


__all__ = [
    "extract_all_types",
    "extract_type_definition",
    "extract_type_structure",
    "extract_types_for_signature",
    "extract_types_from_file",
]
