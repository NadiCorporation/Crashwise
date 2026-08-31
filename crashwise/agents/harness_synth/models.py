# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Pydantic data models for AST code analysis, type extraction, and harness synthesis.

Defines strict models representing discovered entry points, call graphs,
type definitions, and structured AST analysis results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    """Strict, non-frozen base model for AST and harness synthesis objects."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )


class FieldLayout(_StrictModel):
    """Layout information for a struct, class, or union field."""

    name: str = Field(..., description="Field identifier name")
    type_name: str = Field(..., description="C/C++ type of the field (e.g. 'uint32_t', 'char*')")
    is_pointer: bool = Field(default=False, description="Whether the field is a pointer type")
    is_array: bool = Field(default=False, description="Whether the field is a fixed-size array")
    array_size: int | None = Field(default=None, description="Dimension size if fixed-size array")
    is_nested_struct: bool = Field(
        default=False, description="Whether this field is an inline nested struct/union"
    )
    nested_type_name: str | None = Field(
        default=None, description="Name of the nested struct type if applicable"
    )


class TypeDefinition(_StrictModel):
    """Structured representation of an extracted C/C++ type."""

    name: str = Field(..., description="Type name or typedef alias")
    kind: str = Field(
        default="struct",
        description="Type classification: 'struct', 'class', 'enum', 'typedef', or 'union'",
    )
    raw_definition: str = Field(
        default="", description="Original C/C++ source definition code block"
    )
    fields: list[FieldLayout] = Field(
        default_factory=list, description="Fields if struct/class/union"
    )
    enum_values: list[str] = Field(
        default_factory=list, description="Enum variant identifiers if enum"
    )
    alias_for: str | None = Field(
        default=None, description="Underlying type name if this is a typedef"
    )
    nested_types: list[TypeDefinition] = Field(
        default_factory=list, description="Nested type definitions declared within this type"
    )


class EntryPoint(_StrictModel):
    """A candidate fuzzing entry point discovered by AST analysis."""

    name: str = Field(..., description="Function name, e.g. ``parse_packet``")
    signature: str = Field(..., description="Best-effort full signature line")
    line: int = Field(..., ge=1, description="1-indexed source line number")
    takes_buffer: bool = Field(
        default=False,
        description=(
            "True if the first/second args look like (uint8_t*, size_t) — i.e. "
            "the function can be driven directly by libFuzzer's input buffer."
        ),
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Heuristic 0..1 ranking for prioritisation",
    )
    call_depth: int = Field(
        default=0,
        ge=0,
        description="Transitive call graph depth reachable from this entry point",
    )
    callees: list[str] = Field(
        default_factory=list,
        description="Direct callee function names called by this entry point",
    )
    namespace: str = Field(
        default="",
        description="Enclosing C++ namespace or class scope (e.g. 'net::protocol')",
    )
    is_template: bool = Field(
        default=False,
        description="Whether the entry point is a C++ template function/method",
    )


class ApiParam(_StrictModel):
    """A parameter of an API function."""

    name: str = Field(default="", description="Parameter identifier name")
    type_name: str = Field(
        ..., description="C/C++ type (e.g. 'int', 'const uint8_t*', 'TargetCtx*')"
    )
    is_pointer: bool = Field(default=False, description="Whether parameter is a pointer type")
    is_buffer: bool = Field(
        default=False,
        description="Whether parameter is a raw byte buffer (uint8_t*, char*)",
    )
    is_size: bool = Field(
        default=False, description="Whether parameter is a size/length argument"
    )
    is_context: bool = Field(
        default=False, description="Whether parameter is a context/handle pointer"
    )
    is_enum: bool = Field(default=False, description="Whether parameter is an enum type")
    is_integral: bool = Field(
        default=False, description="Whether parameter is an integer/scalar type"
    )
    is_bool: bool = Field(default=False, description="Whether parameter is a boolean flag")


class ApiFunction(_StrictModel):
    """An API function participating in a lifecycle sequence."""

    name: str = Field(..., description="Function identifier name")
    signature: str = Field(..., description="Full function signature")
    return_type: str = Field(default="void", description="C/C++ return type")
    params: list[ApiParam] = Field(
        default_factory=list, description="Extracted parameters"
    )
    role: str = Field(
        default="process",
        description="Lifecycle role: 'init', 'configure', 'process', or 'cleanup'",
    )
    context_type: str = Field(
        default="", description="Context struct/typedef name if associated"
    )
    call_depth: int = Field(
        default=0, ge=0, description="Transitive call graph depth"
    )
    score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Heuristic ranking score"
    )
    line: int = Field(default=1, ge=1, description="1-indexed line number in source")


class ApiSequence(_StrictModel):
    """A stateful sequence of API calls (init -> configure -> process -> cleanup)."""

    init_function: ApiFunction | None = Field(
        default=None, description="Initialization/allocation function"
    )
    configure_functions: list[ApiFunction] = Field(
        default_factory=list, description="Configuration functions called on context"
    )
    process_function: ApiFunction = Field(
        ..., description="Main processing/parsing function that consumes fuzzed data"
    )
    cleanup_function: ApiFunction | None = Field(
        default=None, description="Cleanup/destruction/free function"
    )
    context_type: str = Field(
        default="", description="Context struct or typedef type name"
    )
    context_var_name: str = Field(
        default="ctx", description="C++ variable name for context handle"
    )
    reachability_depth: int = Field(
        default=1,
        ge=0,
        description="Maximum reachability depth reachable across the chain",
    )
    score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Sequence heuristic score"
    )


class AnalysisResult(_StrictModel):
    """Complete outcome of AST-based static analysis for a target or source file."""

    entry_points: list[EntryPoint] = Field(
        default_factory=list,
        description="Prioritised list of candidate fuzzing entry points",
    )
    api_sequences: list[ApiSequence] = Field(
        default_factory=list,
        description="Discovered API lifecycle sequences (init -> configure -> process -> cleanup)",
    )
    call_graph: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Adjacency list mapping caller function names to direct callees",
    )
    reachability_depths: dict[str, int] = Field(
        default_factory=dict,
        description="Map of function name to maximum transitive call depth reached via BFS",
    )
    type_definitions: dict[str, str] = Field(
        default_factory=dict,
        description="Map of type name to raw C/C++ definition string",
    )
    structured_types: dict[str, Any] = Field(
        default_factory=dict,
        description="Map of type name to structured TypeDefinition / dict representation",
    )
    source_path: Path | None = Field(
        default=None,
        description="Path to the primary analysed source or header file",
    )
    language: str = Field(
        default="cpp",
        description="Detected programming language ('c' or 'cpp')",
    )


__all__ = [
    "AnalysisResult",
    "ApiFunction",
    "ApiParam",
    "ApiSequence",
    "EntryPoint",
    "FieldLayout",
    "TypeDefinition",
    "_StrictModel",
]
