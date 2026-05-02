# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the harness-synth code analyzer."""

from __future__ import annotations

from pathlib import Path

from crashwise.agents.harness_synth.analyzer import (
    detect_language,
    find_entry_points,
)

_LIBFUZZER_SHAPE = """\
#include <cstdint>
#include <cstddef>

int parse_packet(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    return data[0] + data[1];
}

void unrelated() {
    return;
}
"""

_C_STRING_PARSER = """\
#include <stdio.h>
#include <string.h>

int decode_header(const char *input) {
    if (!input) return -1;
    return (int)strlen(input);
}
"""

_NO_HITS = """\
int main(int argc, char **argv) {
    return 0;
}
"""


def test_detect_language_extensions(tmp_path: Path) -> None:
    assert detect_language(tmp_path / "x.c") == "c"
    assert detect_language(tmp_path / "x.h") == "c"
    assert detect_language(tmp_path / "x.cpp") == "cpp"
    assert detect_language(tmp_path / "x.cxx") == "cpp"
    assert detect_language(tmp_path / "x.hpp") == "cpp"


def test_find_entry_points_libfuzzer_shape() -> None:
    eps = find_entry_points(_LIBFUZZER_SHAPE)
    assert len(eps) >= 1
    top = eps[0]
    assert top.name == "parse_packet"
    assert top.takes_buffer is True
    assert top.score == 1.0
    assert top.line >= 1


def test_find_entry_points_c_string_parser() -> None:
    eps = find_entry_points(_C_STRING_PARSER)
    names = {ep.name for ep in eps}
    assert "decode_header" in names
    decode = next(ep for ep in eps if ep.name == "decode_header")
    assert decode.takes_buffer is True
    assert 0.5 <= decode.score <= 1.0


def test_find_entry_points_returns_empty_for_irrelevant_code() -> None:
    eps = find_entry_points(_NO_HITS)
    assert eps == []


def test_find_entry_points_dedupes_overloads() -> None:
    src = """\
int handle(const uint8_t *d, size_t n) { return 0; }
int handle(const uint8_t *d, size_t n) { return 1; }
"""
    eps = find_entry_points(src)
    assert sum(1 for ep in eps if ep.name == "handle") == 1
