# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for the research / seeding brain (Phase 7)."""

from __future__ import annotations

import pytest

from crashwise.agents.research.harvester import harvest_seeds
from crashwise.agents.research.transformer import (
    _extract_base64,
    _extract_c_payload,
    _extract_hex_escapes,
    _extract_python_payload,
    _synthesize_payload,
    transform_poc,
)
from crashwise.core.models import SeedMetadata, SeedSource


# ── Harvester tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_harvester_finds_openssl_cves() -> None:
    seeds = await harvest_seeds("openssl", max_results=5)
    assert len(seeds) >= 2
    assert any(s.seed_id == "CVE-2022-3602" for s in seeds)
    assert all(s.target_name == "openssl" for s in seeds)


@pytest.mark.asyncio
async def test_harvester_fuzzy_matches() -> None:
    """Searching for ``openssl-3.0`` should still match ``openssl``."""
    seeds = await harvest_seeds("openssl-3.0", max_results=5)
    assert len(seeds) >= 1
    assert any("CVE" in s.seed_id for s in seeds)


@pytest.mark.asyncio
async def test_harvester_fallback_for_unknown_target() -> None:
    seeds = await harvest_seeds("totally-unknown-project-xyz")
    assert len(seeds) == 1
    assert seeds[0].source == SeedSource.GITHUB
    assert "github-poc" in seeds[0].seed_id


@pytest.mark.asyncio
async def test_harvester_respects_max_results() -> None:
    seeds = await harvest_seeds("openssl", max_results=1)
    assert len(seeds) == 1


# ── Transformer extraction tests ─────────────────────────────────────────────


def test_extract_c_payload() -> None:
    source = """
    unsigned char payload[] = {
      0x48, 0x65, 0x6c, 0x6c, 0x6f
    };
    """
    payload = _extract_c_payload(source)
    assert payload == b"Hello"


def test_extract_c_payload_with_comments() -> None:
    source = """
    unsigned char payload[] = {
      0x41, /* A */
      0x42, // B
      0x43
    };
    """
    payload = _extract_c_payload(source)
    assert payload == b"ABC"


def test_extract_python_payload_bytes() -> None:
    source = "payload = b'CRASHWISE\\xff\\xfe\\xfd\\xfc'\n"
    payload = _extract_python_payload(source)
    assert payload is not None
    assert payload.startswith(b"CRASHWISE")


def test_extract_hex_escapes() -> None:
    source = r'buf = "\x41\x42\x43\x44"'
    payload = _extract_hex_escapes(source)
    assert payload == b"ABCD"


def test_extract_base64() -> None:
    source = 'encoded = "SGVsbG8gV29ybGQhVGhpcyBpcyBhIHRlc3Q="'
    payload = _extract_base64(source)
    assert payload == b"Hello World!This is a test"


# ── Transformer synthesis tests ──────────────────────────────────────────────


def test_synthesize_payload_png() -> None:
    meta = SeedMetadata(seed_id="test", target_name="libpng")
    payload = _synthesize_payload(meta)
    assert payload.startswith(b"\x89PNG\r\n\x1a\n")


def test_synthesize_payload_jpeg() -> None:
    meta = SeedMetadata(seed_id="test", target_name="libjpeg")
    payload = _synthesize_payload(meta)
    assert payload.startswith(b"\xff\xd8\xff")


def test_synthesize_payload_generic() -> None:
    meta = SeedMetadata(seed_id="test", target_name="random-lib")
    payload = _synthesize_payload(meta)
    assert b"CRASHWISE" in payload


# ── Transformer integration tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_transform_c_poc(tmp_path: Path) -> None:
    poc = tmp_path / "poc.c"
    poc.write_text(
        "unsigned char payload[] = { 0x41, 0x42, 0x43 };\n",
        encoding="utf-8",
    )
    meta = SeedMetadata(
        seed_id="CVE-TEST-001",
        target_name="testlib",
        source=SeedSource.CVE,
        language="c",
        downloaded_path=poc,
    )
    out_dir = tmp_path / "corpus"
    result = await transform_poc(meta, output_dir=out_dir)
    assert result.seed_path is not None
    assert result.seed_path.exists()
    assert result.seed_path.read_bytes() == b"ABC"


@pytest.mark.asyncio
async def test_transform_python_poc(tmp_path: Path) -> None:
    poc = tmp_path / "poc.py"
    poc.write_text("payload = b'CRASHWISE'\n", encoding="utf-8")
    meta = SeedMetadata(
        seed_id="github-poc-test",
        target_name="testlib",
        source=SeedSource.GITHUB,
        language="python",
        downloaded_path=poc,
    )
    out_dir = tmp_path / "corpus"
    result = await transform_poc(meta, output_dir=out_dir)
    assert result.seed_path is not None
    assert result.seed_path.exists()
    assert b"CRASHWISE" in result.seed_path.read_bytes()


@pytest.mark.asyncio
async def test_transform_missing_source_synthesizes(tmp_path: Path) -> None:
    meta = SeedMetadata(
        seed_id="missing",
        target_name="libpng",
        source=SeedSource.MANUAL,
    )
    out_dir = tmp_path / "corpus"
    result = await transform_poc(meta, output_dir=out_dir)
    assert result.seed_path is not None
    assert result.seed_path.exists()
    assert result.seed_path.read_bytes().startswith(b"\x89PNG")
