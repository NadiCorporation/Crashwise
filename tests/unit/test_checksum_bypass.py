# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Coverage Guard & Checksum Bypass (Requirement R3)."""

from __future__ import annotations

import struct
import tempfile
import zlib
from pathlib import Path

import pytest

from crashwise.agents.harness_synth.evolution import (
    evolve_harness,
    evolve_harness_for_checksum,
)
from crashwise.agents.research.checksum_detector import (
    ChecksumDetector,
    ChecksumInfo,
    detect_checksums,
)
from crashwise.agents.research.coverage_analyzer import (
    analyze_coverage,
)
from crashwise.agents.research.seed_corpus import (
    SeedCorpusGenerator,
    create_elf_seed,
    create_gzip_seed,
    create_jpeg_seed,
    create_png_seed,
    create_zip_seed,
    generate_seeds,
)
from crashwise.core.models import (
    BlockerType,
    CoverageBlocker,
    EvolveHarnessInput,
)

# ── 1. ChecksumDetector: CRC32 Detection ──────────────────────────────────────


def test_detect_crc32_polynomial_and_tables() -> None:
    source = """
#include <stdint.h>
#include <stddef.h>

static const uint32_t crc32_tab[256] = { 0x00000000, 0x77073096, ... };

uint32_t compute_crc(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc = (crc >> 8) ^ 0xEDB88320 ^ crc32_tab[(crc ^ buf[i]) & 0xFF];
    }
    return crc;
}

int parse_png_chunk(const uint8_t *data, size_t size) {
    uint32_t expected_crc = 0;
    if (calculate_crc(data, size) != expected_crc) {
        return -1;
    }
    return 0;
}
"""
    results = ChecksumDetector.detect_checksums(source)
    assert len(results) >= 2
    assert all(isinstance(r, ChecksumInfo) for r in results)
    crc_matches = [r for r in results if r.algorithm == "crc32"]

    assert len(crc_matches) >= 2

    # Check polynomial detection
    poly_match = next((r for r in crc_matches if "0xEDB88320" in r.details or "0xEDB88320" in r.pattern_matched), None)
    assert poly_match is not None
    assert poly_match.confidence >= 0.9

    # Check function call detection
    func_match = next((r for r in crc_matches if "calculate_crc" in r.pattern_matched), None)
    assert func_match is not None
    assert func_match.function_name == "parse_png_chunk"


def test_detect_crc32_forward_polynomial() -> None:
    source = """
uint32_t crc32_mpeg(const uint8_t *data, size_t len) {
    uint32_t poly = 0x04C11DB7;
    uint32_t crc = crc32_z(0, data, len);
    return crc ^ poly;
}
"""
    results = detect_checksums(source)
    crc_matches = [r for r in results if r.algorithm == "crc32"]
    assert len(crc_matches) >= 1
    assert any("0x04C11DB7" in r.details or "crc32_z" in r.pattern_matched for r in crc_matches)


# ── 2. ChecksumDetector: Adler32 Detection ────────────────────────────────────


def test_detect_adler32_formula_and_calls() -> None:
    source = """
#include <stdint.h>
#include <stddef.h>

uint32_t update_adler(const uint8_t *buf, size_t len) {
    uint32_t s1 = 1;
    uint32_t s2 = 0;
    for (size_t i = 0; i < len; ++i) {
        s1 = (s1 + buf[i]) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return (s2 << 16) | s1;
}

int verify_zlib_stream(const uint8_t *data, size_t len) {
    if (adler32(1L, data, len) != 0x12345678) {
        return 0;
    }
    return 1;
}
"""
    results = detect_checksums(source)
    adler_matches = [r for r in results if r.algorithm == "adler32"]
    assert len(adler_matches) >= 2

    # Check modulo 65521
    modulo_match = next((r for r in adler_matches if "65521" in r.details), None)
    assert modulo_match is not None

    # Check word combine (s2 << 16) | s1
    combine_match = next((r for r in adler_matches if "word" in r.details.lower() or "s2" in r.pattern_matched), None)
    assert combine_match is not None


# ── 3. ChecksumDetector: SHA Family & Cryptographic Hashes ────────────────────


def test_detect_sha256_digest_comparison() -> None:
    source = """
#include <openssl/sha.h>
#include <string.h>

int verify_firmware(const uint8_t *image, size_t len, const uint8_t *expected_hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, image, len);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &ctx);

    if (memcmp(digest, expected_hash, SHA256_DIGEST_LENGTH) != 0) {
        return -1;
    }
    return 0;
}
"""
    results = detect_checksums(source)
    sha256_matches = [r for r in results if r.algorithm == "sha256"]
    assert len(sha256_matches) >= 1
    assert sha256_matches[0].function_name == "verify_firmware"
    assert sha256_matches[0].confidence >= 0.85


def test_detect_sha1_and_md5_patterns() -> None:
    source = """
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>

void hash_legacy(const uint8_t *data, size_t len) {
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, data, len);

    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, data, len);
}
"""
    results = detect_checksums(source)
    algos = {r.algorithm for r in results}
    assert "md5" in algos
    assert "sha1" in algos


# ── 4. ChecksumDetector: Custom Checksum Loops ────────────────────────────────


def test_detect_custom_checksum_loops() -> None:
    source = """
#include <stdint.h>
#include <stddef.h>

uint8_t xor_validate(const uint8_t *buf, size_t len) {
    uint8_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum ^= buf[i];
    }
    return sum;
}

uint16_t byte_checksum(const uint8_t *data, size_t size) {
    uint16_t checksum = 0;
    for (size_t i = 0; i < size; ++i) {
        checksum += data[i];
    }
    return checksum;
}
"""
    results = detect_checksums(source)
    algos = {r.algorithm for r in results}
    assert "custom_xor" in algos or "custom_sum" in algos


# ── 5. CoverageAnalyzer: Integration with BlockerType.CHECKSUM ────────────────


@pytest.mark.asyncio
async def test_coverage_analyzer_identifies_checksum_blocker() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "parser.c"
        src.write_text("""#include <stdint.h>
#include <stddef.h>

int parse_packet(const uint8_t *data, size_t len) {
    if (len < 8) return 0;
    if (crc32(0, data, len) != 0x12345678) {
        return -1;
    }
    return 1;
}
""")
        # 1. Static fallback
        static_analysis = await analyze_coverage(src, "")
        assert len(static_analysis.blockers) >= 1
        static_checksum = [b for b in static_analysis.blockers if b.blocker_type == BlockerType.CHECKSUM]
        assert len(static_checksum) >= 1
        assert static_checksum[0].checksum_algorithm == "crc32"
        assert static_checksum[0].confidence >= 0.5

        # 2. Coverage report (line 6 missed)
        cov_text = "SF:parser.c\nDA:5,1\nDA:6,0\nend_of_record"
        analysis = await analyze_coverage(src, cov_text)

    assert len(analysis.blockers) >= 1
    checksum_blockers = [b for b in analysis.blockers if b.blocker_type == BlockerType.CHECKSUM]
    assert len(checksum_blockers) >= 1
    blocker = checksum_blockers[0]
    assert blocker.checksum_algorithm == "crc32"
    assert "CRC32" in blocker.expected_value or "crc32" in blocker.checksum_algorithm
    assert blocker.confidence >= 0.8



# ── 6. Harness Evolution: CRC32 Wrapper ───────────────────────────────────────


@pytest.mark.asyncio
async def test_evolution_crc32_harness_wrapper() -> None:
    blocker = CoverageBlocker(
        blocker_type=BlockerType.CHECKSUM,
        line_number=6,
        function_name="process_png_data",
        condition_text="if (crc32(0, data, size) != expected)",
        expected_value="valid CRC32",
        checksum_algorithm="crc32",
        checksum_offset=0,
        checksum_endianness="little",
        payload_offset=4,
        confidence=0.9,
    )
    current_harness = """
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    process_png_data(data, size);
    return 0;
}
"""
    payload = EvolveHarnessInput(
        current_harness_code=current_harness,
        blocker=blocker,
        target_function="process_png_data",
    )
    result = await evolve_harness(payload)

    assert result.evolved_harness_code != ""
    assert "compute_crc32" in result.evolved_harness_code
    assert "0xEDB88320" in result.evolved_harness_code
    assert "process_png_data" in result.evolved_harness_code
    assert "payload.data()" in result.evolved_harness_code
    assert "payload.size()" in result.evolved_harness_code
    assert "-lz" in result.compilation_command or "clang++" in result.compilation_command


# ── 7. Harness Evolution: Adler32 and SHA-256 Wrappers ────────────────────────


@pytest.mark.asyncio
async def test_evolution_adler32_harness_wrapper() -> None:
    blocker = CoverageBlocker(
        blocker_type=BlockerType.CHECKSUM,
        line_number=10,
        function_name="decompress_zlib",
        condition_text="if (adler32(1, data, size) != expected)",
        expected_value="valid Adler32",
        checksum_algorithm="adler32",
        checksum_offset=0,
        checksum_endianness="big",
        payload_offset=2,
        confidence=0.9,
    )
    current_harness = """
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    decompress_zlib(data, size);
    return 0;
}
"""
    evolved_code = evolve_harness_for_checksum(current_harness, blocker)

    assert "compute_adler32" in evolved_code
    assert "65521" in evolved_code
    assert "decompress_zlib" in evolved_code
    assert "payload.data()" in evolved_code


@pytest.mark.asyncio
async def test_evolution_sha256_harness_wrapper() -> None:
    blocker = CoverageBlocker(
        blocker_type=BlockerType.CHECKSUM,
        line_number=15,
        function_name="authenticate_message",
        condition_text="if (memcmp(digest, expected, 32) != 0)",
        expected_value="valid SHA-256",
        checksum_algorithm="sha256",
        checksum_offset=0,
        checksum_endianness="big",
        payload_offset=32,
        confidence=0.9,
    )
    current_harness = """
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    authenticate_message(data, size);
    return 0;
}
"""
    evolved_code = evolve_harness_for_checksum(current_harness, blocker)

    assert "SHA256" in evolved_code
    assert "<openssl/sha.h>" in evolved_code
    assert "authenticate_message" in evolved_code


# ── 8. SeedCorpusGenerator: PNG Generation ────────────────────────────────────


def test_seed_corpus_generator_png_with_valid_crc() -> None:
    png_bytes = create_png_seed(width=1, height=1, color_type=2, payload_data=b"\x00\xff\x00")

    # Verify PNG Signature (8 bytes)
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    # Verify IHDR chunk structure & CRC
    ihdr_len = struct.unpack(">I", png_bytes[8:12])[0]
    assert ihdr_len == 13
    assert png_bytes[12:16] == b"IHDR"

    ihdr_data = png_bytes[16:29]
    ihdr_crc = struct.unpack(">I", png_bytes[29:33])[0]
    expected_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    assert ihdr_crc == expected_crc

    # Verify IEND chunk
    assert png_bytes.endswith(b"\x00\x00\x00\x00IEND\xaeB\x60\x82")


# ── 9. SeedCorpusGenerator: ZIP Generation ────────────────────────────────────


def test_seed_corpus_generator_zip_with_valid_crc() -> None:
    file_data = b"HELLO_CRASHWISE_FUZZER\n"
    zip_bytes = create_zip_seed(filename="input.txt", file_data=file_data)

    # Verify Local File Header
    assert zip_bytes.startswith(b"PK\x03\x04")
    crc_in_header = struct.unpack("<I", zip_bytes[14:18])[0]
    expected_crc = zlib.crc32(file_data) & 0xFFFFFFFF
    assert crc_in_header == expected_crc

    # Verify Central Directory & EOCD
    assert b"PK\x01\x02" in zip_bytes
    assert b"PK\x05\x06" in zip_bytes


# ── 10. SeedCorpusGenerator: JPEG, ELF, GZIP Seeds ────────────────────────────


def test_seed_corpus_generator_jpeg_elf_gzip() -> None:
    # JPEG
    jpeg_bytes = create_jpeg_seed()
    assert jpeg_bytes.startswith(b"\xff\xd8\xff\xe0")
    assert b"JFIF" in jpeg_bytes
    assert jpeg_bytes.endswith(b"\xff\xd9")

    # ELF 64-bit
    elf_bytes = create_elf_seed(is_64bit=True)
    assert elf_bytes.startswith(b"\x7fELF\x02\x01\x01")
    e_machine = struct.unpack("<H", elf_bytes[18:20])[0]
    assert e_machine == 0x3E  # x86_64

    # GZIP
    raw_data = b"CRASHWISE_GZIP_TEST_DATA\n"
    gzip_bytes = create_gzip_seed(uncompressed_data=raw_data)
    assert gzip_bytes.startswith(b"\x1f\x8b\x08")  # GZIP magic + Deflate
    # Check trailer CRC32 (last 8 bytes: 4 bytes CRC + 4 bytes ISIZE)
    trailer_crc = struct.unpack("<I", gzip_bytes[-8:-4])[0]
    expected_crc = zlib.crc32(raw_data) & 0xFFFFFFFF
    assert trailer_crc == expected_crc
    trailer_isize = struct.unpack("<I", gzip_bytes[-4:])[0]
    assert trailer_isize == len(raw_data)


def test_seed_corpus_generator_registry_and_files(tmp_path: Path) -> None:
    seeds = generate_seeds("png")
    assert len(seeds) >= 1
    assert seeds[0].startswith(b"\x89PNG")

    file_paths = SeedCorpusGenerator.generate_seed_corpus("zip", tmp_path, max_seeds=3)
    assert len(file_paths) >= 1
    for p in file_paths:
        assert p.exists()
        assert p.stat().st_size > 0
        content = p.read_bytes()
        assert content.startswith(b"PK\x03\x04")
