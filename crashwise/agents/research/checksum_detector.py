# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Checksum and Guard Detector — identifies checksum validation and hash verification
routines in target C/C++ source code.

Fuzzing targets with checksums (CRC32, Adler32, SHA-256, MD5, custom sums)
frequently stall because random mutations have an infinitesimal probability
of satisfying a 32-bit (1 in 4.3 billion) or 256-bit hash check.

The ChecksumDetector statically analyzes source code to identify:
1. CRC32 polynomials, lookup table references, and function calls.
2. Adler32 modulo-65521 arithmetic and function calls.
3. SHA-1, SHA-256, SHA-512, MD5, and OpenSSL EVP digest verification.
4. Custom checksum loops (XOR folded sum, additive byte sum).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from pydantic import Field

from crashwise.core.logging import get_logger
from crashwise.core.models import _StrictModel

log = get_logger(__name__)


# ── Checksum Info Model ──────────────────────────────────────────────────────


class ChecksumInfo(_StrictModel):
    """Metadata describing a detected checksum verification or calculation."""

    algorithm: str = Field(
        ...,
        description="Detected checksum algorithm ('crc32', 'adler32', 'sha256', 'sha1', 'md5', 'custom_xor', 'custom_sum')",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Offset in input payload where the checksum is expected to be stored",
    )
    endianness: str = Field(
        default="little",
        max_length=16,
        description="Endianness of the checksum field ('little' or 'big')",
    )
    payload_offset: int = Field(
        default=0,
        ge=0,
        description="Offset in input payload where the hashed/checksummed data begins",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0 to 1.0)",
    )
    function_name: str = Field(
        default="",
        max_length=256,
        description="Function containing the checksum check or calculation",
    )
    line_number: int = Field(
        default=0,
        ge=0,
        description="Source line number where the pattern was detected",
    )
    pattern_matched: str = Field(
        default="",
        max_length=512,
        description="Short description or snippet of the matched pattern",
    )
    details: str = Field(
        default="",
        max_length=1024,
        description="Additional technical notes (polynomials, formulas, etc.)",
    )


# ── Detection Patterns ───────────────────────────────────────────────────────

# CRC32 Polynomials (IEEE 802.3, Castagnoli, CRC-16)
_CRC32_POLYNOMIALS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b0xEDB88320\b", re.IGNORECASE), "CRC32 IEEE 802.3 reverse polynomial (0xEDB88320)"),
    (re.compile(r"\b0x04C11DB7\b", re.IGNORECASE), "CRC32 IEEE 802.3 forward polynomial (0x04C11DB7)"),
    (re.compile(r"\b0x82F63B78\b", re.IGNORECASE), "CRC32-C Castagnoli reverse polynomial (0x82F63B78)"),
    (re.compile(r"\b0x1EDC6F41\b", re.IGNORECASE), "CRC32-C Castagnoli forward polynomial (0x1EDC6F41)"),
    (re.compile(r"\b0x8005\b", re.IGNORECASE), "CRC16-IBM polynomial (0x8005)"),
    (re.compile(r"\b0x1021\b", re.IGNORECASE), "CRC16-CCITT polynomial (0x1021)"),
]

# CRC Table references
_CRC_TABLE_RE = re.compile(
    r"\b(?:crc_table|crc32_tab(?:le)?|crc32_tab\d*|crc_32_tab|crc32_lookup|crctable|crc32_lut|g_crc32_table|crc_lut)\b",
    re.IGNORECASE,
)

# CRC Function names / invocations
_CRC_FUNC_RE = re.compile(
    r"\b(?:crc32|crc32_z|crc32_ieee|calculate_crc|compute_crc32|calc_crc32|crc32_update|crc_calc|update_crc|crc32_byte|crc32_buf|crc_32|crc16|compute_crc)\s*\(",
    re.IGNORECASE,
)

# Adler32 modulo math & combination
_ADLER_MODULO_RE = re.compile(
    r"(?:%\s*65521|\b65521[UL]?\b|BASE\s+65521|MOD_ADLER\s+65521)",
    re.IGNORECASE,
)

_ADLER_COMPOSE_RE = re.compile(
    r"\(\s*(\w+)\s*<<\s*16\s*\)\s*(?:\||\+)\s*(\w+)",
    re.IGNORECASE,
)

_ADLER_FUNC_RE = re.compile(
    r"\b(?:adler32|adler32_z|calc_adler|adler32_update|compute_adler32|adler32_buf|adler_32)\s*\(",
    re.IGNORECASE,
)

# SHA family & MD5 OpenSSL / Crypto APIs
_SHA256_RE = re.compile(
    r"\b(?:SHA256_Init|SHA256_Update|SHA256_Final|SHA256|sha256_init|sha256_update|sha256_final|sha256_starts|sha256_finish|sha256_ctx|EVP_sha256)\b",
    re.IGNORECASE,
)

_SHA1_RE = re.compile(
    r"\b(?:SHA1_Init|SHA1_Update|SHA1_Final|SHA1|sha1_init|sha1_update|sha1_final|sha1_ctx|EVP_sha1)\b",
    re.IGNORECASE,
)

_SHA512_RE = re.compile(
    r"\b(?:SHA512_Init|SHA512_Update|SHA512_Final|SHA512|SHA384_Init|SHA384_Update|SHA384_Final|EVP_sha512|EVP_sha384)\b",
    re.IGNORECASE,
)

_MD5_RE = re.compile(
    r"\b(?:MD5_Init|MD5_Update|MD5_Final|MD5|md5_init|md5_update|md5_final|md5_ctx|EVP_md5)\b",
    re.IGNORECASE,
)

_EVP_DIGEST_RE = re.compile(
    r"\b(?:EVP_DigestInit|EVP_DigestUpdate|EVP_DigestFinal|EVP_Q_digest|crypto_hash)\b",
    re.IGNORECASE,
)

_DIGEST_MEMCMP_RE = re.compile(
    r"(?:memcmp|CRYPTO_memcmp|timingsafe_bcmp)\s*\([^)]*?(?:digest|hash|md|sha|mac|expected_hash|actual_hash|checksum)[^)]*?\)",
    re.IGNORECASE,
)

# Custom XOR checksum loops
_XOR_SUM_RE = re.compile(
    r"(?:\w+\s*\^=\s*(?:\*\w+|\w+\[[^\]]+\])|\w+\s*=\s*\w+\s*\^\s*(?:\*\w+|\w+\[[^\]]+\]))",
    re.IGNORECASE,
)

# Custom Additive Byte Sum loops
_BYTE_SUM_RE = re.compile(
    r"(?:(?:sum|chksum|csum|checksum)\s*\+=\s*(?:\*\w+|\w+\[[^\]]+\])|(?:sum|chksum|csum|checksum)\s*=\s*\(\s*(?:sum|chksum|csum|checksum)\s*\+\s*(?:\*\w+|\w+\[[^\]]+\])\s*\)\s*&\s*0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)


# ── ChecksumDetector Class ───────────────────────────────────────────────────


class ChecksumDetector:
    """Static analysis engine for detecting checksum verification in C/C++ targets."""

    _NAME_ALGO_HINTS: ClassVar[dict[str, str]] = {
        "png": "crc32",
        "zip": "crc32",
        "gzip": "crc32",
        "zlib": "adler32",
        "tar": "custom_sum",
    }

    @classmethod
    def detect_checksums(
        cls,
        source_code: str,
        workdir: Path | None = None,
    ) -> list[ChecksumInfo]:
        """Analyze source code and find all checksum patterns.

        Parameters
        ----------
        source_code:
            C/C++ source code text to analyze.
        workdir:
            Optional repository root directory.

        Returns
        -------
        List of ChecksumInfo objects sorted by confidence (highest first).
        """
        results: list[ChecksumInfo] = []
        lines = source_code.splitlines()

        # Track algorithms already detected at specific functions to avoid redundant duplicates
        seen_keys: set[tuple[str, str, int]] = set()

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("//") or line_str.startswith("/*") or line_str.startswith("*"):
                continue

            func_name = cls._find_function_for_line(idx, lines)

            # 1. CRC32 Detection
            # Polynomials
            for poly_pat, poly_desc in _CRC32_POLYNOMIALS:
                if poly_pat.search(line):
                    endian = "big" if "png" in func_name.lower() or "network" in func_name.lower() else "little"
                    key = ("crc32", func_name, idx)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        results.append(
                            ChecksumInfo(
                                algorithm="crc32",
                                offset=0,
                                endianness=endian,
                                payload_offset=4 if "png" in func_name.lower() else 0,
                                confidence=0.95,
                                function_name=func_name,
                                line_number=idx,
                                pattern_matched=poly_pat.pattern,
                                details=poly_desc,
                            )
                        )

            # CRC Tables
            if _CRC_TABLE_RE.search(line):
                key = ("crc32", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="crc32",
                            offset=0,
                            endianness="little",
                            payload_offset=0,
                            confidence=0.90,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="CRC32 lookup table reference",
                        )
                    )

            # CRC Function calls
            if _CRC_FUNC_RE.search(line):
                key = ("crc32", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    endian = "big" if "png" in func_name.lower() or "network" in func_name.lower() else "little"
                    results.append(
                        ChecksumInfo(
                            algorithm="crc32",
                            offset=0,
                            endianness=endian,
                            payload_offset=4 if "png" in func_name.lower() else 0,
                            confidence=0.92,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="CRC32 calculation function invocation",
                        )
                    )

            # 2. Adler32 Detection
            if _ADLER_MODULO_RE.search(line):
                key = ("adler32", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="adler32",
                            offset=0,
                            endianness="big",
                            payload_offset=2 if "zlib" in func_name.lower() else 0,
                            confidence=0.95,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="Adler32 modulo 65521 arithmetic",
                        )
                    )

            if _ADLER_COMPOSE_RE.search(line):
                key = ("adler32", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="adler32",
                            offset=0,
                            endianness="big",
                            payload_offset=0,
                            confidence=0.88,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="Adler32 (s2 << 16) | s1 high/low word combination",
                        )
                    )

            if _ADLER_FUNC_RE.search(line):
                key = ("adler32", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="adler32",
                            offset=0,
                            endianness="big",
                            payload_offset=0,
                            confidence=0.92,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="Adler32 calculation function invocation",
                        )
                    )

            # 3. SHA Family & Cryptographic Hashes
            if _SHA256_RE.search(line):
                key = ("sha256", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="sha256",
                            offset=0,
                            endianness="big",
                            payload_offset=32,
                            confidence=0.95,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="SHA-256 digest computation (OpenSSL / crypto API)",
                        )
                    )

            if _SHA1_RE.search(line):
                key = ("sha1", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="sha1",
                            offset=0,
                            endianness="big",
                            payload_offset=20,
                            confidence=0.95,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="SHA-1 digest computation",
                        )
                    )

            if _SHA512_RE.search(line):
                key = ("sha512", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="sha512",
                            offset=0,
                            endianness="big",
                            payload_offset=64,
                            confidence=0.95,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="SHA-512 / SHA-384 digest computation",
                        )
                    )

            if _MD5_RE.search(line):
                key = ("md5", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="md5",
                            offset=0,
                            endianness="little",
                            payload_offset=16,
                            confidence=0.95,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="MD5 digest computation",
                        )
                    )

            if _EVP_DIGEST_RE.search(line) and not (_SHA256_RE.search(line) or _SHA1_RE.search(line) or _MD5_RE.search(line)):
                key = ("sha256", func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm="sha256",
                            offset=0,
                            endianness="big",
                            payload_offset=32,
                            confidence=0.90,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details="OpenSSL EVP generic message digest verification",
                        )
                    )

            if _DIGEST_MEMCMP_RE.search(line):
                # Infer algorithm from context or default to sha256 / crc32
                algo = "sha256"
                if "32" in line or "crc" in line.lower():
                    algo = "crc32"
                elif "sha1" in line.lower() or "20" in line:
                    algo = "sha1"
                elif "md5" in line.lower() or "16" in line:
                    algo = "md5"

                key = (algo, func_name, idx)
                if key not in seen_keys:
                    seen_keys.add(key)
                    results.append(
                        ChecksumInfo(
                            algorithm=algo,
                            offset=0,
                            endianness="big" if algo in ("sha256", "sha1") else "little",
                            payload_offset=32 if algo == "sha256" else 0,
                            confidence=0.88,
                            function_name=func_name,
                            line_number=idx,
                            pattern_matched=line_str[:128],
                            details=f"Digest comparison via memcmp ({algo})",
                        )
                    )

            # 4. Custom XOR loops
            if _XOR_SUM_RE.search(line):
                # Verify that it is in a loop context (scan nearby lines for while/for)
                has_loop = cls._has_nearby_loop(idx, lines)
                if has_loop:
                    key = ("custom_xor", func_name, idx)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        results.append(
                            ChecksumInfo(
                                algorithm="custom_xor",
                                offset=0,
                                endianness="little",
                                payload_offset=1,
                                confidence=0.82,
                                function_name=func_name,
                                line_number=idx,
                                pattern_matched=line_str[:128],
                                details="Custom XOR folded checksum accumulation loop",
                            )
                        )

            # 5. Custom Byte Sum loops
            if _BYTE_SUM_RE.search(line):
                has_loop = cls._has_nearby_loop(idx, lines)
                if has_loop:
                    key = ("custom_sum", func_name, idx)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        results.append(
                            ChecksumInfo(
                                algorithm="custom_sum",
                                offset=0,
                                endianness="little",
                                payload_offset=1,
                                confidence=0.80,
                                function_name=func_name,
                                line_number=idx,
                                pattern_matched=line_str[:128],
                                details="Custom additive byte sum checksum loop",
                            )
                        )

        # Sort by confidence descending, then by line number
        results.sort(key=lambda item: (-item.confidence, item.line_number))
        return results

    @classmethod
    def _find_function_for_line(cls, line_num: int, lines: list[str]) -> str:
        """Scan backwards from line_num to find enclosing C/C++ function name."""
        for i in range(min(line_num - 1, len(lines) - 1), -1, -1):
            line = lines[i].strip()
            match = re.match(r"^(?:[\w\s\*&:<>,]+?\s+)?(\w+)\s*\([^)]*\)\s*(?:\{|const)?", line)
            if match:
                candidate = match.group(1)
                if candidate not in {"if", "while", "for", "switch", "return", "sizeof", "else"}:
                    return candidate
        return "unknown"

    @classmethod
    def _has_nearby_loop(cls, line_num: int, lines: list[str], window: int = 6) -> bool:
        """Check if nearby lines (+/- window) contain a for/while loop construct."""
        start = max(0, line_num - window)
        end = min(len(lines), line_num + window)
        for i in range(start, end):
            line_candidate = lines[i].strip()
            if re.search(r"\b(?:for|while|do)\s*\(", line_candidate):
                return True
        return False



def detect_checksums(
    source_code: str,
    workdir: Path | None = None,
) -> list[ChecksumInfo]:
    """Top-level functional interface for checksum detection."""
    return ChecksumDetector.detect_checksums(source_code, workdir=workdir)


__all__ = ["ChecksumDetector", "ChecksumInfo", "detect_checksums"]
