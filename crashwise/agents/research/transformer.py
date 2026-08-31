# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""PoC Transformer — turns C / Python proof-of-concept code into minimal
binary seeds that a fuzzer can ingest.

The transformer uses lightweight static analysis (regex + heuristics) to
extract payload bytes from PoC source files.  When no explicit payload is
found it synthesises a minimal file based on the target file format.
"""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from crashwise.agents.research.seed_corpus import (
    create_elf_seed,
    create_gzip_seed,
    create_jpeg_seed,
    create_png_seed,
    create_zip_seed,
    generate_seeds,
)
from crashwise.core.logging import get_logger
from crashwise.core.models import SeedMetadata

log = get_logger(__name__)


# ── Regex patterns for payload extraction ────────────────────────────────────

# Hex string:  {0x41, 0x42, 0x43} or "\x41\x42\x43"
_HEX_ARRAY_RE = re.compile(
    r"\{([\s0-9a-fA-Fx,]+)\}",
    re.MULTILINE,
)

_HEX_ESCAPE_RE = re.compile(
    r"(?:\\x[0-9a-fA-F]{2})+",
)

# Base64 literals inside quotes.
_B64_RE = re.compile(
    r"[\"']([A-Za-z0-9+/]{20,}={0,2})[\"']",
)

# Python bytes / bytearray literals:  b'...'  or  b"..."
_PY_BYTES_RE = re.compile(
    r"b[\"']([\x00-\xFF]+?)[\"']",
    re.DOTALL,
)

# Raw byte arrays in C: unsigned char payload[] = { ... };
_C_ARRAY_RE = re.compile(
    r"unsigned\s+char\s+\w+\[\]\s*=\s*\{([^}]+)\}",
    re.MULTILINE,
)


# ── Public API ───────────────────────────────────────────────────────────────

async def transform_poc(
    metadata: SeedMetadata,
    *,
    output_dir: Path,
) -> SeedMetadata:
    """Transform a PoC file into a binary fuzzer seed.

    Parameters
    ----------
    metadata:
        Seed metadata (must have ``downloaded_path`` set).
    output_dir:
        Directory where the transformed seed will be written.

    Returns
    -------
    Updated metadata with ``seed_path`` populated.
    """
    log.info(
        "transformer.start",
        seed_id=metadata.seed_id,
        language=metadata.language,
        output_dir=str(output_dir),
    )

    if metadata.downloaded_path is None or not metadata.downloaded_path.exists():
        log.warning(
            "transformer.no_source",
            seed_id=metadata.seed_id,
            path=str(metadata.downloaded_path),
        )
        # Synthesize a minimal seed based on target heuristics.
        seed_path = _synthesize_seed(metadata, output_dir)
        metadata.seed_path = seed_path
        return metadata

    source = metadata.downloaded_path.read_text(errors="ignore")
    payload: bytes | None = None

    # Try C-style hex array first.
    if metadata.language in ("c", "cpp", "c++"):
        payload = _extract_c_payload(source)

    # Try Python bytes / base64.
    if payload is None and metadata.language == "python":
        payload = _extract_python_payload(source)

    # Generic hex-escape fallback.
    if payload is None:
        payload = _extract_hex_escapes(source)

    # Base64 fallback.
    if payload is None:
        payload = _extract_base64(source)

    # Last resort: synthesise.
    if payload is None:
        payload = _synthesize_payload(metadata)

    # Write seed.
    output_dir.mkdir(parents=True, exist_ok=True)
    seed_path = output_dir / f"{metadata.seed_id}.seed"
    seed_path.write_bytes(payload)
    metadata.seed_path = seed_path

    log.info(
        "transformer.complete",
        seed_id=metadata.seed_id,
        seed_path=str(seed_path),
        size=len(payload),
    )
    return metadata


# ── Extraction helpers ───────────────────────────────────────────────────────

def _extract_c_payload(source: str) -> bytes | None:
    """Pull bytes from C-style ``unsigned char arr[] = { ... }`` definitions."""
    match = _C_ARRAY_RE.search(source)
    if not match:
        return None

    hex_part = match.group(1)
    # Remove C-style comments and whitespace.
    hex_part = re.sub(r"/\*.*?\*/", "", hex_part, flags=re.DOTALL)
    hex_part = re.sub(r"//.*", "", hex_part)
    hex_part = hex_part.replace(" ", "").replace("\n", "").replace("\t", "")

    try:
        byte_vals = [int(x, 0) for x in hex_part.split(",") if x]
        return bytes(byte_vals)
    except ValueError:
        return None


def _extract_python_payload(source: str) -> bytes | None:
    """Pull bytes from Python ``b'...'`` literals or base64 strings."""
    # Try raw bytes literal first.
    for m in _PY_BYTES_RE.finditer(source):
        try:
            raw = m.group(1).encode("latin-1")
            # Attempt to decode as a Python bytes literal.
            return raw.decode("unicode_escape").encode("latin-1")
        except (UnicodeDecodeError, ValueError):
            continue

    # Fall back to base64 inside the Python file.
    return _extract_base64(source)


def _extract_hex_escapes(source: str) -> bytes | None:
    """Find ``\\x41\\x42`` style escapes anywhere in the source."""
    matches = _HEX_ESCAPE_RE.findall(source)
    if not matches:
        return None

    # Pick the longest match — usually the actual payload.
    longest = max(matches, key=len)
    try:
        decoded_text = str(longest.encode().decode("unicode_escape"))
        return decoded_text.encode("latin-1")
    except (UnicodeDecodeError, ValueError):
        return None



def _extract_base64(source: str) -> bytes | None:
    """Find and decode base64 strings in source."""
    for m in _B64_RE.finditer(source):
        try:
            return base64.b64decode(m.group(1), validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


def _synthesize_payload(metadata: SeedMetadata) -> bytes:
    """Create a minimal payload when no explicit bytes are found in the PoC."""
    target = metadata.target_name.lower()

    # Format-specific magic headers with valid checksums
    if "png" in target:
        return create_png_seed()
    if "jpeg" in target or "jpg" in target:
        return create_jpeg_seed()
    if "pdf" in target:
        return b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n"
    if "zip" in target:
        return create_zip_seed()
    if "gzip" in target or "gz" in target:
        return create_gzip_seed()
    if "zlib" in target:
        return generate_seeds("zlib")[0]
    if "elf" in target:
        return create_elf_seed(is_64bit=True)

    seeds = generate_seeds(target)
    if seeds:
        return seeds[0]

    # Generic: a few nulls + some ASCII to trigger parsers.
    return b"\x00\x00\x00\x00CRASHWISE\xff\xfe\xfd\xfc"



def _synthesize_seed(metadata: SeedMetadata, output_dir: Path) -> Path:
    """Write a synthesised seed file and return its path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    seed_path = output_dir / f"{metadata.seed_id}.seed"
    payload = _synthesize_payload(metadata)
    seed_path.write_bytes(payload)
    return seed_path
