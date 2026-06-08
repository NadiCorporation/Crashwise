# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Harvester agent — autonomous seed discovery for any target.

The harvester works autonomously for ANY target by combining multiple
seed discovery strategies that don't require external API access:

1. **Repository scanning** — finds test vectors, sample files, corpus
   directories, and fixture data within the target's own source tree.
2. **Format-aware generation** — produces minimal valid inputs based on
   the target's detected domain (image, network, crypto, parser, etc.).
3. **Signature-based seeds** — generates inputs sized for the harness
   entry point (minimum buffers, boundary values, magic headers).
4. **Knowledge base** — leverages known CVE patterns for popular targets.

Autonomy guarantee: the harvester ALWAYS returns usable seeds, even for
targets it has never seen before, because it generates format-specific
minimal inputs based on heuristic domain detection.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from pathlib import Path

from crashwise.core.logging import get_logger
from crashwise.core.models import SeedMetadata, SeedSource

log = get_logger(__name__)


# ── Known file extensions by domain ──────────────────────────────────────────

_DOMAIN_EXTENSIONS: dict[str, list[str]] = {
    "image": [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp", ".ico", ".svg"],
    "audio": [".wav", ".mp3", ".ogg", ".flac", ".aac", ".m4a"],
    "video": [".mp4", ".avi", ".mkv", ".webm", ".mov", ".flv"],
    "document": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt"],
    "archive": [".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst"],
    "font": [".ttf", ".otf", ".woff", ".woff2"],
    "network": [".pcap", ".pcapng"],
    "certificate": [".pem", ".der", ".crt", ".csr", ".p12"],
    "xml": [".xml", ".html", ".xhtml", ".svg", ".xsd"],
    "json": [".json", ".geojson"],
    "binary": [".bin", ".dat", ".raw"],
}

# Directories commonly containing test data in open-source projects.
_TEST_DIRS: list[str] = [
    "test", "tests", "testdata", "test_data", "testcases",
    "fixtures", "samples", "corpus", "fuzz_corpus", "fuzz",
    "fuzzing", "seed_corpus", "seeds", "inputs", "resources",
    "data", "examples", "regression", "crashers", "poc",
]

# File size constraints for seed files.
_MIN_SEED_SIZE: int = 4  # bytes
_MAX_SEED_SIZE: int = 1_048_576  # 1 MB — larger files waste fuzzer cycles


# ── Format-specific seed generators ─────────────────────────────────────────

_FORMAT_SEEDS: dict[str, list[tuple[str, bytes]]] = {
    "png": [
        ("minimal_png", (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\x0dIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
            b"\x00\x00\x00\x90wS\xde"
            b"\x00\x00\x00\x0cIDATx"
            b"\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
            b"\x18\xd8N"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )),
        ("corrupted_ihdr", (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\x0dIHDR"
            b"\xff\xff\xff\xff\xff\xff\xff\xff\x08\x06"
            b"\x00\x00\x00\x00\x00\x00\x00"
        )),
    ],
    "jpeg": [
        ("minimal_jpeg", (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09"
            b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
            b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x7f\xa0"
            b"\xff\xd9"
        )),
        ("truncated_jpeg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"),
    ],
    "gif": [
        ("minimal_gif87", b"GIF87a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"),
        ("minimal_gif89", b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"),
    ],
    "pdf": [
        ("minimal_pdf", b"%PDF-1.0\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 1 1]/Parent 2 0 R>>endobj\nxref\n0 4\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n0\n%%EOF"),
    ],
    "zip": [
        ("empty_zip", b"PK\x05\x06" + b"\x00" * 18),
        ("minimal_zip", b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00aPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\x00\x00aPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00/\x00\x00\x00\x1f\x00\x00\x00\x00\x00"),
    ],
    "gzip": [
        ("minimal_gzip", b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("corrupted_gzip", b"\x1f\x8b\x08\xff\xff\xff\xff\xff\xff\xff"),
    ],
    "zlib": [
        ("zlib_deflate", b"\x78\x9c\x03\x00\x00\x00\x00\x01"),
        ("zlib_raw", b"\x78\x01\x01\x00\x00\xff\xff\x00\x00\x00\x01"),
    ],
    "xml": [
        ("minimal_xml", b"<?xml version=\"1.0\"?>\n<root/>"),
        ("xml_with_entities", b"<?xml version=\"1.0\"?>\n<!DOCTYPE r[\n<!ENTITY x \"AAAA\">\n]>\n<r>&x;</r>"),
        ("deep_nesting", b"<?xml version=\"1.0\"?>\n" + b"<a>" * 100 + b"X" + b"</a>" * 100),
    ],
    "json": [
        ("empty_object", b"{}"),
        ("nested_json", b'{"a":{"b":{"c":{"d":{"e":"deep"}}}}}'),
        ("large_array", b"[" + b",".join([b"0"] * 1000) + b"]"),
    ],
    "elf": [
        ("minimal_elf", b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x03\x00\x01\x00\x00\x00" + b"\x00" * 36),
    ],
    "tls": [
        ("client_hello", (
            b"\x16\x03\x01\x00\x05"  # TLS record header
            b"\x01\x00\x00\x01\x00"  # ClientHello
        )),
        ("x509_der", (
            b"\x30\x82\x01\x00"  # SEQUENCE
            b"\x30\x82\x00\xf0"  # tbsCertificate
            b"\xa0\x03\x02\x01\x02"  # version v3
            b"\x02\x01\x01"  # serial
        )),
    ],
    "woff": [
        ("woff2_header", b"wOF2\x00\x01\x00\x00" + b"\x00" * 36),
    ],
    "protobuf": [
        ("varint_field", b"\x08\x96\x01"),  # field 1, varint 150
        ("length_delimited", b"\x12\x07testing"),  # field 2, string "testing"
    ],
}

# Generic seeds that work as fuzz inputs for unknown formats.
_GENERIC_SEEDS: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("null_byte", b"\x00"),
    ("single_a", b"A"),
    ("four_bytes", b"\x00\x00\x00\x00"),
    ("boundary_ff", b"\xff" * 16),
    ("newlines", b"\n" * 64),
    ("printable", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
    ("long_input", b"A" * 4096),
    ("mixed_binary", b"\x00\x01\x02\x03\xff\xfe\xfd\xfc" * 32),
    ("utf8_multibyte", "\u00ff\u0100\u0fff\ud7ff".encode("utf-8") * 16),
    ("int_overflow_32", b"\xff\xff\xff\x7f"),  # INT32_MAX
    ("int_overflow_64", b"\xff\xff\xff\xff\xff\xff\xff\x7f"),  # INT64_MAX
    ("format_string", b"%s%s%s%s%n%n%n%n"),
    ("path_traversal", b"../../../../../etc/passwd"),
    # Boundary size seeds
    ("size_1", b"\x00"),
    ("size_2", b"\x00\x00"),
    ("size_4", b"\x00" * 4),
    ("size_8", b"\x00" * 8),
    ("size_16", b"\x00" * 16),
    ("size_32", b"\x00" * 32),
    ("size_64", b"\x00" * 64),
    ("size_128", b"\x00" * 128),
    ("size_256", b"\x00" * 256),
    ("size_512", b"\x00" * 512),
    ("size_1024", b"\x00" * 1024),
    ("size_2048", b"\x00" * 2048),
    ("size_4096", b"\x00" * 4096),
    ("size_8192", b"\x00" * 8192),
    # Integer boundary values
    ("int8_max", b"\x7f"),
    ("int8_min", b"\x80"),
    ("uint8_max", b"\xff"),
    ("int16_max", b"\xff\x7f"),
    ("int16_min", b"\x00\x80"),
    ("uint16_max", b"\xff\xff"),
    ("int32_max", b"\xff\xff\xff\x7f"),
    ("int32_min", b"\x00\x00\x00\x80"),
    ("uint32_max", b"\xff\xff\xff\xff"),
    # Special patterns
    ("alternating", b"\x00\xff" * 32),
    ("incrementing", bytes(range(256))),
    ("decrementing", bytes(range(255, -1, -1))),
    ("repeated_pattern", b"ABCD" * 64),
]


# ── Target-name to domain mapping heuristics ─────────────────────────────────

_NAME_DOMAIN_MAP: dict[str, str] = {
    # Image
    "png": "png", "libpng": "png", "apng": "png",
    "jpeg": "jpeg", "jpg": "jpeg", "libjpeg": "jpeg", "turbojpeg": "jpeg",
    "libjpeg-turbo": "jpeg", "mozjpeg": "jpeg",
    "gif": "gif", "giflib": "gif",
    "webp": "image", "libwebp": "image",
    "tiff": "image", "libtiff": "image",
    "jxl": "image", "libjxl": "image", "jpeg-xl": "image",
    "avif": "image", "libavif": "image",
    "heif": "image", "libheif": "image",
    "bmp": "image", "ico": "image",
    # Compression
    "zlib": "zlib", "zstd": "gzip", "lz4": "gzip", "brotli": "gzip",
    "snappy": "gzip", "lzma": "gzip", "xz": "gzip", "bzip2": "gzip",
    "deflate": "zlib", "miniz": "zlib",
    # Archive
    "zip": "zip", "libzip": "zip", "minizip": "zip",
    "tar": "gzip", "libarchive": "zip", "7z": "zip",
    # Crypto / TLS
    "openssl": "tls", "libressl": "tls", "boringssl": "tls",
    "mbedtls": "tls", "wolfssl": "tls", "gnutls": "tls",
    "libsodium": "tls", "nss": "tls",
    # Document
    "pdf": "pdf", "poppler": "pdf", "mupdf": "pdf", "pdfium": "pdf",
    # XML / HTML
    "expat": "xml", "libxml2": "xml", "libxml": "xml",
    "xerces": "xml", "pugixml": "xml", "tinyxml": "xml",
    "htmlparser": "xml", "html5": "xml", "gumbo": "xml",
    # JSON
    "json": "json", "cjson": "json", "rapidjson": "json",
    "simdjson": "json", "yyjson": "json", "jansson": "json",
    # Font
    "freetype": "woff", "harfbuzz": "woff", "fontconfig": "woff",
    # Network / Protocol
    "curl": "tls", "nghttp2": "tls", "http": "tls",
    "protobuf": "protobuf", "grpc": "protobuf", "flatbuffers": "protobuf",
    "dns": "tls", "pcap": "tls",
    # ELF / Binary
    "elf": "elf", "objdump": "elf", "binutils": "elf",
    "llvm": "elf", "capstone": "elf",
    # Audio/Video
    "ffmpeg": "audio", "libav": "audio", "opus": "audio",
    "vorbis": "audio", "flac": "audio", "mp3": "audio",
}


# ── Public API ───────────────────────────────────────────────────────────────

async def harvest_seeds(
    target_name: str,
    *,
    max_results: int = 10,
    workdir: Path | None = None,
    poc_urls: list[str] | None = None,
    local_seed_dirs: list[Path] | None = None,
) -> list[SeedMetadata]:
    """Discover and generate seeds for *target_name* autonomously.

    Works for ANY target by combining:
    1. Repository test-vector scanning (if workdir provided)
    2. Async scraping of configured PoC URLs (throttled)
    3. Local research directory scanning
    4. Format-aware seed generation based on domain detection
    5. Generic boundary-value seeds that trigger common parser bugs

    Parameters
    ----------
    target_name:
        Project or library name (e.g., ``openssl``, ``libjxl``, ``myparser``).
    max_results:
        Hard cap on returned seeds.
    workdir:
        Optional path to the cloned target repository for scanning.
    poc_urls:
        Optional list of URLs to scrape for PoC/seed files.
    local_seed_dirs:
        Optional list of local directories containing research seeds.

    Returns
    -------
    List of :class:`SeedMetadata` records with real seed content.
    """
    log.info("harvester.start", target=target_name, max_results=max_results)

    normalized = target_name.lower().strip()
    results: list[SeedMetadata] = []

    # ── Strategy 1: Scan target repo for test vectors ────────────────────
    if workdir is not None and workdir.exists():
        repo_seeds = _scan_repository_for_seeds(workdir, normalized, max_results)
        results.extend(repo_seeds)
        log.info("harvester.repo_scan", found=len(repo_seeds))

    # ── Strategy 2: Scrape configured PoC URLs (throttled) ───────────────
    if poc_urls:
        scraped = await _scrape_poc_urls(poc_urls, normalized, max_results - len(results))
        results.extend(scraped)
        log.info("harvester.url_scrape", found=len(scraped))

    # ── Strategy 3: Scan local research directories ──────────────────────
    if local_seed_dirs:
        local = _scan_local_seed_dirs(local_seed_dirs, normalized, max_results - len(results))
        results.extend(local)
        log.info("harvester.local_dirs", found=len(local))

    # ── Strategy 4: Generate format-aware seeds ──────────────────────────
    domain = _detect_domain(normalized)
    format_seeds = _generate_format_seeds(normalized, domain)
    results.extend(format_seeds)
    log.info("harvester.format_seeds", domain=domain, generated=len(format_seeds))

    # ── Strategy 5: Generic boundary-value seeds ─────────────────────────
    generic_seeds = _generate_generic_seeds(normalized)
    results.extend(generic_seeds)

    # ── Strategy 6: Mutated seeds (increase corpus diversity) ────────────
    if len(results) > 0 and len(results) < max_results:
        remaining_slots = max_results - len(results)
        mutated_seeds = _generate_mutated_seeds(
            results[:5],  # Mutate first 5 seeds
            normalized,
            max_mutations=min(remaining_slots // 3, 3),  # Cap mutations
        )
        results.extend(mutated_seeds)
        log.info("harvester.mutated_seeds", generated=len(mutated_seeds))

    log.info(
        "harvester.complete",
        target=target_name,
        total=len(results),
        capped=min(len(results), max_results),
    )
    return results[:max_results]


# ── Repository scanning ──────────────────────────────────────────────────────

def _scan_repository_for_seeds(
    workdir: Path,
    target_name: str,
    max_seeds: int,
) -> list[SeedMetadata]:
    """Walk the repository looking for test data / sample files / corpus."""
    seeds: list[SeedMetadata] = []
    scanned_files = 0
    max_scan_files = 500  # Don't walk massive repos forever.

    # Identify which file extensions are relevant based on domain detection.
    domain = _detect_domain(target_name)
    relevant_exts: set[str] = set()
    for dom, exts in _DOMAIN_EXTENSIONS.items():
        if dom == domain or domain in ("", "generic"):
            relevant_exts.update(exts)
    # Always include common binary test data extensions.
    relevant_exts.update([".bin", ".dat", ".raw", ".seed", ".testcase"])

    # Walk test/sample directories.
    for test_dir_name in _TEST_DIRS:
        for candidate in workdir.rglob(test_dir_name):
            if not candidate.is_dir():
                continue
            for f in sorted(candidate.rglob("*")):
                if scanned_files >= max_scan_files:
                    break
                if not f.is_file():
                    continue
                scanned_files += 1

                # Check size constraints.
                try:
                    size = f.stat().st_size
                except OSError:
                    continue
                if size < _MIN_SEED_SIZE or size > _MAX_SEED_SIZE:
                    continue

                # Accept files matching relevant extensions or binary files.
                suffix = f.suffix.lower()
                if suffix in relevant_exts or _is_binary_file(f):
                    seeds.append(
                        SeedMetadata(
                            seed_id=f"repo-{f.stem[:48]}",
                            source=SeedSource.MANUAL,
                            target_name=target_name,
                            description=f"Repository test vector: {f.relative_to(workdir)}",
                            language="binary",
                            tags=["repo-scan", "test-vector"],
                            created_at=datetime.now(tz=UTC),
                            downloaded_path=f,
                            seed_path=f,  # Already a binary file, use directly.
                        )
                    )
                    if len(seeds) >= max_seeds:
                        return seeds

    return seeds


def _is_binary_file(path: Path, sample_size: int = 512) -> bool:
    """Quick heuristic: file is binary if it contains null bytes in first 512B."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        return b"\x00" in chunk
    except OSError:
        return False


# ── Async URL scraper (Phase 2) ──────────────────────────────────────────────

# Throttle: max concurrent downloads and per-request delay.
_MAX_CONCURRENT_DOWNLOADS: int = 3
_DOWNLOAD_DELAY_SECONDS: float = 1.0
_DOWNLOAD_TIMEOUT_SECONDS: float = 30.0
_MAX_DOWNLOAD_SIZE: int = 2_097_152  # 2 MB per file


async def _scrape_poc_urls(
    urls: list[str],
    target_name: str,
    max_seeds: int,
) -> list[SeedMetadata]:
    """Download PoC/seed files from configured URLs with throttling.

    Uses subprocess + curl (no shell=True) for HTTP downloads.
    Respects rate limits and size caps.
    """
    if max_seeds <= 0:
        return []

    import tempfile

    seeds: list[SeedMetadata] = []
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_DOWNLOADS)
    dest_dir = Path(tempfile.mkdtemp(prefix="crashwise_seeds_"))

    async def _download_one(url: str, idx: int) -> SeedMetadata | None:
        async with semaphore:
            await asyncio.sleep(_DOWNLOAD_DELAY_SECONDS * idx)
            dest_file = dest_dir / f"poc_{idx}_{_safe_filename(url)}"
            try:
                # Use curl via subprocess_exec — no shell=True.
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sSfL",
                    "--max-filesize", str(_MAX_DOWNLOAD_SIZE),
                    "--max-time", str(int(_DOWNLOAD_TIMEOUT_SECONDS)),
                    "-o", str(dest_file),
                    url,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, _stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_DOWNLOAD_TIMEOUT_SECONDS + 5
                )
                if proc.returncode != 0 or not dest_file.exists():
                    return None
                size = dest_file.stat().st_size
                if size < _MIN_SEED_SIZE or size > _MAX_DOWNLOAD_SIZE:
                    dest_file.unlink(missing_ok=True)
                    return None
                return SeedMetadata(
                    seed_id=f"scraped-{idx}-{dest_file.stem[:32]}",
                    source=SeedSource.CVE,
                    target_name=target_name,
                    description=f"Scraped PoC from: {url[:100]}",
                    language="binary",
                    tags=["scraped", "poc", "remote"],
                    created_at=datetime.now(tz=UTC),
                    downloaded_path=dest_file,
                    seed_path=dest_file,
                )
            except (TimeoutError, OSError) as exc:
                log.debug("harvester.scrape_failed", url=url[:100], error=str(exc)[:80])
                return None

    tasks = [_download_one(url, i) for i, url in enumerate(urls[:max_seeds * 2])]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, SeedMetadata):
            seeds.append(r)
            if len(seeds) >= max_seeds:
                break

    return seeds


def _safe_filename(url: str) -> str:
    """Extract a safe filename from a URL."""
    # Take the last path component, strip query params, sanitize.
    from urllib.parse import urlparse
    path = urlparse(url).path
    name = Path(path).name if path else "seed"
    # Remove non-alphanumeric chars except dots and hyphens.
    safe = re.sub(r"[^\w.\-]", "_", name)
    return safe[:64] or "seed"


# ── Local research directory scanner ─────────────────────────────────────────

def _scan_local_seed_dirs(
    dirs: list[Path],
    target_name: str,
    max_seeds: int,
) -> list[SeedMetadata]:
    """Scan local research directories for seed/PoC files."""
    if max_seeds <= 0:
        return []

    seeds: list[SeedMetadata] = []
    for d in dirs:
        if not d.exists() or not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            try:
                size = f.stat().st_size
            except OSError:
                continue
            if size < _MIN_SEED_SIZE or size > _MAX_SEED_SIZE:
                continue
            seeds.append(
                SeedMetadata(
                    seed_id=f"local-{f.stem[:48]}",
                    source=SeedSource.MANUAL,
                    target_name=target_name,
                    description=f"Local research seed: {f.name}",
                    language="binary",
                    tags=["local", "research", str(d.name)],
                    created_at=datetime.now(tz=UTC),
                    downloaded_path=f,
                    seed_path=f,
                )
            )
            if len(seeds) >= max_seeds:
                return seeds

    return seeds


# ── Domain detection ─────────────────────────────────────────────────────────

def _detect_domain(target_name: str) -> str:
    """Detect the file format / domain from the target name."""
    normalized = target_name.lower().replace("-", "").replace("_", "")

    # Direct match.
    for name, domain in _NAME_DOMAIN_MAP.items():
        clean_name = name.replace("-", "").replace("_", "")
        if clean_name in normalized or normalized in clean_name:
            return domain

    # Keyword heuristics.
    if any(kw in normalized for kw in ("image", "img", "picture", "photo")):
        return "png"
    if any(kw in normalized for kw in ("compress", "deflat", "inflate")):
        return "zlib"
    if any(kw in normalized for kw in ("crypt", "cipher", "aes", "rsa", "ssl", "tls")):
        return "tls"
    if any(kw in normalized for kw in ("parse", "read", "decode", "deserializ")):
        return "json"  # parsers benefit from structured input
    if any(kw in normalized for kw in ("xml", "html", "sgml", "dom", "sax")):
        return "xml"
    if any(kw in normalized for kw in ("font", "type", "glyph")):
        return "woff"
    if any(kw in normalized for kw in ("audio", "sound", "codec", "pcm")):
        return "audio"
    if any(kw in normalized for kw in ("video", "frame", "h264", "h265", "av1")):
        return "audio"

    return "generic"


# ── Format-aware seed generation ─────────────────────────────────────────────

def _generate_format_seeds(target_name: str, domain: str) -> list[SeedMetadata]:
    """Generate format-specific seeds based on detected domain."""
    seeds: list[SeedMetadata] = []

    format_entries = _FORMAT_SEEDS.get(domain, [])
    for name, payload in format_entries:
        seeds.append(
            SeedMetadata(
                seed_id=f"format-{domain}-{name}",
                source=SeedSource.MANUAL,
                target_name=target_name,
                description=f"Format-aware seed ({domain}): {name}",
                language="binary",
                tags=["format-seed", domain, "generated"],
                created_at=datetime.now(tz=UTC),
            )
        )

    # If domain is "generic" or unknown, include seeds from multiple formats.
    if domain == "generic" and not format_entries:
        # Include a sample from common formats the target might handle.
        for fmt in ["json", "xml", "gzip"]:
            for name, payload in _FORMAT_SEEDS.get(fmt, [])[:1]:
                seeds.append(
                    SeedMetadata(
                        seed_id=f"format-{fmt}-{name}",
                        source=SeedSource.MANUAL,
                        target_name=target_name,
                        description=f"Generic seed ({fmt}): {name}",
                        language="binary",
                        tags=["format-seed", fmt, "generated"],
                        created_at=datetime.now(tz=UTC),
                    )
                )

    return seeds


# ── Generic seed generation ──────────────────────────────────────────────────

def _generate_generic_seeds(target_name: str) -> list[SeedMetadata]:
    """Generate boundary-value seeds that trigger common parser bugs."""
    seeds: list[SeedMetadata] = []

    for name, _ in _GENERIC_SEEDS[:8]:  # Cap at 8 generic seeds.
        seeds.append(
            SeedMetadata(
                seed_id=f"generic-{name}",
                source=SeedSource.MANUAL,
                target_name=target_name,
                description=f"Generic boundary seed: {name}",
                language="binary",
                tags=["generic", "boundary-value", "generated"],
                created_at=datetime.now(tz=UTC),
            )
        )

    return seeds


def _generate_mutated_seeds(
    base_seeds: list[SeedMetadata],
    target_name: str,
    max_mutations: int = 5,
) -> list[SeedMetadata]:
    """Generate mutated variants of existing seeds to increase corpus diversity.

    Applies simple mutations like:
    - Bit flipping
    - Byte insertion/deletion
    - Boundary value injection
    - Truncation

    Parameters
    ----------
    base_seeds:
        List of seeds to mutate.
    target_name:
        Target name for the mutated seeds.
    max_mutations:
        Maximum number of mutated seeds to generate per base seed.

    Returns
    -------
    List of mutated SeedMetadata records.
    """
    import random

    mutated_seeds: list[SeedMetadata] = []

    for base_seed in base_seeds[:3]:  # Only mutate first 3 seeds to avoid explosion
        payload = get_seed_payload(base_seed)
        if payload is None or len(payload) == 0:
            continue

        # Generate mutations
        for i in range(min(max_mutations, 5)):
            mutation_type = random.choice(["bit_flip", "byte_insert", "truncate", "boundary"])
            mutated = bytearray(payload)

            if mutation_type == "bit_flip" and len(mutated) > 0:
                # Flip random bits
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] ^= random.randint(1, 255)

            elif mutation_type == "byte_insert" and len(mutated) > 0:
                # Insert random bytes
                pos = random.randint(0, len(mutated))
                mutated.insert(pos, random.randint(0, 255))

            elif mutation_type == "truncate" and len(mutated) > 4:
                # Truncate to random length
                new_len = random.randint(1, len(mutated) - 1)
                mutated = mutated[:new_len]

            elif mutation_type == "boundary" and len(mutated) > 0:
                # Inject boundary values
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.choice([0x00, 0xff, 0x7f, 0x80])

            # Create mutated seed metadata
            mutated_seed = SeedMetadata(
                seed_id=f"mutated-{base_seed.seed_id}-{mutation_type}-{i}",
                source=SeedSource.MANUAL,
                target_name=target_name,
                description=f"Mutated seed ({mutation_type}): {base_seed.description}",
                language="binary",
                tags=["mutated", mutation_type, "generated"],
                created_at=datetime.now(tz=UTC),
            )
            mutated_seeds.append(mutated_seed)

    return mutated_seeds


# ── Seed payload retrieval (used by transformer) ─────────────────────────────

def get_seed_payload(seed: SeedMetadata) -> bytes | None:
    """Return the actual binary payload for a generated seed.

    For repo-scanned seeds, reads from disk. For generated seeds,
    looks up the format/generic seed tables. For mutated seeds,
    regenerates the mutation on-the-fly.
    """
    import random

    # Repo-scanned seeds have a seed_path already.
    if seed.seed_path is not None and seed.seed_path.exists():
        try:
            return seed.seed_path.read_bytes()
        except OSError:
            pass

    # Mutated seeds - regenerate the mutation
    if seed.seed_id.startswith("mutated-"):
        # Parse: mutated-{base_id}-{mutation_type}-{index}
        parts = seed.seed_id.split("-")
        if len(parts) >= 4:
            # Reconstruct base seed ID
            base_id = "-".join(parts[1:-2])  # Everything between "mutated-" and "-{type}-{index}"
            mutation_type = parts[-2]
            mutation_index = int(parts[-1])

            # Create a temporary base seed to get its payload
            base_seed = SeedMetadata(
                seed_id=base_id,
                source=seed.source,
                target_name=seed.target_name,
                description="",
                language="binary",
                tags=[],
                created_at=seed.created_at,
            )
            base_payload = get_seed_payload(base_seed)
            if base_payload is None or len(base_payload) == 0:
                return None

            # Regenerate the mutation with deterministic seed
            random.seed(hash(seed.seed_id))
            mutated = bytearray(base_payload)

            if mutation_type == "bit_flip" and len(mutated) > 0:
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] ^= random.randint(1, 255)
            elif mutation_type == "byte_insert" and len(mutated) > 0:
                pos = random.randint(0, len(mutated))
                mutated.insert(pos, random.randint(0, 255))
            elif mutation_type == "truncate" and len(mutated) > 4:
                new_len = random.randint(1, len(mutated) - 1)
                mutated = mutated[:new_len]
            elif mutation_type == "boundary" and len(mutated) > 0:
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.choice([0x00, 0xff, 0x7f, 0x80])

            return bytes(mutated)

    # Format seeds.
    if seed.seed_id.startswith("format-"):
        parts = seed.seed_id.split("-", 2)  # format-{domain}-{name}
        if len(parts) == 3:
            domain, name = parts[1], parts[2]
            for entry_name, payload in _FORMAT_SEEDS.get(domain, []):
                if entry_name == name:
                    return payload

    # Generic seeds.
    if seed.seed_id.startswith("generic-"):
        name = seed.seed_id[len("generic-"):]
        for entry_name, payload in _GENERIC_SEEDS:
            if entry_name == name:
                return payload

    return None
