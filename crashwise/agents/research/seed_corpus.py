# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Seed Corpus Generator — synthesizes valid seed files containing correct magic headers
and precalculated checksums for structured formats (PNG, ZIP, JPEG, ELF, GZIP, etc.).

Initial seed quality dictates whether a fuzzer penetrates parsing guards or gets
immediately rejected by header/checksum validation.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import ClassVar

from crashwise.core.logging import get_logger

log = get_logger(__name__)


# ── Format Builders with Valid Precomputed Checksums ─────────────────────────


def create_png_seed(
    width: int = 1,
    height: int = 1,
    color_type: int = 2,  # 2 = Truecolor (RGB), 6 = RGBA, 0 = Grayscale
    payload_data: bytes = b"\xff\x00\x00",
) -> bytes:
    """Generate a valid PNG file with precalculated IHDR, IDAT, and IEND chunk CRCs."""
    signature = b"\x89PNG\r\n\x1a\n"

    # 1. IHDR Chunk
    ihdr_data = struct.pack(
        ">IIBBBBB",
        width,
        height,
        8,  # bit depth = 8
        color_type,
        0,  # compression = deflate
        0,  # filter = standard
        0,  # interlace = none
    )
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    # 2. IDAT Chunk (Scanline data: filter type 0 + raw pixel bytes)
    scanline = b"\x00" + payload_data
    compressed_idat = zlib.compress(scanline, level=6)
    idat_crc = zlib.crc32(b"IDAT" + compressed_idat) & 0xFFFFFFFF
    idat_chunk = (
        struct.pack(">I", len(compressed_idat))
        + b"IDAT"
        + compressed_idat
        + struct.pack(">I", idat_crc)
    )

    # 3. IEND Chunk
    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    return signature + ihdr_chunk + idat_chunk + iend_chunk


def create_zip_seed(
    filename: str = "seed.txt",
    file_data: bytes = b"CRASHWISE_FUZZ_SEED_PAYLOAD\n",
) -> bytes:
    """Generate a valid ZIP archive with valid local/central header CRC32 and sizes."""
    filename_bytes = filename.encode("utf-8")
    crc = zlib.crc32(file_data) & 0xFFFFFFFF
    compressed_size = len(file_data)
    uncompressed_size = len(file_data)

    # 1. Local File Header
    local_header = struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",
        20,  # version needed: 2.0
        0,   # flags
        0,   # compression: stored (no compression)
        0,   # mod time
        0x21, # mod date
        crc,
        compressed_size,
        uncompressed_size,
        len(filename_bytes),
        0,   # extra field length
    ) + filename_bytes + file_data

    # 2. Central Directory Header
    central_dir = struct.pack(
        "<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02",
        0x0314,  # version made by: Unix 2.0
        20,      # version needed
        0,       # flags
        0,       # compression method: stored
        0,       # mod time
        0x21,    # mod date
        crc,
        compressed_size,
        uncompressed_size,
        len(filename_bytes),
        0,       # extra field length
        0,       # file comment length
        0,       # disk number start
        0,       # internal attrs
        0x81A40000, # external attrs (0644 standard file)
        0,       # relative offset of local header
    ) + filename_bytes

    # 3. End of Central Directory Record (EOCD)
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,  # disk number
        0,  # disk with central directory
        1,  # entries on this disk
        1,  # total entries
        len(central_dir),
        len(local_header),
        0,  # comment length
    )

    return local_header + central_dir + eocd


def create_jpeg_seed() -> bytes:
    """Generate a valid minimal JPEG JFIF baseline image."""
    soi = b"\xff\xd8"
    app0 = (
        b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    )
    # DQT: Quantization Table
    dqt = (
        b"\xff\xdb\x00\x43\x00"
        b"\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09\x08\x0a\x0c\x14"
        b"\x0d\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a"
        b"\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342"
    )
    # SOF0: Baseline 1x1 Grayscale
    sof0 = b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    # DHT: Huffman Table
    dht = (
        b"\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
    )
    # SOS: Start of Scan
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7f\xa0"
    eoi = b"\xff\xd9"

    return soi + app0 + dqt + sof0 + dht + sos + eoi


def create_elf_seed(is_64bit: bool = True) -> bytes:
    """Generate a valid ELF binary header with program header."""
    if is_64bit:
        # ELF64 Header (64 bytes)
        ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        elf_hdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident,
            2,       # e_type: ET_EXEC
            0x3E,    # e_machine: EM_X86_64
            1,       # e_version: EV_CURRENT
            0x400000,# e_entry: 0x400000
            64,      # e_phoff: 64 (immediately after ELF header)
            0,       # e_shoff: 0
            0,       # e_flags: 0
            64,      # e_ehsize: 64
            56,      # e_phentsize: 56
            1,       # e_phnum: 1
            64,      # e_shentsize: 64
            0,       # e_shnum: 0
            0,       # e_shstrndx: 0
        )
        # Program header: PT_LOAD (56 bytes)
        prog_hdr = struct.pack(
            "<IIQQQQQQ",
            1,       # p_type: PT_LOAD
            5,       # p_flags: PF_R | PF_X
            0,       # p_offset: 0
            0x400000,# p_vaddr
            0x400000,# p_paddr
            120,     # p_filesz
            120,     # p_memsz
            0x1000,  # p_align
        )
        return elf_hdr + prog_hdr
    else:
        # ELF32 Header (52 bytes)
        ident = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        elf_hdr = struct.pack(
            "<16sHHIIIIIHHHHHH",
            ident,
            2,       # e_type: ET_EXEC
            3,       # e_machine: EM_386
            1,       # e_version: EV_CURRENT
            0x8048000,# e_entry
            52,      # e_phoff: 52
            0,       # e_shoff
            0,       # e_flags
            52,      # e_ehsize: 52
            32,      # e_phentsize: 32
            1,       # e_phnum: 1
            40,      # e_shentsize: 40
            0,       # e_shnum: 0
            0,       # e_shstrndx: 0
        )
        # Program header (32 bytes)
        prog_hdr = struct.pack(
            "<IIIIIIII",
            1,       # p_type: PT_LOAD
            0,       # p_offset
            0x8048000,# p_vaddr
            0x8048000,# p_paddr
            84,      # p_filesz
            84,      # p_memsz
            5,       # p_flags: PF_R | PF_X
            0x1000,  # p_align
        )
        return elf_hdr + prog_hdr


def create_gzip_seed(uncompressed_data: bytes = b"CRASHWISE_GZIP_CORPUS_SEED\n") -> bytes:
    """Generate a valid GZIP stream with header, deflate blocks, and trailer CRC32/ISIZE."""
    # 1. 10-byte GZIP header
    header = struct.pack(
        "<2sBBIBB",
        b"\x1f\x8b",  # ID1, ID2
        8,            # CM: Deflate
        0,            # FLG: none
        0,            # MTIME: 0
        0,            # XFL: 0
        3,            # OS: Unix
    )


    # 2. Deflate compressed blocks (raw deflate without zlib header/adler32)
    compressor = zlib.compressobj(level=6, method=zlib.DEFLATED, wbits=-zlib.MAX_WBITS)
    deflate_data = compressor.compress(uncompressed_data) + compressor.flush()

    # 3. 8-byte trailer: CRC32 and ISIZE (little-endian)
    crc = zlib.crc32(uncompressed_data) & 0xFFFFFFFF
    isize = len(uncompressed_data) & 0xFFFFFFFF
    trailer = struct.pack("<II", crc, isize)

    return header + deflate_data + trailer


# ── Seed Corpus Generator Class ──────────────────────────────────────────────


class SeedCorpusGenerator:
    """Generates valid seed files with precomputed magic headers and checksums."""

    _FORMAT_REGISTRY: ClassVar[dict[str, list[bytes]]] = {}

    @classmethod
    def generate_seeds(cls, format_name: str) -> list[bytes]:
        """Generate a list of valid seed byte payloads for the given format.

        Parameters
        ----------
        format_name:
            Format identifier ('png', 'zip', 'jpeg', 'jpg', 'elf', 'gzip', 'zlib', 'xml', 'json').

        Returns
        -------
        List of binary seeds with valid checksums and headers.
        """
        fmt = format_name.lower().strip()

        if fmt in ("png", "apng", "image/png"):
            return [
                create_png_seed(width=1, height=1, color_type=2, payload_data=b"\xff\x00\x00"),
                create_png_seed(width=2, height=2, color_type=6, payload_data=b"\xff\x00\x00\xff\x00\xff\x00\xff\x00\x00\xff\xff\xff\xff\xff\xff"),
                create_png_seed(width=1, height=1, color_type=0, payload_data=b"\x80"),
            ]

        if fmt in ("zip", "archive", "pkzip", "application/zip"):
            return [
                create_zip_seed(filename="file.txt", file_data=b"CRASHWISE_FUZZ_1\n"),
                create_zip_seed(filename="data.bin", file_data=b"\x00\x01\x02\x03\x04\x05\x06\x07"),
                create_zip_seed(filename="empty.txt", file_data=b""),
            ]

        if fmt in ("jpeg", "jpg", "image/jpeg"):
            return [
                create_jpeg_seed(),
                b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9",
            ]

        if fmt in ("elf", "binary", "executable"):
            return [
                create_elf_seed(is_64bit=True),
                create_elf_seed(is_64bit=False),
            ]

        if fmt in ("gzip", "gz", "application/gzip"):
            return [
                create_gzip_seed(b"CRASHWISE_SEED_PAYLOAD_A\n"),
                create_gzip_seed(b"1234567890\n"),
                create_gzip_seed(b""),
            ]

        if fmt in ("zlib", "deflate"):
            return [
                zlib.compress(b"CRASHWISE_ZLIB_SEED\n"),
                zlib.compress(b"\x00" * 32),
            ]

        if fmt in ("xml", "svg", "html"):
            return [
                b'<?xml version="1.0" encoding="UTF-8"?>\n<root><item id="1">seed</item></root>\n',
                b'<?xml version="1.0"?>\n<!DOCTYPE root [\n<!ENTITY test "crashwise">\n]>\n<root>&test;</root>\n',
            ]

        if fmt in ("json", "geojson"):
            return [
                b'{"name": "crashwise", "version": 1, "items": [1, 2, 3], "valid": true}\n',
                b'{"a": {"b": {"c": "nested"}}}\n',
            ]

        # Generic default seeds
        return [
            b"CRASHWISE_DEFAULT_SEED_01\n",
            b"\x00\x00\x00\x00\xff\xff\xff\xff",
        ]

    @classmethod
    def generate_seed_corpus(
        cls,
        target_name: str,
        output_dir: Path,
        max_seeds: int = 10,
    ) -> list[Path]:
        """Generate on-disk seed corpus files for target_name.

        Parameters
        ----------
        target_name:
            Target identifier or format.
        output_dir:
            Directory to write the seeds to.
        max_seeds:
            Maximum number of seeds to write.

        Returns
        -------
        List of created seed file paths.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        seeds_data = cls.generate_seeds(target_name)
        written_paths: list[Path] = []

        for idx, payload in enumerate(seeds_data[:max_seeds]):
            seed_file = output_dir / f"seed_{idx:03d}_{target_name.lower().replace('/', '_')}.seed"
            seed_file.write_bytes(payload)
            written_paths.append(seed_file)

        return written_paths


def generate_seeds(format_name: str) -> list[bytes]:
    """Standalone functional interface for seed generation."""
    return SeedCorpusGenerator.generate_seeds(format_name)


__all__ = [
    "SeedCorpusGenerator",
    "create_elf_seed",
    "create_gzip_seed",
    "create_jpeg_seed",
    "create_png_seed",
    "create_zip_seed",
    "generate_seeds",
]
