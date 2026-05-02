# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Harvester agent — discovers PoCs and seeds for a target project.

The harvester searches public sources (GitHub, CVE databases) for
proof-of-concept code related to a given target name.  In the current
phase the search is **mocked** — it pattern-matches against a small
built-in knowledge base.  A future iteration can swap in real web
scraping or LLM-powered search.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from crashwise.core.logging import get_logger
from crashwise.core.models import SeedMetadata, SeedSource

log = get_logger(__name__)

# ── Built-in knowledge base (mock) ───────────────────────────────────────────
# Maps target names (lowercase) to a list of seed metadata records.
_KNOWN_POC_DB: dict[str, list[dict]] = {
    "openssl": [
        {
            "seed_id": "CVE-2022-3602",
            "source": SeedSource.CVE,
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3602",
            "description": "X.509 Email Address Buffer Overflow",
            "language": "c",
            "tags": ["buffer-overflow", "x509", "critical"],
        },
        {
            "seed_id": "CVE-2023-0286",
            "source": SeedSource.CVE,
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0286",
            "description": "X.509 Common Name Buffer Overflow",
            "language": "c",
            "tags": ["buffer-overflow", "x509", "high"],
        },
    ],
    "libpng": [
        {
            "seed_id": "CVE-2015-8126",
            "source": SeedSource.CVE,
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8126",
            "description": "Buffer overflow in png_get_PLTE / png_set_PLTE",
            "language": "c",
            "tags": ["buffer-overflow", "png", "medium"],
        },
    ],
    "libjpeg": [
        {
            "seed_id": "CVE-2020-13790",
            "source": SeedSource.CVE,
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13790",
            "description": "Heap-based buffer over-read in get_sof",
            "language": "c",
            "tags": ["buffer-over-read", "jpeg", "medium"],
        },
    ],
    "zlib": [
        {
            "seed_id": "CVE-2018-25032",
            "source": SeedSource.CVE,
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-25032",
            "description": "Memory corruption on deflate",
            "language": "c",
            "tags": ["memory-corruption", "compression", "high"],
        },
    ],
}

# GitHub-style mock entries for generic targets.
_GITHUB_POC_TEMPLATE = {
    "source": SeedSource.GITHUB,
    "url": "https://github.com/{owner}/poc-{target}",
    "description": "Community PoC for {target}",
    "language": "python",
    "tags": ["poc", "community"],
}


# ── Public API ───────────────────────────────────────────────────────────────

async def harvest_seeds(
    target_name: str,
    *,
    max_results: int = 10,
) -> list[SeedMetadata]:
    """Discover PoC seeds for *target_name*.

    Parameters
    ----------
    target_name:
        Project or library name (e.g., ``openssl``, ``libpng``).
    max_results:
        Hard cap on returned seeds.

    Returns
    -------
    List of :class:`SeedMetadata` records.  May be empty when nothing is
    known about the target.
    """
    log.info("harvester.start", target=target_name, max_results=max_results)

    normalized = target_name.lower().strip()
    results: list[SeedMetadata] = []

    # 1. Exact match against built-in DB.
    if normalized in _KNOWN_POC_DB:
        for entry in _KNOWN_POC_DB[normalized]:
            results.append(
                SeedMetadata(
                    seed_id=entry["seed_id"],
                    source=entry["source"],
                    target_name=target_name,
                    url=entry.get("url"),
                    description=entry["description"],
                    language=entry["language"],
                    tags=entry["tags"],
                    created_at=datetime.now(tz=UTC),
                )
            )

    # 2. Fuzzy / heuristic match — any target containing known keywords.
    for db_target, entries in _KNOWN_POC_DB.items():
        if db_target in normalized or normalized in db_target:
            for entry in entries:
                # Avoid duplicates.
                if any(r.seed_id == entry["seed_id"] for r in results):
                    continue
                results.append(
                    SeedMetadata(
                        seed_id=entry["seed_id"],
                        source=entry["source"],
                        target_name=target_name,
                        url=entry.get("url"),
                        description=entry["description"],
                        language=entry["language"],
                        tags=entry["tags"],
                        created_at=datetime.now(tz=UTC),
                    )
                )

    # 3. GitHub fallback — generic community PoC pattern.
    if not results:
        safe_name = re.sub(r"[^a-z0-9_-]", "", normalized)[:32]
        results.append(
            SeedMetadata(
                seed_id=f"github-poc-{safe_name}",
                source=SeedSource.GITHUB,
                target_name=target_name,
                url=f"https://github.com/crashwise/poc-{safe_name}",
                description=f"Community PoC for {target_name}",
                language="python",
                tags=["poc", "community"],
                created_at=datetime.now(tz=UTC),
            )
        )

    log.info(
        "harvester.complete",
        target=target_name,
        found=len(results),
        capped=min(len(results), max_results),
    )
    return results[:max_results]
