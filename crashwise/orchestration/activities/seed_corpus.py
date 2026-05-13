# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``seed_corpus`` activity — discovers, transforms, and organises
high-value fuzzing seeds before the main campaign starts.

The activity is the Temporal-side glue around the research agents
(:mod:`crashwise.agents.research`).  It runs the harvester to find
public PoCs, transforms each PoC into a minimal binary seed, and writes
everything into a ``corpus/`` directory that the fuzzer will ingest.
"""

from __future__ import annotations

from pathlib import Path

from temporalio import activity

from crashwise.agents.research.harvester import harvest_seeds
from crashwise.agents.research.transformer import transform_poc
from crashwise.core.config import get_settings
from crashwise.core.database import Seed, get_session
from crashwise.core.logging import get_logger
from crashwise.core.models import SeedCorpusInput, SeedMetadata
from crashwise.core.storage import sync_directory, upload_file

log = get_logger(__name__)


@activity.defn(name="seed_corpus")
async def seed_corpus(inp: SeedCorpusInput) -> list[Path]:
    """Harvest and transform seeds for *inp.target_name*.

    Parameters
    ----------
    inp:
        Bundle of target name, working directory, and max seed count.

    Returns
    -------
    List of filesystem paths to binary seed files ready for the fuzzer.
    """
    info = activity.info()
    log.info(
        "seed_corpus.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        target=inp.target_name,
        max_seeds=inp.max_seeds,
    )

    corpus_dir = inp.workdir / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    # 1. Harvest seed metadata from public sources.
    seeds: list[SeedMetadata] = await harvest_seeds(
        inp.target_name, max_results=inp.max_seeds, workdir=inp.workdir,
    )

    # 2. For each seed, resolve its binary payload and write to corpus.
    seed_paths: list[Path] = []
    for seed in seeds:
        # If the seed already has a valid path (repo-scanned), use it directly.
        if seed.seed_path is not None and seed.seed_path.exists():
            # Copy into corpus directory for the fuzzer.
            dest = corpus_dir / seed.seed_path.name
            if not dest.exists():
                try:
                    dest.write_bytes(seed.seed_path.read_bytes())
                    seed_paths.append(dest)
                except OSError:
                    pass
            continue

        # Resolve payload from the harvester's seed tables.
        from crashwise.agents.research.harvester import get_seed_payload
        payload = get_seed_payload(seed)
        if payload is not None:
            seed_file = corpus_dir / f"{seed.seed_id}.seed"
            seed_file.write_bytes(payload)
            seed.seed_path = seed_file
            seed_paths.append(seed_file)
            continue

        # Fallback: create a stub PoC and transform it.
        poc_dir = inp.workdir / "pocs"
        poc_dir.mkdir(parents=True, exist_ok=True)
        poc_path = poc_dir / f"{seed.seed_id}.poc"

        if seed.language == "python":
            poc_path.write_text(
                f"# PoC for {seed.seed_id}\n"
                f"payload = b'CRASHWISE' + b'\\xff\\xfe\\xfd\\xfc'\n"
                f"# Trigger: {seed.description}\n",
                encoding="utf-8",
            )
        else:
            poc_path.write_text(
                f"/* PoC for {seed.seed_id} */\n"
                f"unsigned char payload[] = {{\n"
                f"  0x43, 0x52, 0x41, 0x53, 0x48, 0x57, 0x49, 0x53, 0x45,\n"
                f"  0xff, 0xfe, 0xfd, 0xfc\n"
                f"}};\n"
                f"/* Trigger: {seed.description} */\n",
                encoding="utf-8",
            )

        seed.downloaded_path = poc_path
        seed = await transform_poc(seed, output_dir=corpus_dir)
        if seed.seed_path is not None and seed.seed_path.exists():
            seed_paths.append(seed.seed_path)

    # 3. Persist to database when campaign_id is provided.
    if inp.campaign_id is not None:
        await _persist_seeds(inp.campaign_id, seeds)

    # 4. Upload seeds to R2 for distributed workers.
    if get_settings().r2_enabled and inp.campaign_id is not None:
        prefix = f"campaigns/{inp.campaign_id}/corpus"
        await sync_directory(corpus_dir, prefix, direction="up")
        log.info("seed_corpus.r2_synced", prefix=prefix, count=len(seed_paths))

    log.info(
        "seed_corpus.complete",
        target=inp.target_name,
        harvested=len(seeds),
        transformed=len(seed_paths),
        corpus_dir=str(corpus_dir),
    )
    return seed_paths


async def _persist_seeds(
    campaign_id: str,
    seeds: list[SeedMetadata],
) -> None:
    """Write harvested seeds to the DB."""
    from uuid import UUID

    async with get_session() as session:
        for meta in seeds:
            db_seed = Seed(
                campaign_id=UUID(campaign_id),
                seed_id=meta.seed_id,
                source=meta.source.value,
                target_name=meta.target_name,
                url=str(meta.url) if meta.url else None,
                description=meta.description,
                language=meta.language,
                tags=meta.tags,
                downloaded_path=str(meta.downloaded_path) if meta.downloaded_path else "",
                seed_path=str(meta.seed_path) if meta.seed_path else "",
            )
            session.add(db_seed)
        await session.commit()
        log.info("seed_corpus.db_persisted", campaign_id=campaign_id, count=len(seeds))
