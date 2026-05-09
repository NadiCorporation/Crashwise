# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""``inject_seeds`` activity — God-Mode operator hook.

Drops one or more researcher-supplied seed files into the active fuzzing
corpus directory while a campaign is running. Triggered by the
``inject_seed`` workflow signal and the ``crashwise signal inject_seed``
CLI command.

Hardened paths
--------------

* Filenames are stripped of any directory components (``Path.name``) and
  rejected if the result is empty / contains shell escapes.
* Total injection size is capped at 16 MiB per signal to prevent an
  operator (or an attacker who has compromised an operator account) from
  filling the host disk.
* Each file is written atomically (write to ``.tmp`` → ``rename``) so a
  fuzzer that is concurrently scanning the corpus directory can never
  observe a partial seed.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from temporalio import activity

from crashwise.core.logging import get_logger

log = get_logger(__name__)

# Hard limits — these are operator-injection safety rails, not regular
# fuzzer corpus limits (libFuzzer/AFL ingest larger seeds via -max_len).
_MAX_TOTAL_BYTES: int = 16 * 1024 * 1024
_MAX_PER_FILE_BYTES: int = 4 * 1024 * 1024
_MAX_FILES_PER_CALL: int = 64


@activity.defn(name="inject_seeds")
async def inject_seeds(payload: dict[str, Any]) -> dict[str, Any]:
    """Write operator-supplied seeds into ``corpus_dir``.

    Parameters
    ----------
    payload:
        ``{"corpus_dir": str, "seeds": [{"filename": str, "data_b64": str}, ...],
        "campaign_id": str | None}``

    Returns
    -------
    ``{"written": int, "rejected": int, "reasons": list[str]}``
    """
    info = activity.info()

    corpus_dir_str = payload.get("corpus_dir", "")
    if not corpus_dir_str:
        raise ValueError("inject_seeds: missing corpus_dir")
    corpus_dir = Path(corpus_dir_str).resolve()
    corpus_dir.mkdir(parents=True, exist_ok=True)

    seeds = payload.get("seeds") or []
    if not isinstance(seeds, list):
        raise ValueError("inject_seeds: seeds must be a list")
    if len(seeds) > _MAX_FILES_PER_CALL:
        seeds = seeds[:_MAX_FILES_PER_CALL]

    log.info(
        "inject_seeds.start",
        workflow_id=info.workflow_id,
        attempt=info.attempt,
        corpus_dir=str(corpus_dir),
        count=len(seeds),
        campaign_id=payload.get("campaign_id"),
    )

    written = 0
    rejected = 0
    reasons: list[str] = []
    total_bytes = 0

    for entry in seeds:
        filename = (entry or {}).get("filename", "")
        data_b64 = (entry or {}).get("data_b64", "")
        # Sanitise filename: must be a basename, no traversal.
        safe_name = Path(filename).name
        if not safe_name or safe_name in {".", ".."} or "/" in filename or "\\" in filename:
            rejected += 1
            reasons.append(f"reject:filename:{filename!r}")
            continue
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:  # broad-except
            rejected += 1
            reasons.append(f"reject:b64:{safe_name}")
            continue
        if len(raw) == 0:
            rejected += 1
            reasons.append(f"reject:empty:{safe_name}")
            continue
        if len(raw) > _MAX_PER_FILE_BYTES:
            rejected += 1
            reasons.append(f"reject:too_large:{safe_name}:{len(raw)}")
            continue
        if total_bytes + len(raw) > _MAX_TOTAL_BYTES:
            rejected += 1
            reasons.append(f"reject:budget:{safe_name}")
            continue

        # Confirm the resolved destination stays inside the corpus directory.
        dest = (corpus_dir / safe_name).resolve()
        try:
            dest.relative_to(corpus_dir)
        except ValueError:
            rejected += 1
            reasons.append(f"reject:traversal:{safe_name}")
            continue

        # Atomic write.
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        try:
            tmp.write_bytes(raw)
            tmp.replace(dest)
        except OSError as exc:
            rejected += 1
            reasons.append(f"reject:io:{safe_name}:{exc!s:.80}")
            continue

        total_bytes += len(raw)
        written += 1
        log.info(
            "inject_seeds.wrote",
            filename=safe_name,
            bytes=len(raw),
            dest=str(dest),
        )

    log.info(
        "inject_seeds.complete",
        written=written,
        rejected=rejected,
        total_bytes=total_bytes,
    )
    return {"written": written, "rejected": rejected, "reasons": reasons}


__all__ = ["inject_seeds"]
