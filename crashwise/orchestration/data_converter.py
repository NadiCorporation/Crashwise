# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Pydantic-aware Temporal data converter.

We re-export ``temporalio.contrib.pydantic.pydantic_data_converter`` so all
client/worker construction in CrashWise routes Pydantic models, ``Path``,
``HttpUrl``, ``StrEnum``, and timezone-aware ``datetime`` payloads through
Pydantic's serialisation pipeline. This keeps the type-safe boundary between
workflows and activities lossless across the wire.
"""

from __future__ import annotations

from temporalio.contrib.pydantic import pydantic_data_converter

__all__ = ["pydantic_data_converter"]
