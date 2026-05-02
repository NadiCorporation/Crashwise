# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Structured logging configuration via :mod:`structlog`.

Use :func:`get_logger` everywhere — never ``logging.getLogger`` directly.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from crashwise.core.config import get_settings

_CONFIGURED: bool = False


def configure_logging() -> None:
    """Idempotently configure stdlib logging + structlog processors."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level_name = get_settings().log_level.upper()
    level = getattr(logging, level_name, logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=level,
    )

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        cache_logger_on_first_use=True,
    )
    _CONFIGURED = True


def get_logger(name: str | None = None, **initial: Any) -> structlog.stdlib.BoundLogger:
    """Return a configured structlog logger, optionally bound with context."""
    configure_logging()
    logger: structlog.stdlib.BoundLogger = (
        structlog.get_logger(name) if name else structlog.get_logger()
    )
    if initial:
        logger = logger.bind(**initial)
    return logger
