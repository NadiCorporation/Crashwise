# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Temporal client wrapper.

Centralises the connection logic so every component (CLI, worker, tests)
hits the cluster the same way. Connection establishment is wrapped with
:mod:`tenacity` so transient cluster unavailability — common during local
``docker compose up`` — does not torpedo the caller.

Usage
-----
::

    from crashwise.orchestration.client import connect, start_main_workflow

    client = await connect()
    handle = await start_main_workflow(client, payload)
    result = await handle.result()
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Sequence
from typing import Any

from temporalio.client import Client, WorkflowHandle
from temporalio.service import RPCError, RPCStatusCode
from tenacity import (
    AsyncRetrying,
    RetryError,
    before_sleep_log,
    retry_if_exception_type,
    stop_after_attempt,
    stop_after_delay,
    wait_exponential,
)

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger
from crashwise.core.models import FuzzingInput, FuzzingOutput
from crashwise.orchestration.data_converter import pydantic_data_converter

log = get_logger(__name__)


class TemporalConnectionError(RuntimeError):
    """Raised when CrashWise cannot reach the Temporal cluster."""


# ── Connection ────────────────────────────────────────────────────────────────
async def connect(
    *,
    host: str | None = None,
    namespace: str | None = None,
    timeout_seconds: float = 30.0,
    max_attempts: int = 8,
) -> Client:
    """Connect to Temporal with bounded exponential backoff.

    Parameters
    ----------
    host:
        ``host:port``. Falls back to ``TEMPORAL_HOST`` from settings.
    namespace:
        Temporal namespace. Falls back to ``TEMPORAL_NAMESPACE``.
    timeout_seconds:
        Total wall-clock budget for connection establishment.
    max_attempts:
        Hard cap on retry attempts within ``timeout_seconds``.
    """
    settings = get_settings()
    host = host or settings.temporal_host
    namespace = namespace or settings.temporal_namespace

    log.info(
        "temporal.connect.begin",
        host=host,
        namespace=namespace,
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
    )

    retrying = AsyncRetrying(
        retry=retry_if_exception_type((RPCError, OSError, asyncio.TimeoutError)),
        stop=(stop_after_delay(timeout_seconds) | stop_after_attempt(max_attempts)),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=5.0),
        before_sleep=before_sleep_log(logging.getLogger("crashwise.tenacity"), logging.WARNING),
        reraise=True,
    )

    try:
        async for attempt in retrying:
            with attempt:
                client = await asyncio.wait_for(
                    Client.connect(
                        host,
                        namespace=namespace,
                        data_converter=pydantic_data_converter,
                    ),
                    timeout=min(10.0, timeout_seconds),
                )
    except RetryError as exc:
        last = exc.last_attempt.exception() if exc.last_attempt else None
        raise TemporalConnectionError(
            f"could not reach Temporal at {host} after {max_attempts} attempts: {last!r}"
        ) from last
    except (TimeoutError, RPCError, OSError) as exc:
        # Surface the original error class with a friendly message.
        if isinstance(exc, RPCError) and exc.status == RPCStatusCode.NOT_FOUND:
            raise TemporalConnectionError(f"namespace {namespace!r} not found on {host}") from exc
        raise TemporalConnectionError(f"failed to connect to Temporal at {host}: {exc!r}") from exc

    log.info("temporal.connect.ready", host=host, namespace=namespace)
    return client


# ── Workflow start helpers ────────────────────────────────────────────────────
def _new_workflow_id(prefix: str = "crashwise") -> str:
    return f"{prefix}-{uuid.uuid4()}"


async def start_main_workflow(
    client: Client,
    payload: FuzzingInput,
    *,
    workflow_id: str | None = None,
    task_queue: str | None = None,
) -> WorkflowHandle[Any, FuzzingOutput]:
    """Submit a :class:`MainFuzzingWorkflow` execution and return the handle."""
    settings = get_settings()
    task_queue = task_queue or settings.temporal_task_queue
    workflow_id = workflow_id or _new_workflow_id()

    log.info(
        "temporal.start_workflow",
        workflow_id=workflow_id,
        task_queue=task_queue,
        target_repo=str(payload.target_repo),
        fuzzer=payload.fuzzer_type.value,
    )

    handle = await client.start_workflow(
        "MainFuzzingWorkflow",
        payload,
        id=workflow_id,
        task_queue=task_queue,
    )
    return handle


async def execute_main_workflow(
    payload: FuzzingInput,
    *,
    workflow_id: str | None = None,
    task_queue: str | None = None,
    host: str | None = None,
    namespace: str | None = None,
) -> FuzzingOutput:
    """End-to-end convenience: connect, start, await, return the result."""
    client = await connect(host=host, namespace=namespace)
    handle = await start_main_workflow(
        client,
        payload,
        workflow_id=workflow_id,
        task_queue=task_queue,
    )
    log.info("temporal.await_result", workflow_id=handle.id)
    result: FuzzingOutput = await handle.result()
    return result


__all__: Sequence[str] = (
    "TemporalConnectionError",
    "connect",
    "execute_main_workflow",
    "start_main_workflow",
)
