# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Temporal worker bootstrap.

Run as a module::

    python -m crashwise.orchestration.worker

…or via the CLI::

    crashwise worker

The worker registers every workflow exposed by
:mod:`crashwise.orchestration.workflows` and every activity exposed by
:mod:`crashwise.orchestration.activities`, then polls the configured task
queue until SIGINT/SIGTERM. Shutdown is graceful: in-flight activities
get up to ``graceful_shutdown_timeout`` to finish (or to honour cancel).
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from temporalio.client import Client
from temporalio.worker import Worker

from crashwise.core.config import get_settings
from crashwise.core.database import close_db, init_db
from crashwise.core.logging import configure_logging, get_logger
from crashwise.orchestration.activities import ALL_ACTIVITIES
from crashwise.orchestration.client import TemporalConnectionError, connect
from crashwise.orchestration.workflows import ALL_WORKFLOWS

log = get_logger(__name__)


async def run_worker(
    *,
    host: str | None = None,
    namespace: str | None = None,
    task_queue: str | None = None,
    client: Client | None = None,
    workflows: Iterable[type] = ALL_WORKFLOWS,
    activities: Iterable[Any] = ALL_ACTIVITIES,
    graceful_shutdown_timeout: timedelta = timedelta(seconds=30),
) -> None:
    """Boot a worker and block until a stop signal arrives."""
    configure_logging()
    settings = get_settings()
    task_queue = task_queue or settings.temporal_task_queue

    # Initialise persistence layer.
    await init_db()

    if client is None:
        client = await connect(host=host, namespace=namespace)

    log.info(
        "worker.starting",
        task_queue=task_queue,
        workflow_count=len(list(workflows)),
        activity_count=len(list(activities)),
    )

    stop_event = asyncio.Event()

    def _request_stop(signame: str) -> None:
        log.warning("worker.signal_received", signal=signame)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Signal handlers are unsupported on Windows event loops.
        with contextlib.suppress(NotImplementedError):  # pragma: no cover
            loop.add_signal_handler(sig, _request_stop, sig.name)

    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=list(workflows),
        activities=list(activities),
        graceful_shutdown_timeout=graceful_shutdown_timeout,
    )

    log.info("worker.ready", task_queue=task_queue)

    async def _heartbeat_loop() -> None:
        """Periodically register this worker in Redis."""
        from crashwise.core.redis import heartbeat

        while not stop_event.is_set():
            try:
                await heartbeat()
            except Exception:
                pass
            await asyncio.sleep(30)

    heartbeat_task = asyncio.create_task(_heartbeat_loop())

    async with worker:
        await stop_event.wait()
        log.info("worker.shutting_down")

    heartbeat_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await heartbeat_task

    await close_db()
    log.info("worker.stopped")


def main() -> None:
    """CLI / module entrypoint."""
    configure_logging()
    try:
        asyncio.run(run_worker())
    except TemporalConnectionError as exc:
        log.error("worker.connection_failed", error=str(exc))
        raise SystemExit(1) from exc
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        log.info("worker.keyboard_interrupt")


if __name__ == "__main__":  # pragma: no cover
    main()
