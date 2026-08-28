# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Empirical verification suite by Challenger 2 for Milestone M3.

Focus areas:
1. SSE Log Streaming endpoint (GET /api/logs/stream)
   - Initial greeting
   - Tailing existing logs
   - Streaming live appended lines
   - Campaign ID filtering
   - Keepalive ping
   - Dynamic file creation & truncation/rotation
2. System Configuration & .env modification (POST /api/config)
   - Special characters handling
   - Unmanaged variables preservation
   - Comments and structure preservation
   - Pydantic Settings reloading & cache invalidation
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from crashwise.api.main import app
from crashwise.core.config import Settings, get_settings
from crashwise.core.database import close_db, init_db


@pytest.fixture(autouse=True)
async def _fresh_db() -> None:
    """Ensure clean DB for every test."""
    await init_db(drop=True)
    yield
    await close_db()


@pytest.fixture
async def client() -> AsyncClient:
    """Async HTTPX client for FastAPI testing."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ═════════════════════════════════════════════════════════════════════════════
# 1. EMPIRICAL VERIFICATION: SSE Log Streaming (GET /api/logs/stream)
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_sse_initial_greeting(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify initial greeting event format and SSE headers."""
    log_file = tmp_path / "stream_init.log"
    log_file.write_text("[INFO] Existing line\n", encoding="utf-8")
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    response = await client.get("/api/logs/stream?tail=10&max_events=1")
    assert response.status_code == 200
    assert response.headers.get("content-type", "").startswith("text/event-stream")
    assert response.headers.get("cache-control") == "no-cache"
    assert response.headers.get("connection") == "keep-alive"
    assert response.headers.get("x-accel-buffering") == "no"

    content = response.text.strip()
    assert content.startswith("data: ")
    payload = json.loads(content[6:])
    assert payload["level"] == "INFO"
    assert f"[System] Log stream attached to {log_file}" in payload["line"]
    assert "timestamp" in payload


@pytest.mark.asyncio
async def test_sse_tailing_existing_logs(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify tail parameter returns exactly the last N lines in order."""
    log_file = tmp_path / "stream_tail.log"
    lines = [f"[INFO] Log event #{i}" for i in range(1, 101)]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    # Request tail of 15 lines + 1 greeting = 16 events
    response = await client.get("/api/logs/stream?tail=15&max_events=16")
    assert response.status_code == 200
    blocks = [b.strip() for b in response.text.split("\n\n") if b.strip()]
    assert len(blocks) == 16

    # First event is greeting
    assert "Log stream attached" in blocks[0]

    # Next 15 events are lines #86 to #100
    for idx, block in enumerate(blocks[1:], start=86):
        assert block.startswith("data: ")
        data = json.loads(block[6:])
        assert data["line"] == f"[INFO] Log event #{idx}"


@pytest.mark.asyncio
async def test_sse_streaming_live_appended_lines(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SSE stream dynamically picks up lines appended while connected."""
    log_file = tmp_path / "stream_live.log"
    log_file.write_text("[INFO] Initial line\n", encoding="utf-8")
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    async def writer():
        await asyncio.sleep(0.2)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("[INFO] Dynamic live event 1\n")
            f.flush()
        await asyncio.sleep(0.3)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("[INFO] Dynamic live event 2\n")
            f.flush()

    writer_task = asyncio.create_task(writer())

    # Limit to 6 events (greeting + initial line + live 1 + keepalive + live 2 + keepalive)
    response = await client.get("/api/logs/stream?tail=10&max_events=6")
    await writer_task

    assert response.status_code == 200
    content = response.text
    assert "[System] Log stream attached" in content
    assert "[INFO] Initial line" in content
    assert "[INFO] Dynamic live event 1" in content
    assert "[INFO] Dynamic live event 2" in content


@pytest.mark.asyncio
async def test_sse_campaign_id_filtering(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify filtering by campaign_id works for both initial tail and live lines."""
    log_file = tmp_path / "stream_filter.log"
    log_file.write_text(
        "[INFO] target=cjson campaign_id=camp-target-alpha step 1\n"
        "[INFO] target=re2 campaign_id=camp-target-beta step 1\n"
        "[INFO] general worker heartbeat\n"
        "[INFO] target=cjson campaign_id=camp-target-alpha step 2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    async def live_writer():
        await asyncio.sleep(0.2)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("[INFO] target=re2 campaign_id=camp-target-beta step 2\n")
            f.write("[INFO] target=cjson campaign_id=camp-target-alpha step 3\n")
            f.flush()

    writer_task = asyncio.create_task(live_writer())

    # Greeting + 2 initial alpha lines + 1 live alpha line + keepalive = 5 events
    response = await client.get(
        "/api/logs/stream?campaign_id=camp-target-alpha&tail=10&max_events=5"
    )
    await writer_task

    assert response.status_code == 200
    content = response.text
    assert "Log stream attached" in content
    assert "camp-target-alpha" in content
    assert "step 1" in content
    assert "step 2" in content
    assert "step 3" in content

    # Verify no beta or general lines leaked
    assert "camp-target-beta" not in content
    assert "general worker heartbeat" not in content


@pytest.mark.asyncio
async def test_sse_keepalive_ping(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SSE stream emits ': keepalive' comments when no lines arrive."""
    log_file = tmp_path / "stream_keepalive.log"
    log_file.write_text("[INFO] Start\n", encoding="utf-8")
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    # Greeting + 1 log line + 1 keepalive = 3 events
    response = await client.get("/api/logs/stream?tail=10&max_events=3")
    assert response.status_code == 200
    raw_text = response.text
    assert ": keepalive" in raw_text


@pytest.mark.asyncio
async def test_sse_file_created_after_connection(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SSE stream waits and streams when file is created dynamically."""
    log_file = tmp_path / "created_later.log"
    if log_file.exists():
        log_file.unlink()
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    async def late_creator():
        await asyncio.sleep(0.2)
        log_file.write_text("[INFO] Created after stream started\n", encoding="utf-8")

    creator = asyncio.create_task(late_creator())

    # Greeting + 1 newly created line + keepalive = 4 events
    response = await client.get("/api/logs/stream?tail=10&max_events=4")
    await creator

    assert response.status_code == 200
    assert "[System] Log stream attached" in response.text
    assert "Created after stream started" in response.text


@pytest.mark.asyncio
async def test_sse_log_truncation_and_rotation(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SSE stream handles file truncation/rotation without error."""
    log_file = tmp_path / "rotated.log"
    log_file.write_text("A" * 2000 + "\n", encoding="utf-8")
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    async def truncator():
        await asyncio.sleep(0.2)
        # Truncate and write shorter content
        log_file.write_text("[INFO] New rotated log entry\n", encoding="utf-8")

    tr_task = asyncio.create_task(truncator())

    # 1 greeting + 1 initial line + 1 keepalive (after reset) + 1 new line + 1 keepalive = 5 events
    response = await client.get("/api/logs/stream?tail=1&max_events=5")
    await tr_task

    assert response.status_code == 200
    assert "Log stream attached" in response.text
    assert "New rotated log entry" in response.text


# ═════════════════════════════════════════════════════════════════════════════
# 2. EMPIRICAL STRESS-TEST: .env Writing (POST /api/config)
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_env_special_characters_stress(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Stress test writing URLs, API keys, and paths with special characters."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# Base config\nTEMPORAL_HOST=localhost:7233\n", encoding="utf-8"
    )

    special_payload = {
        "database_url": "postgresql+asyncpg://user:p@ss#word!$%^&*()@localhost:5432/db?ssl=require&opt=1",
        "openai_api_key": "sk-proj-abc=123+xyz#token:special_quote",
        "crashwise_llm_model": "deepseek/deepseek-r1:671b-q4_K_M",
        "webhook_url": "https://hooks.slack.com/services/T00/B00/X00?channel=%23security&alert=true",
        "crashwise_workdir": "/tmp/crashwise path with spaces/and-dashes_123",
        "min_cvss_threshold": 8.75,
    }

    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        response = await client.post("/api/config", json=special_payload)
        assert response.status_code == 200
        res = response.json()
        assert res["restart_required"] is True
        assert len(res["updated_keys"]) == 6

        content = env_file.read_text(encoding="utf-8")
        assert "DATABASE_URL=postgresql+asyncpg://user:p@ss#word!$%^&*()@localhost:5432/db?ssl=require&opt=1" in content
        assert "OPENAI_API_KEY=sk-proj-abc=123+xyz#token:special_quote" in content
        assert "CRASHWISE_LLM_MODEL=deepseek/deepseek-r1:671b-q4_K_M" in content
        assert "WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/X00?channel=%23security&alert=true" in content
        assert "CRASHWISE_WORKDIR=/tmp/crashwise path with spaces/and-dashes_123" in content
        assert "MIN_CVSS_THRESHOLD=8.75" in content


@pytest.mark.asyncio
async def test_env_preserves_unmanaged_variables(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Verify existing unmanaged variables in .env are strictly preserved."""
    env_file = tmp_path / ".env"
    initial_env = (
        "# Custom Third-Party Integrations\n"
        "CUSTOM_PROMETHEUS_PORT=9100\n"
        "DATADOG_API_KEY=dd-secret-9999\n"
        "MY_ARBITRARY_FLAG=yes\n"
        "\n"
        "# Crashwise Managed\n"
        "TEMPORAL_HOST=localhost:7233\n"
        "CRASHWISE_API_PORT=8000\n"
    )
    env_file.write_text(initial_env, encoding="utf-8")

    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        update_payload = {
            "temporal_host": "temporal.corp.internal:7233",
            "crashwise_api_port": 8888,
        }
        response = await client.post("/api/config", json=update_payload)
        assert response.status_code == 200

        updated_text = env_file.read_text(encoding="utf-8")

        # Unmanaged variables MUST be preserved verbatim
        assert "CUSTOM_PROMETHEUS_PORT=9100" in updated_text
        assert "DATADOG_API_KEY=dd-secret-9999" in updated_text
        assert "MY_ARBITRARY_FLAG=yes" in updated_text

        # Managed variables MUST be updated
        assert "TEMPORAL_HOST=temporal.corp.internal:7233" in updated_text
        assert "CRASHWISE_API_PORT=8888" in updated_text
        assert "TEMPORAL_HOST=localhost:7233" not in updated_text
        assert "CRASHWISE_API_PORT=8000" not in updated_text


@pytest.mark.asyncio
async def test_env_preserves_comments_and_structure(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Verify comments, separators, and structural layout are retained."""
    env_file = tmp_path / ".env"
    initial_env = (
        "###############################################################################\n"
        "# SECTION 1: TEMPORAL ORCHESTRATION\n"
        "###############################################################################\n"
        "# Primary cluster endpoint\n"
        "TEMPORAL_HOST=old-temporal:7233\n"
        "# Task queue name\n"
        "TEMPORAL_TASK_QUEUE=crashwise\n"
        "\n"
        "###############################################################################\n"
        "# SECTION 2: AI INFERENCE\n"
        "###############################################################################\n"
        "AI_PROVIDER=ollama\n"
    )
    env_file.write_text(initial_env, encoding="utf-8")

    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        update_payload = {
            "temporal_host": "new-temporal:7233",
            "ai_provider": "venice",
            "ai_model": "llama-3.3-70b",
        }
        response = await client.post("/api/config", json=update_payload)
        assert response.status_code == 200

        content = env_file.read_text(encoding="utf-8")

        # Header comments preserved
        assert "# SECTION 1: TEMPORAL ORCHESTRATION" in content
        assert "# Primary cluster endpoint" in content
        assert "# SECTION 2: AI INFERENCE" in content

        # Updated existing keys
        assert "TEMPORAL_HOST=new-temporal:7233" in content
        assert "AI_PROVIDER=venice" in content
        assert "TEMPORAL_TASK_QUEUE=crashwise" in content

        # Appended new key
        assert "AI_MODEL=llama-3.3-70b" in content


@pytest.mark.asyncio
async def test_env_settings_reloading_and_pydantic_parsing(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that after POST /api/config, get_settings() parses the updated .env."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TEMPORAL_HOST=init:7233\n"
        "CRASHWISE_BUILD_TIMEOUT=300\n"
        "NOTIFICATIONS_ENABLED=false\n",
        encoding="utf-8",
    )

    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        update_payload = {
            "temporal_host": "updated:7233",
            "crashwise_build_timeout": 600,
            "notifications_enabled": True,
            "min_cvss_threshold": 9.5,
        }
        response = await client.post("/api/config", json=update_payload)
        assert response.status_code == 200

    # Ensure get_settings.cache_clear() was called and Settings loads updated .env
    # Clear monkeypatched env vars that might shadow .env
    monkeypatch.delenv("TEMPORAL_HOST", raising=False)
    monkeypatch.delenv("CRASHWISE_BUILD_TIMEOUT", raising=False)
    monkeypatch.delenv("NOTIFICATIONS_ENABLED", raising=False)
    monkeypatch.delenv("MIN_CVSS_THRESHOLD", raising=False)

    get_settings.cache_clear()
    settings = Settings(_env_file=str(env_file))
    assert settings.temporal_host == "updated:7233"
    assert settings.crashwise_build_timeout == 600
    assert settings.notifications_enabled is True
    assert settings.min_cvss_threshold == 9.5
