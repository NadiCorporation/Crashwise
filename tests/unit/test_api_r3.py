# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit and integration tests for Milestone M3: API Extensions & Web UI Backend."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from crashwise.api.main import (
    app,
)
from crashwise.core.config import get_settings
from crashwise.core.database import (
    Campaign,
    Crash,
    FuzzingRun,
    close_db,
    get_session,
    init_db,
)


@pytest.fixture(autouse=True)
async def _fresh_db() -> None:
    """Drop and recreate database tables before every test."""
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


# ── 1. GET /api/config ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_system_config_returns_non_secret_and_masked_keys(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /api/config returns non-secret fields and masked secret indicators."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-1234567890abcdef")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-abcdefghijklmn")
    monkeypatch.setenv("GOOGLE_API_KEY", "AIzaSyD-1234567890abcdef")
    monkeypatch.setenv("AI_API_KEY", "secret-custom-token-xyz")
    monkeypatch.setenv("TEMPORAL_HOST", "cluster-temporal:7233")
    monkeypatch.setenv("CRASHWISE_API_PORT", "9000")
    monkeypatch.setenv("NOTIFICATIONS_ENABLED", "true")
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("MIN_CVSS_THRESHOLD", "8.5")

    get_settings.cache_clear()

    response = await client.get("/api/config")
    assert response.status_code == 200
    data = response.json()

    # Verify non-secret fields
    assert data["temporal_host"] == "cluster-temporal:7233"
    assert data["crashwise_api_port"] == 9000
    assert data["notifications_enabled"] is True
    assert data["webhook_url"] == "https://hooks.slack.com/services/T00/B00/X00"
    assert data["min_cvss_threshold"] == 8.5
    assert "database_url" in data
    assert "redis_url" in data
    assert "worker_name" in data

    # Verify secret presence flags
    assert data["has_openai_api_key"] is True
    assert data["has_anthropic_api_key"] is True
    assert data["has_google_api_key"] is True
    assert data["has_ai_api_key"] is True

    # Verify secrets are NOT leaked in plaintext
    assert "sk-proj-1234567890abcdef" not in str(data)
    assert "sk-ant-api03-abcdefghijklmn" not in str(data)
    assert "AIzaSyD-1234567890abcdef" not in str(data)
    assert "secret-custom-token-xyz" not in str(data)

    # Verify masked format
    assert data["openai_api_key_masked"] is not None
    assert "..." in data["openai_api_key_masked"] or "****" in data["openai_api_key_masked"]
    assert data["anthropic_api_key_masked"] is not None
    assert data["google_api_key_masked"] is not None
    assert data["ai_api_key_masked"] is not None


@pytest.mark.asyncio
async def test_get_system_config_when_no_keys_set(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /api/config handles missing API keys gracefully."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)

    get_settings.cache_clear()

    response = await client.get("/api/config")
    assert response.status_code == 200
    data = response.json()

    assert data["has_openai_api_key"] is False
    assert data["has_anthropic_api_key"] is False
    assert data["has_google_api_key"] is False
    assert data["has_ai_api_key"] is False
    assert data["openai_api_key_masked"] is None


# ── 2. POST /api/config ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_post_system_config_updates_env_file(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /api/config updates .env key-value pairs safely and returns restart_required."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# Initial comment\nTEMPORAL_HOST=localhost:7233\nCRASHWISE_API_PORT=8000\n",
        encoding="utf-8",
    )

    # Point Path(".env") to our temporary .env
    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        update_payload = {
            "temporal_host": "remote-temporal.internal:7233",
            "crashwise_api_port": 9090,
            "notifications_enabled": True,
            "min_cvss_threshold": 9.0,
            "ai_provider": "venice",
            "openai_api_key": "sk-new-key-123456",
        }

        response = await client.post("/api/config", json=update_payload)
        assert response.status_code == 200
        res_data = response.json()

        assert res_data["restart_required"] is True
        assert "TEMPORAL_HOST" in res_data["updated_keys"]
        assert "CRASHWISE_API_PORT" in res_data["updated_keys"]
        assert "NOTIFICATIONS_ENABLED" in res_data["updated_keys"]
        assert "OPENAI_API_KEY" in res_data["updated_keys"]

        # Check content in .env file
        updated_content = env_file.read_text(encoding="utf-8")
        assert "# Initial comment" in updated_content
        assert "TEMPORAL_HOST=remote-temporal.internal:7233" in updated_content
        assert "CRASHWISE_API_PORT=9090" in updated_content
        assert "NOTIFICATIONS_ENABLED=true" in updated_content
        assert "MIN_CVSS_THRESHOLD=9.0" in updated_content
        assert "AI_PROVIDER=venice" in updated_content
        assert "OPENAI_API_KEY=sk-new-key-123456" in updated_content


# ── 3. GET /api/workers ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_workers_fallback_local_worker(client: AsyncClient) -> None:
    """GET /api/workers returns local worker telemetry when Redis is empty/disabled."""
    async with get_session() as session:
        session.add(
            Campaign(
                target_repo="https://github.com/example/target",
                target_name="target-a",
                fuzzer_type="libfuzzer",
            )
        )
        session.add(
            Campaign(
                target_repo="https://github.com/example/target2",
                target_name="target-b",
                fuzzer_type="afl++",
            )
        )
        await session.commit()

    with patch("crashwise.api.main.list_active_workers", AsyncMock(return_value=[])):
        response = await client.get("/api/workers")
        assert response.status_code == 200
        workers = response.json()

        assert len(workers) == 1
        w = workers[0]
        assert w["name"] == get_settings().worker_name
        assert w["status"] == "online"
        assert w["task_queue"] == get_settings().temporal_task_queue
        assert w["campaigns_processed"] == 2
        assert w["uptime_seconds"] > 0
        assert w["last_heartbeat"] is not None


@pytest.mark.asyncio
async def test_get_workers_with_redis_replicas(client: AsyncClient) -> None:
    """GET /api/workers returns all active replicas from Redis registry."""
    with patch(
        "crashwise.api.main.list_active_workers",
        AsyncMock(return_value=["worker-node-1", "worker-node-2", "worker-node-3"]),
    ):
        response = await client.get("/api/workers")
        assert response.status_code == 200
        workers = response.json()

        assert len(workers) == 3
        names = [w["name"] for w in workers]
        assert "worker-node-1" in names
        assert "worker-node-2" in names
        assert "worker-node-3" in names


# ── 4. GET /campaigns/{campaign_id}/crashes/{crash_id} ────────────────────────


@pytest.mark.asyncio
async def test_get_crash_detail_full_payload(
    client: AsyncClient, tmp_path: Path
) -> None:
    """GET /campaigns/{campaign_id}/crashes/{crash_id} returns all diagnostic fields."""
    log_file = tmp_path / "asan_report.log"
    log_file.write_text("==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0001", encoding="utf-8")

    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        run = FuzzingRun(
            campaign_id=campaign.id,
            iteration=0,
            status="completed",
        )
        session.add(run)
        await session.commit()

        crash = Crash(
            run_id=run.id,
            crash_type="heap-buffer-overflow",
            severity="critical",
            severity_score=9,
            vulnerability_type="cwe-122",
            suggested_patch="--- target.c\n+++ target.c\n@@ -10 +10 @@\n- buf[i] = x;\n+ if (i < len) buf[i] = x;",
            verification_status="fixed",
            verification_stdout="Sanitizer passed, 0 errors",
            verification_stderr="",
            stack_trace="#0 0x5555 in parse_buffer /target.c:42\n#1 0x5556 in main /main.c:10",
            stack_hash="deadbeef1234",
            signal="SIGSEGV",
            logs_path=str(log_file),
            poc_code="#include <stdio.h>\nint main() { return 0; }",
            poc_compiled=True,
            poc_verified=True,
            reachability="deep-parse",
            reachability_score=0.95,
            primitive="write-what-where",
        )
        session.add(crash)
        await session.commit()

        camp_id = str(campaign.id)
        crash_id = str(crash.id)

    response = await client.get(f"/campaigns/{camp_id}/crashes/{crash_id}")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == crash_id
    assert data["campaign_id"] == camp_id
    assert data["crash_type"] == "heap-buffer-overflow"
    assert data["severity"] == "critical"
    assert data["severity_score"] == 9
    assert data["vulnerability_type"] == "cwe-122"
    assert "if (i < len)" in data["suggested_patch"]
    assert data["verification_status"] == "fixed"
    assert data["verification_stdout"] == "Sanitizer passed, 0 errors"
    assert "parse_buffer" in data["stack_trace"]
    assert data["stack_hash"] == "deadbeef1234"
    assert data["signal"] == "SIGSEGV"
    assert "AddressSanitizer" in data["sanitizer_output"]
    assert "int main()" in data["poc_code"]
    assert data["poc_compiled"] is True
    assert data["poc_verified"] is True
    assert data["reachability"] == "deep-parse"
    assert data["reachability_score"] == 0.95
    assert data["primitive"] == "write-what-where"


@pytest.mark.asyncio
async def test_get_crash_detail_not_found(client: AsyncClient) -> None:
    """GET /campaigns/{campaign_id}/crashes/{crash_id} returns 404 for non-existent crash."""
    random_camp_id = str(uuid4())
    random_crash_id = str(uuid4())
    response = await client.get(f"/campaigns/{random_camp_id}/crashes/{random_crash_id}")
    assert response.status_code == 404


# ── 5. GET /api/logs/stream ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_logs_sse_endpoint(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /api/logs/stream streams log lines via SSE."""
    log_file = tmp_path / "test_worker.log"
    log_file.write_text(
        "[2026-08-28T09:00:00] [INFO] Worker node initialized\n"
        "[2026-08-28T09:00:01] [INFO] campaign_id=camp-123 setup_target starting\n"
        "[2026-08-28T09:00:02] [ERROR] campaign_id=camp-999 build error\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    response = await client.get("/api/logs/stream?tail=10&max_events=4")
    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")
    content = response.text
    assert "data:" in content
    assert "Log stream attached" in content
    assert "Worker node initialized" in content


@pytest.mark.asyncio
async def test_stream_logs_with_campaign_filter(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /api/logs/stream filters lines by campaign_id."""
    log_file = tmp_path / "test_filter.log"
    log_file.write_text(
        "line-for-target-alpha campaign_id=alpha-111\n"
        "line-for-target-beta campaign_id=beta-222\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    response = await client.get("/api/logs/stream?campaign_id=alpha-111&tail=10&max_events=2")
    assert response.status_code == 200
    content = response.text
    assert "alpha-111" in content
    assert "beta-222" not in content


@pytest.mark.asyncio
async def test_stream_logs_non_existent_file(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /api/logs/stream handles non-existent log file gracefully without crashing."""
    non_existent = tmp_path / "does_not_exist.log"
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(non_existent))

    response = await client.get("/api/logs/stream?tail=10&max_events=1")
    assert response.status_code == 200
    content = response.text
    assert "data:" in content
    assert "Log stream attached" in content

