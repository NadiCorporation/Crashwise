# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Empirical Challenger Test Suite for Milestone M3 (Challenger 1).

Adversarial testing, edge case verification, and failure mode analysis for:
1. GET /api/config & POST /api/config (secret masking, .env mutation, cache clearing)
2. GET /api/workers (Redis fallback, cluster scaling, DB aggregation)
3. GET /campaigns/{campaign_id}/crashes/{crash_id} (deep diagnostics, file I/O resilience)
4. GET /api/logs/stream (SSE streaming, live polling, log rotation, tail filtering)
"""

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


# ═════════════════════════════════════════════════════════════════════════════
# 1. EMPIRICAL CHALLENGE: GET /api/config & POST /api/config
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_config_secret_masking_edge_cases(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Adversarial test for secret masking with short, empty, and unusual key formats."""
    # Test short keys (less than 7 chars)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-12")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-1")
    monkeypatch.setenv("GOOGLE_API_KEY", "AIza1")
    monkeypatch.setenv("AI_API_KEY", "abc")

    get_settings.cache_clear()

    resp = await client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()

    # Verify no index out of bounds errors occurred and flags are True
    assert data["has_openai_api_key"] is True
    assert data["has_anthropic_api_key"] is True
    assert data["has_google_api_key"] is True
    assert data["has_ai_api_key"] is True

    # Check mask values are fallback masks
    assert data["openai_api_key_masked"] == "sk-...********"
    assert data["anthropic_api_key_masked"] == "sk-ant-...********"
    assert data["google_api_key_masked"] == "AIza...********"
    assert data["ai_api_key_masked"] == "********"

    # Verify raw secret strings are strictly NOT present in JSON text
    raw_json = resp.text
    assert "sk-12" not in raw_json
    assert "sk-ant-1" not in raw_json
    assert "AIza1" not in raw_json
    assert '"abc"' not in raw_json


@pytest.mark.asyncio
async def test_post_config_preserves_comments_and_updates_exact_keys(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Test that POST /api/config preserves comments, unmanaged keys, and correctly updates multiple types."""
    env_file = tmp_path / ".env"
    initial_content = (
        "# Server Config Header\n"
        "EXISTING_CUSTOM_KEY=custom_value_123\n"
        "# Database section\n"
        "DATABASE_URL=sqlite+aiosqlite:///./old.db\n"
        "TEMPORAL_HOST=old-temporal:7233\n"
        "# Trailing comment\n"
    )
    env_file.write_text(initial_content, encoding="utf-8")

    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        payload = {
            "temporal_host": "new-temporal-cluster:7233",
            "crashwise_api_port": 8888,
            "redis_enabled": True,
            "min_cvss_threshold": 8.0,
            "crashwise_workdir": "/custom/workdir",
            "crashwise_build_timeout": 1200,
        }

        resp = await client.post("/api/config", json=payload)
        assert resp.status_code == 200
        res_json = resp.json()
        assert res_json["restart_required"] is True
        assert set(res_json["updated_keys"]) == {
            "TEMPORAL_HOST",
            "CRASHWISE_API_PORT",
            "REDIS_ENABLED",
            "MIN_CVSS_THRESHOLD",
            "CRASHWISE_WORKDIR",
            "CRASHWISE_BUILD_TIMEOUT",
        }

        # Inspect resulting .env file
        updated_text = env_file.read_text(encoding="utf-8")
        assert "# Server Config Header" in updated_text
        assert "EXISTING_CUSTOM_KEY=custom_value_123" in updated_text
        assert "DATABASE_URL=sqlite+aiosqlite:///./old.db" in updated_text
        assert "# Database section" in updated_text
        assert "# Trailing comment" in updated_text

        # Verify updated values
        assert "TEMPORAL_HOST=new-temporal-cluster:7233" in updated_text
        assert "CRASHWISE_API_PORT=8888" in updated_text
        assert "REDIS_ENABLED=true" in updated_text
        assert "MIN_CVSS_THRESHOLD=8.0" in updated_text
        assert "CRASHWISE_WORKDIR=/custom/workdir" in updated_text
        assert "CRASHWISE_BUILD_TIMEOUT=1200" in updated_text


@pytest.mark.asyncio
async def test_post_config_empty_payload(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Test POST /api/config with empty payload behaves gracefully."""
    env_file = tmp_path / ".env"
    env_file.write_text("SOME_KEY=value\n", encoding="utf-8")

    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        resp = await client.post("/api/config", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["restart_required"] is True
        assert data["updated_keys"] == []
        assert env_file.read_text(encoding="utf-8") == "SOME_KEY=value\n"


# ═════════════════════════════════════════════════════════════════════════════
# 2. EMPIRICAL CHALLENGE: GET /api/workers
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_workers_aggregates_multiple_campaigns_and_runs(
    client: AsyncClient,
) -> None:
    """Verify campaigns_processed count accurately sums database records."""
    async with get_session() as session:
        for i in range(7):
            session.add(
                Campaign(
                    target_repo=f"https://github.com/org/repo{i}",
                    target_name=f"repo{i}",
                    fuzzer_type="libfuzzer",
                )
            )
        await session.commit()

    with patch("crashwise.api.main.list_active_workers", AsyncMock(return_value=[])):
        resp = await client.get("/api/workers")
        assert resp.status_code == 200
        workers = resp.json()
        assert len(workers) == 1
        assert workers[0]["campaigns_processed"] == 7
        assert workers[0]["uptime_seconds"] == 3600.0
        assert workers[0]["status"] == "online"


@pytest.mark.asyncio
async def test_get_workers_multi_replica_telemetry(
    client: AsyncClient,
) -> None:
    """Verify cluster worker endpoint returns complete telemetry for all replicas."""
    replicas = [f"crashwise-worker-{i}" for i in range(5)]
    with patch("crashwise.api.main.list_active_workers", AsyncMock(return_value=replicas)):
        resp = await client.get("/api/workers")
        assert resp.status_code == 200
        workers = resp.json()
        assert len(workers) == 5
        for i, w in enumerate(workers):
            assert w["name"] == f"crashwise-worker-{i}"
            assert w["status"] == "online"
            assert w["task_queue"] == get_settings().temporal_task_queue
            assert w["uptime_seconds"] > 0
            assert w["last_heartbeat"] is not None


# ═════════════════════════════════════════════════════════════════════════════
# 3. EMPIRICAL CHALLENGE: GET /campaigns/{campaign_id}/crashes/{crash_id}
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_crash_detail_sanitizer_disk_read_and_fallback(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Test reading ASan report from disk and fallback when file is missing."""
    asan_file = tmp_path / "asan_crash.log"
    asan_content = (
        "==45678==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n"
        "    #0 0x55a1b2c in cJSON_Parse /cJSON.c:1024\n"
        "    #1 0x55a1d4e in LLVMFuzzerTestOneInput /harness.cc:18\n"
    )
    asan_file.write_text(asan_content, encoding="utf-8")

    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/DaveGamble/cJSON",
            target_name="cJSON",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        run = FuzzingRun(campaign_id=campaign.id, iteration=1, status="completed")
        session.add(run)
        await session.commit()

        # Crash 1: Has valid logs_path pointing to real file
        crash1 = Crash(
            run_id=run.id,
            crash_type="SEGV",
            severity="high",
            severity_score=7,
            vulnerability_type="cwe-476",
            suggested_patch="if (!ptr) return NULL;",
            stack_trace="#0 0x55a1b2c in cJSON_Parse",
            stack_hash="hash_crash_1_abc",
            logs_path=str(asan_file),
            poc_code="#include <stdio.h>\nint main(){return 0;}",
            poc_compiled=True,
            poc_verified=True,
            reachability="parser",
            reachability_score=0.88,
            primitive="null-deref-read",
        )
        # Crash 2: Missing logs_path (falls back to stack_trace)
        crash2 = Crash(
            run_id=run.id,
            crash_type="heap-buffer-overflow",
            severity="critical",
            severity_score=10,
            vulnerability_type="cwe-122",
            stack_trace="==ERROR: heap-buffer-overflow fallback trace",
            stack_hash="hash_crash_2_def",
            logs_path=str(tmp_path / "non_existent_file.log"),
            reachability="core",
        )
        session.add(crash1)
        session.add(crash2)
        await session.commit()

        camp_id = str(campaign.id)
        c1_id = str(crash1.id)
        c2_id = str(crash2.id)

    # 1. Test crash1 reads from disk
    resp1 = await client.get(f"/campaigns/{camp_id}/crashes/{c1_id}")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["id"] == c1_id
    assert "==45678==ERROR: AddressSanitizer" in data1["sanitizer_output"]
    assert data1["poc_code"] == "#include <stdio.h>\nint main(){return 0;}"
    assert data1["poc_compiled"] is True
    assert data1["poc_verified"] is True
    assert data1["reachability_score"] == 0.88
    assert data1["primitive"] == "null-deref-read"

    # 2. Test crash2 falls back to stack_trace without 500 error
    resp2 = await client.get(f"/campaigns/{camp_id}/crashes/{c2_id}")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["id"] == c2_id
    assert data2["sanitizer_output"] == "==ERROR: heap-buffer-overflow fallback trace"
    assert data2["poc_compiled"] is False
    assert data2["poc_verified"] is False


@pytest.mark.asyncio
async def test_get_crash_detail_invalid_ids(client: AsyncClient) -> None:
    """Test GET crash detail handles invalid UUID and 404 properly."""
    resp = await client.get(f"/campaigns/{uuid4()}/crashes/{uuid4()}")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ═════════════════════════════════════════════════════════════════════════════
# 4. EMPIRICAL CHALLENGE: GET /api/logs/stream (SSE)
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_stream_logs_live_polling_and_rotation(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test SSE log streamer initial tail, dynamic updates, and file rotation."""
    log_file = tmp_path / "live_worker.log"
    log_file.write_text(
        "Initial line 1\n"
        "Initial line 2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    # Request with max_events=3
    resp = await client.get("/api/logs/stream?tail=5&max_events=3")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")
    body = resp.text
    assert "Log stream attached" in body
    assert "Initial line 1" in body
    assert "Initial line 2" in body


@pytest.mark.asyncio
async def test_stream_logs_tail_clamping(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test tail parameter correctly limits historical lines sent."""
    log_file = tmp_path / "tail_worker.log"
    lines = [f"Log line number {i}" for i in range(50)]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("CRASHWISE_LOG_FILE", str(log_file))

    # tail=3 + initial attachment line = 4 events
    resp = await client.get("/api/logs/stream?tail=3&max_events=4")
    assert resp.status_code == 200
    body = resp.text
    assert "Log line number 49" in body
    assert "Log line number 48" in body
    assert "Log line number 47" in body
    assert "Log line number 10" not in body


@pytest.mark.asyncio
async def test_get_crash_detail_mismatched_campaign_fallback(
    client: AsyncClient,
) -> None:
    """Test GET crash detail handles query when crash is queried by direct ID or fallback."""
    async with get_session() as session:
        campaign = Campaign(
            target_repo="https://github.com/example/target",
            target_name="target",
            fuzzer_type="libfuzzer",
        )
        session.add(campaign)
        await session.commit()

        run = FuzzingRun(campaign_id=campaign.id, iteration=0, status="completed")
        session.add(run)
        await session.commit()

        crash = Crash(
            run_id=run.id,
            crash_type="SEGV",
            severity="medium",
            stack_hash="stack_hash_fallback_test",
            reachability="parser",
        )
        session.add(crash)
        await session.commit()

        crash_id = str(crash.id)

    # Query with random campaign_id (triggers fallback select)
    random_camp_id = str(uuid4())
    resp = await client.get(f"/campaigns/{random_camp_id}/crashes/{crash_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == crash_id
    assert data["crash_type"] == "SEGV"


@pytest.mark.asyncio
async def test_post_config_special_characters_and_urls(
    client: AsyncClient, tmp_path: Path
) -> None:
    """Test POST /api/config handles special characters, query strings, and long URLs."""
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")

    with patch("crashwise.api.main.Path", side_effect=lambda p: env_file if str(p) == ".env" else Path(p)):
        payload = {
            "webhook_url": "https://hooks.slack.com/services/T00/B00/X00?token=abc%20123&flag=true#section",
            "openai_api_base": "https://custom-gateway.internal:8443/v1/models/gpt-4o",
            "log_level": "DEBUG",
        }
        resp = await client.post("/api/config", json=payload)
        assert resp.status_code == 200

        content = env_file.read_text(encoding="utf-8")
        assert "WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/X00?token=abc%20123&flag=true#section" in content
        assert "OPENAI_API_BASE=https://custom-gateway.internal:8443/v1/models/gpt-4o" in content
        assert "LOG_LEVEL=DEBUG" in content

