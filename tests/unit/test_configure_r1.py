# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Unit tests for Configuration Wizard & Non-interactive CLI R1 upgrades."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from crashwise.cli import app
from crashwise.core.configure import (
    _write_formatted_env,
    run_configure_non_interactive,
    run_configure_wizard,
)

runner = CliRunner()


def test_write_formatted_env_creates_sections(tmp_path: Path) -> None:
    """Verify _write_formatted_env groups keys into proper sections."""
    env_file = tmp_path / ".env"
    data = {
        "CRASHWISE_API_PORT": "9000",
        "TEMPORAL_HOST": "remote:7233",
        "DATABASE_URL": "postgresql+asyncpg://user:pass@db:5432/test",
        "CRASHWISE_LLM_MODEL": "gpt-4o",
        "OPENAI_API_KEY": "sk-test1234",
        "AI_PROVIDER": "ollama",
        "AI_MODEL": "llama3.1:8b",
        "CUSTOM_EXTRA_VAR": "hello_world",
    }
    _write_formatted_env(env_file, data)

    content = env_file.read_text(encoding="utf-8")
    assert "# ── Agentic Workflows (LangChain) ──" in content
    assert "CRASHWISE_LLM_MODEL=gpt-4o" in content
    assert "OPENAI_API_KEY=sk-test1234" in content

    assert "# ── Crash Triage ──" in content
    assert "AI_PROVIDER=ollama" in content
    assert "AI_MODEL=llama3.1:8b" in content

    assert "# ── Infrastructure & Services ──" in content
    assert "CRASHWISE_API_PORT=9000" in content
    assert "TEMPORAL_HOST=remote:7233" in content
    assert "DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/test" in content

    assert "# ── Other ──" in content
    assert "CUSTOM_EXTRA_VAR=hello_world" in content


def test_run_configure_non_interactive_creates_env(tmp_path: Path) -> None:
    """Verify run_configure_non_interactive creates a complete .env from args."""
    env_file = tmp_path / "test.env"
    run_configure_non_interactive(
        env_path=env_file,
        api_port=9999,
        temporal_host="temporal.corp:7233",
        temporal_namespace="fuzzing",
        temporal_task_queue="fast-queue",
        database_url="postgresql+asyncpg://postgres:pass@localhost:5432/cw",
        redis_url="redis://localhost:6379/2",
        worker_name="worker-custom-1",
        workdir=Path("/mnt/fast_nvme/cw"),
        build_timeout=1200,
        llm_provider="openai",
        llm_model="gpt-4o",
        llm_api_key="sk-openai-key",
        openai_api_base="https://custom.openai.endpoint/v1",
        ai_provider="venice",
        ai_model="llama-3.3-70b",
        ai_api_key="venice-key-123",
        ollama_url="http://localhost:11434",
    )

    assert env_file.exists()
    content = env_file.read_text(encoding="utf-8")
    assert "CRASHWISE_API_PORT=9999" in content
    assert "TEMPORAL_HOST=temporal.corp:7233" in content
    assert "TEMPORAL_NAMESPACE=fuzzing" in content
    assert "TEMPORAL_TASK_QUEUE=fast-queue" in content
    assert "DATABASE_URL=postgresql+asyncpg://postgres:pass@localhost:5432/cw" in content
    assert "REDIS_URL=redis://localhost:6379/2" in content
    assert "WORKER_NAME=worker-custom-1" in content
    assert "CRASHWISE_WORKDIR=/mnt/fast_nvme/cw" in content
    assert "CRASHWISE_BUILD_TIMEOUT=1200" in content
    assert "CRASHWISE_LLM_MODEL=gpt-4o" in content
    assert "OPENAI_API_KEY=sk-openai-key" in content
    assert "OPENAI_API_BASE=https://custom.openai.endpoint/v1" in content
    assert "AI_PROVIDER=venice" in content
    assert "AI_MODEL=llama-3.3-70b" in content
    assert "AI_API_KEY=venice-key-123" in content
    assert "OLLAMA_URL=http://localhost:11434" in content


def test_run_configure_non_interactive_merges_existing(tmp_path: Path) -> None:
    """Verify run_configure_non_interactive preserves unmodified existing variables."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "EXISTING_SECRET=keep_me\n"
        "TEMPORAL_HOST=old_host:7233\n"
        "CRASHWISE_API_PORT=8000\n",
        encoding="utf-8",
    )

    run_configure_non_interactive(
        env_path=env_file,
        temporal_host="new_host:7233",
        workdir=Path("/var/crashwise"),
    )

    content = env_file.read_text(encoding="utf-8")
    assert "EXISTING_SECRET=keep_me" in content
    assert "TEMPORAL_HOST=new_host:7233" in content
    assert "CRASHWISE_API_PORT=8000" in content
    assert "CRASHWISE_WORKDIR=/var/crashwise" in content


def test_run_configure_non_interactive_anthropic_key(tmp_path: Path) -> None:
    """Verify Anthropic key routing."""
    env_file = tmp_path / ".env"
    run_configure_non_interactive(
        env_path=env_file,
        llm_provider="anthropic",
        llm_api_key="sk-ant-testkey",
    )
    content = env_file.read_text(encoding="utf-8")
    assert "ANTHROPIC_API_KEY=sk-ant-testkey" in content


def test_run_configure_non_interactive_ollama_setup(tmp_path: Path) -> None:
    """Verify Ollama routing in non-interactive mode."""
    env_file = tmp_path / ".env"
    run_configure_non_interactive(
        env_path=env_file,
        llm_provider="ollama",
        ollama_url="http://my-ollama:11434",
    )
    content = env_file.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=ollama" in content
    assert "OPENAI_API_BASE=http://my-ollama:11434/v1" in content


def test_run_configure_wizard_interactive(tmp_path: Path) -> None:
    """Verify run_configure_wizard interactive prompts across all 3 sections."""
    env_file = tmp_path / "interactive.env"

    # Inputs for:
    # Section 1: agentic_choice (1=Anthropic), model (1=claude-sonnet-4-5), api_key
    # Section 2: triage_choice (1=Ollama), ollama_url, model
    # Section 3: api_port, temporal_host, db_url, redis_url, worker_name, workdir
    prompts_responses = [
        "1",                    # Section 1: Anthropic
        "1",                    # Section 1: Model default 1
        "sk-ant-secret",        # Section 1: API key
        "1",                    # Section 2: Ollama
        "http://local:11434",   # Section 2: Ollama URL
        "llama3.1:8b",          # Section 2: Model
        "8888",                 # Section 3: API Port
        "temporal:7233",        # Section 3: Temporal Host
        "sqlite+aiosqlite:///./test.db", # Section 3: DB URL
        "redis://redis:6379/0", # Section 3: Redis URL
        "test-worker-node",     # Section 3: Worker Name
        "/mnt/crashwise",       # Section 3: Workdir
    ]

    with patch("rich.prompt.Prompt.ask", side_effect=prompts_responses):
        saved = run_configure_wizard(env_path=env_file)
        assert saved == env_file
        content = env_file.read_text(encoding="utf-8")
        assert "ANTHROPIC_API_KEY=sk-ant-secret" in content
        assert "AI_PROVIDER=ollama" in content
        assert "CRASHWISE_API_PORT=8888" in content
        assert "TEMPORAL_HOST=temporal:7233" in content
        assert "DATABASE_URL=sqlite+aiosqlite:///./test.db" in content
        assert "REDIS_URL=redis://redis:6379/0" in content
        assert "WORKER_NAME=test-worker-node" in content
        assert "CRASHWISE_WORKDIR=/mnt/crashwise" in content


def test_cli_configure_non_interactive(tmp_path: Path) -> None:
    """Verify CLI `crashwise configure --non-interactive` flag execution."""
    env_file = tmp_path / "cli.env"
    result = runner.invoke(
        app,
        [
            "configure",
            "--non-interactive",
            "--env-file",
            str(env_file),
            "--temporal-host",
            "cluster-temporal:7233",
            "--api-port",
            "9090",
            "--workdir",
            "/var/cw-work",
            "--build-timeout",
            "600",
            "--worker-name",
            "fuzz-worker-9",
        ],
    )
    assert result.exit_code == 0
    assert "Configuration saved to" in result.output
    assert env_file.exists()

    content = env_file.read_text(encoding="utf-8")
    assert "TEMPORAL_HOST=cluster-temporal:7233" in content
    assert "CRASHWISE_API_PORT=9090" in content
    assert "CRASHWISE_WORKDIR=/var/cw-work" in content
    assert "CRASHWISE_BUILD_TIMEOUT=600" in content
    assert "WORKER_NAME=fuzz-worker-9" in content
