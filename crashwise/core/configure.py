# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Interactive LLM configuration wizard.

Guides the user through choosing providers and models for both
agentic workflows (harness synthesis, evolution, exploit gen) and
crash triage (root-cause analysis, patch suggestions).

Writes the result to ``.env`` in the current directory.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

# ── Provider catalogs ────────────────────────────────────────────────────────

AGENTIC_PROVIDERS = {
    "1": ("anthropic", "Anthropic (Claude)"),
    "2": ("openai", "OpenAI (GPT)"),
    "3": ("ollama", "Ollama (Local)"),
    "4": ("custom", "OpenAI-Compatible API (Together, Groq, vLLM, etc.)"),
}

TRIAGE_PROVIDERS = {
    "1": ("ollama", "Ollama (Local — private, free)"),
    "2": ("venice", "Venice AI (Cloud — privacy-focused)"),
    "3": ("custom", "OpenAI-Compatible API (custom endpoint)"),
    "4": ("none", "None (heuristic regex only, no AI)"),
}

ANTHROPIC_MODELS = [
    "claude-sonnet-4-5",
    "claude-sonnet-4-20250514",
    "claude-opus-4-20250514",
    "claude-3-5-haiku-20241022",
]

OPENAI_MODELS = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "o3-mini",
]


def _pick_from_menu(title: str, options: dict[str, tuple[str, str]]) -> str:
    """Display a numbered menu and return the chosen key."""
    console.print(f"\n[bold]{title}[/]")
    for key, (_, label) in options.items():
        console.print(f"  [cyan]{key}[/]) {label}")
    while True:
        choice = Prompt.ask("Choose", choices=list(options.keys()))
        return options[choice][0]


def _pick_model(models: list[str], provider_label: str) -> str:
    """Let user pick from known models or type a custom one."""
    console.print(f"\n[bold]Available {provider_label} models:[/]")
    for i, m in enumerate(models, 1):
        console.print(f"  [cyan]{i}[/]) {m}")
    console.print(f"  [cyan]{len(models) + 1}[/]) Custom (type model name)")
    choice = Prompt.ask("Choose", default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(models):
            return models[idx]
    except ValueError:
        pass
    # Custom or invalid → ask for name
    return Prompt.ask("Model name")


def run_configure_wizard(env_path: Path | None = None) -> Path:
    """Run the interactive LLM configuration wizard. Returns path to .env."""
    if env_path is None:
        env_path = Path(".env")

    console.print(
        Panel(
            "[bold]CrashWise LLM Configuration Wizard[/]\n\n"
            "This will configure AI providers for:\n"
            "  • [cyan]Agentic workflows[/] — harness synthesis, code evolution, exploit generation\n"
            "  • [cyan]Crash triage[/] — root-cause analysis, patch suggestions\n\n"
            "Your choices will be saved to [bold].env[/]",
            title="⚙️  Configure",
            border_style="cyan",
        )
    )

    env_lines: dict[str, str] = {}

    # ── Load existing .env to preserve non-LLM settings ──────────────────────
    existing: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip()

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 1: Agentic Workflows
    # ═══════════════════════════════════════════════════════════════════════════
    console.print("\n[bold underline]1. Agentic Workflows[/]")
    console.print(
        "[dim]Used for: harness synthesis, coverage-guided evolution, exploit generation.[/]"
    )

    agentic_choice = _pick_from_menu("Provider:", AGENTIC_PROVIDERS)

    if agentic_choice == "anthropic":
        model = _pick_model(ANTHROPIC_MODELS, "Anthropic")
        api_key = Prompt.ask("Anthropic API key", password=True)
        env_lines["CRASHWISE_LLM_MODEL"] = model
        env_lines["ANTHROPIC_API_KEY"] = api_key

    elif agentic_choice == "openai":
        model = _pick_model(OPENAI_MODELS, "OpenAI")
        api_key = Prompt.ask("OpenAI API key", password=True)
        env_lines["CRASHWISE_LLM_MODEL"] = model
        env_lines["OPENAI_API_KEY"] = api_key

    elif agentic_choice == "ollama":
        ollama_url = Prompt.ask("Ollama URL", default="http://localhost:11434")
        model = Prompt.ask("Model name (run 'ollama list' to see available)", default="llama3.1:8b")
        env_lines["CRASHWISE_LLM_MODEL"] = model
        env_lines["OPENAI_API_KEY"] = "ollama"
        env_lines["OPENAI_API_BASE"] = f"{ollama_url.rstrip('/')}/v1"

    elif agentic_choice == "custom":
        base_url = Prompt.ask("API base URL (e.g. https://api.together.xyz/v1)")
        api_key = Prompt.ask("API key", password=True)
        model = Prompt.ask("Model name (must match provider's catalog)")
        env_lines["CRASHWISE_LLM_MODEL"] = model
        env_lines["OPENAI_API_KEY"] = api_key
        env_lines["OPENAI_API_BASE"] = base_url

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 2: Crash Triage
    # ═══════════════════════════════════════════════════════════════════════════
    console.print("\n[bold underline]2. Crash Triage[/]")
    console.print(
        "[dim]Used for: crash root-cause analysis, patch suggestions, CVSS scoring.[/]"
    )
    console.print(
        Panel(
            "[yellow bold]⚠️  Privacy Notice[/]\n\n"
            "If you choose a [bold]cloud[/] provider, crash data (stack traces, ASAN reports,\n"
            "source snippets around the bug) will be sent to that provider's servers for\n"
            "analysis. Crashes may contain [bold]security-sensitive information[/] about\n"
            "undisclosed vulnerabilities (potential zero-days).\n\n"
            "If you are working on [bold]private targets[/] or [bold]pre-disclosure bugs[/],\n"
            "consider using [cyan]Ollama (local)[/] to keep everything on your machine.",
            border_style="yellow",
        )
    )

    triage_choice = _pick_from_menu("Provider:", TRIAGE_PROVIDERS)

    if triage_choice == "ollama":
        ollama_url = Prompt.ask("Ollama URL", default="http://localhost:11434")
        model = Prompt.ask("Model name", default="llama3.1:8b")
        env_lines["AI_PROVIDER"] = "ollama"
        env_lines["AI_MODEL"] = model
        env_lines["OLLAMA_URL"] = ollama_url

    elif triage_choice == "venice":
        api_key = Prompt.ask("Venice API key", password=True)
        model = Prompt.ask("Model name", default="llama-3.3-70b")
        env_lines["AI_PROVIDER"] = "venice"
        env_lines["AI_API_KEY"] = api_key
        env_lines["AI_MODEL"] = model

    elif triage_choice == "custom":
        console.print(
            "[dim]Custom triage uses an OpenAI-compatible endpoint (/v1/chat/completions).[/]"
        )
        base_url = Prompt.ask("API base URL (e.g. https://integrate.api.nvidia.com/v1)")
        api_key = Prompt.ask("API key (leave empty if none)", password=True, default="")
        model = Prompt.ask("Model name")
        env_lines["AI_PROVIDER"] = "openai_compatible"
        env_lines["AI_MODEL"] = model
        env_lines["OLLAMA_URL"] = base_url
        if api_key:
            env_lines["AI_API_KEY"] = api_key

    elif triage_choice == "none":
        env_lines["AI_PROVIDER"] = ""
        console.print(
            "  [dim]Triage will use heuristic ASAN/GDB regex parsing only (still works well).[/]"
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION 3: Infrastructure & Services
    # ═══════════════════════════════════════════════════════════════════════════
    console.print("\n[bold underline]3. Infrastructure & Services[/]")
    console.print(
        "[dim]Configure API port, Temporal orchestrator, databases, worker, and workdir.[/]"
    )

    api_port = Prompt.ask(
        "API Port (CRASHWISE_API_PORT)",
        default=existing.get("CRASHWISE_API_PORT", "8000"),
    )
    temporal_host = Prompt.ask(
        "Temporal Host (TEMPORAL_HOST)",
        default=existing.get("TEMPORAL_HOST", "localhost:7233"),
    )
    db_url = Prompt.ask(
        "Database URL (DATABASE_URL)",
        default=existing.get("DATABASE_URL", "sqlite+aiosqlite:///./crashwise.db"),
    )
    redis_url = Prompt.ask(
        "Redis URL (REDIS_URL)",
        default=existing.get("REDIS_URL", "redis://localhost:6379/0"),
    )
    worker_name = Prompt.ask(
        "Worker Name (WORKER_NAME)",
        default=existing.get("WORKER_NAME", "crashwise-worker-0"),
    )
    workdir = Prompt.ask(
        "Workdir Root (CRASHWISE_WORKDIR)",
        default=existing.get("CRASHWISE_WORKDIR", "/tmp/crashwise"),
    )

    env_lines["CRASHWISE_API_PORT"] = api_port
    env_lines["TEMPORAL_HOST"] = temporal_host
    env_lines["DATABASE_URL"] = db_url
    env_lines["REDIS_URL"] = redis_url
    env_lines["WORKER_NAME"] = worker_name
    env_lines["CRASHWISE_WORKDIR"] = workdir

    # ═══════════════════════════════════════════════════════════════════════════
    # Write .env
    # ═══════════════════════════════════════════════════════════════════════════

    # Merge: new values override existing, preserve everything else
    merged = {**existing, **env_lines}
    _write_formatted_env(env_path, merged)

    console.print(
        Panel(
            f"[bold green]Configuration saved to {env_path}[/]\n\n"
            "Next steps:\n"
            "  • Run [bold]crashwise doctor[/] to verify connectivity\n"
            "  • Run [bold]crashwise run[/] to start fuzzing",
            title="✅ Done",
            border_style="green",
        )
    )

    return env_path


def _write_formatted_env(env_path: Path, merged: dict[str, str]) -> None:
    """Write formatted key-values to .env with clean section headers."""
    output_lines: list[str] = [
        "# CrashWise Configuration",
        "# Generated by: crashwise configure",
        "",
    ]

    # Group keys by category
    llm_keys = {
        "CRASHWISE_LLM_MODEL",
        "CRASHWISE_LLM_TEMPERATURE",
        "CRASHWISE_LLM_MAX_TOKENS",
        "CRASHWISE_LLM_REASONING_EFFORT",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "GOOGLE_API_KEY",
    }
    triage_keys = {"AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "OLLAMA_URL"}
    infra_keys = {
        "CRASHWISE_API_PORT",
        "CRASHWISE_API_URL",
        "TEMPORAL_HOST",
        "TEMPORAL_NAMESPACE",
        "TEMPORAL_TASK_QUEUE",
        "DATABASE_URL",
        "REDIS_URL",
        "REDIS_ENABLED",
        "WORKER_NAME",
        "CRASHWISE_WORKDIR",
        "CRASHWISE_BUILD_TIMEOUT",
    }

    output_lines.append("# ── Agentic Workflows (LangChain) ──")
    for k in sorted(llm_keys):
        if k in merged:
            output_lines.append(f"{k}={merged[k]}")
    output_lines.append("")

    output_lines.append("# ── Crash Triage ──")
    for k in sorted(triage_keys):
        if k in merged:
            output_lines.append(f"{k}={merged[k]}")
    output_lines.append("")

    output_lines.append("# ── Infrastructure & Services ──")
    for k in sorted(infra_keys):
        if k in merged:
            output_lines.append(f"{k}={merged[k]}")
    output_lines.append("")

    # Everything else
    other_keys = set(merged.keys()) - llm_keys - triage_keys - infra_keys
    if other_keys:
        output_lines.append("# ── Other ──")
        for k in sorted(other_keys):
            output_lines.append(f"{k}={merged[k]}")
        output_lines.append("")

    env_path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")


def run_configure_non_interactive(
    *,
    env_path: Path = Path(".env"),
    api_port: int | None = None,
    temporal_host: str | None = None,
    temporal_namespace: str | None = None,
    temporal_task_queue: str | None = None,
    database_url: str | None = None,
    redis_url: str | None = None,
    worker_name: str | None = None,
    workdir: Path | str | None = None,
    build_timeout: int | None = None,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    llm_api_key: str | None = None,
    openai_api_base: str | None = None,
    ai_provider: str | None = None,
    ai_model: str | None = None,
    ai_api_key: str | None = None,
    ollama_url: str | None = None,
) -> Path:
    """Headless configuration writer for CI/CD environments."""
    existing: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip()

    updates: dict[str, str] = {}
    if api_port is not None:
        updates["CRASHWISE_API_PORT"] = str(api_port)
    if temporal_host is not None:
        updates["TEMPORAL_HOST"] = temporal_host
    if temporal_namespace is not None:
        updates["TEMPORAL_NAMESPACE"] = temporal_namespace
    if temporal_task_queue is not None:
        updates["TEMPORAL_TASK_QUEUE"] = temporal_task_queue
    if database_url is not None:
        updates["DATABASE_URL"] = database_url
    if redis_url is not None:
        updates["REDIS_URL"] = redis_url
    if worker_name is not None:
        updates["WORKER_NAME"] = worker_name
    if workdir is not None:
        updates["CRASHWISE_WORKDIR"] = str(workdir)
    if build_timeout is not None:
        updates["CRASHWISE_BUILD_TIMEOUT"] = str(build_timeout)

    if llm_model is not None:
        updates["CRASHWISE_LLM_MODEL"] = llm_model
    if llm_provider == "anthropic" and llm_api_key:
        updates["ANTHROPIC_API_KEY"] = llm_api_key
    elif llm_provider in ("openai", "custom") and llm_api_key:
        updates["OPENAI_API_KEY"] = llm_api_key
    elif llm_provider == "ollama":
        updates["OPENAI_API_KEY"] = "ollama"
        if ollama_url:
            updates["OPENAI_API_BASE"] = f"{ollama_url.rstrip('/')}/v1"
    elif llm_api_key:
        if llm_api_key.startswith("sk-ant-"):
            updates["ANTHROPIC_API_KEY"] = llm_api_key
        else:
            updates["OPENAI_API_KEY"] = llm_api_key

    if openai_api_base is not None:
        updates["OPENAI_API_BASE"] = openai_api_base

    if ai_provider is not None:
        updates["AI_PROVIDER"] = ai_provider
    if ai_model is not None:
        updates["AI_MODEL"] = ai_model
    if ai_api_key is not None:
        updates["AI_API_KEY"] = ai_api_key
    if ollama_url is not None:
        updates["OLLAMA_URL"] = ollama_url

    merged = {**existing, **updates}
    _write_formatted_env(env_path, merged)
    return env_path
