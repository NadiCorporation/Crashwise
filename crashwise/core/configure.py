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
    # Write .env
    # ═══════════════════════════════════════════════════════════════════════════

    # Merge: new values override existing, preserve everything else
    merged = {**existing, **env_lines}

    # Write with section comments
    output_lines: list[str] = [
        "# CrashWise Configuration",
        "# Generated by: crashwise configure",
        "",
    ]

    # Group LLM keys together
    llm_keys = {
        "CRASHWISE_LLM_MODEL", "CRASHWISE_LLM_TEMPERATURE",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_API_BASE",
    }
    triage_keys = {"AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "OLLAMA_URL"}

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

    # Everything else
    other_keys = set(merged.keys()) - llm_keys - triage_keys
    if other_keys:
        output_lines.append("# ── Other ──")
        for k in sorted(other_keys):
            output_lines.append(f"{k}={merged[k]}")
        output_lines.append("")

    env_path.write_text("\n".join(output_lines) + "\n")

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
