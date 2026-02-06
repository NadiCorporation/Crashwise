"""Project initialization commands."""
# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.

from __future__ import annotations

import os
from pathlib import Path
from textwrap import dedent
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt

from ..config import ensure_project_config
from ..database import ensure_project_db

console = Console()
app = typer.Typer()


@app.command()
def project(
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Project name (defaults to current directory name)"
    ),
    api_url: Optional[str] = typer.Option(
        None,
        "--api-url",
        "-u",
        help="Crashwise API URL (defaults to http://localhost:8000)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force initialization even if project already exists",
    ),
):
    """
    📁 Initialize a new Crashwise project in the current directory.

    This creates a .crashwise directory with:
    • SQLite database for storing runs, findings, and crashes
    • Configuration file with project settings
    • Default ignore patterns and preferences
    """
    current_dir = Path.cwd()
    crashwise_dir = current_dir / ".crashwise"

    # Check if project already exists
    if crashwise_dir.exists() and not force:
        if crashwise_dir.is_dir() and any(crashwise_dir.iterdir()):
            console.print(
                "❌ Crashwise project already exists in this directory", style="red"
            )
            console.print("Use --force to reinitialize", style="dim")
            raise typer.Exit(1)

    # Get project name
    if not name:
        name = Prompt.ask("Project name", default=current_dir.name, console=console)

    # Get API URL
    if not api_url:
        api_url = Prompt.ask(
            "Crashwise API URL", default="http://localhost:8000", console=console
        )

    # Confirm initialization
    console.print(f"\n📁 Initializing Crashwise project: [bold cyan]{name}[/bold cyan]")
    console.print(f"📍 Location: [dim]{current_dir}[/dim]")
    console.print(f"🔗 API URL: [dim]{api_url}[/dim]")

    if not Confirm.ask("\nProceed with initialization?", default=True, console=console):
        console.print("❌ Initialization cancelled", style="yellow")
        raise typer.Exit(0)

    try:
        # Create .crashwise directory
        console.print("\n🔨 Creating project structure...")
        crashwise_dir.mkdir(exist_ok=True)

        # Initialize configuration
        console.print("⚙️  Setting up configuration...")
        ensure_project_config(
            project_dir=current_dir,
            project_name=name,
            api_url=api_url,
        )

        # Initialize database
        console.print("🗄️  Initializing database...")
        ensure_project_db(current_dir)

        _ensure_env_file(crashwise_dir, force)
        _ensure_agents_registry(crashwise_dir, force)

        # Create .gitignore if needed
        gitignore_path = current_dir / ".gitignore"
        gitignore_entries = [
            "# Crashwise CLI",
            ".crashwise/findings.db-*",  # SQLite temp files
            ".crashwise/cache/",
            ".crashwise/temp/",
        ]

        if gitignore_path.exists():
            with open(gitignore_path, "r") as f:
                existing_content = f.read()

            if "# Crashwise CLI" not in existing_content:
                with open(gitignore_path, "a") as f:
                    f.write(f"\n{chr(10).join(gitignore_entries)}\n")
                console.print("📝 Updated .gitignore with Crashwise entries")
        else:
            with open(gitignore_path, "w") as f:
                f.write(f"{chr(10).join(gitignore_entries)}\n")
            console.print("📝 Created .gitignore")

        # Create README if it doesn't exist
        readme_path = current_dir / "README.md"
        if not readme_path.exists():
            readme_content = f"""# {name}

Crashwise security testing project.

## Quick Start

```bash
# List available workflows
crashwise workflows

# Submit a workflow for analysis
crashwise workflow run <workflow-name> /path/to/target

# View findings
crashwise finding <run-id>
```

## Project Structure

- `.crashwise/` - Project data and configuration
- `.crashwise/config.yaml` - Project configuration
- `.crashwise/findings.db` - Local database for runs and findings
"""

            with open(readme_path, "w") as f:
                f.write(readme_content)
            console.print("📚 Created README.md")

        console.print("\n✅ Crashwise project initialized successfully!", style="green")
        console.print("\n🎯 Next steps:")
        console.print("   • cw workflows - See available workflows")
        console.print("   • cw status - Check API connectivity")
        console.print("   • cw workflow <workflow> <path> - Start your first analysis")
        console.print("   • edit .crashwise/.env with API keys & provider settings")

    except Exception as e:
        console.print(f"\n❌ Initialization failed: {e}", style="red")
        raise typer.Exit(1)


@app.callback()
def init_callback():
    """
    📁 Initialize Crashwise projects and components
    """


def _ensure_env_file(crashwise_dir: Path, force: bool) -> None:
    """Create or update the .crashwise/.env file with AI defaults."""

    env_path = crashwise_dir / ".env"
    if env_path.exists() and not force:
        console.print("🧪 Using existing .crashwise/.env (use --force to regenerate)")
        return

    console.print("🧠 Configuring AI environment...")
    console.print("   • Default LLM provider: openai")
    console.print("   • Default LLM model: litellm_proxy/gpt-5-mini")
    console.print("   • To customise provider/model later, edit .crashwise/.env")

    llm_provider = "openai"
    llm_model = "litellm_proxy/gpt-5-mini"

    # Check for global virtual keys from volumes/env/.env
    global_env_key = None
    for parent in crashwise_dir.parents:
        global_env = parent / "volumes" / "env" / ".env"
        if global_env.exists():
            try:
                for line in global_env.read_text(encoding="utf-8").splitlines():
                    if line.strip().startswith("OPENAI_API_KEY=") and "=" in line:
                        key_value = line.split("=", 1)[1].strip()
                        if key_value and not key_value.startswith("your-") and key_value.startswith("sk-"):
                            global_env_key = key_value
                            console.print(f"   • Found virtual key in {global_env.relative_to(parent)}")
                            break
            except Exception:
                pass
            break

    api_key = Prompt.ask(
        "OpenAI API key (leave blank to use global virtual key)" if global_env_key else "OpenAI API key (leave blank to fill manually)",
        default="",
        show_default=False,
        console=console,
    )

    # Use global key if user didn't provide one
    if not api_key and global_env_key:
        api_key = global_env_key

    session_db_path = crashwise_dir / "crashwise_sessions.db"
    session_db_rel = session_db_path.relative_to(crashwise_dir.parent)

    env_lines = [
        "# Crashwise AI configuration",
        "# Populate the API key(s) that match your LLM provider",
        "",
        f"LLM_PROVIDER={llm_provider}",
        f"LLM_MODEL={llm_model}",
        f"LITELLM_MODEL={llm_model}",
        "LLM_ENDPOINT=http://localhost:10999",
        "LLM_API_KEY=",
        "LLM_EMBEDDING_MODEL=litellm_proxy/text-embedding-3-large",
        "LLM_EMBEDDING_ENDPOINT=http://localhost:10999",
        f"OPENAI_API_KEY={api_key}",
        "CRASHWISE_MCP_URL=http://localhost:8010/mcp",
        "",
        "# Cognee configuration mirrors the primary LLM by default",
        f"LLM_COGNEE_PROVIDER={llm_provider}",
        f"LLM_COGNEE_MODEL={llm_model}",
        "LLM_COGNEE_ENDPOINT=http://localhost:10999",
        "LLM_COGNEE_API_KEY=",
        "LLM_COGNEE_EMBEDDING_MODEL=litellm_proxy/text-embedding-3-large",
        "LLM_COGNEE_EMBEDDING_ENDPOINT=http://localhost:10999",
        "COGNEE_MCP_URL=",
        "",
        "# Session persistence options: inmemory | sqlite",
        "SESSION_PERSISTENCE=sqlite",
        f"SESSION_DB_PATH={session_db_rel}",
        "",
        "# Optional integrations",
        "AGENTOPS_API_KEY=",
        "CRASHWISE_DEBUG=0",
        "",
    ]

    env_path.write_text("\n".join(env_lines), encoding="utf-8")
    console.print(f"📝 Created {env_path.relative_to(crashwise_dir.parent)}")

    template_path = crashwise_dir / ".env.template"
    if not template_path.exists() or force:
        template_lines = []
        for line in env_lines:
            if line.startswith("OPENAI_API_KEY="):
                template_lines.append("OPENAI_API_KEY=")
            elif line.startswith("LLM_API_KEY="):
                template_lines.append("LLM_API_KEY=")
            elif line.startswith("LLM_COGNEE_API_KEY="):
                template_lines.append("LLM_COGNEE_API_KEY=")
            else:
                template_lines.append(line)
        template_path.write_text("\n".join(template_lines), encoding="utf-8")
        console.print(f"📝 Created {template_path.relative_to(crashwise_dir.parent)}")

    # SQLite session DB will be created automatically when first used by the AI agent


def _ensure_agents_registry(crashwise_dir: Path, force: bool) -> None:
    """Create a starter agents.yaml registry if needed."""

    agents_path = crashwise_dir / "agents.yaml"
    if agents_path.exists() and not force:
        return

    template = dedent(
        """\
        # Crashwise Registered Agents
        # Populate this list to auto-register remote agents when the AI CLI starts
        registered_agents: []

        # Example:
        # registered_agents:
        #   - name: Calculator
        #     url: http://localhost:10201
        #     description: Sample math agent
        """.strip()
    )

    agents_path.write_text(template + "\n", encoding="utf-8")
    console.print(f"📝 Created {agents_path.relative_to(crashwise_dir.parent)}")
