# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Top-level CLI entry point.

Exposes the ``crashwise`` console script declared in ``pyproject.toml``.

Commands
--------
* ``crashwise version``   — Print the installed version.
* ``crashwise info``      — Print runtime configuration.
* ``crashwise init``      — One-time database initialisation.
* ``crashwise doctor``    — System health diagnostic.
* ``crashwise setup``     — Auto-install missing build tools (Debian/Ubuntu/Arch/Fedora).
* ``crashwise run``       — Submit a fuzzing workflow.
* ``crashwise worker``    — Start a Temporal worker.
* ``crashwise api``       — Launch the FastAPI management server.
* ``crashwise dashboard`` — Launch the Streamlit intelligence dashboard.
* ``crashwise signal``    — Send a God-Mode signal (force_pivot, inject_seed,
                            pause_hunt, resume_hunt) to a live campaign.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import typer
import uvicorn
from rich.console import Console
from rich.json import JSON

from crashwise import __version__
from crashwise.core.config import get_settings
from crashwise.core.database import close_db, init_db
from crashwise.core.logging import configure_logging, get_logger
from crashwise.core.manifest import load_manifest_or_none
from crashwise.core.models import FuzzerType, FuzzingInput, FuzzingOutput
from crashwise.orchestration.client import (
    TemporalConnectionError,
    connect,
    start_main_workflow,
)
from crashwise.orchestration.worker import run_worker

console = Console(stderr=False)
log = get_logger(__name__)

app: typer.Typer = typer.Typer(
    name="crashwise",
    help="CrashWise — autonomous AI-powered fuzzing & crash triage.",
    no_args_is_help=True,
    add_completion=False,
)


# ── Meta commands ────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Print the installed CrashWise version."""
    typer.echo(f"crashwise {__version__}")


@app.command()
def configure(
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Run non-interactively and apply CLI options directly to .env",
    ),
    env_file: Path = typer.Option(
        Path(".env"),
        "--env-file",
        help="Path to .env configuration file",
    ),
    api_port: int | None = typer.Option(
        None,
        "--api-port",
        help="CrashWise API server port (CRASHWISE_API_PORT)",
    ),
    temporal_host: str | None = typer.Option(
        None,
        "--temporal-host",
        help="Temporal orchestrator host:port (TEMPORAL_HOST)",
    ),
    temporal_namespace: str | None = typer.Option(
        None,
        "--temporal-namespace",
        help="Temporal namespace (TEMPORAL_NAMESPACE)",
    ),
    temporal_task_queue: str | None = typer.Option(
        None,
        "--temporal-task-queue",
        help="Temporal task queue (TEMPORAL_TASK_QUEUE)",
    ),
    database_url: str | None = typer.Option(
        None,
        "--database-url",
        help="SQLAlchemy database URL (DATABASE_URL)",
    ),
    redis_url: str | None = typer.Option(
        None,
        "--redis-url",
        help="Redis URL (REDIS_URL)",
    ),
    worker_name: str | None = typer.Option(
        None,
        "--worker-name",
        help="Worker name identifier (WORKER_NAME)",
    ),
    workdir: Path | None = typer.Option(
        None,
        "--workdir",
        help="Root target workdir path (CRASHWISE_WORKDIR)",
    ),
    build_timeout: int | None = typer.Option(
        None,
        "--build-timeout",
        help="Target build timeout in seconds (CRASHWISE_BUILD_TIMEOUT)",
    ),
    llm_provider: str | None = typer.Option(
        None,
        "--llm-provider",
        help="LLM provider for agentic workflows (anthropic/openai/ollama/custom)",
    ),
    llm_model: str | None = typer.Option(
        None,
        "--llm-model",
        help="LLM model name (CRASHWISE_LLM_MODEL)",
    ),
    llm_api_key: str | None = typer.Option(
        None,
        "--llm-api-key",
        help="API key for agentic LLM provider",
    ),
    openai_api_base: str | None = typer.Option(
        None,
        "--openai-api-base",
        help="Custom OpenAI-compatible base URL (OPENAI_API_BASE)",
    ),
    ai_provider: str | None = typer.Option(
        None,
        "--ai-provider",
        help="AI provider for crash triage (ollama/venice/openai_compatible/none)",
    ),
    ai_model: str | None = typer.Option(
        None,
        "--ai-model",
        help="AI model for crash triage (AI_MODEL)",
    ),
    ai_api_key: str | None = typer.Option(
        None,
        "--ai-api-key",
        help="API key for crash triage (AI_API_KEY)",
    ),
    ollama_url: str | None = typer.Option(
        None,
        "--ollama-url",
        help="Ollama base URL (OLLAMA_URL)",
    ),
) -> None:
    """Configure CrashWise AI providers, infrastructure, and runtime settings.

    Runs interactive wizard by default, or accepts flags in --non-interactive mode.
    Saves configuration to .env (or custom --env-file).
    """
    if non_interactive:
        from crashwise.core.configure import run_configure_non_interactive

        saved = run_configure_non_interactive(
            env_path=env_file,
            api_port=api_port,
            temporal_host=temporal_host,
            temporal_namespace=temporal_namespace,
            temporal_task_queue=temporal_task_queue,
            database_url=database_url,
            redis_url=redis_url,
            worker_name=worker_name,
            workdir=workdir,
            build_timeout=build_timeout,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_api_key=llm_api_key,
            openai_api_base=openai_api_base,
            ai_provider=ai_provider,
            ai_model=ai_model,
            ai_api_key=ai_api_key,
            ollama_url=ollama_url,
        )
        console.print(f"[bold green]Configuration saved to[/] {saved}")
    else:
        from crashwise.core.configure import run_configure_wizard

        run_configure_wizard(env_path=env_file)


@app.command()
def info() -> None:
    """Print runtime + configuration metadata."""
    settings = get_settings()
    typer.echo(f"CrashWise {__version__}")
    typer.echo(f"  env:        {settings.crashwise_env}")
    typer.echo(f"  log_level:  {settings.log_level}")
    typer.echo(f"  temporal:   {settings.temporal_host} (ns={settings.temporal_namespace})")
    typer.echo(f"  task_queue: {settings.temporal_task_queue}")
    typer.echo(f"  db_url:     {settings.database_url}")
    typer.echo(f"  redis:      {settings.redis_url or 'disabled'}")
    typer.echo(f"  r2:         {'enabled' if settings.r2_enabled else 'disabled'}")
    typer.echo(f"  llm_model:  {settings.crashwise_llm_model}")
    typer.echo(f"  ai_triage:  {settings.ai_provider or 'disabled'}")


@app.command()
def init(
    target_dir: Path = typer.Argument(Path("."), help="Directory to initialise"),
    db_force: bool = typer.Option(False, "--db-force", help="Drop and recreate DB tables"),
) -> None:
    """Initialise a CrashWise project in the target directory.

    Three-step wizard:
      1. Detect target language and build system.
      2. Generate crashwise.yaml manifest.
      3. Create database tables.
    """
    configure_logging()
    from crashwise.core.discovery import discover_project
    from crashwise.core.manifest import MANIFEST_FILENAME

    target_dir = target_dir.resolve()
    if not target_dir.is_dir():
        console.print(f"[bold red]Not a directory:[/] {target_dir}")
        raise typer.Exit(code=1)

    console.print("[bold cyan]CrashWise Project Initialisation[/]")
    console.print(f"Target directory: {target_dir}")
    console.print()

    # Step 1: Detect target.
    console.print("[bold]Step 1/3:[/] Detecting project...")
    profile = discover_project(target_dir)
    if profile is None:
        console.print("[bold yellow]  Could not auto-detect project type.[/]")
        console.print("  Using generic C defaults.")
        from crashwise.core.discovery import DiscoveredProfile
        profile = DiscoveredProfile(
            name=target_dir.name,
            language="c",
            build_system="custom",
            build_command="make",
            output_dir="build",
        )
    console.print(f"  [green]Found:[/] {profile.name} ({profile.language})")
    console.print(f"  [green]Build:[/] {profile.build_system}")
    if profile.harness_path:
        console.print(f"  [green]Harness:[/] {profile.harness_path}")
    console.print()

    # Step 2: Generate manifest.
    console.print("[bold]Step 2/3:[/] Generating manifest...")
    manifest = profile.to_manifest()
    manifest_path = target_dir / MANIFEST_FILENAME
    manifest.to_file(manifest_path)
    console.print(f"  [green]Created:[/] {manifest_path}")
    console.print()

    # Step 3: Database.
    console.print("[bold]Step 3/3:[/] Initialising database...")
    try:
        asyncio.run(_init_db_async(drop_all=db_force))
        action = "recreated" if db_force else "created"
        console.print(f"  [green]Database tables {action} successfully.[/]")
    except Exception as exc:  # pragma: no cover
        console.print(f"  [bold yellow]Database init skipped:[/] {exc}")
    console.print()

    console.print("[bold green]Project initialisation complete![/]")
    console.print(f"Run [bold]crashwise run[/] in {target_dir} to start fuzzing.")


async def _init_db_async(*, drop_all: bool = False) -> None:
    """Async helper for DB initialisation used by the init command."""
    await init_db(drop=drop_all)
    await close_db()


# ── Sentinel commands ────────────────────────────────────────────────────────


@app.command()
def doctor(
    temporal_host: str = typer.Option("localhost", "--temporal-host"),
    temporal_port: int = typer.Option(7233, "--temporal-port"),
    redis_host: str = typer.Option("localhost", "--redis-host"),
    redis_port: int = typer.Option(6379, "--redis-port"),
    llm_base_url: str = typer.Option("http://localhost:11434", "--llm-url"),
) -> None:
    """Run system health diagnostics (the Sentinel)."""
    from crashwise.core.sentinel import (
        CheckStatus,
        get_missing_packages,
        run_all_checks,
    )

    configure_logging()
    console.print("[bold cyan]CrashWise System Sentinel[/]")
    console.print("Scanning host environment...\n")

    report = asyncio.run(
        run_all_checks(
            temporal_host=temporal_host,
            temporal_port=temporal_port,
            redis_host=redis_host,
            redis_port=redis_port,
            llm_base_url=llm_base_url,
        )
    )

    # Print results grouped by category
    for category, checks in report.by_category().items():
        console.print(f"[bold]{category.upper()}[/]")
        for check in checks:
            icon = {
                CheckStatus.OK: "[green]✓[/]",
                CheckStatus.WARN: "[yellow]![/]",
                CheckStatus.FAIL: "[red]✗[/]",
                CheckStatus.SKIP: "[dim]-[/]",
            }[check.status]
            console.print(f"  {icon} {check.name}: {check.message}")
            if check.detail:
                console.print(f"      [dim]{check.detail}[/]")
            if check.remediation:
                console.print(f"      [dim]→ {check.remediation}[/]")
        console.print()

    # Summary
    total = len(report.checks)
    console.print(
        f"[bold]Summary:[/] {report.ok_count}/{total} OK, "
        f"{report.warn_count} warnings, {report.fail_count} failures"
    )
    if report.healthy:
        console.print("[bold green]System is ready for CrashWise.[/]")
    else:
        console.print("[bold red]System is NOT ready.[/] Run [bold]crashwise setup[/] to fix.")
        missing = get_missing_packages(report)
        if missing:
            console.print(f"[dim]Missing packages: {', '.join(missing)}[/]")


@app.command()
def setup(
    dry_run: bool = typer.Option(False, "--dry-run", help="Print script without running"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write script to file"),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Non-interactive: assume 'yes' to all prompts (CI / scripted use).",
    ),
) -> None:
    """Auto-install missing dependencies for the current Linux distribution.

    Detects the host distro from ``/etc/os-release`` and dispatches to
    ``apt`` (Debian/Ubuntu), ``pacman`` (Arch), or ``dnf`` (Fedora). The
    command is interactive by default — you will be asked to confirm
    every privileged action (package install, ``usermod -aG docker``,
    ``systemctl start docker``, …). Use ``--yes`` for unattended runs.
    """
    from crashwise.core.sentinel import (
        detect_distro,
        generate_setup_script,
        get_missing_packages,
        run_all_checks,
    )

    configure_logging()
    info_distro = detect_distro()
    distro_label = info_distro.pretty_name or info_distro.id_ or info_distro.family
    console.print("[bold cyan]CrashWise Provisioner[/]")
    console.print(
        f"  Distro: [green]{distro_label}[/]  (family: {info_distro.family})"
    )
    console.print("  Analysing system requirements...\n")

    report = asyncio.run(run_all_checks())
    missing = get_missing_packages(report)

    if not missing:
        console.print("[bold green]All required packages are already installed.[/]")
    else:
        script = generate_setup_script(missing)

        if output:
            output.write_text(script, encoding="utf-8")
            console.print(f"[bold green]Setup script written to:[/] {output}")
            if dry_run:
                return

        if dry_run:
            console.print("[bold]Generated setup script:[/]")
            console.print(script)
            return

        console.print(
            f"[bold]Will install {len(missing)} packages:[/] "
            f"{', '.join(missing)}"
        )
        if not yes and not typer.confirm("Proceed with installation?", default=True):
            console.print("[yellow]Skipped package install.[/]")
        else:
            console.print("[dim]This may take a few minutes...[/]\n")
            try:
                proc = subprocess.run(
                    ["bash", "-c", script],
                    capture_output=False,
                    text=True,
                )
                if proc.returncode == 0:
                    console.print("\n[bold green]Package install complete.[/]")
                else:
                    console.print(
                        f"\n[bold red]Package install failed (exit {proc.returncode}).[/]"
                    )
                    raise typer.Exit(code=proc.returncode)
            except FileNotFoundError:
                console.print(
                    "[bold red]bash not found. Cannot execute setup script.[/]"
                )
                raise typer.Exit(code=1) from None

    # ── Post-install: docker group + daemon socket ────────────────────
    _interactive_post_install(yes=yes)


def _interactive_post_install(*, yes: bool) -> None:
    """Surface the two most common post-install footguns and offer to fix them.

    1. The current user is not in the ``docker`` group → ``docker run``
       returns "permission denied" and CrashWise campaigns fail at the
       first activity.  We offer to run ``sudo usermod -aG docker $USER``
       and remind the user to log out / back in.

    2. The Docker daemon socket is not responding → offer to start it
       via ``systemctl start docker``.
    """
    import grp
    import os
    import shutil

    # Track whether we mutated the docker group during this run so we can
    # emit a final "log out / log back in" banner — without it, the very
    # next ``crashwise doctor`` call shows a confusing "permission denied"
    # because the kernel still uses the pre-usermod credentials.
    usermod_just_applied: bool = False

    # ── Docker group membership ──────────────────────────────────────
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    if user:
        try:
            docker_grp = grp.getgrnam("docker")
            in_group = user in docker_grp.gr_mem or os.getgid() == docker_grp.gr_gid
        except KeyError:
            in_group = True  # No docker group at all → install will create it.
        if not in_group:
            console.print()
            console.print(
                f"[bold yellow]![/] User [bold]{user}[/] is not in the "
                "[bold]docker[/] group. Without group membership, CrashWise "
                "cannot launch fuzzing containers."
            )
            do_it = yes or typer.confirm(
                f"Run 'sudo usermod -aG docker {user}' now?",
                default=True,
            )
            if do_it:
                if shutil.which("sudo") or os.geteuid() == 0:
                    cmd = (
                        ["usermod", "-aG", "docker", user]
                        if os.geteuid() == 0
                        else ["sudo", "usermod", "-aG", "docker", user]
                    )
                    proc = subprocess.run(cmd, capture_output=False)
                    if proc.returncode == 0:
                        usermod_just_applied = True
                        console.print(
                            "[bold green]✓[/] User added to docker group. "
                            "[bold yellow]Log out and back in[/] for the change "
                            "to take effect (or run 'newgrp docker' for the "
                            "current shell)."
                        )
                    else:
                        console.print(
                            f"[bold red]usermod failed (exit {proc.returncode}).[/]"
                        )
                else:
                    console.print(
                        "[red]sudo is not available; run "
                        f"'usermod -aG docker {user}' as root manually.[/]"
                    )
            else:
                console.print("[yellow]Skipped docker-group fix.[/]")

    # ── Docker daemon socket ─────────────────────────────────────────
    if shutil.which("docker"):
        try:
            probe = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            probe_rc = probe.returncode
            probe_err = (probe.stderr or "") + (probe.stdout or "")
        except (subprocess.SubprocessError, OSError) as exc:
            probe_rc = 1
            probe_err = str(exc)
        # If the daemon is up but the failure is "permission denied", the
        # systemctl prompt below is the wrong fix — that's a stale-shell
        # group-membership problem and the only cure is logout/newgrp.
        is_perm = "permission denied" in probe_err.lower()
        if probe_rc != 0 and not is_perm:
            console.print()
            console.print(
                "[bold yellow]![/] Docker daemon is not responding "
                "(socket may be down)."
            )
            do_it = yes or typer.confirm(
                "Run 'sudo systemctl start docker' now?",
                default=True,
            )
            if do_it:
                cmd = (
                    ["systemctl", "start", "docker"]
                    if os.geteuid() == 0
                    else ["sudo", "systemctl", "start", "docker"]
                )
                proc = subprocess.run(cmd, capture_output=False)
                if proc.returncode == 0:
                    console.print("[bold green]✓[/] Docker daemon started.")
                else:
                    console.print(
                        f"[bold red]systemctl start docker failed (exit {proc.returncode}).[/]"
                    )
            else:
                console.print("[yellow]Skipped daemon start.[/]")
        elif probe_rc != 0 and is_perm:
            console.print()
            console.print(
                "[bold yellow]![/] Docker daemon is running, but this shell "
                "cannot reach the socket (permission denied).  This is a "
                "stale-session problem — the docker group is on disk but "
                "the current shell hasn't picked it up yet."
            )
            console.print(
                "  → [bold]Log out and log back in[/], or run "
                "[bold]'newgrp docker'[/] in this shell."
            )

    console.print("\n[bold green]Setup finished.[/]")
    if usermod_just_applied:
        console.print(
            "[bold yellow]Important:[/] you were just added to the [bold]docker[/] "
            "group.  Linux only re-evaluates group membership at LOGIN — your "
            "current shell still has the old credential set."
        )
        console.print(
            "  → Run [bold]exit[/] and SSH/log in again, or run "
            "[bold]newgrp docker[/] right now for a one-shell quick fix."
        )
    console.print("Then run [bold]crashwise doctor[/] to verify.")


# ── Pre-flight gate (T4) ──────────────────────────────────────────────────────


_REQUIRED_CHECK_NAMES: tuple[str, ...] = (
    "runtime.docker",
    "build.clang",
    "build.gcc",
)


def _run_preflight_or_exit() -> None:
    """Refuse to launch a campaign when critical dependencies are missing.

    Runs the Sentinel and inspects the subset of checks that absolutely
    must pass before any fuzzing activity is submitted to Temporal:

    * ``runtime.docker``  — without a working Docker daemon, every fuzz
      iteration's containerised execution will fail.
    * ``build.clang``     — the harness compiler.
    * ``build.gcc``       — used by the fallback compile path and by
      many target build systems.

    All other Sentinel checks (LLVM dev libs, AFL++, Temporal/Redis/LLM
    services, …) emit warnings via ``crashwise doctor`` but do not block
    a campaign; they have well-defined fallbacks (Docker worker,
    libFuzzer, mock LLM provider, etc.).
    """
    from crashwise.core.sentinel import (
        CheckStatus,
        detect_distro,
        run_all_checks,
    )

    console.print("[bold cyan]Pre-flight check (Sentinel)[/]  ", end="")
    distro_info = detect_distro()
    distro_label = (
        distro_info.pretty_name or distro_info.id_ or distro_info.family
    )
    console.print(f"[dim]({distro_label})[/]")

    try:
        report = asyncio.run(run_all_checks())
    except Exception as exc:  # broad-except — never trust the system check itself
        console.print(
            f"[bold red]Pre-flight check failed to run:[/] {exc}\n"
            "[dim]Pass --skip-preflight to bypass at your own risk.[/]"
        )
        raise typer.Exit(code=1) from exc

    blockers = [
        c
        for c in report.checks
        if c.name in _REQUIRED_CHECK_NAMES and c.status == CheckStatus.FAIL
    ]
    if not blockers:
        console.print("[bold green]✓ Pre-flight passed.[/]\n")
        return

    console.print("[bold red]✗ Pre-flight failed — campaign refused.[/]\n")
    for c in blockers:
        console.print(f"  [red]✗[/] [bold]{c.name}[/]: {c.message}")
        if c.detail:
            console.print(f"      [dim]{c.detail}[/]")
        if c.remediation:
            console.print(f"      [dim]→ {c.remediation}[/]")
    console.print(
        "\n[dim]Run [bold]crashwise doctor[/] for the full report, "
        "or [bold]crashwise setup[/] to install missing dependencies. "
        "Override with --skip-preflight at your own risk.[/]"
    )
    raise typer.Exit(code=1)


# ── Core commands ────────────────────────────────────────────────────────────


@app.command()
def run(
    target_repo: str | None = typer.Argument(None, help="Git URL of the target project (optional if crashwise.yaml present)"),
    fuzzer: FuzzerType = typer.Option(FuzzerType.LIBFUZZER, "--fuzzer", "-f"),
    timeout_seconds: int = typer.Option(300, "--timeout", "-t", min=10, max=86_400),
    branch: str | None = typer.Option(None, "--branch", "-b"),
    harness: str | None = typer.Option(None, "--harness", "-H"),
    sanitizers: str = typer.Option("address,undefined", "--sanitizers", "-s"),
    custom_flags: str | None = typer.Option(None, "--custom-flags", help="Custom AFL++ or libFuzzer flags"),
    model: str | None = typer.Option(None, "--model", help="LLM model (e.g. deepseek-chat, claude-sonnet-4-5, gpt-4o)"),
    temperature: float | None = typer.Option(None, "--temperature", help="LLM temperature (0.0 to 2.0)"),
    base_url: str | None = typer.Option(None, "--base-url", help="OpenAI-compatible base URL (e.g. https://api.deepseek.com)"),
    api_key: str | None = typer.Option(None, "--api-key", help="LLM API key"),
    reasoning_effort: str | None = typer.Option(None, "--reasoning-effort", help="Reasoning effort ('low', 'medium', 'high')"),
    max_synth_retries: int = typer.Option(4, "--max-synth-retries", help="Max harness synthesis retry attempts"),
    enable_mab: bool = typer.Option(False, "--mab", help="Enable Multi-Armed Bandit strategy switching"),
    mab_algorithm: str = typer.Option("thompson", "--mab-algorithm", help="MAB algorithm ('thompson' or 'ucb1')"),
    enable_self_healing: bool = typer.Option(False, "--self-healing", help="Enable autonomous build & patch repair agent"),
    max_repair_attempts: int = typer.Option(10, "--max-repair-attempts", help="Max healing agent iterations"),
    host: str | None = typer.Option(None, "--host"),
    namespace: str | None = typer.Option(None, "--namespace"),
    task_queue: str | None = typer.Option(None, "--task-queue"),
    name: str | None = typer.Option(None, "--name", help="Target name or identifier"),
    subdir: str | None = typer.Option(None, "--subdir", "--target-subdir", help="Subdirectory inside repo to target"),
    clone_depth: int = typer.Option(1, "--clone-depth", help="Git clone depth (0 for full clone)", min=0),
    manifest: Path | None = typer.Option(None, "--manifest", help="Path to crashwise.yaml"),
    skip_preflight: bool = typer.Option(
        False,
        "--skip-preflight",
        help=(
            "Skip the Sentinel pre-flight check. NOT recommended — only "
            "use when you know the host is configured (e.g. inside the "
            "Dockerised worker)."
        ),
    ),
    detach: bool = typer.Option(
        False,
        "--detach",
        "-d",
        help="Submit the workflow and exit immediately (print workflow ID).",
    ),
) -> None:
    """Submit a :class:`MainFuzzingWorkflow` and print the result.

    If ``target_repo`` is omitted, CrashWise searches for ``crashwise.yaml``
    in the current directory and uses it as the configuration source.

    Pre-flight gate (T4)
    --------------------
    Before any workflow is submitted, the Sentinel runs a fast subset of
    its checks (Docker daemon, Clang, GCC). If any of these critical
    dependencies is missing, the campaign is refused with an actionable
    remediation hint instead of crashing five minutes later inside a
    Temporal activity. Use ``--skip-preflight`` to override.
    """
    configure_logging()

    # ── Pre-flight gate ───────────────────────────────────────────────
    if not skip_preflight:
        _run_preflight_or_exit()

    # Zero-config: load from manifest if target_repo not provided.
    if target_repo is None:
        manifest_obj = load_manifest_or_none(manifest)
        if manifest_obj is None:
            console.print("[bold red]No target_repo provided and no crashwise.yaml found.[/]")
            console.print("Run [bold]crashwise init[/] to create a manifest, or provide a Git URL.")
            raise typer.Exit(code=1)
        console.print("[bold cyan]Loaded manifest:[/] crashwise.yaml")
        target_repo = str(manifest_obj.project.repo_url or "")
        if not target_repo:
            console.print("[bold red]Manifest does not specify project.repo_url.[/]")
            raise typer.Exit(code=1)
        # Override CLI options with manifest values.
        fuzzer = _fuzzer_from_string(manifest_obj.fuzzing.fuzzer) or fuzzer
        timeout_seconds = manifest_obj.fuzzing.timeout_seconds or timeout_seconds
        harness = harness or (manifest_obj.build.harness_path or None)
        sanitizers = manifest_obj.fuzzing.sanitizers or sanitizers
        console.print(f"  Project: [green]{manifest_obj.project.name}[/] ({manifest_obj.project.language})")
        console.print(f"  Build:   [green]{manifest_obj.build.system}[/]")

    payload_dict: dict[str, Any] = {
        "target_repo": target_repo,
        "target_name": name,
        "target_subdir": subdir,
        "target_clone_depth": clone_depth,
        "fuzzer_type": fuzzer,
        "timeout_seconds": timeout_seconds,
        "target_branch": branch,
        "harness_path": harness,
        "sanitizers": sanitizers,
        "custom_fuzzer_flags": custom_flags,
        "llm_model": model,
        "llm_temperature": temperature,
        "llm_base_url": base_url,
        "llm_api_key": api_key,
        "reasoning_effort": reasoning_effort,
        "max_synth_retries": max_synth_retries,
        "enable_mab": enable_mab,
        "mab_algorithm": mab_algorithm,
        "enable_self_healing": enable_self_healing,
        "healing_max_attempts": max_repair_attempts,
    }
    payload = FuzzingInput.model_validate(payload_dict)
    console.print("[bold cyan]Submitting MainFuzzingWorkflow[/]")
    console.print(JSON(payload.model_dump_json(indent=2)))

    api_url = os.environ.get("CRASHWISE_API_URL") or get_settings().crashwise_api_url

    # Try submitting via the API (creates campaign record + starts workflow).
    async def _submit_via_api() -> tuple[str, str] | None:
        import httpx

        target_name = name or target_repo.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    f"{api_url}/campaigns/start",
                    json={
                        "target_repo": target_repo,
                        "target_name": target_name,
                        "target_subdir": subdir,
                        "target_clone_depth": clone_depth,
                        "fuzzer_type": fuzzer.value,
                        "timeout_seconds": timeout_seconds,
                        "target_branch": branch,
                        "harness_path": harness,
                        "sanitizers": sanitizers,
                        "custom_fuzzer_flags": custom_flags,
                        "llm_model": model,
                        "llm_temperature": temperature,
                        "llm_base_url": base_url,
                        "llm_api_key": api_key,
                        "reasoning_effort": reasoning_effort,
                        "max_synth_retries": max_synth_retries,
                        "enable_mab": enable_mab,
                        "mab_algorithm": mab_algorithm,
                        "enable_self_healing": enable_self_healing,
                        "healing_max_attempts": max_repair_attempts,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return str(data["campaign_id"]), data["workflow_id"]
        except Exception:
            return None

    # Fall back to direct Temporal submission (no campaign record in dashboard).
    async def _submit_direct() -> str:
        client = await connect(host=host, namespace=namespace)
        handle = await start_main_workflow(client, payload, task_queue=task_queue)
        return handle.id

    # Submit
    api_result = asyncio.run(_submit_via_api())
    if api_result:
        campaign_id, workflow_id = api_result
        console.print(f"[bold green]Campaign created:[/] {campaign_id}")
        console.print(f"[bold green]Workflow started:[/] {workflow_id}")
    else:
        try:
            workflow_id = asyncio.run(_submit_direct())
            console.print(f"[bold green]Workflow submitted (direct):[/] {workflow_id}")
            console.print("[dim]API unreachable — campaign won't appear in dashboard.[/]")
        except TemporalConnectionError as exc:
            console.print(f"[bold red]Temporal connection failed:[/] {exc}")
            raise typer.Exit(code=1) from exc

    if detach:
        console.print(f"Use [bold]crashwise signal {workflow_id} <signal>[/] to control it.")
    else:
        console.print(f"\n[bold cyan]⏳ Workflow running...[/] (timeout: {timeout_seconds}s)")
        console.print("[dim]Waiting for result. Use --detach to submit and exit immediately.[/]\n")
        try:
            async def _await_result() -> FuzzingOutput:

                client = await connect(host=host, namespace=namespace)
                handle = client.get_workflow_handle(workflow_id)
                return cast(FuzzingOutput, await handle.result())

            result = asyncio.run(_await_result())
            console.print("[bold green]✓ Workflow complete![/]")
            import json as _json
            data = result.model_dump_json(indent=2) if hasattr(result, "model_dump_json") else _json.dumps(result, indent=2, default=str)
            console.print(JSON(data))
        except TemporalConnectionError as exc:
            console.print(f"[bold red]Temporal connection failed:[/] {exc}")
            raise typer.Exit(code=1) from exc
        except Exception as exc:
            console.print(f"[bold red]Workflow failed:[/] {exc}")
            raise typer.Exit(code=1) from exc


def _fuzzer_from_string(value: str) -> FuzzerType | None:
    """Map manifest fuzzer string to FuzzerType enum."""
    mapping = {
        "libfuzzer": FuzzerType.LIBFUZZER,
        "afl++": FuzzerType.AFLPP,
        "honggfuzz": FuzzerType.HONGGFUZZ,
    }
    return mapping.get(value.lower())


@app.command()
def worker(
    host: str | None = typer.Option(None, "--host", help="Temporal host:port"),
    namespace: str | None = typer.Option(None, "--namespace", help="Temporal namespace"),
    task_queue: str | None = typer.Option(None, "--task-queue", help="Task queue name"),
) -> None:
    """Run a CrashWise Temporal worker (blocks until SIGINT/SIGTERM)."""
    configure_logging()
    try:
        asyncio.run(run_worker(host=host, namespace=namespace, task_queue=task_queue))
    except TemporalConnectionError as exc:
        console.print(f"[bold red]Temporal connection failed:[/] {exc}")
        raise typer.Exit(code=1) from exc


# ── Service commands ───────────────────────────────────────────────────────────


@app.command()
def api(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes"),
    workers: int = typer.Option(1, "--workers", "-w", help="Uvicorn worker processes"),
) -> None:
    """Launch the FastAPI management server."""
    configure_logging()
    log.info("api.starting", host=host, port=port, reload=reload, workers=workers)
    uvicorn.run(
        "crashwise.api.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,
        log_level=get_settings().log_level.lower(),
    )


@app.command()
def dashboard(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8501, "--port", "-p", help="Bind port"),
    api_url: str | None = typer.Option(
        None, "--api-url", help="Base URL for the management API"
    ),
) -> None:
    """Launch the Streamlit intelligence dashboard."""
    configure_logging()
    dashboard_path = Path(__file__).parent / "dashboard" / "app.py"
    if not dashboard_path.exists():
        console.print(f"[bold red]Dashboard not found:[/] {dashboard_path}")
        raise typer.Exit(code=1)

    env = os.environ.copy()
    if api_url:
        env["CRASHWISE_API_URL"] = api_url

    log.info("dashboard.starting", host=host, port=port, api_url=api_url)
    cmd = [
        sys.executable, "-m", "streamlit", "run", str(dashboard_path),
        "--server.address", host,
        "--server.port", str(port),
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
    ]
    subprocess.run(cmd, env=env, check=False)


@app.command()
def signal(
    workflow_id: str = typer.Argument(..., help="Temporal workflow ID of the live campaign"),
    signal_type: str = typer.Argument(
        ...,
        help="One of: force_pivot | inject_seed | pause_hunt | resume_hunt",
    ),
    data: str = typer.Option(
        "",
        "--data",
        "-d",
        help=(
            "Signal payload. force_pivot: free-text reason. "
            "inject_seed: 'filename=PATH' (file is read and base64-encoded). "
            "pause_hunt / resume_hunt: ignored."
        ),
    ),
    host: str | None = typer.Option(None, "--host"),
    namespace: str | None = typer.Option(None, "--namespace"),
) -> None:
    """Send a God-Mode signal to a running campaign workflow.

    Examples
    --------
    \b
    crashwise signal crashwise-abc123 force_pivot --data "JXL plateau"
    crashwise signal crashwise-abc123 inject_seed --data "filename=/tmp/poc.jxl"
    crashwise signal crashwise-abc123 pause_hunt
    crashwise signal crashwise-abc123 resume_hunt
    """
    configure_logging()
    from crashwise.orchestration.client import connect

    valid = {"force_pivot", "inject_seed", "pause_hunt", "resume_hunt"}
    if signal_type not in valid:
        console.print(
            f"[bold red]Unknown signal type:[/] {signal_type}. "
            f"Valid: {', '.join(sorted(valid))}"
        )
        raise typer.Exit(code=2)

    async def _send() -> None:
        try:
            client = await connect(host=host, namespace=namespace)
        except TemporalConnectionError as exc:
            console.print(f"[bold red]Temporal connection failed:[/] {exc}")
            raise typer.Exit(code=1) from exc

        handle = client.get_workflow_handle(workflow_id)

        if signal_type == "force_pivot":
            reason = data or "operator request"
            await handle.signal("force_pivot", reason)
            console.print(
                f"[bold green]Signal sent:[/] force_pivot — reason={reason!r}"
            )
        elif signal_type == "inject_seed":
            # Parse ``filename=PATH`` (the only supported form for now).
            if not data.startswith("filename="):
                console.print(
                    "[bold red]inject_seed requires --data 'filename=PATH'[/]"
                )
                raise typer.Exit(code=2)
            seed_path = Path(data.removeprefix("filename=")).expanduser().resolve()
            if not seed_path.is_file():
                console.print(f"[bold red]Seed file not found:[/] {seed_path}")
                raise typer.Exit(code=2)
            import base64

            raw = seed_path.read_bytes()
            payload = {
                "filename": seed_path.name,
                "data_b64": base64.b64encode(raw).decode("ascii"),
            }
            await handle.signal("inject_seed", payload)
            console.print(
                f"[bold green]Signal sent:[/] inject_seed — "
                f"file={seed_path.name} ({len(raw)} bytes)"
            )
        elif signal_type == "pause_hunt":
            await handle.signal("pause_hunt", True)
            console.print("[bold green]Signal sent:[/] pause_hunt — campaign will pause")
        else:  # resume_hunt
            await handle.signal("pause_hunt", False)
            console.print("[bold green]Signal sent:[/] resume_hunt — campaign will resume")

        # Best-effort: read back operator notes via query so the user sees
        # the workflow has acknowledged the signal.
        try:
            notes = await handle.query("operator_notes")
            if notes:
                console.print("[dim]Recent operator notes:[/]")
                for n in notes[-5:]:
                    console.print(f"  • {n}")
        except Exception as exc:  # broad-except — diagnostic only
            log.debug("signal.query_skipped", error=str(exc))

    try:
        asyncio.run(_send())
    except typer.Exit:
        raise
    except Exception as exc:  # broad-except
        console.print(f"[bold red]Signal delivery failed:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def exploit(
    crash_id: str = typer.Argument(..., help="Database UUID of the crash"),
    verify: bool = typer.Option(False, "--verify", "-v", help="Compile and verify the PoC"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write PoC to file"),
) -> None:
    """Generate a standalone PoC exploit for a confirmed crash.

    Looks up the crash in the database, runs the Exploit Architect agent,
    and optionally compiles + verifies the generated PoC.
    """
    configure_logging()
    from uuid import UUID

    from crashwise.agents.triage.exploit_gen import generate_exploit
    from crashwise.agents.triage.models import CrashReport
    from crashwise.core.database import Crash, get_session
    from crashwise.orchestration.activities.verify_poc import verify_poc

    async def _generate() -> None:
        async with get_session() as session:
            crash = await session.get(Crash, UUID(crash_id))
            if crash is None:
                console.print(f"[bold red]Crash not found:[/] {crash_id}")
                raise typer.Exit(code=1)

            console.print(f"[bold cyan]Generating PoC for crash {crash_id}[/]")
            console.print(f"  Type: {crash.crash_type}")
            console.print(f"  Signal: {crash.signal}")

            # Build CrashReport from DB record.
            report = CrashReport(
                crash_id=crash_id,
                raw_text=crash.stack_trace,
                signal=crash.signal,
                asan_output=crash.stack_trace,
            )

            result = await generate_exploit(report, target_func="")

            console.print(f"\n[bold green]Primitive:[/] {result.primitive}")
            console.print(f"[bold green]Reachability:[/] {result.reachability.value} ({result.reachability_score}/10)")
            console.print(f"[bold green]Confidence:[/] {result.confidence}")
            if result.notes:
                console.print(f"[bold green]Notes:[/] {result.notes}")

            # Write to file or stdout.
            if output:
                output.write_text(result.poc_code, encoding="utf-8")
                console.print(f"\n[bold green]PoC written to:[/] {output}")
            else:
                console.print("\n[bold green]Generated PoC:[/]")
                console.print(result.poc_code)

            # Update DB with PoC metadata.
            crash.poc_code = result.poc_code
            crash.reachability = result.reachability.value
            crash.reachability_score = result.reachability_score
            crash.primitive = result.primitive
            await session.commit()

            # Optional verification.
            if verify and result.poc_code:
                console.print("\n[bold cyan]Verifying PoC...[/]")
                from crashwise.core.models import PocVerifyInput

                verify_result = await verify_poc(
                    PocVerifyInput(
                        crash_id=crash_id,
                        poc_code=result.poc_code,
                        compilation_command=result.compilation_command,
                        expected_signal=crash.signal or "SIGSEGV",
                        expected_asan_pattern=crash.crash_type,
                    )
                )

                crash.poc_compiled = verify_result.compiled
                crash.poc_verified = verify_result.crash_reproduced
                await session.commit()

                if verify_result.compiled:
                    console.print("[bold green]Compilation:[/] OK")
                else:
                    console.print("[bold red]Compilation:[/] FAILED")
                    console.print(f"  {verify_result.stderr[:500]}")

                if verify_result.crash_reproduced:
                    console.print(f"[bold green]Crash reproduced:[/] YES ({verify_result.signal_received})")
                else:
                    console.print("[bold yellow]Crash reproduced:[/] NO")

    try:
        asyncio.run(_generate())
    except Exception as exc:
        console.print(f"[bold red]PoC generation failed:[/] {exc}")
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":  # pragma: no cover
    app()
