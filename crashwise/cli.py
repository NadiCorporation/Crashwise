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
* ``crashwise setup``     — Auto-install missing build tools (Debian/Ubuntu).
* ``crashwise run``       — Submit a fuzzing workflow.
* ``crashwise worker``    — Start a Temporal worker.
* ``crashwise api``       — Launch the FastAPI management server.
* ``crashwise dashboard`` — Launch the Streamlit intelligence dashboard.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import typer
import uvicorn
from rich.console import Console
from rich.json import JSON

from crashwise import __version__
from crashwise.core.config import get_settings
from crashwise.core.database import close_db, init_db
from crashwise.core.logging import configure_logging, get_logger
from crashwise.core.manifest import CrashwiseManifest, load_manifest_or_none
from crashwise.core.models import FuzzerType, FuzzingInput
from crashwise.orchestration.client import (
    TemporalConnectionError,
    execute_main_workflow,
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
    from crashwise.core.database import close_db, init_db
    from crashwise.core.discovery import discover_project
    from crashwise.core.manifest import CrashwiseManifest, MANIFEST_FILENAME

    target_dir = target_dir.resolve()
    if not target_dir.is_dir():
        console.print(f"[bold red]Not a directory:[/] {target_dir}")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]CrashWise Project Initialisation[/]")
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
    await init_db(drop_all=drop_all)
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
        generate_setup_script,
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
) -> None:
    """Auto-install missing build tools on Debian/Ubuntu.

    Runs ``apt-get`` commands to install packages identified by ``doctor``.
    Use ``--dry-run`` to preview the script without executing it.
    """
    from crashwise.core.sentinel import (
        generate_setup_script,
        get_missing_packages,
        run_all_checks,
    )

    configure_logging()
    console.print("[bold cyan]CrashWise Provisioner[/]")
    console.print("Analysing system requirements...\n")

    report = asyncio.run(run_all_checks())
    missing = get_missing_packages(report)

    if not missing:
        console.print("[bold green]All required packages are already installed.[/]")
        return

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

    # Execute the script
    console.print(f"[bold]Installing {len(missing)} packages:[/] {', '.join(missing)}")
    console.print("[dim]This may take a few minutes...[/]\n")

    try:
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=False,
            text=True,
        )
        if proc.returncode == 0:
            console.print("\n[bold green]Setup complete![/]")
        else:
            console.print(f"\n[bold red]Setup failed with exit code {proc.returncode}.[/]")
            raise typer.Exit(code=proc.returncode)
    except FileNotFoundError:
        console.print("[bold red]bash not found. Cannot execute setup script.[/]")
        raise typer.Exit(code=1)


# ── Core commands ────────────────────────────────────────────────────────────


@app.command()
def run(
    target_repo: str | None = typer.Argument(None, help="Git URL of the target project (optional if crashwise.yaml present)"),
    fuzzer: FuzzerType = typer.Option(FuzzerType.LIBFUZZER, "--fuzzer", "-f"),
    timeout_seconds: int = typer.Option(60, "--timeout", "-t", min=10, max=86_400),
    branch: str | None = typer.Option(None, "--branch", "-b"),
    harness: str | None = typer.Option(None, "--harness", "-H"),
    sanitizers: str = typer.Option("address,undefined", "--sanitizers", "-s"),
    host: str | None = typer.Option(None, "--host"),
    namespace: str | None = typer.Option(None, "--namespace"),
    task_queue: str | None = typer.Option(None, "--task-queue"),
    manifest: Path | None = typer.Option(None, "--manifest", "-m", help="Path to crashwise.yaml"),
) -> None:
    """Submit a :class:`MainFuzzingWorkflow` and print the result.

    If ``target_repo`` is omitted, CrashWise searches for ``crashwise.yaml``
    in the current directory and uses it as the configuration source.
    """
    configure_logging()

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

    payload = FuzzingInput.model_validate(
        {
            "target_repo": target_repo,
            "fuzzer_type": fuzzer,
            "timeout_seconds": timeout_seconds,
            "target_branch": branch,
            "harness_path": harness,
            "sanitizers": sanitizers,
        }
    )
    console.print("[bold cyan]Submitting MainFuzzingWorkflow[/]")
    console.print(JSON(payload.model_dump_json(indent=2)))

    try:
        result = asyncio.run(
            execute_main_workflow(
                payload,
                host=host,
                namespace=namespace,
                task_queue=task_queue,
            )
        )
    except TemporalConnectionError as exc:
        console.print(f"[bold red]Temporal connection failed:[/] {exc}")
        raise typer.Exit(code=1) from exc

    console.print("[bold green]Workflow result:[/]")
    console.print(JSON(result.model_dump_json(indent=2)))


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
                stack_trace=crash.stack_trace,
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
                    console.print(f"[bold green]Compilation:[/] OK")
                else:
                    console.print(f"[bold red]Compilation:[/] FAILED")
                    console.print(f"  {verify_result.stderr[:500]}")

                if verify_result.crash_reproduced:
                    console.print(f"[bold green]Crash reproduced:[/] YES ({verify_result.signal_received})")
                else:
                    console.print(f"[bold yellow]Crash reproduced:[/] NO")

    try:
        asyncio.run(_generate())
    except Exception as exc:
        console.print(f"[bold red]PoC generation failed:[/] {exc}")
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":  # pragma: no cover
    app()
