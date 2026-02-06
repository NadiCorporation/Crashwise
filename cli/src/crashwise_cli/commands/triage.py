"""
LLM-powered crash log triage for Crashwise findings.

Analyzes, clusters, and summarizes fuzzing crash logs using LLM.
Uses llm_resolver for all LLM calls (enforces OAuth + policy).

Examples:
    cw findings triage <run-id>                    # Basic triage
    cw findings triage <run-id> --provider openai_codex  # Use specific provider
    cw findings triage <run-id> --format markdown  # Markdown report
    cw findings triage <run-id> --format sarif     # SARIF output
"""

from __future__ import annotations

import json
import re
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..llm_resolver import get_llm_client, PolicyViolationError, LLMResolverError
from ..exceptions import CrashwiseError
from ..database import get_project_db

console = Console()


@dataclass
class Crash:
    """Represents a single crash/finding."""

    id: str
    type: str  # ASAN, UBSAN, assertion, etc.
    raw_log: str
    sanitizer_output: Optional[str] = None
    stack_trace: Optional[List[str]] = None
    source_location: Optional[str] = None

    def get_signature(self) -> str:
        """Generate crash signature for clustering."""
        # Use sanitizer type + top 3 stack frames
        parts = [self.type]
        if self.stack_trace and len(self.stack_trace) >= 3:
            parts.extend(self.stack_trace[:3])
        elif self.sanitizer_output:
            # Extract first line of sanitizer output
            first_line = self.sanitizer_output.split("\n")[0][:100]
            parts.append(first_line)

        sig = "|".join(parts)
        return hashlib.sha1(sig.encode()).hexdigest()[:16]


@dataclass
class CrashCluster:
    """Cluster of similar crashes."""

    signature: str
    crashes: List[Crash]
    representative: Crash
    summary: Optional[str] = None
    severity: Optional[str] = None
    root_cause: Optional[str] = None

    def count(self) -> int:
        return len(self.crashes)


def parse_crash_log(log_content: str) -> Crash:
    """Parse crash log and extract structured information.

    Supports:
    - AddressSanitizer (ASAN)
    - UndefinedBehaviorSanitizer (UBSAN)
    - Assertion failures
    - Python exceptions (Atheris)
    - Rust panics (cargo-fuzz)
    """
    crash_type = "unknown"
    sanitizer_output = None
    stack_trace = []
    source_location = None

    # Detect ASAN
    if "ERROR: AddressSanitizer:" in log_content:
        crash_type = "ASAN"
        # Extract ASAN error message
        match = re.search(r"ERROR: AddressSanitizer:.*?\n", log_content)
        if match:
            sanitizer_output = match.group(0).strip()

        # Extract stack trace
        stack_match = re.findall(r"#\d+ 0x[0-9a-f]+ in (.*?)\n", log_content)
        stack_trace = stack_match[:10]  # Top 10 frames

        # Extract source location
        loc_match = re.search(r"([\w/.-]+\.\w+):(\d+):(\d+)", log_content)
        if loc_match:
            source_location = loc_match.group(0)

    # Detect UBSAN
    elif "runtime error:" in log_content:
        crash_type = "UBSAN"
        match = re.search(r"runtime error:.*?\n", log_content)
        if match:
            sanitizer_output = match.group(0).strip()

    # Detect Python/Atheris exceptions
    elif "Traceback (most recent call last):" in log_content:
        crash_type = "python_exception"
        lines = log_content.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("  File "):
                stack_trace.append(line.strip())
            elif i > 0 and lines[i - 1].startswith("  File ") and line.strip():
                stack_trace.append(line.strip())
                break

    # Detect Rust panics
    elif "thread 'main' panicked at" in log_content or "panicked at" in log_content:
        crash_type = "rust_panic"
        match = re.search(r"panicked at.*?'(.*?)'", log_content)
        if match:
            sanitizer_output = match.group(0)

    # Detect assertion failures
    elif "Assertion" in log_content and "failed" in log_content:
        crash_type = "assertion"
        match = re.search(r"Assertion.*?failed.*", log_content)
        if match:
            sanitizer_output = match.group(0)

    crash_id = hashlib.md5(log_content[:500].encode()).hexdigest()[:12]

    return Crash(
        id=crash_id,
        type=crash_type,
        raw_log=log_content,
        sanitizer_output=sanitizer_output,
        stack_trace=stack_trace if stack_trace else None,
        source_location=source_location,
    )


def cluster_crashes(crashes: List[Crash]) -> List[CrashCluster]:
    """Cluster crashes by signature."""
    clusters: Dict[str, CrashCluster] = {}

    for crash in crashes:
        sig = crash.get_signature()

        if sig not in clusters:
            clusters[sig] = CrashCluster(
                signature=sig, crashes=[crash], representative=crash
            )
        else:
            clusters[sig].crashes.append(crash)

    return list(clusters.values())


def sanitize_for_llm(text: str, max_length: int = 4000) -> str:
    """Sanitize crash log for LLM processing.

    - Truncates if too long
    - Removes potential PII (IPs, emails, usernames, paths)
    - Masks obvious secrets/tokens
    - Keeps essential crash info
    """
    # Remove potential PII patterns
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]", text)
    text = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL]", text
    )
    # Mask common home directory paths
    text = re.sub(r"/(home|Users)/[^\s]+", "/[REDACTED_PATH]", text)
    # Mask obvious secrets in key=value forms
    text = re.sub(
        r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        text,
    )
    # Mask long hex-like strings
    text = re.sub(r"\b[a-fA-F0-9]{32,}\b", "[HEX]", text)

    # Truncate if needed
    if len(text) > max_length:
        text = text[:max_length] + "\n[... truncated ...]"

    return text


def _request_llm_completion(llm_config: Dict[str, Any], prompt: str) -> str:
    """Call LLM endpoint with basic retry/backoff.

    Raises on final failure; does not log secrets.
    """
    import urllib.request
    import urllib.error
    import time

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {llm_config['api_key']}",
    }

    data = {
        "model": f"{llm_config['provider']}/{llm_config['model']}",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 500,
    }

    base_url = llm_config.get("base_url") or "https://api.openai.com/v1"
    url = f"{base_url}/chat/completions"

    max_retries = 3
    backoff = 2

    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                url, data=json.dumps(data).encode(), headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=60) as response:
                result = json.loads(response.read().decode())
                return result["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                time.sleep(backoff ** attempt)
                continue
            raise
        except urllib.error.URLError:
            if attempt < max_retries:
                time.sleep(backoff ** attempt)
                continue
            raise

    raise RuntimeError("LLM request failed after retries")


def analyze_cluster_with_llm(
    cluster: CrashCluster, provider: Optional[str] = None, model: Optional[str] = None
) -> CrashCluster:
    """Use LLM to analyze crash cluster and generate summary.

    Args:
        cluster: Crash cluster to analyze
        provider: LLM provider (uses resolver if not specified)
        model: LLM model (uses resolver if not specified)

    Returns:
        Cluster with summary, severity, root_cause populated

    Raises:
        PolicyViolationError: If provider usage blocked by policy
        LLMResolverError: If LLM client cannot be created
    """
    # Get LLM configuration through resolver (enforces OAuth + policy)
    try:
        llm_config = get_llm_client(provider=provider, model=model)
    except PolicyViolationError as e:
        console.print(f"[red]Policy violation: {e}[/red]")
        raise
    except LLMResolverError as e:
        console.print(f"[red]LLM configuration error: {e}[/red]")
        raise

    # Sanitize crash log
    safe_log = sanitize_for_llm(cluster.representative.raw_log)

    # Build prompt
    prompt = f"""You are a security researcher analyzing a fuzzing crash. Analyze this crash log and provide:

1. SUMMARY: A concise 1-2 sentence description of what caused the crash
2. SEVERITY: Rate as CRITICAL, HIGH, MEDIUM, or LOW based on security impact
3. ROOT_CAUSE: The likely underlying vulnerability or bug

Crash Type: {cluster.representative.type}
Stack Trace (if available): {cluster.representative.stack_trace or "N/A"}

Crash Log:
```
{safe_log}
```

Respond in this exact format:
SUMMARY: <your summary>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
ROOT_CAUSE: <your analysis>"""

    # Call LLM (implementation depends on provider)
    # For now, we'll use a simple HTTP request to LiteLLM-compatible endpoint
    try:
        content = _request_llm_completion(llm_config, prompt)

        # Parse response
        summary_match = re.search(
            r"SUMMARY:\s*(.+?)(?=\nSEVERITY:|$)", content, re.DOTALL
        )
        severity_match = re.search(r"SEVERITY:\s*(\w+)", content)
        root_cause_match = re.search(r"ROOT_CAUSE:\s*(.+?)(?=\n|$)", content, re.DOTALL)

        cluster.summary = (
            summary_match.group(1).strip()
            if summary_match
            else "Unable to generate summary"
        )
        cluster.severity = (
            severity_match.group(1).strip().upper() if severity_match else "UNKNOWN"
        )
        cluster.root_cause = (
            root_cause_match.group(1).strip() if root_cause_match else "Unknown"
        )

    except Exception as e:
        console.print(f"[yellow]Warning: LLM analysis failed: {e}[/yellow]")
        cluster.summary = "LLM analysis failed"
        cluster.severity = "UNKNOWN"
        cluster.root_cause = str(e)

    return cluster


def export_markdown(clusters: List[CrashCluster], output_path: Path) -> None:
    """Export clusters to Markdown report."""
    with open(output_path, "w") as f:
        f.write("# Crashwise Crash Triage Report\n\n")
        f.write(f"Total Clusters: {len(clusters)}\n")
        f.write(f"Total Crashes: {sum(c.count() for c in clusters)}\n\n")

        for i, cluster in enumerate(clusters, 1):
            f.write(f"## Cluster {i}: {cluster.signature}\n\n")
            f.write(f"- **Crash Count:** {cluster.count()}\n")
            f.write(f"- **Type:** {cluster.representative.type}\n")
            f.write(f"- **Severity:** {cluster.severity or 'Unknown'}\n\n")

            if cluster.summary:
                f.write(f"**Summary:** {cluster.summary}\n\n")

            if cluster.root_cause:
                f.write(f"**Root Cause:** {cluster.root_cause}\n\n")

            if cluster.representative.source_location:
                f.write(f"**Location:** {cluster.representative.source_location}\n\n")

            f.write("---\n\n")


def export_sarif(clusters: List[CrashCluster], output_path: Path, run_id: str) -> None:
    """Export clusters to SARIF format."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "Crashwise Crash Triage", "version": "1.0.0"}
                },
                "results": [],
            }
        ],
    }

    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "UNKNOWN": "warning",
    }

    for cluster in clusters:
        result = {
            "ruleId": f"crashwise.crash.{cluster.representative.type}",
            "message": {
                "text": cluster.summary or f"Crash cluster: {cluster.signature}"
            },
            "level": severity_map.get(cluster.severity or "UNKNOWN", "warning"),
            "properties": {
                "crashCount": cluster.count(),
                "crashType": cluster.representative.type,
                "severity": cluster.severity or "UNKNOWN",
                "rootCause": cluster.root_cause or "Unknown",
            },
        }

        if cluster.representative.source_location:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": cluster.representative.source_location
                        }
                    }
                }
            ]

        sarif["runs"][0]["results"].append(result)

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


def triage(
    run_id: str,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    format: str = "table",
    output: Optional[Path] = None,
    skip_llm: bool = False,
) -> None:
    """Triage crashes from a workflow run.

    Args:
        run_id: Workflow run ID to analyze
        provider: LLM provider (optional, uses config default)
        model: LLM model (optional, uses config default)
        format: Output format (table, markdown, sarif)
        output: Output file path (optional)
        skip_llm: Skip LLM analysis, just cluster
    """
    console.print(
        Panel.fit(
            f"[bold cyan]🔍 Crash Triage: Run {run_id}[/bold cyan]", border_style="cyan"
        )
    )

    # Load crashes from database
    db = get_project_db()
    if not db:
        raise CrashwiseError("No project database found", hint="Run 'cw init' first")

    # Get findings for this run
    findings = db.get_findings(run_id)
    if not findings:
        console.print(f"[yellow]No findings found for run {run_id}[/yellow]")
        return

    # Parse crashes
    crashes: List[Crash] = []

    def _append_log(log_content: Optional[str]) -> None:
        if not log_content:
            return
        crash = parse_crash_log(log_content)
        crashes.append(crash)

    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                _append_log(finding.get("log") or finding.get("details") or finding.get("message"))
    else:
        # FindingRecord from DB (SARIF-based)
        sarif_data = getattr(findings, "sarif_data", {}) or {}
        for run in sarif_data.get("runs", []) or []:
            for result in run.get("results", []) or []:
                message = (result.get("message") or {}).get("text")
                details = (result.get("properties") or {}).get("details")
                _append_log(details or message)

    # Also include crash records if present
    try:
        crash_records = db.get_crashes(run_id)
    except Exception:
        crash_records = []

    for record in crash_records:
        _append_log(record.stack_trace or record.signal or "")

    if not crashes:
        console.print("[yellow]No crash logs found to analyze[/yellow]")
        return

    console.print(f"Found {len(crashes)} crashes")

    # Cluster crashes
    clusters = cluster_crashes(crashes)
    console.print(f"Grouped into {len(clusters)} clusters")

    # LLM analysis (if not skipped)
    if not skip_llm:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Analyzing clusters with LLM...", total=len(clusters)
            )

            for cluster in clusters:
                try:
                    analyze_cluster_with_llm(cluster, provider, model)
                except (PolicyViolationError, LLMResolverError) as e:
                    console.print(f"[red]Failed to analyze cluster: {e}[/red]")
                    cluster.summary = "Analysis blocked by policy"
                    cluster.severity = "UNKNOWN"
                    cluster.root_cause = str(e)
                progress.advance(task)

    # Output results
    if format == "table":
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Cluster", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Count", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Summary", style="white")

        for i, cluster in enumerate(clusters, 1):
            table.add_row(
                f"#{i}",
                cluster.representative.type,
                str(cluster.count()),
                cluster.severity or "-",
                (cluster.summary or "-")[:50] + "..."
                if cluster.summary and len(cluster.summary) > 50
                else (cluster.summary or "-"),
            )

        console.print(table)

    elif format == "markdown":
        output_path = output or Path(f"triage-{run_id}.md")
        export_markdown(clusters, output_path)
        console.print(f"[green]Markdown report saved to {output_path}[/green]")

    elif format == "sarif":
        output_path = output or Path(f"triage-{run_id}.sarif")
        export_sarif(clusters, output_path, run_id)
        console.print(f"[green]SARIF report saved to {output_path}[/green]")

    # Summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total clusters: {len(clusters)}")
    console.print(f"  Total crashes: {sum(c.count() for c in clusters)}")

    if not skip_llm:
        severities = {}
        for c in clusters:
            sev = c.severity or "UNKNOWN"
            severities[sev] = severities.get(sev, 0) + c.count()

        console.print(f"\n[bold]By Severity:[/bold]")
        for sev, count in sorted(severities.items()):
            color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(sev, "white")
            console.print(f"  [{color}]{sev}: {count}[/{color}]")
