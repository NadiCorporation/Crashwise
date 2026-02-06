# Crashwise CLI Reference

Complete reference for the Crashwise CLI (`cw` command). Use this as your quick lookup for all commands, options, and examples.

---

## Global Options

| Option | Description |
|--------|-------------|
| `--help`, `-h` | Show help message |
| `--version`, `-v` | Show version information |

---

## Core Commands

### `cw init`

Initialize a new Crashwise project in the current directory.

**Usage:**
```bash
cw init [OPTIONS]
```

**Options:**
- `--name`, `-n` — Project name (defaults to current directory name)
- `--api-url`, `-u` — Crashwise API URL (defaults to http://localhost:8000)
- `--force`, `-f` — Force initialization even if project already exists

**Examples:**
```bash
cw init                           # Initialize with defaults
cw init --name my-project         # Set custom project name
cw init --api-url http://prod:8000  # Use custom API URL
```

---

### `cw status`

Show project and latest execution status.

**Usage:**
```bash
cw status
```

**Example Output:**
```
📊 Project Status
   Project: my-security-project
   API URL: http://localhost:8000

Latest Execution:
   Run ID: security_scan-a1b2c3
   Workflow: security_assessment
   Status: COMPLETED
   Started: 2 hours ago
```

---

### `cw config`

Manage project configuration.

**Usage:**
```bash
cw config                    # Show all config
cw config <key>              # Get specific value
cw config <key> <value>      # Set value
```

**Examples:**
```bash
cw config                         # Display all settings
cw config api_url                 # Get API URL
cw config api_url http://prod:8000  # Set API URL
```

---

### `cw clean`

Clean old execution data and findings.

**Usage:**
```bash
cw clean [OPTIONS]
```

**Options:**
- `--days`, `-d` — Remove data older than this many days (default: 90)
- `--dry-run` — Show what would be deleted without deleting

**Examples:**
```bash
cw clean                    # Clean data older than 90 days
cw clean --days 30          # Clean data older than 30 days
cw clean --dry-run          # Preview what would be deleted
```

---

## Workflow Commands

### `cw workflows`

Browse and list available workflows.

**Usage:**
```bash
cw workflows [COMMAND]
```

**Subcommands:**
- `list` — List all available workflows
- `info <workflow>` — Show detailed workflow information
- `params <workflow>` — Show workflow parameters

**Examples:**
```bash
cw workflows list                    # List all workflows
cw workflows info python_sast        # Show workflow details
cw workflows params python_sast      # Show parameters
```

---

### `cw workflow`

Execute and manage individual workflows.

**Usage:**
```bash
cw workflow <COMMAND>
```

**Subcommands:**

#### `cw workflow run`

Execute a security testing workflow.

**Usage:**
```bash
cw workflow run <workflow> <target> [params...] [OPTIONS]
```

**Arguments:**
- `<workflow>` — Workflow name
- `<target>` — Target path to analyze
- `[params...]` — Parameters as `key=value` pairs

**Options:**
- `--param-file`, `-f` — JSON file containing workflow parameters
- `--timeout`, `-t` — Execution timeout in seconds
- `--interactive` / `--no-interactive`, `-i` / `-n` — Interactive parameter input (default: interactive)
- `--wait`, `-w` — Wait for execution to complete
- `--live`, `-l` — Start live monitoring after execution
- `--auto-start` / `--no-auto-start` — Automatically start required worker
- `--auto-stop` / `--no-auto-stop` — Automatically stop worker after completion
- `--fail-on` — Fail build if findings match SARIF level (error, warning, note, info, all, none)
- `--export-sarif` — Export SARIF results to file after completion

**Examples:**
```bash
# Basic workflow execution
cw workflow run python_sast ./project

# With parameters
cw workflow run python_sast ./project check_secrets=true

# CI/CD integration - fail on errors
cw workflow run python_sast ./project --wait --no-interactive \
  --fail-on error --export-sarif results.sarif

# With parameter file
cw workflow run python_sast ./project --param-file config.json

# Live monitoring for fuzzing
cw workflow run atheris_fuzzing ./project --live
```

#### `cw workflow status`

Check status of latest or specific workflow execution.

**Usage:**
```bash
cw workflow status [run_id]
```

**Examples:**
```bash
cw workflow status                     # Show latest execution status
cw workflow status python_sast-abc123  # Show specific execution
```

#### `cw workflow history`

Show execution history.

**Usage:**
```bash
cw workflow history [OPTIONS]
```

**Options:**
- `--limit`, `-l` — Number of executions to show (default: 10)

**Example:**
```bash
cw workflow history --limit 20
```

#### `cw workflow retry`

Retry a failed workflow execution.

**Usage:**
```bash
cw workflow retry <run_id>
```

**Example:**
```bash
cw workflow retry python_sast-abc123
```

---

## Finding Commands

### `cw findings`

Browse all findings across executions.

**Usage:**
```bash
cw findings [COMMAND]
```

**Subcommands:**

#### `cw findings list`

List findings from a specific run.

**Usage:**
```bash
cw findings list [run_id] [OPTIONS]
```

**Options:**
- `--format` — Output format: table, json, sarif (default: table)
- `--save` — Save findings to file

**Examples:**
```bash
cw findings list                        # Show latest findings
cw findings list python_sast-abc123     # Show specific run
cw findings list --format json          # JSON output
cw findings list --format sarif --save  # Export SARIF
```

#### `cw findings export`

Export findings to various formats.

**Usage:**
```bash
cw findings export <run_id> [OPTIONS]
```

**Options:**
- `--format` — Output format: json, sarif, csv
- `--output`, `-o` — Output file path

**Example:**
```bash
cw findings export python_sast-abc123 --format sarif --output results.sarif
```

#### `cw findings history`

Show finding history across multiple runs.

**Usage:**
```bash
cw findings history [OPTIONS]
```

**Options:**
- `--limit`, `-l` — Number of runs to include (default: 10)

---

### `cw finding`

View and analyze individual findings.

**Usage:**
```bash
cw finding [id]                         # Show latest or specific finding
cw finding show <run_id> --rule <rule>  # Show specific finding detail
```

**Examples:**
```bash
cw finding                                # Show latest finding
cw finding python_sast-abc123             # Show specific run findings
cw finding show python_sast-abc123 --rule f2cf5e3e  # Show specific finding
```

---

## Worker Management Commands

### `cw worker`

Manage Temporal workers for workflow execution.

**Usage:**
```bash
cw worker <COMMAND>
```

**Subcommands:**

#### `cw worker list`

List Crashwise workers and their status.

**Usage:**
```bash
cw worker list [OPTIONS]
```

**Options:**
- `--all`, `-a` — Show all workers (including stopped)

**Examples:**
```bash
cw worker list          # Show running workers
cw worker list --all    # Show all workers
```

**Example Output:**
```
Crashwise Workers
┏━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Worker  ┃ Status    ┃ Uptime         ┃
┡━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ android │ ● Running │ 5 minutes ago  │
│ python  │ ● Running │ 10 minutes ago │
└─────────┴───────────┴────────────────┘

✅ 2 worker(s) running
```

#### `cw worker start`

Start a specific worker.

**Usage:**
```bash
cw worker start <name> [OPTIONS]
```

**Arguments:**
- `<name>` — Worker name (e.g., python, android, rust, secrets)

**Options:**
- `--build` — Rebuild worker image before starting

**Examples:**
```bash
cw worker start python           # Start Python worker
cw worker start android --build  # Rebuild and start Android worker
```

**Available Workers:**
- `python` — Python security analysis and fuzzing
- `android` — Android APK analysis
- `rust` — Rust fuzzing and analysis
- `secrets` — Secret detection workflows
- `ossfuzz` — OSS-Fuzz integration

#### `cw worker stop`

Stop all running Crashwise workers.

**Usage:**
```bash
cw worker stop [OPTIONS]
```

**Options:**
- `--all` — Stop all workers (default behavior, flag for clarity)

**Example:**
```bash
cw worker stop
```

**Note:** This command stops only worker containers, leaving core services (backend, temporal, minio) running.

---

## Monitoring Commands

### `cw monitor`

Real-time monitoring for running workflows.

**Usage:**
```bash
cw monitor [COMMAND]
```

**Subcommands:**
- `live <run_id>` — Live monitoring for a specific execution
- `stats <run_id>` — Show statistics for fuzzing workflows

**Examples:**
```bash
cw monitor live atheris-abc123    # Monitor fuzzing campaign
cw monitor stats atheris-abc123   # Show fuzzing statistics
```

---

## AI Integration Commands

### `cw ai`

AI-powered analysis and assistance.

**Usage:**
```bash
cw ai [COMMAND]
```

**Subcommands:**
- `analyze <run_id>` — Analyze findings with AI
- `explain <finding_id>` — Get AI explanation of a finding
- `remediate <finding_id>` — Get remediation suggestions

**Examples:**
```bash
cw ai analyze python_sast-abc123           # Analyze all findings
cw ai explain python_sast-abc123:finding1  # Explain specific finding
cw ai remediate python_sast-abc123:finding1  # Get fix suggestions
```

---

## Knowledge Ingestion Commands

### `cw ingest`

Ingest knowledge into the AI knowledge base.

**Usage:**
```bash
cw ingest [COMMAND]
```

**Subcommands:**
- `file <path>` — Ingest a file
- `directory <path>` — Ingest directory contents
- `workflow <workflow_name>` — Ingest workflow documentation

**Examples:**
```bash
cw ingest file ./docs/security.md           # Ingest single file
cw ingest directory ./docs                  # Ingest directory
cw ingest workflow python_sast              # Ingest workflow docs
```

---

## Common Workflow Examples

### CI/CD Integration

```bash
# Run security scan in CI, fail on errors
cw workflow run python_sast . \
  --wait \
  --no-interactive \
  --fail-on error \
  --export-sarif results.sarif
```

### Local Development

```bash
# Quick security check
cw workflow run python_sast ./my-code

# Check specific file types
cw workflow run python_sast . file_extensions='[".py",".js"]'

# Interactive parameter configuration
cw workflow run python_sast . --interactive
```

### Fuzzing Workflows

```bash
# Start fuzzing with live monitoring
cw workflow run atheris_fuzzing ./project --live

# Long-running fuzzing campaign
cw workflow run ossfuzz_campaign ./project \
  --auto-start \
  duration=3600 \
  --live
```

### Worker Management

```bash
# Check which workers are running
cw worker list

# Start needed worker manually
cw worker start python --build

# Stop all workers when done
cw worker stop
```

---

## Configuration Files

### Project Config (`.crashwise/config.json`)

```json
{
  "project_name": "my-security-project",
  "api_url": "http://localhost:8000",
  "default_workflow": "python_sast",
  "auto_start_workers": true,
  "auto_stop_workers": false
}
```

### Parameter File Example

```json
{
  "check_secrets": true,
  "file_extensions": [".py", ".js", ".go"],
  "severity_threshold": "medium",
  "exclude_patterns": ["**/test/**", "**/vendor/**"]
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Findings matched `--fail-on` criteria |
| 3 | Worker startup failed |
| 4 | Workflow execution failed |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CRASHWISE_API_URL` | Backend API URL | http://localhost:8000 |
| `CRASHWISE_ROOT` | Crashwise installation directory | Auto-detected |
| `CRASHWISE_DEBUG` | Enable debug logging | false |

---

## Tips and Best Practices

1. **Use `--no-interactive` in CI/CD** — Prevents prompts that would hang automated pipelines
2. **Use `--fail-on` for quality gates** — Fail builds based on finding severity
3. **Export SARIF for tool integration** — Most security tools support SARIF format
4. **Let workflows auto-start workers** — More efficient than manually managing workers
5. **Use `--wait` with `--export-sarif`** — Ensures results are available before export
6. **Check `cw worker list` regularly** — Helps manage system resources
7. **Use parameter files for complex configs** — Easier to version control and reuse

---

## Related Documentation

- [Docker Setup](../how-to/docker-setup.md) — Worker management and Docker configuration
- [Getting Started](../tutorial/getting-started.md) — Complete setup guide
- [Workflow Guide](../how-to/create-workflow.md) — Detailed workflow documentation
- [CI/CD Integration](../how-to/cicd-integration.md) — CI/CD setup examples

---

**Need Help?**

```bash
cw --help                # General help
cw workflow run --help   # Command-specific help
cw worker --help         # Worker management help
```
