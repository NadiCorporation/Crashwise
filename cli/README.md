# Crashwise CLI

🛡️ **Crashwise CLI** - Command-line interface for Crashwise security testing platform

A comprehensive CLI for managing security testing workflows, monitoring runs in real-time, and analyzing findings with beautiful terminal interfaces and persistent project management.

## ✨ Features

- 📁 **Project Management** - Initialize and manage Crashwise projects with local databases
- 🔧 **Workflow Management** - Browse, configure, and run security testing workflows
- 🚀 **Workflow Execution** - Execute and manage security testing workflows
- 🔍 **Findings Analysis** - View, export, and analyze security findings in multiple formats
- 📊 **Real-time Monitoring** - Live dashboards for fuzzing statistics and crash reports
- ⚙️ **Configuration** - Flexible project and global configuration management
- 🎨 **Rich UI** - Beautiful tables, progress bars, and interactive prompts
- 💾 **Persistent Storage** - SQLite database for runs, findings, and crash data
- 🛡️ **Error Handling** - Comprehensive error handling with user-friendly messages
- 🔄 **Network Resilience** - Automatic retries and graceful degradation

## 🚀 Quick Start

### Installation

#### Prerequisites
- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) package manager

#### Install Crashwise CLI
```bash
# Clone the repository
git clone https://github.com/YahyaToubali/Crashwise.git
cd Crashwise/cli

# Install globally with uv (recommended)
uv tool install .

# Alternative: Install in development mode
uv sync
uv add --editable ../sdk
uv tool install --editable .

# Verify installation
crashwise --help
```

#### Shell Completion (Optional)
```bash
# Install completion for your shell
crashwise --install-completion
```

### Initialize Your First Project

```bash
# Create a new project directory
mkdir my-security-project
cd my-security-project

# Initialize Crashwise project
cw init

# Check status
crashwise status
```

This creates a `.crashwise/` directory with:
- SQLite database for persistent storage
- Configuration file (`config.yaml`)
- Project metadata

### Run Your First Analysis

```bash
# List available workflows
crashwise workflows list

# Get workflow details
crashwise workflows info security_assessment

# Submit a workflow for analysis
crashwise workflow run security_assessment /path/to/your/code


# View findings when complete
crashwise finding <execution-id>
```

## 📚 Command Reference

### Project Management

#### `cw init`
Initialize a new Crashwise project in the current directory.

```bash
cw init --name "My Security Project" --api-url "http://localhost:8000"
```

**Options:**
- `--name, -n` - Project name (defaults to directory name)
- `--api-url, -u` - Crashwise API URL (defaults to http://localhost:8000)
- `--force, -f` - Force initialization even if project exists

#### `crashwise status`
Show comprehensive project and API status information.

```bash
crashwise status
```

Displays:
- Project information and configuration
- Database statistics (runs, findings, crashes)
- API connectivity and available workflows

### Workflow Management

#### `crashwise workflows list`
List all available security testing workflows.

```bash
crashwise workflows list
```

#### `crashwise workflows info <workflow-name>`
Show detailed information about a specific workflow.

```bash
crashwise workflows info security_assessment
```

Displays:
- Workflow metadata (version, author, description)
- Parameter schema and requirements
- Supported volume modes and features

#### `crashwise workflows parameters <workflow-name>`
Interactive parameter builder for workflows.

```bash
# Interactive mode
crashwise workflows parameters security_assessment

# Save parameters to file
crashwise workflows parameters security_assessment --output params.json

# Non-interactive mode (show schema only)
crashwise workflows parameters security_assessment --no-interactive
```

### Workflow Execution

#### `crashwise workflow run <workflow> <target-path>`
Execute a security testing workflow with **automatic file upload**.

```bash
# Basic execution - CLI automatically detects local files and uploads them
crashwise workflow run security_assessment /path/to/code

# With parameters
crashwise workflow run security_assessment /path/to/binary \
  --param timeout=3600 \
  --param iterations=10000

# With parameter file
crashwise workflow run security_assessment /path/to/code \
  --param-file my-params.json

# Wait for completion
crashwise workflow run security_assessment /path/to/code --wait
```

**Automatic File Upload Behavior:**

The CLI intelligently handles target files based on whether they exist locally:

1. **Local file/directory exists** → **Automatic upload to MinIO**:
   - CLI creates a compressed tarball (`.tar.gz`) for directories
   - Uploads via HTTP to backend API
   - Backend stores in MinIO with unique `target_id`
   - Worker downloads from MinIO when ready to analyze
   - ✅ **Works from any machine** (no shared filesystem needed)

2. **Path doesn't exist locally** → **Path-based submission** (legacy):
   - Path is sent to backend as-is
   - Backend expects target to be accessible on its filesystem
   - ⚠️ Only works when CLI and backend share filesystem

**Example workflow:**
```bash
$ cw workflow security_assessment ./my-project

🔧 Getting workflow information for: security_assessment
📦 Detected local directory: ./my-project (21 files)
🗜️  Creating compressed tarball...
📤 Uploading to backend (0.01 MB)...
✅ Upload complete! Target ID: 548193a1-f73f-4ec1-8068-19ec2660b8e4

🎯 Executing workflow:
   Workflow: security_assessment
   Target: my-project.tar.gz (uploaded)
   Volume Mode: ro
   Status: 🔄 RUNNING

✅ Workflow started successfully!
   Execution ID: security_assessment-52781925
```

**Upload Details:**
- **Max file size**: 10 GB (configurable on backend)
- **Compression**: Automatic for directories (reduces upload time)
- **Storage**: Files stored in MinIO (S3-compatible)
- **Lifecycle**: Automatic cleanup after 7 days
- **Caching**: Workers cache downloaded targets for faster repeated workflows

**Options:**
- `--param, -p` - Parameter in key=value format (can be used multiple times)
- `--param-file, -f` - JSON file containing parameters
- `--volume-mode, -v` - Volume mount mode: `ro` (read-only) or `rw` (read-write)
- `--timeout, -t` - Execution timeout in seconds
- `--interactive/--no-interactive, -i/-n` - Interactive parameter input
- `--wait, -w` - Wait for execution to complete

**Worker Lifecycle Options (v0.7.0):**
- `--auto-start/--no-auto-start` - Auto-start required worker (default: from config)
- `--auto-stop/--no-auto-stop` - Auto-stop worker after completion (default: from config)

**Examples:**
```bash
# Worker starts automatically (default behavior)
crashwise workflow ossfuzz_campaign . project_name=zlib

# Disable auto-start (worker must be running already)
crashwise workflow ossfuzz_campaign . --no-auto-start

# Auto-stop worker after completion
crashwise workflow ossfuzz_campaign . --wait --auto-stop
```

#### `crashwise workflow status [execution-id]`
Check the status of a workflow execution.

```bash
# Check specific execution
crashwise workflow status abc123def456

# Check most recent execution
crashwise workflow status
```

#### `crashwise workflow history`
Show workflow execution history from local database.

```bash
# List all executions
crashwise workflow history

# Filter by workflow
crashwise workflow history --workflow security_assessment

# Filter by status
crashwise workflow history --status completed

# Limit results
crashwise workflow history --limit 10
```

#### `crashwise workflow retry <execution-id>`
Retry a workflow with the same or modified parameters.

```bash
# Retry with same parameters
crashwise workflow retry abc123def456

# Modify parameters interactively
crashwise workflow retry abc123def456 --modify-params
```

### Findings Management

#### `crashwise finding [execution-id]`
View security findings for a specific execution.

```bash
# Display latest findings
crashwise finding

# Display specific execution findings
crashwise finding abc123def456
```

#### `crashwise findings`
Browse all security findings from local database.

```bash
# List all findings
crashwise findings

# Show findings history
crashwise findings history --limit 20
```

#### `crashwise finding export [execution-id]`
Export security findings in various formats.

```bash
# Export latest findings
crashwise finding export --format json

# Export specific execution findings
crashwise finding export abc123def456 --format sarif

# Export as CSV with output file
crashwise finding export abc123def456 --format csv --output report.csv

# Export as HTML report
crashwise finding export --format html --output report.html
```

### Configuration Management

#### `crashwise config show`
Display current configuration settings.

```bash
# Show project configuration
crashwise config show

# Show global configuration
crashwise config show --global
```

#### `crashwise config set <key> <value>`
Set a configuration value.

```bash
# Project settings
crashwise config set project.api_url "http://api.crashwise.com"
crashwise config set project.default_timeout 7200
crashwise config set project.default_workflow "security_assessment"

# Retention settings
crashwise config set retention.max_runs 200
crashwise config set retention.keep_findings_days 120

# Preferences
crashwise config set preferences.auto_save_findings true
crashwise config set preferences.show_progress_bars false

# Global configuration
crashwise config set project.api_url "http://global.api.com" --global
```

#### `crashwise config get <key>`
Get a specific configuration value.

```bash
crashwise config get project.api_url
crashwise config get retention.max_runs --global
```

#### `crashwise config reset`
Reset configuration to defaults.

```bash
# Reset project configuration
crashwise config reset

# Reset global configuration
crashwise config reset --global

# Skip confirmation
crashwise config reset --force
```

#### `crashwise config edit`
Open configuration file in default editor.

```bash
# Edit project configuration
crashwise config edit

# Edit global configuration
crashwise config edit --global
```

## 🏗️ Project Structure

When you initialize a Crashwise project, the following structure is created:

```
my-project/
├── .crashwise/
│   ├── config.yaml          # Project configuration
│   └── findings.db          # SQLite database
├── .gitignore               # Updated with Crashwise entries
└── README.md                # Project README (if created)
```

### Database Schema

The SQLite database stores:

- **runs** - Workflow run history and metadata
- **findings** - Security findings and SARIF data
- **crashes** - Crash reports and fuzzing data

### Configuration Format

Project configuration (`.crashwise/config.yaml`):

```yaml
project:
  name: "My Security Project"
  api_url: "http://localhost:8000"
  default_timeout: 3600
  default_workflow: null

retention:
  max_runs: 100
  keep_findings_days: 90

preferences:
  auto_save_findings: true
  show_progress_bars: true
  table_style: "rich"
  color_output: true

workers:
  auto_start_workers: true    # Auto-start workers when needed
  auto_stop_workers: false    # Auto-stop workers after completion
  worker_startup_timeout: 60  # Worker startup timeout (seconds)
  docker_compose_file: null   # Custom docker-compose.yml path
```

## 🔧 Advanced Usage

### Parameter Handling

Crashwise CLI supports flexible parameter input:

1. **Command line parameters**:
   ```bash
   cw workflow workflow-name /path key1=value1 key2=value2
   ```

2. **Parameter files**:
   ```bash
   echo '{"timeout": 3600, "threads": 4}' > params.json
   cw workflow workflow-name /path --param-file params.json
   ```

3. **Interactive prompts**:
   ```bash
   cw workflow workflow-name /path --interactive
   ```

4. **Parameter builder**:
   ```bash
   cw workflows parameters workflow-name --output my-params.json
   cw workflow workflow-name /path --param-file my-params.json
   ```

### Environment Variables

Override configuration with environment variables:

```bash
export CRASHWISE_API_URL="http://production.api.com"
export CRASHWISE_TIMEOUT="7200"
```

### Data Retention

Configure automatic cleanup of old data:

```bash
# Keep only 50 runs
crashwise config set retention.max_runs 50

# Keep findings for 30 days
crashwise config set retention.keep_findings_days 30
```

### Export Formats

Support for multiple export formats:

- **JSON** - Simplified findings structure
- **CSV** - Tabular data for spreadsheets
- **HTML** - Interactive web report
- **SARIF** - Standard security analysis format

## 🛠️ Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/YahyaToubali/Crashwise.git
cd Crashwise/cli

# Install in development mode
uv sync
uv add --editable ../sdk

# Install CLI in editable mode
uv tool install --editable .
```

### Project Structure

```
cli/
├── src/crashwise_cli/
│   ├── __init__.py
│   ├── main.py              # Main CLI app
│   ├── config.py            # Configuration management
│   ├── database.py          # Database operations
│   ├── exceptions.py        # Error handling
│   ├── api_validation.py    # API response validation
│   └── commands/            # Command implementations
│       ├── init.py          # Project initialization
│       ├── workflows.py     # Workflow management
│       ├── runs.py          # Run management
│       ├── findings.py      # Findings management
│       ├── config.py        # Configuration commands
│       └── status.py        # Status information
├── pyproject.toml           # Project configuration
└── README.md               # This file
```

### Running Tests

```bash
# Run tests (when available)
uv run pytest

# Code formatting
uv run black src/
uv run isort src/

# Type checking
uv run mypy src/
```

## ⚠️ Troubleshooting

### Common Issues

#### "No Crashwise project found"
```bash
# Initialize a project first
cw init
```

#### API Connection Failed
```bash
# Check API URL configuration
crashwise config get project.api_url

# Test API connectivity
crashwise status

# Update API URL if needed
crashwise config set project.api_url "http://correct-url:8000"
```

#### Permission Errors
```bash
# Ensure proper permissions for project directory
chmod -R 755 .crashwise/

# Check file ownership
ls -la .crashwise/
```

#### Database Issues
```bash
# Check database file exists
ls -la .crashwise/findings.db

# Reinitialize if corrupted (will lose data)
rm .crashwise/findings.db
cw init --force
```

### Environment Variables

Set these environment variables for debugging:

```bash
export CRASHWISE_DEBUG=1           # Enable debug logging
export CRASHWISE_API_URL="..."     # Override API URL
export CRASHWISE_TIMEOUT="30"      # Override timeout
```

### Getting Help

```bash
# General help
crashwise --help

# Command-specific help
cw workflows --help
cw workflow run --help

# Show version
crashwise --version
```

## 🏆 Example Workflow

Here's a complete example of analyzing a project:

```bash
# 1. Initialize project
mkdir my-security-audit
cd my-security-audit
cw init --name "Security Audit 2024"

# 2. Check available workflows
crashwise workflows list

# 3. Submit comprehensive security assessment
cw workflow security_assessment /path/to/source/code --wait

# 4. View findings in table format
crashwise findings get <run-id>

# 5. Export detailed report
crashwise findings export <run-id> --format html --output security_report.html

# 6. Check project statistics
crashwise status
```

## 📜 License

This project is licensed under the terms specified in the main Crashwise repository.

## 🤝 Contributing

Contributions are welcome! Please see the main Crashwise repository for contribution guidelines.

---

**Crashwise CLI** - Making security testing workflows accessible and efficient from the command line.
