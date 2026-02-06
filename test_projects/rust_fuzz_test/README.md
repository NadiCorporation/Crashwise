# rust_fuzz_test

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
