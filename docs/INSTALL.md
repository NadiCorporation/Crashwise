<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# Installation

## Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Linux x86_64, kernel ≥ 5.10 |
| Python | 3.11, 3.12, or 3.13 |
| RAM | 8 GB |
| Disk | 50 GB free |
| Git | Any recent version |

All other dependencies (Docker, Clang, GCC, LLVM, AFL++) are provisioned by `crashwise setup`.

---

## Install CrashWise

```bash
git clone https://github.com/yahyatoubali/Crashwise.git && cd Crashwise
uv sync  # or: python -m venv .venv && source .venv/bin/activate && pip install -e .
crashwise version
```

---

## LLM Provider Setup & Configuration

Configure your preferred LLM provider and infrastructure settings via the interactive or headless wizard:

```bash
# Interactive configuration wizard
crashwise configure

# Headless / CI configuration
crashwise configure --non-interactive \
  --temporal-host=localhost:7233 \
  --api-port=8000 \
  --database-url=sqlite+aiosqlite:///./crashwise.db \
  --workdir=/tmp/crashwise
```

Or configure `.env` directly:

```bash
# DeepSeek (OpenAI-compatible)
OPENAI_API_BASE=https://api.deepseek.com
OPENAI_API_KEY=sk-...
MODEL_NAME=deepseek-chat
TEMPERATURE=0.0

# Anthropic Claude
CRASHWISE_LLM_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-...

# Ollama / Local vLLM
OPENAI_API_BASE=http://localhost:11434/v1
OPENAI_API_KEY=ollama
MODEL_NAME=llama3.1:8b
```

---

## Provision System Dependencies

```bash
crashwise setup
```

This command:
1. Detects the Linux distribution from `/etc/os-release` (Alpine, Arch, Debian, Fedora, RHEL, Ubuntu)
2. Installs Docker, Docker Compose v2, CMake, Clang, LLD, GCC, LLVM via the native package manager (`apk`, `pacman`, `apt`, `dnf`)
3. Installs AFL++ (from AUR on Arch, from `universe` on Ubuntu, packages on Alpine/Fedora)
4. Adds the current user to the `docker` group if missing
5. Starts the Docker daemon if stopped

### Non-interactive mode

```bash
crashwise setup --yes              # skip all prompts
crashwise setup --dry-run          # print commands without executing
crashwise setup --output setup.sh  # write script to file for review
```

### Verify

```bash
crashwise doctor
```

---

## Distro-Specific Notes

### Alpine Linux

```bash
apk add python3 py3-pip git build-base cmake clang llvm
```

### Arch Linux

```bash
sudo pacman -S --needed python python-pip git base-devel
```

AFL++ is in the AUR:

```bash
yay -S aflplusplus
```

> Optional — the Docker worker image ships AFL++ pre-installed.

### Ubuntu (22.04 / 24.04)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git build-essential
```

> The AFL++ binary package is named `afl++` (not `aflplusplus`). If `apt` reports "Unable to locate package", run `sudo add-apt-repository universe && sudo apt-get update`.

### Fedora / RHEL

```bash
sudo dnf install python3 python3-pip git gcc gcc-c++ cmake clang llvm
```

---

## Infrastructure Stack

```bash
docker compose up -d
```

This starts:

| Service | Port | Purpose |
|---|---|---|
| Temporal Server | 7233 | Workflow orchestration (gRPC) |
| Temporal UI | 8233 | Workflow timeline & debug interface |
| PostgreSQL | 5432 | Relational persistence |
| Redis | 6379 | Distributed state, heartbeats, deduplication |
| MinIO | 9000 / 9001 | S3-compatible artifact storage |
| CrashWise API | 8000 | FastAPI REST API & SSE telemetry |
| CrashWise Web UI | 3000 | Next.js 14 7-Tab Production Command Center |

### Initialize database

```bash
crashwise init
```

---

## Launching Campaigns

```bash
# Standard blocking run with automatic harness synthesis
crashwise run https://github.com/madler/zlib --timeout 600

# Monorepo / sub-directory target scoping & clone depth
crashwise run https://github.com/google/re2 \
  --target-subdir "re2" \
  --target-clone-depth 1 \
  --timeout 300

# Granular configuration with custom engine flags, LLM routing, and MAB
crashwise run targets/libtgvoip \
  --timeout 300 \
  --fuzzer libfuzzer \
  --sanitizers address,undefined \
  --custom-flags "-dict=json.dict -max_len=1024" \
  --model deepseek-chat \
  --base-url https://api.deepseek.com \
  --api-key sk-... \
  --temperature 0.0 \
  --mab \
  --mab-algorithm thompson \
  --self-healing \
  --max-repair-attempts 10

# Detached submission
crashwise run --detach https://github.com/madler/zlib
```

The pre-flight gate validates Docker, Clang, GCC, and LLM connectivity before submission. Override with `--skip-preflight` if running inside the worker container.

### God-Mode signals (live campaign control)

```bash
crashwise signal <workflow_id> force_pivot
crashwise signal <workflow_id> inject_seed --data filename=poc.bin
crashwise signal <workflow_id> pause_hunt
crashwise signal <workflow_id> resume_hunt
```

Workflow IDs are printed by `crashwise run` and visible in Temporal UI at `http://localhost:8233` or Next.js Dashboard at `http://localhost:3000`.

---

## Troubleshooting

### `docker-compose` v1 — `KeyError: 'ContainerConfig'`

The legacy Python `docker-compose` (v1.29.x) is incompatible with Docker Engine 24+. Switch to the v2 plugin:

```bash
# Arch
sudo pacman -Syu docker docker-compose docker-buildx

# Ubuntu
sudo apt-get remove docker-compose
sudo apt-get install docker-compose-plugin
```

Verify: `docker compose version` must report `v2.x.x`.

> Always use `docker compose` (space, no hyphen) — not `docker-compose`.

### "Permission denied" connecting to Docker daemon

Three distinct causes:

| Symptom | Fix |
|---|---|
| User just added to `docker` group | Log out and back in, or run `newgrp docker` |
| User not in `docker` group | `sudo usermod -aG docker $USER` then re-login |
| Docker daemon not running | `sudo systemctl start docker && sudo systemctl enable docker` |

`crashwise doctor` diagnoses which case applies.

### "Cannot reach Temporal at localhost:7233"

```bash
docker compose ps          # check if temporal is running
docker compose up -d       # bring it up
```

### `crashwise: command not found` under sudo

The binary lives in `.venv/bin/`. Either use the full path or avoid sudo:

```bash
./.venv/bin/crashwise doctor
# or
crashwise doctor   # no sudo needed for diagnostics
```

### "afl++ not found on host"

This is a warning, not a failure. The Docker worker ships AFL++ pre-installed. For host-native install:

- **Arch:** `yay -S aflplusplus`
- **Ubuntu:** `sudo apt-get install afl++`

---

## Uninstall

```bash
deactivate
rm -rf .venv

# System packages (optional):
sudo pacman -Rns docker docker-compose     # Arch
sudo apt-get purge docker.io docker-compose-plugin  # Ubuntu
```
