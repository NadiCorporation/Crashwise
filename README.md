<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

<h1 align="center">CrashWise</h1>

<h4 align="center">Autonomous AI-Powered Fuzzing & Crash Triage Platform</h4>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#llm-configuration">LLM Configuration</a> •
  <a href="#docker-compose-reference">Docker Compose</a> •
  <a href="#cli-reference">CLI</a> •
  <a href="#testing">Testing</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-416%20passing-brightgreen" alt="416 tests passing">
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue" alt="Python versions">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/temporal-1.25-blue" alt="Temporal">
  <img src="https://img.shields.io/badge/docker-ready-blue" alt="Docker Ready">
  <img src="https://img.shields.io/badge/distros-Arch%20%7C%20Ubuntu%20%7C%20Fedora-orange" alt="Linux Distros">
  <img src="https://img.shields.io/badge/sandbox-network%20none%20%7C%20read--only-purple" alt="Sandboxed">
</p>

---

> **Built by [Yahya Toubali](https://github.com/yahyatoubali), Security Researcher** — developing CrashWise under
> the **Nadicorp** label. Designed for offensive security teams, vulnerability
> researchers, and bug bounty hunters who need to discover, triage, and
> weaponise zero-day memory-safety bugs at scale.

---

## Key Features

| Capability | Description |
|-----------|-------------|
| **Temporal Orchestration** | Durable, distributed workflow engine for long-running fuzz campaigns with automatic retry, state persistence, and horizontal worker scaling. |
| **Zero-Config Onboarding** | `crashwise init` auto-detects your project's build system (CMake, Make, Meson, Bazel, Cargo, Go), language, and harness, then generates a `crashwise.yaml` manifest. |
| **Distro-Native Provisioning** | Sentinel detects Arch / Ubuntu / Fedora from `/etc/os-release` and dispatches `pacman` / `apt` / `dnf` accordingly — no Debian-only assumptions. AUR packages (e.g. `aflplusplus`) are split onto a dedicated rail with `yay` / `paru` detection. |
| **Mandatory Pre-flight Gate** | `crashwise run` refuses to launch until Docker, Clang, and GCC are confirmed working — opaque mid-campaign failures replaced with actionable remediation hints. |
| **AI-Driven Harness Synthesis** | LangGraph agent reads target source code and autonomously generates AFL++/libFuzzer-compatible C/C++ harnesses with fallback templates. |
| **Coverage-Guided Harness Evolution** | When fuzzing plateaus, the workflow identifies the *exact* blocker (magic value, length check, checksum) at the *exact* source line, then hands the structured blocker to the LLM evolution agent. Bounded by `max_evolution_count` to prevent runaway LLM spend. |
| **Multi-Armed Bandit Strategy Switching** | Thompson Sampling + UCB1 dynamically pivots between AFL++ and libFuzzer strategies based on real-time coverage feedback. |
| **God-Mode Signals** | Live workflow control: `crashwise signal <id> force_pivot`, `inject_seed`, `pause_hunt`, `resume_hunt`. Researchers can force a strategy pivot, drop a manually-crafted seed into the running corpus, or pause the campaign for review. |
| **Hardened Sandbox (S6)** | Fuzzer containers launch with `--network none`, `--read-only` rootfs, size-capped tmpfs, `--cap-drop ALL`, `no-new-privileges`, and a pre-flight `docker rm -f` to kill stale containers. |
| **Shell-Free Hot-Swap** | LLM-supplied compile commands are parsed with `shlex` and executed via `subprocess_exec` against an allow-list of compilers. No `shell=True`, no metacharacter expansion, no RCE surface. |
| **Intelligent Triage** | LLM-powered crash classification (ASAN/GDB) with deterministic regex fallback. Deduplicates by stack-hash. |
| **KernelBridge** | Native Linux kernel fuzzing via syzkaller integration — parses OOPS, KASAN, and KFENCE reports. |
| **Automated PoC / Exploit Generation** | Exploit Architect agent transforms crash data into standalone C PoCs with reachability analysis and primitive detection. |
| **Patch Verification** | End-to-end pipeline: clone → apply patch → build → regression test → verify crash is fixed. |
| **Auto-Disclosure Engine** | CVSS v3.1 scoring, platform-specific report generation (HackerOne, Bugcrowd, kernel ML), and webhook/email/PGP notifications. |
| **Intelligence Dashboard** | Streamlit-based real-time dashboard for campaign monitoring, crash heatmaps, CWE filtering, patch viewing, and bounty export. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CrashWise Control Plane                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  CLI (Typer)  │  FastAPI REST API  │  Streamlit Dashboard  │  Temporal UI  │
├───────────────┴────────────────────┴───────────────────────┴───────────────┤
│                         Temporal Server (Workflows)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
│  │ MainFuzzing │  │ VerifyPatch │  │  SeedCorpus │  │ NotifyStake-    │   │
│  │  Workflow   │  │  Workflow   │  │  Workflow   │  │   holders       │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────────┘   │
├─────────┼────────────────┼────────────────┼─────────────────────────────────┤
│         ▼                ▼                ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     Temporal Activities (22 total)                   │    │
│  │  setup_target      execute_fuzzing     triage_results               │    │
│  │  seed_corpus       analyze_progress    analyze_crash                │    │
│  │  pivot_strategy    analyze_coverage    evolve_harness               │    │
│  │  hot_swap_harness  mutate_harness      inject_seeds                 │    │
│  │  verify_patch      verify_poc          notify_stakeholders          │    │
│  │  kernel_monitor    profile_target      execute_job                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Agent Layer (LangGraph + LLM)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ HarnessSynth │  │   Triage     │  │   Patcher    │  │ ExploitArch  │   │
│  │   Agent      │  │   Agent      │  │   Agent      │  │    Agent     │   │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤   │
│  │ Coverage     │  │   MAB        │  │   Profiler   │  │ Reachability │   │
│  │ Analyzer     │  │ Strategist   │  │   Agent      │  │   Engine     │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Execution Layer                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │  Docker    │  │   QEMU     │  │   Local    │  │  Kernel (syzkaller)│   │
│  │  (AFL++)   │  │  (KVM)     │  │ (libFuzzer)│  │                    │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Persistence & Storage                                │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │ PostgreSQL │  │   Redis    │  │  Cloudflare│  │   Local SQLite     │   │
│  │ (Campaigns)│  │ (Counters) │  │    R2      │  │   (dev mode)       │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ (strict mypy) |
| Orchestration | Temporal (Python SDK) |
| AI / LLM | LangGraph + LangChain (Anthropic, OpenAI, Ollama, Venice) |
| Web API | FastAPI + Uvicorn |
| Dashboard | Streamlit |
| CLI | Typer + Rich |
| Database | PostgreSQL (prod) / SQLite (dev) via SQLAlchemy async |
| Cache | Redis |
| Object Storage | Cloudflare R2 / S3-compatible |
| Fuzzers | AFL++, libFuzzer, honggfuzz |
| Execution | Docker (hardened), QEMU/KVM |
| Build | hatchling + uv |

---

## Installation

### Prerequisites

| Requirement | Minimum | Notes |
|------------|---------|-------|
| **Python** | 3.11+ | 3.12 recommended |
| **Docker** | 20.10+ | With Docker Compose v2 plugin |
| **OS** | Linux | Arch, Ubuntu 22.04+, Fedora 38+ |
| **RAM** | 8 GB | 16 GB recommended for parallel fuzzing |
| **Disk** | 50 GB free | Fuzzing generates large corpora |

### Method 1: pipx (Recommended for Users)

```bash
# Install pipx if you don't have it
python3 -m pip install --user pipx
pipx ensurepath

# Install CrashWise
pipx install crashwise

# Verify
crashwise --version
crashwise doctor
```

### Method 2: uv (Recommended for Development)

```bash
# Install uv (fast Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/yahyatoubali/Crashwise.git
cd Crashwise

# Install in development mode
uv sync

# Verify
uv run crashwise --version
uv run crashwise doctor
```

### Method 3: pip (Standard)

```bash
git clone https://github.com/yahyatoubali/Crashwise.git
cd Crashwise

python3 -m venv .venv
source .venv/bin/activate
pip install -e .

crashwise --version
crashwise doctor
```

### Post-Install: System Dependencies

CrashWise needs build tools (Clang, GCC, CMake) and Docker for fuzzing.
The built-in setup wizard handles everything:

```bash
# Interactive setup — detects your distro and installs missing tools
crashwise setup

# Check system health
crashwise doctor
```

**Or install manually:**

<details>
<summary>Ubuntu / Debian</summary>

```bash
sudo apt-get update
sudo apt-get install -y \
  docker.io docker-compose-plugin \
  clang lld llvm-dev \
  gcc g++ cmake \
  afl++

# Add yourself to the docker group (log out & back in after)
sudo usermod -aG docker $USER
```
</details>

<details>
<summary>Arch Linux</summary>

```bash
sudo pacman -S --needed \
  docker docker-buildx docker-compose \
  clang lld llvm \
  gcc cmake

# AFL++ is in the AUR
yay -S aflplusplus

# Enable Docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```
</details>

<details>
<summary>Fedora</summary>

```bash
sudo dnf install -y \
  docker docker-compose-plugin \
  clang lld llvm-devel \
  gcc gcc-c++ cmake \
  american-fuzzy-lop

sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```
</details>

> **Note:** If you only use the Docker worker (`Dockerfile.worker`), the host
> does NOT need Clang/GCC/AFL++ installed — everything is bundled in the
> container image. You still need Docker itself.

---

## Quick Start

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env — at minimum, set one LLM API key (see LLM Configuration below)
```

### 2. Start Infrastructure

```bash
# Start all services (Temporal, PostgreSQL, Redis, MinIO)
docker compose up -d

# Verify services are healthy
docker compose ps

# Wait for Temporal to finish schema migration (~60-90s on first boot)
docker compose logs -f temporal-server
```

### 3. Initialize a Target

```bash
# Navigate to a C/C++ project you want to fuzz
cd /path/to/target-project

# Auto-detect build system and generate crashwise.yaml
crashwise init
```

### 4. Run a Fuzzing Campaign

```bash
# Submit the campaign (runs pre-flight checks first)
crashwise run

# Or specify options explicitly
crashwise run \
  --repo https://github.com/example/target.git \
  --fuzzer afl++ \
  --timeout 3600
```

### 5. Monitor

```bash
# View campaign status
crashwise dashboard

# Or use the REST API
curl http://localhost:8000/campaigns
```

---

## LLM Configuration

CrashWise uses AI for two distinct purposes, each with its own configuration:

### 1. Agentic Workflows (Harness Synthesis, Code Evolution, Exploit Gen)

These use **LangChain** and require a high-quality code model. Configure in `.env`:

| Variable | Purpose | Example |
|----------|---------|---------|
| `CRASHWISE_LLM_MODEL` | Model name (determines provider) | `claude-sonnet-4-5` |
| `CRASHWISE_LLM_TEMPERATURE` | Sampling temperature | `0.0` |
| `ANTHROPIC_API_KEY` | Required if model starts with `claude-*` | `sk-ant-...` |
| `OPENAI_API_KEY` | Required for all other models (`gpt-*`, etc.) | `sk-...` |

**Routing logic:**
- Model name starts with `claude` → uses **Anthropic** (`ANTHROPIC_API_KEY`)
- Everything else → uses **OpenAI** (`OPENAI_API_KEY`)

#### Using OpenAI-Compatible Providers

Any provider with an OpenAI-compatible API works (Together AI, Groq, Fireworks,
local vLLM, Ollama with OpenAI shim, etc.):

```bash
# Example: Together AI
CRASHWISE_LLM_MODEL=meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo
OPENAI_API_KEY=your-together-api-key
OPENAI_API_BASE=https://api.together.xyz/v1

# Example: Local vLLM
CRASHWISE_LLM_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct
OPENAI_API_KEY=not-needed
OPENAI_API_BASE=http://localhost:8000/v1

# Example: Groq
CRASHWISE_LLM_MODEL=llama-3.3-70b-versatile
OPENAI_API_KEY=gsk_...
OPENAI_API_BASE=https://api.groq.com/openai/v1
```

### 2. Crash Triage & Root Cause Analysis

This uses a **lightweight inference layer** (direct HTTP, not LangChain) for
crash analysis and patch suggestions. It's optional — without it, triage still
works via heuristic ASAN/GDB parsing.

| Variable | Purpose | Example |
|----------|---------|---------|
| `AI_PROVIDER` | Backend: `ollama`, `venice`, or empty | `ollama` |
| `AI_MODEL` | Model name for the chosen provider | `llama3.1:8b` |
| `AI_API_KEY` | API key (Venice only) | `your-key` |
| `OLLAMA_URL` | Ollama server URL | `http://localhost:11434` |

#### Option A: Ollama (Local, Free, Private)

Best for privacy-sensitive environments. Runs entirely on your machine:

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (8B is fast; 70B is more accurate)
ollama pull llama3.1:8b

# Configure .env
AI_PROVIDER=ollama
AI_MODEL=llama3.1:8b
OLLAMA_URL=http://localhost:11434
```

#### Option B: Venice AI (Cloud, OpenAI-Compatible)

Fast cloud inference with privacy guarantees:

```bash
# Sign up at https://venice.ai and get an API key
AI_PROVIDER=venice
AI_API_KEY=your-venice-api-key
AI_MODEL=llama-3.3-70b
```

#### Option C: No AI Provider (Heuristic-Only)

Perfectly functional — crashes are still classified via regex-based ASAN/GDB
parsing and stack-hash deduplication. You just won't get deep root-cause
analysis or AI-generated patch suggestions:

```bash
AI_PROVIDER=
```

### Recommended Configurations

<details>
<summary><strong>Full Cloud Setup (Best Quality)</strong></summary>

```bash
# Agentic workflows — Anthropic Claude
CRASHWISE_LLM_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-api03-...

# Triage — Venice (fast + private)
AI_PROVIDER=venice
AI_API_KEY=your-venice-key
AI_MODEL=llama-3.3-70b
```
</details>

<details>
<summary><strong>Fully Local Setup (Free, Private)</strong></summary>

```bash
# Agentic workflows — local via Ollama OpenAI shim
CRASHWISE_LLM_MODEL=llama3.1:70b
OPENAI_API_KEY=ollama
OPENAI_API_BASE=http://localhost:11434/v1

# Triage — Ollama direct
AI_PROVIDER=ollama
AI_MODEL=llama3.1:8b
OLLAMA_URL=http://localhost:11434
```
</details>

<details>
<summary><strong>Budget Setup (Cheap Cloud)</strong></summary>

```bash
# Agentic workflows — OpenAI mini
CRASHWISE_LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...

# Triage — heuristic only (free)
AI_PROVIDER=
```
</details>

---

## Docker Compose Reference

The full-stack deployment uses Docker Compose with the following services:

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `temporal-server` | `temporalio/auto-setup:1.25` | 7233 | Workflow engine (gRPC) |
| `temporal-ui` | `temporalio/ui:2.30.0` | 8233 | Temporal Web UI |
| `postgres` | `postgres:16-alpine` | 5432 | Database (Temporal + CrashWise) |
| `redis` | `redis:7-alpine` | 6379 | Counters, dedup, MAB state |
| `minio` | `minio/minio:latest` | 9000, 9001 | Local S3 (R2 emulation) |
| `api` | CrashWise (Dockerfile) | 8000 | FastAPI REST API |
| `dashboard` | CrashWise (Dockerfile) | 8501 | Streamlit UI |
| `worker` | CrashWise (Dockerfile.worker) | — | Temporal worker (fuzzer node) |

### Common Commands

```bash
# Start everything
docker compose up -d

# Start only infrastructure (no CrashWise app containers)
docker compose up -d temporal-server postgres redis minio

# Check service health
docker compose ps

# View logs for a specific service
docker compose logs -f temporal-server
docker compose logs -f worker

# Scale workers horizontally
docker compose up -d --scale worker=4

# Stop everything
docker compose down

# Stop and remove all data (fresh start)
docker compose down -v
```

### First-Boot Timing

On first startup, Temporal runs database schema migrations which can take
**60–90 seconds**. Other services (`api`, `worker`) wait for Temporal's
healthcheck to pass before starting. Monitor with:

```bash
docker compose logs -f temporal-server
# Wait for: "Temporal cluster is healthy"
```

### Troubleshooting Docker Compose

<details>
<summary><code>docker compose up temporal</code> → "no such service: temporal"</summary>

The service is named **`temporal-server`** (not `temporal`):

```bash
docker compose up -d temporal-server
```
</details>

<details>
<summary>Temporal shows UNHEALTHY</summary>

This is usually a timing issue on first boot. The schema migration takes 60-90s:

```bash
# Check progress
docker compose logs temporal-server | tail -20

# If stuck, restart
docker compose restart temporal-server
```
</details>

<details>
<summary>"permission denied" on Docker socket</summary>

Your user isn't in the `docker` group, or you need to re-login:

```bash
# Add to group
sudo usermod -aG docker $USER

# Apply immediately (current shell only)
newgrp docker

# Or log out and back in for full effect
```
</details>

---

## CLI Reference

```
crashwise --help
```

| Command | Description |
|---------|-------------|
| `crashwise version` | Print installed version |
| `crashwise info` | Print runtime configuration |
| `crashwise doctor` | System health diagnostic (checks Docker, build tools, services) |
| `crashwise setup` | Interactive distro-aware dependency installer |
| `crashwise init` | Zero-config project onboarding (generates `crashwise.yaml`) |
| `crashwise run` | Submit a fuzzing workflow (with pre-flight gate) |
| `crashwise worker` | Start a Temporal worker |
| `crashwise api` | Launch the FastAPI management server |
| `crashwise dashboard` | Launch the Streamlit intelligence dashboard |
| `crashwise signal <id> <signal>` | Send a God-Mode signal to a live campaign |

### God-Mode Signals

```bash
# Force the MAB strategist to switch fuzzer strategy
crashwise signal <campaign-id> force_pivot

# Inject a manually-crafted seed into the running corpus
crashwise signal <campaign-id> inject_seed --path /path/to/seed

# Pause a campaign for review
crashwise signal <campaign-id> pause_hunt

# Resume a paused campaign
crashwise signal <campaign-id> resume_hunt
```

---

## Testing

```bash
# Run the full test suite (416 tests)
uv run pytest tests/ -v

# With coverage report
uv run pytest tests/ --cov=crashwise --cov-report=html

# Unit tests only (fast, no infrastructure needed)
uv run pytest tests/unit/ -v

# Lint
uv run ruff check crashwise/ tests/

# Type check
uv run mypy crashwise/
```

---

## Project Structure

```
crashwise/
├── cli.py                    # Typer CLI entry point
├── api/main.py               # FastAPI REST API
├── dashboard/                # Streamlit intelligence dashboard
├── core/                     # Shared foundation layer
│   ├── config.py             #   Pydantic-settings (env-based config)
│   ├── models.py             #   Shared Pydantic data models
│   ├── database.py           #   SQLAlchemy async ORM
│   ├── discovery.py          #   Auto-detection of build systems
│   ├── sentinel.py           #   System diagnostics & provisioning
│   ├── redis.py              #   Redis client
│   ├── storage.py            #   R2/S3 object storage
│   ├── ai_provider.py        #   Ollama/Venice inference providers
│   └── notifications.py      #   Webhook/SMTP/PGP alerts
├── orchestration/            # Temporal workflows + activities
│   ├── workflows/            #   MainFuzzingWorkflow, VerifyPatch, etc.
│   └── activities/           #   22 activity implementations
├── agents/                   # LangGraph AI agents
│   ├── harness_synth/        #   Harness generation & evolution
│   ├── triage/               #   Crash classification & exploit gen
│   ├── feedback/             #   Coverage feedback loop
│   ├── research/             #   Target profiling, CVE harvesting
│   ├── execution/            #   MAB strategist (Thompson Sampling)
│   └── reporting/            #   CVSS scoring & report generation
├── execution/                # Fuzzer execution layer
│   ├── docker_manager.py     #   Hardened Docker orchestration
│   ├── qemu_manager.py       #   QEMU/KVM VMs
│   └── monitor.py            #   Fuzzer stats parsing
└── kernelbridge/             # Linux kernel fuzzing (syzkaller)
```

---

## Development Status

> **CrashWise is under active development (pre-alpha).** The core autonomous
> pipeline works end-to-end, but some components are more mature than others.
> Contributions from the security research community are welcome to help
> improve coverage, fix edge cases, and expand target support.

### What Works Today (Verified)

| Component | Status | Detail |
|-----------|--------|--------|
| Target cloning | ✅ Working | `git clone --recursive` with branch/tag support, shallow + full fallback |
| Build system detection | ✅ Working | CMake, Make, Meson, Bazel, Cargo, Go auto-detected |
| Instrumented build | ✅ Working | Injects `-fsanitize=address,undefined` + coverage flags via CC/CXX/CFLAGS |
| Existing harness detection | ✅ Working | Finds `LLVMFuzzerTestOneInput` in fuzz/harness files |
| AI harness synthesis | ✅ Working | LangGraph agent with retry loop + deterministic fallback |
| Docker fuzzing execution | ✅ Working | Hardened containers with real AFL++/libFuzzer invocation |
| Coverage feedback loop | ✅ Working | AFL++ stats/plot_data parsed, stall detection with 5 conditions |
| MAB strategy switching | ✅ Working | Thompson Sampling between 5 fuzzing configurations |
| Crash triage | ✅ Working | ASAN regex parsing (0.85 confidence) + LLM deep analysis |
| Stack-hash deduplication | ✅ Working | Eliminates duplicate crashes before reporting |
| God-Mode signals | ✅ Working | Pause/resume/pivot/inject with acknowledgement queries |
| Pre-flight gate | ✅ Working | Refuses to launch without Docker/Clang/GCC |

### What's Still Maturing

| Component | Status | What to Expect |
|-----------|--------|----------------|
| Harness evolution (LLM) | ⚠️ Works, quality varies | LLM-generated rewrites depend on model quality; fallback templates always compile |
| Kernel fuzzing (syzkaller) | ⚠️ Parsers only | OOPS/KASAN/KFENCE log parsing works; automated syzkaller campaign orchestration is planned |
| PoC / exploit generation | ⚠️ Template + LLM | Produces standalone C PoCs; reachability analysis is heuristic-based |
| Patch verification | ⚠️ Basic pipeline | Clone → apply → build → test works; complex patches may need manual review |
| Seed harvester | ⚠️ Format-aware generation | Generates valid format seeds (PNG/JPEG/ZIP/etc.); real CVE corpus download is planned |

### What's Planned (Not Yet Implemented)

| Feature | Target Version |
|---------|---------------|
| Multi-target parallel scheduling | v2.0 |
| WebAssembly/WASI target support | v2.0 |
| Cloud-native auto-scaling (Kubernetes) | v2.0 |
| Real CVE corpus download from OSS-Fuzz/exploit-db | v1.2 |
| Dashboard cockpit (live execs/sec, MAB arm, hotspots) | v1.1 |
| Harness lineage DB (crash → run → MAB arm → harness version) | v1.2 |

---

## Supported Targets

### What CrashWise IS Designed For

CrashWise autonomously finds **memory-safety vulnerabilities** in
**open-source C/C++ projects** that compile with standard build systems.

| Requirement | Detail |
|-------------|--------|
| **Source code** | Must be available (git-cloneable). CrashWise compiles with sanitizer instrumentation. |
| **Language** | C, C++, Rust (via Cargo), Go (via go-fuzz) |
| **Build system** | CMake, Make, Meson, Bazel, Cargo, Go modules |
| **Compiler** | Must compile with Clang (for `-fsanitize` support) |
| **OS** | Linux only (AFL++/libFuzzer are Linux-native) |
| **Input type** | File/buffer parsers (image, archive, network, crypto, font, etc.) |

**Best results with:**
- Projects that already have fuzz harnesses (libjxl, openssl, libpng, zlib, freetype)
- Parser libraries that take `(uint8_t*, size_t)` as input
- Projects with CMakeLists.txt or Makefile at the root
- Code with clear entry points (functions named `parse`, `decode`, `read`, etc.)

### What CrashWise is NOT Designed For

| Target Type | Why It Won't Work |
|-------------|-------------------|
| **Closed-source binaries** | Requires source for sanitizer instrumentation. Use AFL++ QEMU mode directly instead. |
| **Windows-only code (MSVC)** | Requires Clang compilation. MSVC sanitizers are not supported. |
| **Managed languages (Java, Python, C#)** | Memory-safety bugs don't apply. Use language-specific fuzzers (Jazzer, Atheris). |
| **Network services / daemons** | CrashWise fuzzes file/buffer parsers, not live network protocols. Use Boofuzz/AFL++ network mode. |
| **GUI applications** | No UI interaction. CrashWise targets library functions, not user-facing apps. |
| **Projects with proprietary dependencies** | Build will fail if required SDKs aren't available in the Docker container. |
| **Extremely large monorepos** | Clone + build timeout (10min + 15min). Projects like Chromium need custom setup. |

### What Might Give False or Poor Results

| Scenario | Risk | Mitigation |
|----------|------|------------|
| No LLM configured | Harness synthesis falls back to a trivial XOR consumer — minimal coverage | Configure at least one LLM (see `.env.example`) |
| Target has no clear entry point | Regex-based entry detection may miss deeply nested APIs | Use `--harness` flag to specify a known fuzz target |
| Complex build (custom toolchains) | Auto-build may fail; campaign continues with source-only harness | Pre-build manually, provide binary via `crashwise.yaml` |
| Short timeout (< 60s) | Not enough time for AFL++ to calibrate | Use `--timeout 600` minimum for meaningful results |
| Target is already heavily fuzzed | Unlikely to find new bugs that OSS-Fuzz missed | Focus on newer/untested code paths or custom entry points |

---

## Current Limitations (Honest Assessment)

This is a **pre-alpha** project. Known limitations:

1. **Build failures are non-fatal** — If the target doesn't compile with
   the injected sanitizer flags (common with complex projects), the
   workflow continues with harness synthesis via `#include`. This may
   produce a harness that exercises fewer code paths.

2. **LLM quality matters** — Harness synthesis quality depends directly on
   the LLM model. Claude Sonnet / GPT-4o produce good harnesses;
   smaller models (7B-13B) often produce code that doesn't compile.
   The fallback harness always works but provides minimal coverage.

3. **Source-level coverage requires llvm-cov tooling** — When `llvm-profdata`
   and `llvm-cov` are available on the worker, CrashWise extracts real
   line-level coverage via `llvm-cov export`. Falls back to sancov
   symbolization, then AFL++ edge-count heuristics when tooling is absent.

4. **Single-target campaigns** — Each `crashwise run` fuzzes one target.
   Parallel multi-target scheduling is planned for v2.0.

5. **Docker worker required** — The fuzzing execution itself happens inside
   Docker containers. The host needs Docker running and the
   `aflplusplus/aflplusplus` / `libfuzzer-runner` images available.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for coding standards, testing
requirements, commit message format, and the pull request process.

---

## Security

If you discover a security vulnerability in CrashWise, please **do not** open a
public issue. Email **crashwise@yahyatoubali.me** with details and we will
coordinate a responsible disclosure timeline.

---

## License

CrashWise is licensed under the [MIT License](./LICENSE).

Copyright (c) 2026 CrashWise Contributors.
