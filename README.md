<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

<h1 align="center">CrashWise</h1>

<h4 align="center">Autonomous AI-Powered Fuzzing & Crash Triage Platform</h4>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#cli-reference">CLI</a> •
  <a href="./docs/INSTALL.md">Install Guide</a> •
  <a href="#testing">Testing</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-405%20passing-brightgreen" alt="405 tests passing">
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue" alt="Python versions">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/temporal-1.25-blue" alt="Temporal">
  <img src="https://img.shields.io/badge/docker-ready-blue" alt="Docker Ready">
  <img src="https://img.shields.io/badge/distros-Arch%20%7C%20Ubuntu%20%7C%20Fedora-orange" alt="Linux Distros">
  <img src="https://img.shields.io/badge/sandbox-network%20none%20%7C%20read--only-purple" alt="Sandboxed">
</p>

---

> **Built by Yahya Toubali, Security Researcher** — developing CrashWise under
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
| **Coverage-Guided Harness Evolution** | When fuzzing plateaus, the workflow runs `analyze_coverage` to identify the *exact* blocker (magic value, length check, checksum, state machine) at the *exact* source line, then hands the structured blocker to the LLM evolution agent — no more `BlockerType.UNKNOWN` stubs. Bounded by `max_evolution_count` to prevent runaway LLM spend. |
| **Multi-Armed Bandit Strategy Switching** | Thompson Sampling + UCB1 dynamically pivots between AFL++ and libFuzzer strategies based on real-time coverage feedback. |
| **God-Mode Signals** | Live workflow control: `crashwise signal <id> force_pivot`, `inject_seed`, `pause_hunt`, `resume_hunt`. Researchers can force a strategy pivot, drop a manually-crafted seed into the running corpus, or pause the campaign for review without restarting. |
| **Hardened Sandbox (S6)** | Fuzzer containers launch with `--network none`, `--read-only` rootfs, size-capped tmpfs, `--cap-drop ALL`, `no-new-privileges`, and a pre-flight `docker rm -f` to kill stale containers. Untrusted harnesses + attacker-controlled corpora are isolated from the host. |
| **Shell-Free Hot-Swap** | LLM-supplied compile commands are parsed with `shlex` and executed via `subprocess_exec` against an allow-list of compilers. No `shell=True`, no metacharacter expansion, no RCE surface. Compiled binaries are persisted to `~/.cache/crashwise/build/` so successful evolutions survive temp-dir cleanup. |
| **Target Profiling & Adaptive Heuristics** | Automatically profiles target domain (crypto, media, network, parser), complexity, attack surface, and dangerous functions to tune fuzzer flags. |
| **Intelligent Triage** | LLM-powered crash classification (ASAN/GDB) with deterministic regex fallback. Deduplicates by stack-hash. |
| **KernelBridge** | Native Linux kernel fuzzing via syzkaller integration — parses OOPS, KASAN, and KFENCE reports. |
| **Hybrid AI Root Cause Analysis** | Ollama (local) or Venice (cloud) inference providers for deep RCA, patch suggestion, and exploitability scoring. |
| **Automated PoC / Exploit Generation** | Exploit Architect agent transforms crash data into standalone C PoCs with reachability analysis and primitive detection. |
| **Patch Verification** | End-to-end pipeline: clone → apply patch → build → regression test → verify crash is fixed. |
| **Auto-Disclosure Engine** | CVSS v3.1 scoring, platform-specific report generation (HackerOne, Bugcrowd, kernel ML), and webhook/email/PGP notifications. |
| **Intelligence Dashboard** | Streamlit-based real-time dashboard for campaign monitoring, crash heatmaps, CWE filtering, patch viewing, and bounty export. |
| **Distributed Storage** | Cloudflare R2 (S3-compatible) for crash artefacts and Redis for counters, dedup cache, and worker heartbeats. |
| **System Sentinel** | `crashwise doctor` diagnoses your host (hardware, Docker, build tools, services). `crashwise setup` is interactive, distro-aware, and offers to fix `docker` group membership and start the daemon. |
| **Master Worker Image** | Self-contained `Dockerfile.worker` bundles AFL++, libFuzzer, Clang, LLVM — the host only needs Docker. |
| **Production Packaging** | Multi-stage Dockerfile, full-stack docker-compose, and GitHub Actions CI/CD with ruff, mypy, pytest, and Docker build. |

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
│  ┌─────────────────────────────────────────────────────────────────────┐      │
│  │                     Temporal Activities (18 total)                   │      │
│  │  setup_target      execute_fuzzing     triage_results               │      │
│  │  seed_corpus       analyze_progress    analyze_crash                │      │
│  │  pivot_strategy    analyze_coverage    evolve_harness               │      │
│  │  hot_swap_harness  mutate_harness      inject_seeds                 │      │
│  │  verify_patch      verify_poc          notify_stakeholders          │      │
│  │  kernel_monitor    profile_target      execute_job                  │      │
│  └─────────────────────────────────────────────────────────────────────┘      │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Agent Layer (LangGraph + LLM)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ HarnessSynth │  │   Triage     │  │   Patcher    │  │ ExploitArch  │  │
│  │   Agent      │  │   Agent      │  │   Agent      │  │    Agent     │  │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤  │
│  │ Coverage     │  │   MAB        │  │   Profiler   │  │ Reachability │  │
│  │ Analyzer     │  │ Strategist   │  │   Agent      │  │   Engine     │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Execution Layer                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │  Docker    │  │   QEMU     │  │   Local    │  │  Kernel (syzkaller)│   │
│  │  (AFL++)   │  │  (KVM)     │  │  (libFuzzer│  │                    │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Persistence & Storage                                │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │ PostgreSQL │  │   Redis    │  │  Cloudflare│  │   Local SQLite     │   │
│  │ (Campaigns)│  │ (Counters) │  │    R2      │  │   (dev mode)       │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Tech Stack**

| Layer | Technology |
|-------|-----------|
| Orchestration | Temporal (Python SDK) |
| AI Engine | LangGraph + LangChain + Venice / Ollama |
| Validation | Pydantic v2 |
| Web API | FastAPI + Uvicorn |
| Dashboard | Streamlit |
| CLI | Typer + Rich |
| Logging | structlog |
| Package Mgmt | uv |
| Lint/Format | ruff |
| Type Check | mypy (strict) |
| Testing | pytest + pytest-asyncio + pytest-cov |
| Fuzzers | AFL++, libFuzzer, honggfuzz |
| Execution | Docker, QEMU/KVM |
| Database | PostgreSQL (prod), SQLite (dev) |
| Cache | Redis |
| Object Storage | Cloudflare R2 / S3-compatible |

---

## Quick Start

### Prerequisites

- Linux x86_64 (kernel ≥ 5.10)
- Python 3.11+
- Docker & Docker Compose
- Git
- ≥ 8 GB RAM, ≥ 50 GB free disk

Everything else (Clang, GCC, LLVM, CMake, AFL++) is provisioned automatically by
`crashwise setup`. See [`docs/INSTALL.md`](./docs/INSTALL.md) for the full
**Zero-Friction Install Guide** covering both Arch Linux and Ubuntu.

### Zero-Friction Install (any distro)

```bash
git clone https://github.com/yahyatoubali/Crashwise.git
cd Crashwise

python -m venv .venv && source .venv/bin/activate
pip install -e .

crashwise setup     # interactive: detects distro, installs deps, fixes docker group
crashwise doctor    # verify the host is ready
```

After `pip install -e .` the `crashwise` binary is on your `$PATH` and works
from any directory.

### System Health Check

```bash
crashwise doctor    # full Sentinel report (hardware, Docker, build tools, services)
crashwise setup     # interactive provisioner (Arch/Ubuntu/Fedora; non-root → sudo)
crashwise setup -y  # non-interactive (CI / scripted use)
crashwise setup --dry-run  # print the install script without executing it
```

### One-Command Stack

> **⚠️ Use `docker compose` (v2 plugin), NOT `docker-compose`.**
> The legacy Python `docker-compose` v1 is incompatible with modern
> Docker Engines and will crash with `KeyError: 'ContainerConfig'`.
> See [docs/INSTALL.md](./docs/INSTALL.md#legacy-docker-compose-v1--keyerror-containerconfig)
> for the migration steps. Verify with `docker compose version` —
> should report `v2.x.x`.

```bash
# 1. Configure (edit secrets as needed)
cp .env.example .env

# 2. Launch the full stack (Temporal, Postgres, Redis, MinIO, API, Dashboard, worker)
docker compose up -d

# 3. Verify services
curl http://localhost:8000/health          # FastAPI API
curl http://localhost:8501/_stcore/health  # Streamlit Dashboard
xdg-open http://localhost:8233             # Temporal Web UI
```

### Zero-Config Target Onboarding

```bash
# 1. Navigate to any C/C++/Rust/Go project
cd /path/to/my-project

# 2. Auto-detect and initialise
crashwise init
# → Detects build system, language, harness
# → Generates crashwise.yaml manifest
# → Initialises database

# 3. Start fuzzing (reads crashwise.yaml automatically)
crashwise run
# → Pre-flight gate verifies Docker / Clang / GCC are working
# → Refuses to launch with actionable hint if anything is missing
```

### Local Development

```bash
# 1. Install dependencies (uv preferred; pip works too)
uv sync                    # or: pip install -e ".[dev]"

# 2. Run the test suite
uv run pytest tests/unit/  # 405 passing tests

# 3. Start a Temporal worker
uv run crashwise worker

# 4. Submit a fuzzing job (in another terminal)
uv run crashwise run https://github.com/libjxl/libjxl \
  --fuzzer libfuzzer \
  --timeout 1800 \
  --sanitizers address,undefined

# 5. Launch the API server
uv run crashwise api --reload

# 6. Launch the dashboard
uv run crashwise dashboard
```

### Live Campaign Control (God-Mode Signals)

While a campaign is running, intervene without restarting:

```bash
# Get the workflow ID from the `crashwise run` output (or Temporal UI).
crashwise signal <workflow_id> force_pivot --data "JXL plateau detected"
crashwise signal <workflow_id> inject_seed --data filename=/tmp/poc.jxl
crashwise signal <workflow_id> pause_hunt
crashwise signal <workflow_id> resume_hunt
```

---

## CLI Reference

```
$ crashwise --help

 Usage: crashwise [OPTIONS] COMMAND [ARGS]...

 CrashWise — autonomous AI-powered fuzzing & crash triage.

╭─ Commands ───────────────────────────────────────────────────────────────╮
│ version      Print the installed CrashWise version.                      │
│ info         Print runtime + configuration metadata.                      │
│ init         Initialise a project (detect → manifest → DB).               │
│ doctor       System health diagnostic (Sentinel).                         │
│ setup        Interactive distro-aware provisioner (Arch/Ubuntu/Fedora).   │
│ run          Submit a fuzzing workflow (with mandatory pre-flight gate).  │
│ worker       Start a Temporal worker.                                     │
│ api          Launch the FastAPI management server.                        │
│ dashboard    Launch the Streamlit intelligence dashboard.                 │
│ signal       Send God-Mode signals to a live campaign workflow.           │
│ exploit      Generate a standalone PoC for a confirmed crash.             │
╰──────────────────────────────────────────────────────────────────────────╯
```

### Example Commands

```bash
# System diagnostics (Sentinel)
crashwise doctor

# Distro-aware provisioning (Arch / Ubuntu / Fedora)
crashwise setup --dry-run   # preview first
crashwise setup             # interactive (asks before each privileged command)
crashwise setup --yes       # non-interactive (CI / scripted)
crashwise setup --output setup.sh   # write the script to a file for review

# Zero-config onboarding
cd my-project && crashwise init && crashwise run

# Explicit target submission (pre-flight gate is on by default)
crashwise run https://github.com/openssl/openssl \
  --fuzzer libfuzzer --timeout 600 --branch master

# Skip the pre-flight gate (only inside the dockerised worker)
crashwise run https://github.com/openssl/openssl --skip-preflight

# God-Mode signals — intervene in a live campaign
crashwise signal crashwise-abc123 force_pivot --data "stuck on magic value"
crashwise signal crashwise-abc123 inject_seed --data filename=/tmp/poc.jxl
crashwise signal crashwise-abc123 pause_hunt
crashwise signal crashwise-abc123 resume_hunt

# Start a worker with custom Temporal endpoint
crashwise worker --host temporal.example.com:7233

# Generate and verify a PoC for crash ID abc-123
crashwise exploit abc-123 --verify --output /tmp/poc.c

# Launch API with multiple workers
crashwise api --port 8000 --workers 4

# Launch dashboard pointing to remote API
crashwise dashboard --api-url https://api.crashwise.io
```

---

## Testing

CrashWise maintains **405 passing tests** across the audited surface (423
collected; the deselected suite excludes 2 pre-existing CLI mocks and 4
network-dependent AI-provider tests).

```bash
# Run the full suite
uv run pytest tests/ -v

# With coverage
uv run pytest tests/ --cov=crashwise --cov-report=html

# Lint and type check
uv run ruff check crashwise/ tests/
uv run ruff format --check crashwise/ tests/
uv run mypy crashwise/ --config-file pyproject.toml
```

| Test Suite | Count | Focus |
|-----------|-------|-------|
| `test_smoke.py` | 4 | Basic imports, config loading |
| `test_models.py` | 4 | Pydantic model round-trips |
| `test_workflow.py` | 3 | Temporal workflow sandbox (incl. MAB-enabled) |
| `test_compiler.py` | 2 | Harness compiler |
| `test_harness_synth_graph.py` | 5 | LangGraph harness generation |
| `test_harness_evolution.py` | 35 | Coverage blockers, harness rewriting |
| `test_analyzer.py` | 5 | Source / coverage analyser |
| `test_triage.py` | 12 | Crash classification, dedup, GDB parsing |
| `test_ai_triage.py` | 16 | LLM-driven triage path |
| `test_exploit_gen.py` | 35 | Exploit Architect, primitives, reachability |
| `test_kernelbridge.py` | 14 | Kernel bridge, OOPS / KASAN / KFENCE parsing |
| `test_execution.py` | 19 | Docker manager, fuzz job execution, S6 sandbox flags |
| `test_real_execution.py` | 6 | Real Docker fuzzing path with mocked daemon |
| `test_feedback.py` | 13 | Coverage analysis, zero-coverage detection (B10) |
| `test_research.py` | 15 | CVE harvester, PoC transformer |
| `test_database.py` | 8 | SQLAlchemy ORM, async CRUD |
| `test_api.py` | 8 | FastAPI endpoints |
| `test_api_v2.py` | 8 | FastAPI v2 endpoints |
| `test_storage.py` | 11 | R2 storage, sync directory |
| `test_redis.py` | 18 | Redis client, MAB persistence, heartbeat |
| `test_verification.py` | 11 | Patch apply, build, regression |
| `test_reporting.py` | 18 | CVSS, report generation, notifications |
| `test_cli.py` | 16 | CLI commands, pre-flight gate, signal command |
| `test_mab_strategist.py` | 23 | Thompson Sampling, UCB1, plateau detection |
| `test_profiler.py` | 26 | Target profiling, attack surface |
| `test_manifest.py` | 27 | Manifest round-trip, discovery, validation |
| `test_sentinel.py` | 61 | Distro detection, per-distro packages, AUR split, sudo prefix |
| **Total** | **423** | **405 passing on touched surface** |

---

## Repository Layout

```
Crashwise/
├── crashwise/                    # Main Python package
│   ├── core/                     # Config, logging, models, database, sentinel
│   │   ├── ai_provider.py        # Ollama / Venice / Null inference providers
│   │   ├── config.py             # Pydantic-settings configuration
│   │   ├── database.py           # SQLAlchemy async ORM (Campaign, Crash, Seed)
│   │   ├── discovery.py          # Autodiscovery engine (CMake, Cargo, Go...)
│   │   ├── logging.py            # structlog setup
│   │   ├── manifest.py           # crashwise.yaml Pydantic model
│   │   ├── models.py             # Pydantic I/O models for all boundaries
│   │   ├── notifications.py      # Webhook + SMTP + PGP notification router
│   │   ├── redis.py              # Redis client (counters, dedup, MAB persistence)
│   │   ├── sentinel.py           # DistroDetector + per-distro provisioner
│   │   └── storage.py            # R2/S3 object storage
│   ├── agents/                   # LangGraph AI agents
│   │   ├── harness_synth/        # Harness synthesis (C/C++ → fuzzer binary)
│   │   │   ├── analyzer.py       # Source-code analyser (entry points, signature)
│   │   │   ├── compiler.py       # Compile orchestration
│   │   │   ├── evolution.py      # Harness Evolution Node (blocker-bypass rewrites)
│   │   │   ├── graph.py          # LangGraph workflow
│   │   │   ├── llm.py            # LLM provider integration
│   │   │   ├── nodes.py          # analyze_code → generate → validate
│   │   │   ├── prompts.py        # System / user / retry prompt templates
│   │   │   ├── state.py          # HarnessState (Pydantic)
│   │   │   └── synth.py          # Top-level synthesise_harness coroutine
│   │   ├── triage/               # Crash triage (analyzer, dedup, exploit_gen)
│   │   ├── feedback/             # Coverage feedback (zero-cov detection, mutation hints)
│   │   ├── research/             # Profiler, harvester, coverage_analyzer, transformer
│   │   ├── execution/            # MAB strategist (Thompson / UCB1)
│   │   └── reporting/            # CVSS calculator + report generator
│   ├── api/                      # FastAPI REST API
│   ├── dashboard/                # Streamlit intelligence dashboard
│   ├── orchestration/            # Temporal workflows & activities
│   │   ├── client.py             # Temporal client with retry logic
│   │   ├── worker.py             # Worker bootstrap
│   │   ├── data_converter.py     # Pydantic ↔ Temporal payload converter
│   │   ├── workflows/            # MainFuzzingWorkflow + signal handlers
│   │   └── activities/           # 18 Temporal activities incl. inject_seeds, evolve_harness, analyze_coverage
│   ├── execution/                # Fuzzer execution backends
│   │   ├── docker_manager.py     # Hardened Docker orchestration (network none, read-only, …)
│   │   ├── monitor.py            # Per-fuzzer health checker (AFL stats vs libFuzzer log)
│   │   ├── dispatcher.py         # Profile-aware fuzzer selection
│   │   └── qemu_manager.py       # QEMU/KVM VM orchestration
│   ├── kernelbridge/             # syzkaller / OOPS / KASAN / KFENCE parser
│   ├── research/                 # Reachability engine
│   └── cli.py                    # Universal CLI entry point (incl. `signal`, pre-flight)
├── tests/                        # Comprehensive test suite
│   └── unit/                     # 27 test files, 423 collected, 405 passing
├── docs/                         # User-facing documentation
│   ├── architecture.md           # In-depth architecture write-up
│   └── INSTALL.md                # Zero-Friction Install Guide (Arch + Ubuntu)
├── .github/workflows/            # CI/CD pipelines
├── docker-compose.yaml           # Full-stack production orchestration
├── Dockerfile                    # Multi-stage production image (API/Dashboard)
├── Dockerfile.worker             # Master Worker fuzz-node (AFL++, Clang, LLVM)
├── pyproject.toml                # uv-managed, PEP 621, console-script entry point
├── CHANGELOG.md                  # Phase-by-phase development history
├── CONTRIBUTING.md               # Project contribution standards
└── LICENSE                       # MIT
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

3. **No source-level coverage mapping** — Coverage data from AFL++ is
   edge-count-based, not line-level (would require `llvm-cov` integration).
   The coverage analyzer uses heuristic blocker detection.

4. **Single-target campaigns** — Each `crashwise run` fuzzes one target.
   Parallel multi-target scheduling is planned for v2.0.

5. **Docker worker required** — The fuzzing execution itself happens inside
   Docker containers. The host needs Docker running and the
   `aflplusplus/aflplusplus` / `libfuzzer-runner` images available.

---

## Contributing

CrashWise is a community-driven project. We welcome contributions that:

- **Fix real bugs** in the pipeline (clone/build/fuzz/triage)
- **Add target support** (new build systems, languages, formats)
- **Improve harness quality** (better LLM prompts, more fallback templates)
- **Expand seed generation** (new format-aware seeds, real corpus download)
- **Harden the sandbox** (seccomp profiles, better OOM handling)

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for coding standards,
commit format, and PR process.

---

## Acknowledgements

CrashWise builds on the shoulders of giants:

- [AFL++](https://github.com/AFLplusplus/AFLplusplus) — The gold-standard fuzzer
- [libFuzzer](https://llvm.org/docs/LibFuzzer.html) — In-process fuzzing engine
- [syzkaller](https://github.com/google/syzkaller) — Linux kernel fuzzing
- [Temporal](https://temporal.io) — Durable execution platform
- [LangGraph](https://langchain-ai.github.io/langgraph/) — LLM agent orchestration
- [Ollama](https://ollama.com) / [Venice.ai](https://venice.ai) — Local & private inference

---

## License

[MIT](./LICENSE) © 2026 CrashWise Contributors

Built with ❤️ by **Yahya Toubali**, Security Researcher — developing under the **Nadicorp** label.
