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
  <a href="#testing">Testing</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-374%20passing-brightgreen" alt="374 tests passing">
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue" alt="Python versions">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/temporal-1.25-blue" alt="Temporal">
  <img src="https://img.shields.io/badge/docker-ready-blue" alt="Docker Ready">
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
| **AI-Driven Harness Synthesis** | LangGraph agent reads target source code and autonomously generates AFL++/libFuzzer-compatible C/C++ harnesses with fallback templates. |
| **Coverage-Guided Harness Evolution** | When fuzzing stalls, the Harness Evolution Node rewrites the harness to bypass coverage blockers (magic values, length checks, checksums, state machines). |
| **Multi-Armed Bandit Strategy Switching** | Thompson Sampling + UCB1 dynamically pivots between AFL++ and libFuzzer strategies based on real-time coverage feedback. |
| **Target Profiling & Adaptive Heuristics** | Automatically profiles target domain (crypto, media, network, parser), complexity, attack surface, and dangerous functions to tune fuzzer flags. |
| **Intelligent Triage** | LLM-powered crash classification (ASAN/GDB) with deterministic regex fallback. Deduplicates by stack-hash. |
| **KernelBridge** | Native Linux kernel fuzzing via syzkaller integration — parses OOPS, KASAN, and KFENCE reports. |
| **Hybrid AI Root Cause Analysis** | Ollama (local) or Venice (cloud) inference providers for deep RCA, patch suggestion, and exploitability scoring. |
| **Automated PoC / Exploit Generation** | Exploit Architect agent transforms crash data into standalone C PoCs with reachability analysis and primitive detection. |
| **Patch Verification** | End-to-end pipeline: clone → apply patch → build → regression test → verify crash is fixed. |
| **Auto-Disclosure Engine** | CVSS v3.1 scoring, platform-specific report generation (HackerOne, Bugcrowd, kernel ML), and webhook/email/PGP notifications. |
| **Intelligence Dashboard** | Streamlit-based real-time dashboard for campaign monitoring, crash heatmaps, CWE filtering, patch viewing, and bounty export. |
| **Distributed Storage** | Cloudflare R2 (S3-compatible) for crash artefacts and Redis for counters, dedup cache, and worker heartbeats. |
| **System Sentinel** | `crashwise doctor` diagnoses your host (hardware, Docker, build tools, services). `crashwise setup` auto-installs missing packages on Debian/Ubuntu. |
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
│  │                     Temporal Activities                              │      │
│  │  setup_target  execute_fuzzing  triage_results  analyze_crash     │      │
│  │  seed_corpus   mutate_harness   verify_patch    verify_poc         │      │
│  │  kernel_monitor analyze_progress pivot_strategy  hot_swap_harness   │      │
│  │  profile_target  notify_stakeholders                               │      │
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

- Python 3.11+
- Docker & Docker Compose
- Git
- CMake, Clang, LLVM (or let `crashwise setup` install them)

### System Health Check

```bash
# Diagnose your host — checks hardware, Docker, build tools, and services
crashwise doctor

# Auto-install missing dependencies (Debian/Ubuntu)
crashwise setup
```

### One-Command Deployment

```bash
# 1. Clone
git clone https://github.com/yahyatoubali/Crashwise.git
cd Crashwise

# 2. Configure (edit secrets as needed)
cp .env.example .env

# 3. Launch the full stack
docker compose up -d

# 4. Verify services
curl http://localhost:8000/health      # FastAPI API
curl http://localhost:8501/_stcore/health  # Streamlit Dashboard
open http://localhost:8233              # Temporal Web UI
```

### Zero-Config Target Onboarding (Phase 19)

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
```

### Local Development

```bash
# 1. Install dependencies (uv)
uv sync

# 2. Run tests
uv run pytest

# 3. Start a Temporal worker
uv run crashwise worker

# 4. In another terminal, submit a fuzzing job
uv run crashwise run https://github.com/glennrp/libpng \
  --fuzzer libfuzzer \
  --timeout 300 \
  --sanitizers address,undefined

# 5. Launch the API server
uv run crashwise api --reload

# 6. Launch the dashboard
uv run crashwise dashboard
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
│ setup        Auto-install missing build tools (Debian/Ubuntu).            │
│ run          Submit a fuzzing workflow (zero-config with manifest).       │
│ worker       Start a Temporal worker.                                     │
│ api          Launch the FastAPI management server.                        │
│ dashboard    Launch the Streamlit intelligence dashboard.                 │
│ exploit      Generate a standalone PoC for a confirmed crash.           │
╰──────────────────────────────────────────────────────────────────────────╯
```

### Example Commands

```bash
# System diagnostics
crashwise doctor

# Auto-provision missing tools
crashwise setup --dry-run   # preview first
crashwise setup             # execute

# Zero-config onboarding
cd my-project && crashwise init && crashwise run

# Explicit target submission
crashwise run https://github.com/openssl/openssl \
  --fuzzer libfuzzer --timeout 600 --branch master

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

CrashWise maintains **374 passing tests** across 20 phases of development:

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
| `test_workflow.py` | 2 | Temporal workflow sandbox |
| `test_activities.py` | 6 | Temporal activity stubs |
| `test_harness_synth.py` | 18 | LangGraph harness generation |
| `test_triage.py` | 12 | Crash classification, dedup, GDB parsing |
| `test_kernel.py` | 8 | Kernel bridge, PoC transformer |
| `test_execution.py` | 10 | Docker manager, fuzz job execution |
| `test_feedback.py` | 14 | Coverage analysis, patch suggestion |
| `test_research.py` | 12 | CVE harvester, PoC transformer |
| `test_database.py` | 10 | SQLAlchemy ORM, async CRUD |
| `test_api.py` | 16 | FastAPI endpoints, DB integration |
| `test_storage.py` | 12 | R2 storage, Redis counters |
| `test_redis.py` | 10 | Redis client, heartbeat |
| `test_ai_provider.py` | 12 | Inference providers (Ollama, Venice, Null) |
| `test_patcher.py` | 8 | Auto-patcher agent |
| `test_dashboard.py` | 6 | Export endpoints |
| `test_verification.py` | 10 | Patch apply, build, regression |
| `test_reporting.py` | 18 | CVSS, report generation, notifications |
| `test_cli.py` | 16 | CLI commands, error handling |
| `test_mab_strategist.py` | 23 | Thompson Sampling, UCB1, plateau detection |
| `test_harness_evolution.py` | 35 | Coverage blockers, harness rewriting |
| `test_profiler.py` | 26 | Target profiling, attack surface |
| `test_manifest.py` | 27 | Manifest round-trip, discovery, validation |
| `test_sentinel.py` | 53 | Sentinel checks, provisioner, report aggregation |
| **Total** | **374** | **100% pass rate** |

---

## Repository Layout

```
crashwise/
├── crashwise/                    # Main Python package
│   ├── core/                     # Config, logging, models, database
│   │   ├── ai_provider.py        # Ollama / Venice / Null inference providers
│   │   ├── config.py             # Pydantic-settings configuration
│   │   ├── database.py           # SQLAlchemy async ORM (Campaign, Crash, Seed)
│   │   ├── discovery.py          # Autodiscovery engine (CMake, Cargo, Go...)
│   │   ├── logging.py            # structlog setup
│   │   ├── manifest.py           # crashwise.yaml Pydantic model
│   │   ├── models.py             # Pydantic I/O models for all boundaries
│   │   ├── notifications.py      # Webhook + SMTP + PGP notification router
│   │   ├── redis.py              # Redis client (counters, dedup, heartbeat)
│   │   ├── sentinel.py           # System diagnostic engine (doctor/setup)
│   │   └── storage.py            # R2/S3 object storage
│   ├── agents/                   # LangGraph AI agents
│   │   ├── harness_synth/        # Harness synthesis (C → fuzzer binary)
│   │   │   ├── agent.py          # LLM harness generator
│   │   │   ├── graph.py          # LangGraph workflow
│   │   │   ├── templates.py      # Fallback templates
│   │   │   ├── validator.py      # Compile-time validation
│   │   │   └── evolution.py      # Harness Evolution Node (Phase 18)
│   │   ├── triage/               # Crash triage (analyzer, dedup)
│   │   ├── feedback/             # Coverage feedback + patch suggestion
│   │   ├── research/             # CVE harvester + PoC transformer
│   │   │   ├── harvester.py      # CVE PoC harvester
│   │   │   ├── profiler.py       # Target profiling (Phase 16)
│   │   │   └── coverage_analyzer.py  # Coverage blocker detection (Phase 18)
│   │   ├── execution/            # MAB strategist + dispatcher (Phase 17)
│   │   │   ├── strategist.py   # Thompson Sampling / UCB1
│   │   │   └── dispatcher.py   # Profile-aware fuzzer selection
│   │   ├── reporting/            # CVSS calculator + report generator
│   │   └── exploit/              # Exploit Architect (Phase 15)
│   │       ├── architect.py      # Primitive detection + LLM
│   │       └── reachability.py   # AST + regex reachability engine
│   ├── api/                      # FastAPI REST API
│   │   └── main.py               # Campaigns, crashes, health, export endpoints
│   ├── dashboard/                # Streamlit intelligence dashboard
│   │   └── app.py                # Campaigns, crash intelligence, cluster status
│   ├── orchestration/            # Temporal workflows & activities
│   │   ├── client.py             # Temporal client with retry logic
│   │   ├── worker.py             # Worker bootstrap
│   │   ├── workflows/            # MainFuzzingWorkflow, VerifyPatchWorkflow
│   │   └── activities/           # All 18 Temporal activities
│   ├── execution/                # Fuzzer execution backends
│   │   ├── docker_manager.py     # Docker container orchestration
│   │   └── qemu_manager.py       # QEMU/KVM VM orchestration
│   └── cli.py                    # Universal CLI entry point
├── tests/                        # Comprehensive test suite
│   └── unit/                     # 374 unit tests (mocked, fast)
├── .github/workflows/            # CI/CD pipelines
│   ├── ci.yml                    # Lint, type-check, test, build
│   └── release.yml               # Automated releases on v* tags
├── docker-compose.yaml           # Full-stack production orchestration
├── Dockerfile                    # Multi-stage production image (API/Dashboard)
├── Dockerfile.worker             # Master Worker fuzz-node (AFL++, Clang, LLVM)
├── pyproject.toml                # uv-managed, PEP 621
├── CHANGELOG.md                  # Phase-by-phase development history
├── CONTRIBUTING.md               # Project contribution standards
└── LICENSE                       # MIT
```

---

## Development Roadmap

| Phase | Status | Highlights |
|-------|--------|-----------|
| Phase 0 | ✅ Complete | Skeleton, config, logging, models |
| Phase 1 | ✅ Complete | Temporal orchestration (workflows, activities, worker) |
| Phase 2 | ✅ Complete | AI-driven harness synthesis (LangGraph agent) |
| Phase 3 | ✅ Complete | Intelligent triage (ASAN/GDB/LLM classification) |
| Phase 4 | ✅ Complete | KernelBridge (syzkaller integration) |
| Phase 5 | ✅ Complete | Execution engine (Docker, QEMU, resource monitoring) |
| Phase 6 | ✅ Complete | Feedback loop (coverage → prompt → re-synth) |
| Phase 7 | ✅ Complete | Seeding brain (CVE harvester, PoC transformer) |
| Phase 8 | ✅ Complete | Persistence (PostgreSQL, SQLite, FastAPI REST) |
| Phase 9 | ✅ Complete | Distributed storage (R2, Redis, MinIO) |
| Phase 10 | ✅ Complete | Hybrid AI agent (Ollama, Venice, Null providers) |
| Phase 11 | ✅ Complete | Intelligence dashboard (Streamlit, export) |
| Phase 12 | ✅ Complete | Patch verification (VerifyPatchWorkflow, regression) |
| Phase 13 | ✅ Complete | Auto-disclosure (CVSS, reports, notifications) |
| Phase 14 | ✅ Complete | Production packaging (Docker, CI/CD, release) |
| Phase 15 | ✅ Complete | PoC generation (Exploit Architect, reachability) |
| Phase 16 | ✅ Complete | Target profiling (domain, complexity, attack surface) |
| Phase 17 | ✅ Complete | MAB strategy switching (Thompson, UCB1, plateau) |
| Phase 18 | ✅ Complete | Harness re-synthesis (7 blocker types, hot-swap) |
| Phase 19 | ✅ Complete | Unified manifest & zero-config onboarding |
| Phase 20 | ✅ Complete | System Sentinel & Master Worker image |
| **v1.0.0** | 🚀 **Current** | **20 phases, 374 tests, production-ready** |
| v1.1.0 | 📋 Planned | Exploit hardening, ROP chain generation |
| v1.2.0 | 📋 Planned | Multi-target campaign scheduling |
| v2.0.0 | 📋 Planned | WebAssembly target support, cloud-native scaling |

---

## Validation Campaign

CrashWise has been validated against real-world targets:

| Target | Component | Result |
|--------|-----------|--------|
| **libtgvoip** (Telegram) | json11 JSON parser | ✅ 754K execs/60s, 788 coverage blocks, 0 crashes |

**Fixes discovered during validation:**
1. `--depth 1` clone misses CMake submodules → use `--recursive`
2. `json11.cpp` missing `#include <cstdint>` on Clang 22 → added
3. Temporal auto-setup fails with missing dynamic config → removed env var
4. MinIO pinned image removed from Docker Hub → use `latest`
5. `init_db()` takes `drop` not `drop_all` → fixed CLI mapping

---

## Contributing

We welcome contributions from the security research community. Please read
[CONTRIBUTING.md](./CONTRIBUTING.md) for our standards on code quality,
commit messages, and pull request etiquette.

**Project Standards (by Yahya Toubali):**
- Every file must include `SPDX-License-Identifier: MIT`
- Strict mypy typing (`--strict`) on all new code
- ruff lint + format before commit
- Tests must pass (`pytest`) and coverage should not drop
- Pydantic models on every public API boundary
- Temporal workflow determinism: no non-deterministic imports in workflow modules

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
