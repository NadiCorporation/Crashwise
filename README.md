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
  <img src="https://img.shields.io/badge/tests-237%20passing-brightgreen" alt="237 tests passing">
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue" alt="Python versions">
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
| **AI-Driven Harness Synthesis** | LangGraph agent that reads target source code and autonomously generates AFL++/libFuzzer-compatible C harnesses. |
| **Intelligent Triage** | LLM-powered crash classification (ASAN/GDB) with deterministic regex fallback. Deduplicates by stack-hash. |
| **KernelBridge** | Native Linux kernel fuzzing via syzkaller integration — parses OOPS, KASAN, and KFENCE reports. |
| **Hybrid AI Root Cause Analysis** | Ollama (local) or Venice (cloud) inference providers for deep RCA, patch suggestion, and exploitability scoring. |
| **Automated PoC / Exploit Generation** | Exploit Architect agent transforms crash data into standalone C PoCs with reachability analysis. |
| **Patch Verification** | End-to-end pipeline: clone → apply patch → build → regression test → verify crash is fixed. |
| **Auto-Disclosure Engine** | CVSS v3.1 scoring, platform-specific report generation (HackerOne, Bugcrowd, kernel ML), and webhook/email notifications. |
| **Intelligence Dashboard** | Streamlit-based real-time dashboard for campaign monitoring, crash heatmaps, CWE filtering, and patch viewing. |
| **Distributed Storage** | Cloudflare R2 (S3-compatible) for crash artefacts and Redis for counters, dedup cache, and worker heartbeats. |
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
│  │ MainFuzzing │  │ VerifyPatch │  │ SeedCorpus  │  │  NotifyStake-   │   │
│  │  Workflow   │  │  Workflow   │  │  Workflow   │  │   holders       │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────────┘   │
├─────────┼────────────────┼────────────────┼─────────────────────────────────┤
│         ▼                ▼                ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐      │
│  │                     Temporal Activities                              │      │
│  │  setup_target  execute_fuzzing  triage_results  analyze_crash     │      │
│  │  seed_corpus   mutate_harness   verify_patch    verify_poc         │      │
│  │  kernel_monitor  analyze_progress  notify_stakeholders             │      │
│  └─────────────────────────────────────────────────────────────────────┘      │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Agent Layer (LangGraph + LLM)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ HarnessSynth │  │   Triage     │  │   Patcher    │  │ ExploitArch  │  │
│  │   Agent      │  │   Agent      │  │   Agent      │  │    Agent     │  │
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
| AI Engine | LangGraph + LangChain + OpenAI/Anthropic/Ollama |
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

### One-Command Deployment

```bash
# 1. Clone
git clone https://github.com/yahyatoubali/Crashwise.git
cd crashwise

# 2. Configure (edit secrets as needed)
cp .env.example .env

# 3. Launch the full stack
docker compose up -d

# 4. Verify services
curl http://localhost:8000/health      # FastAPI API
curl http://localhost:8501/_stcore/health  # Streamlit Dashboard
open http://localhost:8233              # Temporal Web UI
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
│ init         One-time database initialisation (creates tables).           │
│ run          Submit a fuzzing workflow.                                   │
│ worker       Start a Temporal worker.                                     │
│ api          Launch the FastAPI management server.                        │
│ dashboard    Launch the Streamlit intelligence dashboard.                 │
│ exploit      Generate a standalone PoC for a confirmed crash.           │
╰──────────────────────────────────────────────────────────────────────────╯
```

### Example Commands

```bash
# Database setup
crashwise init --force

# Submit a fuzzing campaign
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

CrashWise maintains **237 passing tests** across 15 phases of development:

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
| `test_smoke.py` | 2 | Basic imports, config loading |
| `test_workflow.py` | 2 | Temporal workflow sandbox |
| `test_harness_synth.py` | 8 | LangGraph harness generation |
| `test_triage.py` | 10 | Crash classification, dedup, GDB parsing |
| `test_execution.py` | 5 | Docker manager, fuzz job execution |
| `test_feedback.py` | 7 | Coverage analysis, patch suggestion |
| `test_seeding.py` | 9 | CVE harvester, PoC transformer |
| `test_api.py` | 6 | FastAPI endpoints, DB integration |
| `test_distributed.py` | 12 | R2 storage, Redis counters |
| `test_ai_agent.py` | 8 | Inference providers, patcher |
| `test_dashboard.py` | 4 | Export endpoints |
| `test_verification.py` | 11 | Patch apply, build, regression |
| `test_reporting.py` | 18 | CVSS, report generation, notifications |
| `test_cli.py` | 15 | CLI commands, error handling |
| `test_exploit_gen.py` | 35 | PoC generation, reachability, verification |
| **Total** | **237** | **100% pass rate** |

---

## Repository Layout

```
crashwise/
├── crashwise/                    # Main Python package
│   ├── core/                     # Config, logging, models, database
│   │   ├── ai_provider.py        # Ollama / Venice / Null inference providers
│   │   ├── config.py             # Pydantic-settings configuration
│   │   ├── database.py           # SQLAlchemy async ORM (Campaign, Crash, Seed)
│   │   ├── logging.py            # structlog setup
│   │   ├── models.py             # Pydantic I/O models for all boundaries
│   │   ├── notifications.py      # Webhook + SMTP + PGP notification router
│   │   └── redis.py              # Redis client (counters, dedup, heartbeat)
│   ├── agents/                   # LangGraph AI agents
│   │   ├── harness_synth/        # Harness synthesis (C → fuzzer binary)
│   │   ├── triage/               # Crash triage (analyzer, dedup, exploit_gen)
│   │   ├── feedback/             # Coverage feedback + patch suggestion
│   │   ├── seeding/              # CVE harvester + PoC transformer
│   │   └── reporting/            # CVSS calculator + report generator
│   ├── api/                      # FastAPI REST API
│   │   └── main.py               # Campaigns, crashes, health, export endpoints
│   ├── dashboard/                # Streamlit intelligence dashboard
│   │   └── app.py                # Campaigns, crash intelligence, cluster status
│   ├── orchestration/            # Temporal workflows & activities
│   │   ├── client.py             # Temporal client with retry logic
│   │   ├── worker.py             # Worker bootstrap
│   │   ├── workflows/            # MainFuzzingWorkflow, VerifyPatchWorkflow
│   │   └── activities/           # All 14 Temporal activities
│   ├── execution/                # Fuzzer execution backends
│   │   ├── docker_manager.py     # Docker container orchestration
│   │   └── qemu_manager.py       # QEMU/KVM VM orchestration
│   ├── research/                 # Reachability analysis, static analysis
│   │   └── reachability.py       # AST + regex-based entry point detection
│   └── cli.py                    # Universal CLI entry point
├── tests/                        # Comprehensive test suite
│   └── unit/                     # 237 unit tests (mocked, fast)
├── .github/workflows/            # CI/CD pipelines
│   ├── ci.yml                    # Lint, type-check, test, build
│   └── release.yml               # Automated releases on v* tags
├── docker-compose.yaml           # Full-stack production orchestration
├── Dockerfile                    # Multi-stage production image
├── pyproject.toml                # uv-managed, PEP 621
├── CHANGELOG.md                  # Phase-by-phase development history
├── CONTRIBUTING.md               # Project contribution standards
└── LICENSE                       # MIT
```

---

## Roadmap

| Version | Status | Highlights |
|---------|--------|-----------|
| v0.1.0 | ✅ Complete | Foundation, Temporal, harness synthesis, triage |
| v0.2.0 | ✅ Complete | Kernel bridge, execution layer, feedback loop |
| v0.3.0 | ✅ Complete | Seeding brain, persistence, distributed storage |
| v0.4.0 | ✅ Complete | Hybrid AI agent, dashboard, patch verification |
| v0.5.0 | ✅ Complete | Auto-disclosure (CVSS, reports, notifications) |
| v0.6.0 | ✅ Complete | Production packaging, CI/CD, Docker |
| v0.7.0 | ✅ Complete | PoC generation, reachability analysis |
| **v1.0.0-rc1** | 🚀 **Current** | **Repository finalization, release docs** |
| v1.0.0 | 📋 Planned | First stable release |
| v1.1.0 | 📋 Planned | Exploit hardening, ROP chain generation |
| v1.2.0 | 📋 Planned | Multi-target campaign scheduling |
| v2.0.0 | 📋 Planned | WebAssembly target support, cloud-native scaling |

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
