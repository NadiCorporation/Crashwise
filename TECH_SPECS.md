<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# Technical Specifications & Architectural Evaluation (`TECH_SPECS.md`)

## 1. Executive Technical Summary

CrashWise is an autonomous zero-day vulnerability discovery platform combining:
1. **Cognitive Agent Layer:** LLM-powered static analysis, harness synthesis (LangGraph), automated crash triage, root-cause analysis (RCA), and self-healing build/patch generation.
2. **Deterministic Orchestration:** Durable, distributed workflow lifecycle management (Temporal.io).
3. **Execution Sandbox:** Hardened containerized fuzzing engines (AFL++, libFuzzer) with coverage-guided feedback loops and Multi-Armed Bandit (MAB) dynamic strategy optimization (Thompson Sampling).
4. **Data & Storage Plane:** Unified relational persistence (PostgreSQL/SQLite via SQLAlchemy Async), distributed caching and deduplication (Redis), and blob storage (S3/Cloudflare R2).

---

## 2. Current Architecture & Stack Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Control Plane                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  CLI (Typer + Rich)   │  FastAPI Gateway (Uvicorn)  │  Next.js 14 Dashboard │
│  :terminal            │  :8000 (REST + SSE)          │  :3000 (Web UI)       │
├───────────────────────┴──────────────────────────────┴──────────────────────┤
│                         Temporal Engine (gRPC :7233)                        │
│                         Workflow: MainFuzzingWorkflow, VerifyPatchWorkflow  │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Temporal Worker Layer (Python 3.12+)                │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ 28 Registered Activities (I/O, Compilation, Fuzzing, Healing, Triage) │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Cognitive Agent Layer (LangGraph)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ HarnessSynth │  │   Healing    │  │ CrashTriage  │  │  ExploitGen  │     │
│  │    Agent     │  │ Engine (LLM) │  │  (RCA/CWE)   │  │ (PoC Synthes)│     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Execution Sandboxes (Hardened)                      │
│  ┌─────────────────────────────────┐   ┌──────────────────────────────┐     │
│  │ Docker Engine (AFL++, libFuzzer)│   │ QEMU / KVM (Kernel targets)  │     │
│  │ --init, --network none, -ro     │   │ -nographic, -no-reboot       │     │
│  └─────────────────────────────────┘   └──────────────────────────────┘     │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Persistence & Messaging                             │
│  PostgreSQL 16 (asyncpg) │ Redis 7 (AOF/Cache/MAB) │ MinIO / Cloudflare R2   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Deep-Dive: Architecture, Hardening & Recent Resolutions

### 3.1 Subprocess & Docker Process Isolation
* **Mechanism:** Fuzzer monitoring (`docker logs --tail`, `docker stats`, `docker inspect`) and container lifecycle management (`docker run`, `docker exec`, `docker cp`, `docker stop`, `docker rm`) manage sandboxed execution.
* **Resolution & Hardening:** All container invocations now pass `--init` to run Docker's built-in `tini` as PID 1, eliminating zombie and defunct child processes on aborted or timed-out fuzz runs.

### 3.2 Temporal Workflow Determinism & Payload Limits
* **Mechanism:** Workflow state machines (`MainFuzzingWorkflow`, `VerifyPatchWorkflow`) maintain strict execution determinism across all 28 registered activities.
* **Resolution & Hardening:** Standalone activity `synthesize_harness` isolates LangGraph LLM generation from workflow replay paths. Large blobs and crash contexts are referenced through dedicated paths and persistent storage.

### 3.3 Database Engine Connection Pooling
* **Mechanism:** SQLAlchemy async engine handles relational persistence for campaigns, runs, crashes, seeds, and knowledge graph patterns.
* **Resolution & Hardening:** Implemented connection pooling with `pool_size=20, max_overflow=10, pool_pre_ping=True, pool_recycle=300` and lazy session management in `crashwise/core/database.py`, preventing engine thrashing during crash discovery bursts.

### 3.4 Multi-Provider LLM Orchestration
* **Mechanism:** LangGraph agents (Harness Synthesis, Healing Engine, Crash Triage, Exploit Generation) communicate with LLMs.
* **Resolution & Hardening:** Built universal `llm_factory.py` with dynamic provider routing (DeepSeek, OpenAI, Anthropic, Ollama, vLLM, Venice), token caps, reasoning effort tuning, and AST-level safety validation.

### 3.5 Dynamic Multi-Distro Provisioning & Zero Hardcodes (R1)
* **Mechanism:** Host environment inspection (`sentinel.py`), non-interactive setup (`configure.py`), and containerized runtime settings (`config.py`).
* **Resolution & Hardening:** Added dynamic distro identification supporting Alpine Linux (`apk`), Arch Linux (`pacman`), Fedora/RHEL (`dnf`), and Debian/Ubuntu (`apt`). Parameterized filesystem paths via `CRASHWISE_WORKDIR` (default `/tmp/crashwise`) and `CRASHWISE_BUILD_TIMEOUT` (default `900s`). Converted all `docker-compose.yaml` service credentials and ports to `${VAR:-default}` syntax.

### 3.6 Monorepo Target Scoping & Multi-System Discovery (R2)
* **Mechanism:** Target cloning, build system identification (`discovery.py`), and harness linking (`setup_target.py`, `nodes.py`).
* **Resolution & Hardening:** Added `target_subdir` with traversal sanitization for targeting sub-projects in large monorepos, configurable `target_clone_depth`, Bazel build flag injection + `bazel-bin/` artifact extraction, Meson `--reconfigure --wrap-mode=nofallback`, CMake multi-library ranking matching `target_name`, and dynamic `-Wl,-rpath,<lib_dir>` injection for `.so` shared libraries.

### 3.7 Next.js 14 Web UI Control Plane & FastAPI Management (R3)
* **Mechanism:** Real-time web monitoring and campaign orchestration (`crashwise/web/frontend`, `crashwise/api/main.py`).
* **Resolution & Hardening:** Built a 7-tab Next.js 14 operator control plane (Live Telemetry, Crash Matrix, God-Mode Signals, Campaign Launcher, In-Place System Config with secret masking, Worker Status telemetry, Live SSE Log Terminal) paired with FastAPI endpoints (`/api/config`, `/api/workers`, `/api/logs/stream`, `/campaigns/{id}/crashes/{crash_id}`).

---

## 4. Stack Topology & Component Status

| Component | Status | Production Implementation | Primary Capability |
|---|---|---|---|
| **Container Sandbox** | Production | Docker CLI (`subprocess` + `--init` + `--network none`) | Complete network and process isolation with Tini PID 1 reaping. |
| **Workflow Engine** | Production | Temporal.io (28 Registered Activities) | Durable, replayable state machine resilient to host/worker restarts. |
| **Persistence** | Production | Unified PostgreSQL 16 + Async SQLAlchemy 2.0 (`asyncpg`) | High-concurrency connection pooling (`pool_size=20, max_overflow=10`). |
| **Telemetry & Events** | Production | FastAPI SSE Streams (`/api/logs/stream`, `/telemetry/stream`) | Real-time fuzzer metrics and live log streaming without DB saturation. |
| **Operator UI** | Production | Next.js 14 Control Plane (App Router + Tailwind + TS) | 7-tab responsive Web UI dashboard on `:3000`. |
| **Target Discovery** | Production | Multi-Build Discovery Engine (CMake/Make/Meson/Bazel/Cargo/Go) | Monorepo subdirectory scoping, multi-library ranking, and `.so` RPATH. |
| **LLM Orchestration** | Production | Universal `llm_factory` + LangGraph StateGraph | Vendor-neutral routing across DeepSeek, Anthropic, OpenAI, Venice, Ollama. |

---

## 5. Architectural Verifications

### 5.1 Host & Distro Portability
* Verified across Alpine, Arch, Fedora, and Ubuntu without source code modifications.
* Zero hardcoded filesystem paths or ports in application logic.

### 5.2 Deterministic Workflow State
* Workflows remain strictly deterministic with all I/O isolated to activities.
* Test suite encompasses **786 passing automated unit and integration tests**.

### 5.3 Operator Control & Ergonomics
* Complete control plane available via CLI (`crashwise`), REST API (`:8000`), and Web Dashboard (`:3000`).
* Live runtime manipulation via God-Mode signals (`pause_hunt`, `resume_hunt`, `force_pivot`, `inject_seed`).
