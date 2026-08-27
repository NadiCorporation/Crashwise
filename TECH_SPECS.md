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

---

## 4. Proposed Stack & Infrastructure Upgrades

| Component | Current Stack | Proposed Stack | Primary Justification |
|---|---|---|---|
| **Container Engine** | Docker CLI (`subprocess` + `--init`) | Docker Engine REST API (`aiohttp` over `/var/run/docker.sock`) or containerd | Eliminates fork/exec overhead; sub-millisecond status polling and multiplexed streaming. |
| **Workflow Engine** | Temporal.io (28 Activities) | Temporal.io (Pure Activities + Object Storage References) | Strict determinism; large blobs (corpora, binaries, ASAN logs) stored in R2/S3; only UUIDs/URIs passed in workflows. |
| **Persistence** | Pooled SQLAlchemy 2.0 (asyncpg) | Unified PostgreSQL 16 schema + SQLAlchemy 2.0 (asyncpg) | Single source of truth; persistent connection pooling; eliminates redundant tables and engine re-creation. |
| **Telemetry & Events** | Polled SQL / Ad-hoc SSE | Redis Pub/Sub / SSE Stream via FastAPI | Real-time fuzzer stats broadcasting without database query saturation. |
| **Frontend** | Dual (Streamlit + Next.js 14) | Next.js 14 (App Router + Tailwind + TypeScript) | Unified, reactive production UI; deprecation of prototype Streamlit interface. |
| **LLM Orchestration** | Universal `llm_factory` (Multi-Provider) | Unified `llm_factory` + LangGraph StateGraph + native Docker tool executors | Clean separation of agent prompts, provider-agnostic token management, and hardened sandbox execution. |

---

## 5. Trade-off Analysis

### 5.1 Docker Socket REST API vs. Subprocess CLI
* **Pros:** ~90% reduction in CPU and context-switch overhead; persistent HTTP/1.1 connection over UNIX domain socket; structured JSON responses without text scraping.
* **Cons:** Requires implementing or maintaining a lightweight Docker API client wrapper.
* **Complexity:** Medium (approx. 2-3 days engineering).
* **Verdict:** **Strongly Recommended.**

### 5.2 Artifact Pass-by-Reference (S3/R2) vs. In-Workflow Payloads
* **Pros:** Workflows remain ultra-compact (<50KB history); immune to Temporal 4MB message caps; enables multi-gigabyte corpus transfers.
* **Cons:** Requires active MinIO/S3/R2 instance for local development and integration tests.
* **Complexity:** Low.
* **Verdict:** **Strongly Recommended.**

### 5.3 Unified PostgreSQL Schema vs. Dual Core/Web Schemas
* **Pros:** Eliminates table duplication (`campaigns` vs `web_campaigns`, `crashes` vs `web_crashes`); eliminates connection pool thrashing in `web/hooks.py`; consistent foreign key cascades.
* **Cons:** Requires migrating existing database tables and updating endpoint queries.
* **Complexity:** Low to Medium.
* **Verdict:** **Mandatory for stability.**

### 5.4 Next.js Control Plane vs. Streamlit
* **Pros:** Native WebSocket/SSE support; responsive multi-tab layout (Live Stats, Crash Matrix, God-Mode signal triggers); production-grade security and authentication readiness.
* **Cons:** Requires Node.js runtime and separate build stage (`Dockerfile.frontend`).
* **Complexity:** Already built in codebase (`crashwise/web/frontend`); just requires retiring Streamlit references in docs and CLI defaults.
* **Verdict:** **Adopt Next.js as primary UI; maintain Streamlit only as lightweight CLI fallback.**
