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
│  │ 27 Registered Activities (I/O, Compilation, Fuzzing, Healing, Triage) │  │
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
│  │ --network none, --read-only     │   │ -nographic, -no-reboot       │     │
│  └─────────────────────────────────┘   └──────────────────────────────┘     │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Persistence & Messaging                             │
│  PostgreSQL 16 (asyncpg) │ Redis 7 (AOF/Cache/MAB) │ MinIO / Cloudflare R2   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Deep-Dive: Current Technical Bottlenecks

### 3.1 Subprocess & Docker CLI Overhead
* **Mechanism:** Fuzzer monitoring (`docker logs --tail`, `docker stats`, `docker inspect`) and container lifecycle management (`docker run`, `docker exec`, `docker cp`, `docker stop`, `docker rm`) invoke `asyncio.create_subprocess_exec` on the host Docker binary every second per running campaign.
* **Bottleneck:** Spawning tens of CLI subprocesses per second across concurrent campaigns causes high kernel fork/exec overhead, context switching, and file descriptor thrashing.
* **Risk:** Scaling past 10 concurrent fuzzing nodes induces CLI latency spikes and transient subprocess timeouts.

### 3.2 Temporal Workflow Determinism & Payload Limits
* **Mechanism:** 
  1. `MainFuzzingWorkflow.run` in `crashwise/orchestration/workflows/main.py` contains direct filesystem checks (`rglob`) and synchronous LLM harness synthesis calls on fallback paths.
  2. Large stack traces, ASAN logs, and coverage reports (up to 64KB+ per crash) are transmitted directly across activity arguments and return values.
* **Bottleneck:** Temporal enforces strict execution determinism for event-history replay. Non-deterministic operations inside workflow code risk replay divergence. Furthermore, passing multi-megabyte payloads through Temporal's gRPC event history risks hitting the 4MB payload limit and causes workflow execution bloat.

### 3.3 Database Engine Thrashing & Schema Partitioning
* **Mechanism:**
  1. `crashwise/web/hooks.py` (`persist_crash_to_web`) instantiates and disposes of a brand new SQLAlchemy async engine per crash insertion.
  2. The codebase maintains two separate database schemas and declarative bases: `crashwise.core.database` (`Campaign`, `FuzzingRun`, `Crash`, `Seed`, `CampaignKV`) vs `crashwise.web.models` (`FuzzingCampaign`, `CrashTestCase`).
* **Bottleneck:** Creating and tearing down database connection pools on every crash discovery causes connection spikes on PostgreSQL and degrades throughput during crash bursts.

### 3.4 Cognitive Agent Latency & Cost Accumulation
* **Mechanism:** Multi-turn LangGraph agent loops (Harness Synthesis retry loop, Healing Engine adaptive build/repair, Exploit generation) run synchronously within worker activity slots, consuming 5–15 minutes of wall-clock time per target.
* **Bottleneck:** A stuck compilation or repair loop exhausts API rate limits and locks worker execution threads unless aggressively bounded by `max_attempts` and strict per-turn timeout gates.

---

## 4. Proposed Stack & Infrastructure Upgrades

| Component | Current Stack | Proposed Stack | Primary Justification |
|---|---|---|---|
| **Container Engine** | Docker CLI (`subprocess`) | Docker Engine REST API (`aiohttp` over `/var/run/docker.sock`) or containerd | Eliminates fork/exec overhead; sub-millisecond status polling and multiplexed streaming. |
| **Workflow Engine** | Temporal.io (Python SDK) | Temporal.io (Pure Activities + Object Storage References) | Strict determinism; large blobs (corpora, binaries, ASAN logs) stored in R2/S3; only UUIDs/URIs passed in workflows. |
| **Persistence** | Split SQLAlchemy models (Core + Web) | Unified PostgreSQL 16 schema + SQLAlchemy 2.0 (asyncpg) | Single source of truth; persistent connection pooling; eliminates redundant tables and engine re-creation. |
| **Telemetry & Events** | Polled SQL / Ad-hoc SSE | Redis Pub/Sub / SSE Stream via FastAPI | Real-time fuzzer stats broadcasting without database query saturation. |
| **Frontend** | Dual (Streamlit + Next.js 14) | Next.js 14 (App Router + Tailwind + TypeScript) | Unified, reactive production UI; deprecation of prototype Streamlit interface. |
| **LLM Orchestration** | LangChain / LangGraph + openhands-sdk stub | Unified `llm_factory` + LangGraph StateGraph + native Docker tool executors | Clean separation of agent prompts, provider-agnostic token management, and hardened sandbox execution. |

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
