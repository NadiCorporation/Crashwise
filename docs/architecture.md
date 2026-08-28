<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# Architecture

## System Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Control Plane                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  CLI (Typer)  │  FastAPI REST API  │  Next.js 14 Dashboard  │  Temporal UI  │
│  :terminal    │  :8000 (REST/SSE)  │  :3000 (React UI)      │  :8233        │
├───────────────┴────────────────────┴────────────────────────┴───────────────┤
│                         Temporal Server (gRPC :7233)                        │
│                         PostgreSQL + Redis persistence                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Temporal Worker(s)                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     28 Registered Activities                        │    │
│  │  setup_target              execute_fuzzing      triage_results      │    │
│  │  seed_corpus               analyze_progress     analyze_crash       │    │
│  │  pivot_strategy            analyze_coverage     evolve_harness      │    │
│  │  hot_swap_harness          mutate_harness       inject_seeds        │    │
│  │  verify_patch              verify_poc           notify_stakeholders │    │
│  │  kernel_monitor            profile_target       execute_job         │    │
│  │  read_coverage_data        update_campaign_status                   │    │
│  │  synthesize_exploit        report_crashes       persist_triaged_crash│   │
│  │  run_adaptive_build_activity                    query_campaign_knowledge │
│  │  run_autonomous_repair_activity                 store_campaign_knowledge │
│  │  synthesize_harness                                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Agent Layer (LangGraph + LangChain)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ HarnessSynth │  │   Triage     │  │  Coverage    │  │  Execution   │     │
│  │   Agent      │  │   Agent      │  │  Analyzer    │  │  Strategist  │     │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤     │
│  │  Evolution   │  │  Exploit Gen │  │  Harvester   │  │  Reporting   │     │
│  │   Agent      │  │   Agent      │  │  (Seeds)     │  │  (CVSS)      │     │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤     │
│  │   Healing    │  │ Knowledge    │  │  Feedback    │  │  Semantic    │     │
│  │ Engine (LLM) │  │ Base (DB)    │  │  Analyzer    │  │  Profiler    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Execution Layer                                     │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐     │
│  │  Docker    │  │   QEMU     │  │   Local    │  │  Kernel (syzkaller)│     │
│  │  (AFL++)   │  │  (KVM)     │  │ (libFuzzer)│  │  (parsers only)   │     │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘     │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Persistence & Object Storage                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐     │
│  │ PostgreSQL │  │   Redis    │  │  Cloudflare│  │   Local SQLite     │     │
│  │ (prod :5432)│ │ (state/MAB)│  │  R2 / S3   │  │   (dev mode)       │     │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

```
crashwise run --repo <url> --timeout 600
        │
        ▼
┌─── CLI ────────────────────────────────────────────────────────────────────┐
│  1. Pre-flight gate (sentinel.py): verify Docker, Clang, GCC              │
│  2. Load crashwise.yaml manifest OR build FuzzingInput from CLI args      │
│  3. Submit workflow to Temporal via client.py                              │
└────────────────────────────────────────────────────────────────────────────┘
        │ gRPC
        ▼
┌─── MainFuzzingWorkflow ────────────────────────────────────────────────────┐
│                                                                            │
│  Stage 1: Seed Corpus                                                      │
│  ├─ Scan target repo for test vectors                                      │
│  ├─ Generate format-aware seeds (PNG/JPEG/ZIP/JSON/XML/etc.)               │
│  └─ Generic boundary-value seeds                                           │
│                                                                            │
│  Stage 2: Setup Target                                                     │
│  ├─ git clone --recursive (shallow depth or full clone based on config)    │
│  ├─ Subdirectory scoping (target_subdir) for isolated monorepo targets    │
│  ├─ Detect build system (CMake / Make / Meson / Bazel / Cargo / Go)       │
│  ├─ Build with CC=clang CFLAGS="-fsanitize=address,undefined               │
│  │   -fsanitize-coverage=trace-pc-guard,trace-cmp                          │
│  │   -fprofile-instr-generate -fcoverage-mapping"                          │
│  ├─ Multi-library ranking & bazel-bin/ artifact extraction                 │
│  ├─ Find existing harness OR synthesize via LangGraph agent                │
│  └─ Compile harness linked against target .a/.so (atomic -Wl,-rpath)       │
│                                                                            │
│  Stage 3: Feedback Loop (N iterations)                                     │
│  ├─ God-Mode gate: check pause/inject_seed/force_pivot signals             │
│  ├─ execute_fuzzing: launch hardened Docker container                      │
│  │   └─ Heartbeat loop: parse stats every 1s                              │
│  ├─ analyze_progress: detect stalls (5 conditions)                         │
│  ├─ pivot_strategy (if MAB enabled): Thompson Sampling across 5 arms       │
│  └─ evolve_harness (if 2 pivots fail):                                     │
│      ├─ llvm-cov export for line-level coverage                            │
│      ├─ Identify blocker (magic value, length, checksum, state machine)    │
│      ├─ LLM rewrites harness to bypass blocker                             │
│      └─ Compile + hot-swap binary                                          │
│                                                                            │
│  Stage 4: Triage                                                           │
│  ├─ Parse ASAN output from crash files                                     │
│  ├─ Classify by type (regex heuristics, 0.85 confidence)                   │
│  ├─ LLM deep analysis (if AI_PROVIDER configured)                          │
│  ├─ Stack-hash deduplication (SHA256, Redis fast-path)                      │
│  └─ Persist to database                                                    │
│                                                                            │
│  Return FuzzingOutput                                                      │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Package Layout

```
crashwise/
├── cli.py                          # Typer CLI (12 subcommands + non-interactive configure)
├── api/main.py                     # FastAPI REST API & SSE control plane (:8000)
├── dashboard/app.py                # Streamlit prototype UI (:8501)
├── web/                            # Web Control Plane
│   ├── app.py                      #   FastAPI sub-app with SSE telemetry (/api/v1)
│   ├── models.py                   #   CrashTestCase & FuzzingCampaign ORM
│   ├── hooks.py                    #   Crash persistence hooks
│   └── frontend/                   #   Next.js 14 7-Tab Control Plane (:3000)
│       ├── app/page.tsx            #     Primary reactive dashboard tabs
│       └── components/             #     Control modules
│           ├── campaigns-table.tsx #       Live campaigns overview
│           ├── telemetry.tsx       #       Global execution stats
│           ├── crash-matrix.tsx    #       Deduplicated crash table
│           ├── campaign-launcher.tsx #     Interactive campaign submission form
│           ├── system-config.tsx   #       In-place .env configuration editor
│           ├── worker-status.tsx   #       Worker health & heartbeat telemetry
│           ├── crash-detail-modal.tsx #    Full crash & PoC inspection modal
│           └── log-streamer.tsx    #       Real-time SSE log tail terminal
├── core/
│   ├── config.py                   # Pydantic-settings (CRASHWISE_WORKDIR, env + .env)
│   ├── configure.py                # Interactive & headless CLI wizard
│   ├── models.py                   # 40+ shared Pydantic models (target_subdir, clone_depth)
│   ├── database.py                 # SQLAlchemy async ORM (PostgreSQL / SQLite, pooled)
│   ├── discovery.py                # Multi-build system detection (CMake/Make/Meson/Bazel/Cargo/Go)
│   ├── sentinel.py                 # Multi-distro system diagnostics + provisioning (apk/pacman/apt/dnf)
│   ├── redis.py                    # Distributed state, heartbeats, and locks
│   ├── storage.py                  # R2/S3/MinIO object storage
│   ├── ai_provider.py              # Ollama/Venice/OpenAI-compatible inference
│   ├── llm_factory.py              # Centralized multi-provider LLM factory
│   ├── manifest.py                 # crashwise.yaml schema
│   ├── logging.py                  # Structured logging (structlog)
│   └── notifications.py            # Webhook/SMTP/PGP alerts
├── orchestration/
│   ├── client.py                   # Temporal client & workflow submitter
│   ├── worker.py                   # Temporal worker polling task queue
│   ├── workflows/
│   │   ├── main.py                 # MainFuzzingWorkflow (God-Mode signals)
│   │   └── verify_patch.py         # VerifyPatchWorkflow (autonomous fix verification)
│   └── activities/                 # 28 registered activity implementations
│       ├── setup_target.py         #   Monorepo scoping, Bazel/Meson/CMake multi-lib ranking
│       └── execute_fuzzing.py      #   AsyncPG naive datetime persistence, container exec
├── agents/
│   ├── harness_synth/              # LangGraph harness generation
│   │   ├── graph.py                #   analyze → generate → validate state machine
│   │   ├── nodes.py                #   LLM nodes + atomic -Wl,-rpath injection
│   │   ├── analyzer.py             #   Entry point detection + header API discovery
│   │   ├── compiler.py             #   Compilation + 5s sanity gate
│   │   ├── validator.py            #   Safety checks (regex blocklist)
│   │   ├── evolution.py            #   Coverage-guided harness rewriting
│   │   ├── debug_engine.py         #   GDB crash diagnosis
│   │   ├── type_extractor.py       #   Struct/typedef extraction from headers
│   │   └── build_resolver.py       #   Library/include path discovery
│   ├── healing/                    # LangGraph Adaptive Build & Autonomous Repair
│   │   ├── graph.py                #   Multi-turn compiler & security researcher agent
│   │   └── tools.py                #   Docker exec sandbox tools & file patchers
│   ├── triage/                     # Crash classification + exploit gen (C PoC)
│   ├── feedback/                   # Coverage feedback + agentic stall analysis
│   ├── research/                   # Coverage analysis + seed harvesting + knowledge base
│   │   └── knowledge_base.py       #   Cross-campaign pattern learning & injection
│   ├── execution/                  # MAB strategist (Thompson Sampling + UCB1)
│   └── reporting/                  # CVSS scoring + SARIF/MD report generation
├── execution/
│   ├── docker_manager.py           # Hardened Docker container manager (--init, --network none)
│   ├── qemu_manager.py             # QEMU/KVM VM management
│   ├── monitor.py                  # Fuzzer stats parsing (AFL++ & libFuzzer)
│   └── dispatcher.py               # Backend routing
└── kernelbridge/                   # OOPS/KASAN/KFENCE parsing & Syzkaller repros
```

---

## Design Principles

1. **Determinism boundary.** Workflows are pure state machines. All I/O lives in activities. Temporal replays from history — no side effects in workflow code.

2. **Pydantic contracts.** Every cross-component payload is a versioned model in `core/models.py`. New fields must be additive and default-valued for replay compatibility.

3. **Bounded autonomy.** LLM failures feed back into the LangGraph loop for self-correction. Bounded by `max_retries` (harness), `max_attempts` (healing), and `max_evolution_count` (evolution) to cap LLM spend.

4. **Defense in depth.** LLM-generated code passes: regex validator → clang syntax check → compiler allowlist → Docker sandbox (no network, no caps, read-only rootfs, `--init`).

5. **Database as source of truth.** Redis is a read cache. All persistent state writes to PostgreSQL/SQLite first with persistent connection pooling (`pool_size=20`, `max_overflow=10`, `pool_pre_ping=True`). Campaigns never lose state.

6. **Shell-free execution.** All subprocess calls use `shlex.split` + `create_subprocess_exec`. No `shell=True` anywhere.

7. **Truthful telemetry.** Coverage data is never fabricated. If line-level data is unavailable, the system reports unknown and falls back to static analysis.

---

## LLM Integration & Provider Routing

CrashWise uses a vendor-neutral, universal LLM architecture ([`crashwise/core/llm_factory.py`](file:///home/yahyatoubali/Projects/Crashwise/crashwise/core/llm_factory.py)) supporting dynamic provider selection and runtime parameter overrides:

| Layer | Purpose | Config / Providers | Supported Backends |
|---|---|---|---|
| **Agentic Core** (LangGraph) | Harness synthesis, evolution, exploit gen, adaptive build & self-healing | `MODEL_NAME`, `OPENAI_API_BASE`, `OPENAI_API_KEY`, `TEMPERATURE`, `REASONING_EFFORT` | DeepSeek (`deepseek-chat`), Anthropic Claude (`claude-sonnet-4-5`), OpenAI (`gpt-4o`, `o1`/`o3`), Ollama, vLLM, Venice, Together AI, Groq |
| **Triage & Diagnostics** | Root-cause analysis, CWE classification, patch suggestions | `AI_PROVIDER` (`openai_compatible`, `ollama`, `venice`), `AI_MODEL` | DeepSeek, OpenAI-compatible APIs, local Ollama/vLLM (8B+ models) |

### Runtime Parameter Overrides
Every agent node receives granular overrides via `get_llm_provider()`:
- `model`: Target LLM model name
- `base_url`: OpenAI-compatible endpoint URL
- `api_key`: Secret API token
- `temperature`: Deterministic sampling (default `0.0`)
- `reasoning_effort`: Reasoning intensity for reasoning models (`low`, `medium`, `high`)
- `max_tokens`: Token budget per turn (default `4096`)

---

## Execution Sandbox

Every fuzzer container runs with:

| Constraint | Value | Rationale |
|---|---|---|
| Process init | `--init` | Tini init at PID 1 for clean child process reaping |
| Network | `--network none` | Untrusted harness cannot exfiltrate |
| Filesystem | `--read-only` | Immutable rootfs; all writes go to explicit mounts |
| Capabilities | `--cap-drop ALL` | Drops all Linux capabilities (least privilege) |
| AFL++ capability | `--cap-add SYS_PTRACE` | AFL++ forkserver requires ptrace |
| PIDs | `--pids-limit 1024` | Fork bomb protection |
| Scratch | `--tmpfs /tmp:size=512m` | Capped ephemeral scratch to prevent disk fill |
| Disk quota | `--storage-opt size=5G` | Per-container quota (overlay2+xfs+pquota) |
| Max file size | `--ulimit fsize=10G` | Prevents runaway corpus explosion |

---

## Database Architecture & Connection Pooling

CrashWise uses async SQLAlchemy 2.0 with PostgreSQL in production (`asyncpg`) and SQLite in development (`aiosqlite`). Connection pooling is managed in `crashwise/core/database.py`:
- `pool_size=20`: Maintained persistent connection pool
- `max_overflow=10`: Burst connection buffer
- `pool_pre_ping=True`: Automatic dead connection detection and recovery
- `pool_recycle=300`: Connection recycling every 5 minutes
- Lazy engine instantiation to avoid connection leaks across worker subprocess forks.

```
Campaign                — id, target_repo, target_name, fuzzer_type, status, created_at, updated_at
FuzzingRun              — id, campaign_id, iteration, executions, duration_seconds, coverage_edges, status
Crash                   — id, run_id, crash_type, severity, severity_score, vulnerability_type,
                          suggested_patch, poc_code, poc_compiled, poc_verified, reachability,
                          reachability_score, primitive, stack_trace, stack_hash, signal
Seed                    — id, campaign_id, seed_id, source, target_name, language, tags, content_hash
CampaignKV              — campaign_id, key, value  (MAB state, dynamic campaign properties)
TargetKnowledge         — id, target_name, domain, complexity_score, attack_surface, harness_patterns, blockers
VulnerabilityPattern    — id, target_domain, bug_type, severity, location_pattern, root_cause_summary
StrategyEffectiveness   — id, target_domain, strategy_arm_id, success_count, avg_coverage_gain, score
```

---

## Infrastructure (Docker Compose)

| Service | Image / Build | Port | Purpose |
|---|---|---|---|
| temporal-server | `temporalio/auto-setup:1.25` | 7233 | Workflow engine (gRPC) |
| temporal-ui | `temporalio/ui:2.30.0` | 8233 | Workflow visualization |
| postgres | `postgres:16-alpine` | 5432 | Primary persistence |
| redis | `redis:7-alpine` | 6379 | Distributed state, heartbeats, dedup |
| minio | `minio/minio:latest` | 9000 | Object storage / S3 emulation |
| crashwise-api | `Dockerfile.worker` (`uvicorn crashwise.api.main:app`) | 8000 | REST API & Web control plane backend |
| crashwise-dashboard | `Dockerfile.frontend` (Next.js 14 App) | 3000 | Production Web Command Center UI |
| crashwise-worker | `Dockerfile.worker` (`crashwise worker`) | — | Temporal Activity/Workflow execution worker |

The worker image is a 3-stage build:
1. AFL++ v4.21c compiled from source
2. Python dependencies via uv
3. Runtime: Debian bookworm-slim + clang + cmake + gcc + Docker CLI


---

## Healing Engine (Phase 22)

The Healing Engine is a LangGraph state machine that drives two autonomous loops
inside a Docker-based sandbox:

```
┌─────────────────────────────────────────────────────────────┐
│                    Healing Engine                             │
├─────────────────────────────────────────────────────────────┤
│  Mode: BUILD                    Mode: REPAIR                 │
│  ┌───────────────────┐         ┌───────────────────┐        │
│  │ Clone repo        │         │ Load ASAN log     │        │
│  │ Discover build    │         │ + crash seed path │        │
│  │ Install deps      │         │ + bug_type        │        │
│  │ Inject sanitizers │         │ + root_cause      │        │
│  │ Compile (iterate) │         │ Run GDB           │        │
│  │ signal_completion │         │ Patch source      │        │
│  └───────────────────┘         │ Recompile         │        │
│                                │ Verify fix        │        │
│                                │ signal_completion │        │
│                                └───────────────────┘        │
├─────────────────────────────────────────────────────────────┤
│  Sandbox: Docker container (crashwise-worker:latest)         │
│  Tools: execute_sandbox_command (docker exec)                │
│         edit_sandbox_file (host file I/O on mounted volume)  │
│  LLM: Configurable via llm_factory (DeepSeek/Qwen/Kimi)     │
│  Fallback: If healing fails → legacy setup_target activity   │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow: Triage → Repair

```
TriagedCrashRef {
  crash_id, stack_hash, asan_log, crash_file_path,
  bug_type, severity, signal, stack_trace, root_cause
}
    │
    ▼
run_autonomous_repair_activity(
  crash_id, asan_log, workspace_path, campaign_id,
  max_attempts, crash_file_path, bug_type, root_cause
)
    │
    ▼
HealingState {
  mode=REPAIR, crash_context=asan_log,
  crash_file_path, bug_type, root_cause
}
```

### Fallback Strategy

The workflow always attempts the Healing Engine first. On failure (SDK error,
LLM error, or `success=False`), it falls back to the deterministic
`setup_target` activity which uses scripted build logic.
