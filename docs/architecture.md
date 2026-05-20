<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# Architecture

## System Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Control Plane                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  CLI (Typer)  │  FastAPI REST API  │  Streamlit Dashboard  │  Temporal UI  │
│  :terminal    │  :8000             │  :8501                │  :8233        │
├───────────────┴────────────────────┴───────────────────────┴───────────────┤
│                         Temporal Server (gRPC :7233)                         │
│                         PostgreSQL + Redis persistence                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Temporal Worker(s)                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     23 Registered Activities                         │    │
│  │  setup_target      execute_fuzzing     triage_results               │    │
│  │  seed_corpus       analyze_progress    analyze_crash                │    │
│  │  pivot_strategy    analyze_coverage    evolve_harness               │    │
│  │  hot_swap_harness  mutate_harness      inject_seeds                 │    │
│  │  verify_patch      verify_poc          notify_stakeholders          │    │
│  │  kernel_monitor    profile_target      execute_job                  │    │
│  │  read_coverage_data update_campaign_status                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Agent Layer (LangGraph + LangChain)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ HarnessSynth │  │   Triage     │  │  Coverage    │  │  Execution   │   │
│  │   Agent      │  │   Agent      │  │  Analyzer    │  │  Strategist  │   │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤   │
│  │  Evolution   │  │  Exploit Gen │  │  Harvester   │  │  Reporting   │   │
│  │   Agent      │  │   Agent      │  │  (Seeds)     │  │  (CVSS)      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Execution Layer                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │  Docker    │  │   QEMU     │  │   Local    │  │  Kernel (syzkaller)│   │
│  │  (AFL++)   │  │  (KVM)     │  │ (libFuzzer)│  │  (parsers only)   │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Persistence                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │ PostgreSQL │  │   Redis    │  │  Cloudflare│  │   Local SQLite     │   │
│  │ (prod)     │  │ (state/MAB)│  │    R2      │  │   (dev mode)       │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘   │
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
│  ├─ git clone --recursive (shallow + full fallback)                        │
│  ├─ Detect build system (CMake/Make/Meson/Bazel/Cargo/Go)                  │
│  ├─ Build with CC=clang CFLAGS="-fsanitize=address,undefined               │
│  │   -fsanitize-coverage=trace-pc-guard,trace-cmp                          │
│  │   -fprofile-instr-generate -fcoverage-mapping"                          │
│  ├─ Find existing harness OR synthesize via LangGraph agent                │
│  └─ Compile harness linked against target .a/.o files                      │
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
├── cli.py                          # Typer CLI (10 commands)
├── api/main.py                     # FastAPI REST API
├── dashboard/app.py                # Streamlit UI
├── core/
│   ├── config.py                   # Pydantic-settings (env + .env)
│   ├── models.py                   # 30+ shared Pydantic models
│   ├── database.py                 # SQLAlchemy async ORM
│   ├── discovery.py                # Build system detection (6 systems)
│   ├── sentinel.py                 # System diagnostics + provisioning
│   ├── redis.py                    # Distributed state
│   ├── storage.py                  # R2/S3 object storage
│   ├── ai_provider.py             # Ollama/Venice/OpenAI-compatible inference
│   ├── manifest.py                 # crashwise.yaml schema
│   ├── logging.py                  # Structured logging (structlog)
│   └── notifications.py           # Webhook/SMTP/PGP alerts
├── orchestration/
│   ├── client.py                   # Temporal client
│   ├── worker.py                   # Temporal worker
│   ├── workflows/
│   │   ├── main.py                 # MainFuzzingWorkflow (God-Mode signals)
│   │   └── verify_patch.py        # VerifyPatchWorkflow
│   └── activities/                 # 22 activity implementations
├── agents/
│   ├── harness_synth/              # LangGraph harness generation
│   │   ├── graph.py                #   analyze → generate → validate state machine
│   │   ├── nodes.py                #   LLM nodes + self-correction loop
│   │   ├── analyzer.py             #   Entry point detection + header API discovery
│   │   ├── compiler.py             #   Compilation + 5s sanity gate
│   │   ├── validator.py            #   Safety checks (regex blocklist)
│   │   ├── evolution.py            #   Coverage-guided harness rewriting
│   │   ├── debug_engine.py         #   GDB crash diagnosis
│   │   ├── type_extractor.py       #   Struct/typedef extraction from headers
│   │   └── build_resolver.py       #   Library/include path discovery
│   ├── triage/                     # Crash classification + exploit gen
│   ├── feedback/                   # Coverage feedback + patch generation
│   ├── research/                   # Coverage analysis + seed harvesting
│   ├── execution/                  # MAB strategist (Thompson Sampling + UCB1)
│   └── reporting/                  # CVSS scoring + report generation
├── execution/
│   ├── docker_manager.py           # Hardened Docker orchestration
│   ├── qemu_manager.py            # QEMU/KVM management
│   ├── monitor.py                  # Fuzzer stats parsing
│   └── dispatcher.py              # Backend routing
└── kernelbridge/                   # OOPS/KASAN/KFENCE parsing
```

---

## Design Principles

1. **Determinism boundary.** Workflows are pure state machines. All I/O lives in activities. Temporal replays from history — no side effects in workflow code.

2. **Pydantic contracts.** Every cross-component payload is a versioned model in `core/models.py`. New fields must be additive and default-valued for replay compatibility.

3. **Bounded autonomy.** LLM failures feed back into the LangGraph loop for self-correction. Bounded by `max_retries` (harness) and `max_evolution_count` (evolution) to cap LLM spend.

4. **Defense in depth.** LLM-generated code passes: regex validator → clang syntax check → compiler allowlist → Docker sandbox (no network, no caps, read-only rootfs).

5. **Database as source of truth.** Redis is a read cache. All persistent state writes to PostgreSQL/SQLite first. Campaigns never lose state.

6. **Shell-free execution.** All subprocess calls use `shlex.split` + `create_subprocess_exec`. No `shell=True` anywhere.

7. **Truthful telemetry.** Coverage data is never fabricated. If line-level data is unavailable, the system reports unknown and falls back to static analysis.

---

## LLM Integration

Two independent layers with separate configuration:

| Layer | Purpose | Config | Quality Requirement |
|---|---|---|---|
| Agentic (LangChain) | Harness synthesis, evolution, exploit gen | `CRASHWISE_LLM_MODEL` + API key | High (Claude Sonnet / GPT-4o) |
| Triage (Direct HTTP) | Root cause analysis, patch suggestions | `AI_PROVIDER` + `AI_MODEL` | Low (8B models sufficient) |

The triage layer is optional — falls back to regex-based ASAN classification.

---

## Execution Sandbox

| Constraint | Value | Rationale |
|---|---|---|
| `--network none` | No egress | Untrusted harness cannot exfiltrate |
| `--read-only` | Immutable rootfs | All writes go to explicit mounts |
| `--cap-drop ALL` | No capabilities | Minimum privilege |
| `--cap-add SYS_PTRACE` | AFL++ only | Forkserver requires ptrace |
| `--pids-limit 1024` | Fork bomb protection | |
| `--tmpfs /tmp:size=512m` | Capped scratch | Prevents disk fill |
| `--storage-opt size=5G` | Per-container quota | Requires overlay2+xfs+pquota |
| `--ulimit fsize=10G` | Max file size | Prevents runaway corpus |

---

## Database Schema

```
Campaign        — id, target_repo, status, created_at, updated_at
FuzzingRun      — id, campaign_id, iteration, executions, duration, status
Crash           — id, run_id, crash_type, severity, stack_trace, stack_hash, signal
Seed            — id, campaign_id, source, format, path
CampaignKV      — campaign_id, key, value  (MAB state, campaign state)
```

---

## Infrastructure (Docker Compose)

| Service | Image | Port | Purpose |
|---|---|---|---|
| temporal-server | `temporalio/auto-setup:1.25` | 7233 | Workflow engine |
| temporal-ui | `temporalio/ui:2.30.0` | 8233 | Web UI |
| postgres | `postgres:16-alpine` | 5432 | Database |
| redis | `redis:7-alpine` | 6379 | State cache |
| minio | `minio/minio:latest` | 9000 | S3 emulation (dev) |

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
