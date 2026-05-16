<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 CrashWise Contributors
-->

# CrashWise Architecture

## High-Level Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CrashWise Control Plane                              │
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
│                         Persistence & Storage                                │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │
│  │ PostgreSQL │  │   Redis    │  │  Cloudflare│  │   Local SQLite     │   │
│  │ (prod)     │  │ (state/MAB)│  │    R2      │  │   (dev mode)       │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## End-to-End Data Flow

```
crashwise run --repo <url> --timeout 600
        │
        ▼
┌─── CLI (cli.py) ───────────────────────────────────────────────────────────┐
│  1. Pre-flight gate (sentinel.py): verify Docker, Clang, GCC              │
│  2. Load crashwise.yaml manifest OR build FuzzingInput from CLI args      │
│  3. Submit workflow to Temporal via client.py                              │
└────────────────────────────────────────────────────────────────────────────┘
        │ gRPC
        ▼
┌─── MainFuzzingWorkflow (workflows/main.py) ────────────────────────────────┐
│                                                                            │
│  ┌─ Stage 1: Seed Corpus ──────────────────────────────────────────────┐   │
│  │  seed_corpus activity → harvester.py                                │   │
│  │  • Scan target repo for test vectors                                │   │
│  │  • Generate format-aware seeds (PNG/JPEG/ZIP/JSON/XML/etc.)         │   │
│  │  • Scrape configured PoC URLs (throttled async)                     │   │
│  │  • Generic boundary-value seeds                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─ Stage 2: Setup Target ─────────────────────────────────────────────┐   │
│  │  setup_target activity → setup_target.py                            │   │
│  │  • git clone --recursive (shallow + full fallback)                  │   │
│  │  • Detect build system (CMake/Make/Meson/Bazel/Cargo/Go)            │   │
│  │  • Build with CC=clang CFLAGS="-fsanitize=address,undefined         │   │
│  │    -fsanitize-coverage=trace-pc-guard,trace-cmp"                    │   │
│  │  • Find existing harness (LLVMFuzzerTestOneInput) OR                │   │
│  │  • Synthesize via LangGraph agent (analyze → generate → validate)   │   │
│  │  • Compile harness linked against target .a/.o files                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─ Stage 3: Feedback Loop (N iterations) ─────────────────────────────┐   │
│  │                                                                     │   │
│  │  ┌─ God-Mode Gate ──────────────────────────────────────────────┐   │   │
│  │  │  Check signals: pause_hunt / resume_hunt / inject_seed       │   │   │
│  │  └─────────────────────────────────────────────────────────────-┘   │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  execute_fuzzing activity → DockerManager                           │   │
│  │  • Launch hardened container (--network none, --read-only,          │   │
│  │    --cap-drop ALL, tmpfs, pids-limit, storage-opt)                  │   │
│  │  • Heartbeat loop: parse AFL++/libFuzzer stats every 1s             │   │
│  │  • On exit: stop → preserve_corpus → extract_coverage → cleanup     │   │
│  │           │                                                         │   │
│  │           ▼                                                         │   │
│  │  analyze_progress activity → feedback/analyzer.py                   │   │
│  │  • Detect stall: zero coverage, exec rate collapse, stability       │   │
│  │    drop, coverage plateau (3 consecutive), corpus exhaustion         │   │
│  │           │                                                         │   │
│  │           ▼ (if MAB enabled)                                        │   │
│  │  pivot_strategy activity → strategist.py                            │   │
│  │  • Thompson Sampling + UCB1 across 5 AFL++ configurations           │   │
│  │  • Preserve corpus → switch strategy → restart container            │   │
│  │           │                                                         │   │
│  │           ▼ (if 2 consecutive pivots fail)                          │   │
│  │  analyze_coverage → evolve_harness → hot_swap_harness               │   │
│  │  • llvm-cov export / sancov for line-level coverage                 │   │
│  │  • Identify exact blocker (magic value, length, checksum)           │   │
│  │  • LLM rewrites harness to bypass blocker                           │   │
│  │  • clang -fsyntax-only -Werror validation gate                      │   │
│  │  • Compile + swap binary                                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─ Stage 4: Triage ──────────────────────────────────────────────────-┐   │
│  │  triage_results activity → triage/analyzer.py                       │   │
│  │  • Parse fuzz.log for ASAN output (not just raw crash files)        │   │
│  │  • Regex-based classification (0.85 confidence)                     │   │
│  │  • LLM deep root-cause analysis (if AI_PROVIDER configured)        │   │
│  │  • Stack-hash deduplication (SHA256, Redis fast-path)               │   │
│  │  • Persist to PostgreSQL Crash table                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  Return FuzzingOutput → CLI prints JSON result                             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Package Map

```
crashwise/
├── cli.py                          # Typer CLI (10 commands)
├── api/
│   └── main.py                     # FastAPI REST API (campaigns, crashes, health)
├── dashboard/
│   └── app.py                      # Streamlit intelligence dashboard
├── core/
│   ├── config.py                   # Pydantic-settings (env-based, .env file)
│   ├── models.py                   # 30+ shared Pydantic models (cross-component contracts)
│   ├── database.py                 # SQLAlchemy async ORM (Campaign, FuzzingRun, Crash, Seed, CampaignKV)
│   ├── discovery.py                # Build system auto-detection (6 systems)
│   ├── sentinel.py                 # System diagnostics & distro-aware provisioning
│   ├── redis.py                    # Distributed state (counters, dedup, MAB, campaign state)
│   ├── storage.py                  # R2/S3 object storage (corpus, crashes, reports)
│   ├── ai_provider.py             # Ollama/Venice inference (triage layer)
│   ├── manifest.py                 # crashwise.yaml schema
│   ├── logging.py                  # Structured logging (structlog)
│   └── notifications.py           # Webhook/SMTP/PGP alerts
├── orchestration/
│   ├── client.py                   # Temporal client (connect, submit, query)
│   ├── worker.py                   # Temporal worker (register activities, poll queue)
│   ├── data_converter.py          # Pydantic ↔ Temporal payload serialization
│   ├── workflows/
│   │   ├── main.py                 # MainFuzzingWorkflow (900 lines, God-Mode signals)
│   │   └── verify_patch.py        # VerifyPatchWorkflow (clone → apply → build → test)
│   └── activities/                 # 22 activity implementations
│       ├── setup_target.py         #   Clone + build + harness detection/synthesis
│       ├── execute_fuzzing.py      #   Docker execution + heartbeat loop
│       ├── seed_corpus.py          #   Seed harvesting + corpus preparation
│       ├── analyze_progress.py     #   Stall detection (5 conditions)
│       ├── analyze_coverage.py     #   Coverage analysis (llvm-cov/sancov/AFL)
│       ├── triage_results.py       #   ASAN/GDB parsing + LLM triage
│       ├── analyze_crash.py        #   Deep crash analysis
│       ├── pivot_strategy.py       #   MAB strategy switching
│       ├── evolve_harness.py       #   LLM harness evolution
│       ├── hot_swap_harness.py     #   Compile + swap binary (no shell=True)
│       ├── mutate_harness.py       #   Harness mutation
│       ├── inject_seeds.py         #   God-Mode seed injection
│       ├── verify_patch.py         #   Patch verification pipeline
│       ├── verify_poc.py           #   PoC validation
│       ├── notify_stakeholders.py  #   Webhook/email/PGP notifications
│       ├── kernel_monitor.py       #   OOPS/KASAN/KFENCE log parsing
│       ├── profile_target.py       #   Target profiling
│       ├── execute_job.py          #   Generic job execution
│       └── read_coverage_data.py   #   Coverage data ingestion
├── agents/
│   ├── harness_synth/              # LangGraph harness generation agent
│   │   ├── graph.py                #   State machine: analyze → generate → validate
│   │   ├── nodes.py                #   LLM node implementations + ReAct self-correction
│   │   ├── llm.py                  #   LangChain model factory (Anthropic/OpenAI)
│   │   ├── analyzer.py             #   Entry point detection + header-aware API discovery
│   │   ├── compiler.py             #   clang++ compilation + 5-second sanity gate
│   │   ├── validator.py            #   Safety checks + anti-hallucination guard
│   │   ├── evolution.py            #   Coverage-guided harness rewriting
│   │   ├── debug_engine.py         #   GDB-based crash diagnosis (ReAct loop)
│   │   ├── type_extractor.py       #   Static type extraction from headers
│   │   ├── build_resolver.py       #   Automated library/include path discovery
│   │   ├── prompts.py              #   LLM prompt templates
│   │   ├── state.py                #   LangGraph state schema
│   │   └── synth.py                #   Public API (synthesize_harness)
│   ├── triage/
│   │   ├── analyzer.py             #   LLM + heuristic crash classification
│   │   ├── dedup.py                #   Stack-hash deduplication
│   │   ├── exploit_gen.py          #   PoC/exploit generation
│   │   └── models.py              #   CrashReport, TriageResult, BugType
│   ├── feedback/
│   │   ├── analyzer.py             #   Coverage feedback + stall detection
│   │   ├── patcher.py              #   Patch generation
│   │   └── verifier.py             #   Patch verification
│   ├── research/
│   │   ├── coverage_analyzer.py    #   Blocker identification (lcov/sancov/AFL)
│   │   ├── harvester.py            #   Seed discovery (repo scan, URL scrape, format gen)
│   │   ├── profiler.py             #   Target profiling
│   │   └── transformer.py          #   PoC → binary seed conversion
│   ├── execution/
│   │   └── strategist.py           #   MAB (Thompson Sampling + UCB1)
│   └── reporting/
│       ├── cvss.py                 #   CVSS v3.1 scoring
│       └── generator.py            #   Report generation (HackerOne, Bugcrowd, kernel ML)
├── execution/
│   ├── docker_manager.py           #   Hardened Docker orchestration (start/stop/cp/stats)
│   ├── qemu_manager.py            #   QEMU/KVM VM management
│   ├── monitor.py                  #   Fuzzer stats parsing
│   └── dispatcher.py              #   Backend routing (Docker/QEMU/Local)
├── kernelbridge/
│   ├── parser.py                   #   OOPS/KASAN/KFENCE log parsing
│   └── models.py                  #   Kernel crash models
└── research/
    └── reachability.py             #   Reachability analysis for exploit gen
```

---

## Design Principles

1. **Determinism boundary.** Workflows are pure state machines; all I/O lives in activities. Temporal replays workflows from history — no side effects allowed in workflow code.

2. **Pydantic everywhere.** Every cross-component payload is a versioned model in `core/models.py`. New fields must be additive and default-valued so existing serialised workflow histories remain replayable.

3. **LLM autonomy with bounds.** Compilation/exec failures feed back into the LangGraph loop for autonomous correction. Bounded by `max_evolution_count` to prevent runaway LLM spend.

4. **Defense in depth.** LLM-generated code passes through: regex safety validator → clang -fsyntax-only → compiler allowlist → Docker sandbox (no network, no caps, read-only rootfs).

5. **Database as source of truth.** Redis is a fast-read cache; all persistent state (campaign, MAB, crashes) is written to PostgreSQL/SQLite first. Long-running campaigns never lose state.

6. **Shell-free execution.** All subprocess calls use `shlex` + `subprocess_exec` against an allowlist. No `shell=True` anywhere in the codebase.

7. **Truthful telemetry.** Coverage data is never fabricated. If line-level data is unavailable (AFL++/libFuzzer aggregate-only), the system reports UNKNOWN and falls back to static analysis rather than hallucinating line numbers.

8. **Immutability doctrine.** The agent may only edit harness code and build configuration. Target source files are strictly read-only — the agent cannot "fix" the target to make fuzzing work.

---

## Operation Hydra — Intelligence Layer

The intelligence layer transforms CrashWise from a linear automated fuzzer into an agentic security research suite. It operates in three phases:

### Phase 1: THE SENSES (API Discovery + Truthful Coverage)

```
┌─── Header-Aware API Discovery ─────────────────────────────────────────────┐
│  find_public_api(workdir) → scans .h files for real API surface            │
│  • Resolves typedefs (Bytef→unsigned char, z_streamp→struct*)              │
│  • Scores struct-pointer APIs at 0.85 (needs init but high-value)          │
│  • Detects init/cleanup lifecycle (inflateInit/inflateEnd)                 │
│  • Falls back to .c file scanning only if no headers found                 │
│  Result: compress(0.95) instead of z_error(0.3)                            │
└────────────────────────────────────────────────────────────────────────────┘

┌─── Truthful Coverage Analysis ─────────────────────────────────────────────┐
│  • AFL++/libFuzzer parsers return empty sets (no fake line numbers)         │
│  • Real llvm-cov/sancov/lcov paths unchanged (they have real data)         │
│  • Blocker detection uses static analysis when no line-level data          │
└────────────────────────────────────────────────────────────────────────────┘

┌─── 5-Second Sanity Gate ───────────────────────────────────────────────────┐
│  After compilation: run harness for 5s with -handle_segv=0                 │
│  • If edges_hit < 2 → REJECT (harness doesn't exercise target)            │
│  • If crashed_immediately → trigger GDB diagnosis                          │
│  • Prevents wasting full fuzzing iterations on dead harnesses              │
└────────────────────────────────────────────────────────────────────────────┘
```

### Phase 2: THE BRAIN (Self-Correction ReAct Loop)

```
ValidateHarness → sanity_check() → CRASH?
                                      │ YES
                                      ▼
                              debug_crash(binary)  ← GDB batch mode
                                      │
                                      ▼
                    state.crash_diagnosis = "SIGSEGV in compress,
                                             NULL pointer at line 42"
                                      │
                                      ▼
                    GenerateHarness (LLM sees crash diagnosis)
                                      │
                    "Your harness crashed because strm->next_in was NULL.
                     FIX the initialization."
```

- **GDB Debug Engine:** Runs crashing binary under `gdb --batch` with `-handle_segv=0`
- **Usage Mining:** Scans `test/`, `tests/`, `examples/` for code calling the target function
- **Context Enrichment:** LLM prompt includes crash diagnosis + usage example + type definitions

### Phase 3: THE HANDS (Type Extraction + Build Resolution)

```
┌─── The Navigator Hand (type_extractor.py) ─────────────────────────────────┐
│  extract_types_for_signature(workdir, "compress(Bytef*, uLongf*, ...)")     │
│  → "typedef Byte FAR Bytef;"                                               │
│  → "typedef uLong FAR uLongf;"                                             │
│  → "typedef unsigned long uLong;"                                           │
│  Injected into LLM prompt as ## TYPE DEFINITIONS                           │
└────────────────────────────────────────────────────────────────────────────┘

┌─── The Linker Hand (build_resolver.py) ────────────────────────────────────┐
│  On compile failure:                                                        │
│  • diagnose_compile_error(stderr) → parse "file not found" / "undefined"   │
│  • resolve_build_paths(workdir) → discover .a/.so + include dirs           │
│  • Auto-retry compilation with discovered -I/-L flags                      │
│  • Only count as failure if auto-fix also fails                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Infrastructure (Docker Compose)

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `temporal-server` | `temporalio/auto-setup:1.25` | 7233 | Workflow engine (gRPC) |
| `temporal-ui` | `temporalio/ui:2.30.0` | 8233 | Temporal Web UI |
| `postgres` | `postgres:16-alpine` | 5432 | Database (Temporal + CrashWise) |
| `redis` | `redis:7-alpine` | 6379 | Counters, dedup, MAB state |
| `minio` | `minio/minio:latest` | 9000/9001 | Local S3 (R2 emulation) |
| `api` | CrashWise (Dockerfile) | 8000 | FastAPI REST API |
| `dashboard` | CrashWise (Dockerfile) | 8501 | Streamlit UI |
| `worker` | CrashWise (Dockerfile.worker) | — | Temporal worker + Docker socket |

The worker image (`Dockerfile.worker`) is a 3-stage build:
1. **AFL++ builder** — compiles AFL++ v4.21c from source
2. **Python builder** — installs CrashWise + dependencies via uv
3. **Runtime** — Debian bookworm-slim with clang, cmake, gcc, Docker CLI, AFL++ binaries

---

## Two LLM Layers

CrashWise uses AI at two distinct levels with separate configuration:

### Layer 1: Agentic Workflows (LangChain)
- **Used by:** Harness synthesis, harness evolution, exploit generation
- **Config:** `CRASHWISE_LLM_MODEL` + `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`
- **Routing:** Model name starts with `claude` → Anthropic; else → OpenAI-compatible
- **Quality requirement:** High — needs strong code generation (Claude Sonnet / GPT-4o)

### Layer 2: Crash Triage (Direct HTTP)
- **Used by:** Root cause analysis, patch suggestions
- **Config:** `AI_PROVIDER` + `AI_MODEL` + `AI_API_KEY` or `OLLAMA_URL`
- **Optional:** Falls back to regex-based ASAN parsing without it
- **Quality requirement:** Lower — 8B models work fine for classification

---

## Security Model

| Layer | Control |
|-------|---------|
| **Source validation** | Regex blocklist (fork/exec/system/socket/ptrace/asm) |
| **Syntax validation** | `clang -fsyntax-only -Werror` (catches #define tricks, type errors) |
| **Compilation** | Allowlisted compilers only, `shlex` parsing, no `shell=True` |
| **Runtime sandbox** | `--network none`, `--read-only`, `--cap-drop ALL`, `--tmpfs`, `--pids-limit 1024` |
| **Disk protection** | `--storage-opt size=5G` (xfs+pquota), `--ulimit fsize=10G` |
| **State isolation** | Each campaign gets unique container name, pre-flight `docker rm -f` for stale containers |

---

## Database Schema

```sql
Campaign        — id, target_repo, status, started_at, finished_at, config_json
FuzzingRun      — id, campaign_id, iteration, executions, duration, status
Crash           — id, run_id, crash_type, severity, stack_trace, stack_hash, signal
Seed            — id, campaign_id, source, format, path
CampaignKV      — campaign_id, key, value  (MAB state, campaign state — source of truth)
```

---

## Where Results Live

| What | Where | How to access |
|------|-------|---------------|
| Campaign status | PostgreSQL | `curl :8000/campaigns` or dashboard |
| Crash reports | PostgreSQL + filesystem | `curl :8000/campaigns/{id}/crashes` |
| Fuzzer logs | `/tmp/crashwise/{workflow_id}/fuzz.log` | Worker filesystem |
| Corpus | `/tmp/crashwise/{workflow_id}/corpus_preserved/` | Worker filesystem |
| Coverage data | `/tmp/crashwise/{workflow_id}/coverage_summary.txt` | Worker filesystem |
| Workflow history | Temporal | Temporal UI at `:8233` |
| Artefacts (if R2 enabled) | MinIO/R2 | `campaigns/{id}/crashes/`, `campaigns/{id}/corpus/` |
