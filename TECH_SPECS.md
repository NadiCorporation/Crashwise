# CrashWise Technical Specifications (Operation Megabits)

## 1. System Architecture

CrashWise is structured as a modular Rust workspace consisting of 8 purpose-built crates:

```
Crashwise/
├── Cargo.toml
├── crates/
│   ├── crashwise-core/      # Models, SQLite persistence, Config
│   ├── crashwise-ast/       # Tree-sitter AST, Callgraph, Lifecycle mining
│   ├── crashwise-build/     # CMake/Meson/Make compiler driver
│   ├── crashwise-agent/     # LLM harness synthesizer & sanity gate
│   ├── crashwise-engine/    # Fuzzing runner, sandbox, corpus manager
│   ├── crashwise-triage/    # ASan parser, PoC & patch synthesizer
│   ├── crashwise-server/    # Axum REST & SSE telemetry daemon
│   └── crashwise-cli/       # Single unified CLI binary
└── web/                     # Next.js 15 Web Command Center
```

## 2. End-to-End Pipeline Phases

### Phase 1: Attack Surface AST Analysis (`crashwise-ast`)
- Parses concrete syntax trees using `tree-sitter-c` and `tree-sitter-cpp`.
- Computes callgraphs and scores reachability to dangerous memory sinks (`memcpy`, `strcpy`, `sprintf`, `malloc`, `free`).
- Groups functions into stateful API lifecycles (`Init → Config → Process → Cleanup`).

### Phase 2: Instrumented Target Compilation (`crashwise-build`)
- Automatically detects build system (`CMake`, `Meson`, `Make`, `Autotools`).
- Injects LLVM instrumentation flags (`-fsanitize=address,undefined -fsanitize=fuzzer-no-link -fno-omit-frame-pointer -g -O1`).
- Collects generated static archives (`.a`) and shared libraries (`.so`).

### Phase 3: Cognitive Harness Synthesis (`crashwise-agent`)
- Generates `LLVMFuzzerTestOneInput` harnesses using `FuzzedDataProvider`.
- Captures `clang++` error diagnostics and feeds them back into the LLM context to self-correct in-memory.
- Enforces a 5-second runtime sanity gate against dummy inputs to eliminate false-positive memory leaks.

### Phase 4: High-Throughput Fuzzing (`crashwise-engine`)
- Executes fuzzer in lightweight sandbox with resource limits.
- Manages seed corpus harvesting and monitors for unique coverage edge expansions.

### Phase 5: Crash Triage & Exploit PoC (`crashwise-triage`)
- Parses AddressSanitizer/UBSan output.
- Computes MD5 hash of top stack frames for 100% accurate crash deduplication.
- Generates standalone, self-contained C reproducer files (`poc.c`) with embedded crash byte payloads.
- Synthesizes surgical bounds-check unified diff patches (`.patch`).

### Phase 6: Web Command Center (`crashwise-server` & `web/`)
- Axum REST API and Server-Sent Events (SSE) daemon.
- Next.js web control plane with real-time telemetry streaming and crash viewer.
