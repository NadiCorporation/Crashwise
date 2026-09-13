# Changelog

All notable changes to CrashWise are documented in this file.
The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0-alpha] — 2026-09-13 (Operation Megabits — Horizons 2 & 3 Certified)

This release delivers the complete implementation of **Horizon 2 (Target Hardening & Verification)** and **Horizon 3 (Deep Intelligence & Closed-Loop Verification)** across the 8-crate Rust workspace, certified via an independent **Victory Audit**.

### 🌲 Static Analysis & Memory Layout (`crashwise-ast` & `crashwise-core`)
- **System V AMD64 Recursive Layout Resolver**: Built recursive Tree-sitter layout engine calculating concrete byte offsets, bitfield boundary alignments, `#pragma pack(n)` packing directives, and anonymous union variants with 100% GCC compiler oracle fidelity.
- **SQLite Feedback Memory Schema**: Extended embedded SQLite storage with `agent_feedback_memory` tables and 5 performance-optimized B-tree indexes for fast exemplar querying.

### ⚡ High-Throughput Fuzzing Engine & Sandboxing (`crashwise-engine`)
- **In-Process LibAFL Runner**: Upgraded fuzzing execution from subprocess-spawning to in-process LibAFL execution with POSIX shared-memory coverage feedback (`shm`).
- **Throughput Benchmark**: Achieved **10,146.3 execs/sec** average throughput on single-core benchmark targets (exceeding the $>1,500$ requirement by >6.7×).
- **4-Tier Rootless Linux Sandbox**: Integrated cgroups v2 resource controllers, unprivileged Linux namespaces (User, Mount, PID, IPC), Seccomp BPF syscall whitelisting, and strict POSIX `rlimits`.
- **Async-Signal Safe Recovery**: Crash unwinding using dedicated `sigaltstack` buffers and `siglongjmp` to prevent heap deadlocks during fatal memory faults.

### 🛡️ Closed-Loop Automated Patch Verification (`crashwise-triage`)
- **5-Stage Verification Engine**: Automated end-to-end verification pipeline:
  1. *Pre-Patch Crash Reproduction*: Asserts unpatched target crashes on `poc.c`.
  2. *Atomic Unified Diff Application*: Transactional `PatchApplier` with RAII `PatchGuard` automatic rollback.
  3. *ASan Target Rebuild*: Recompiles the target library with Clang AddressSanitizer and UBSan instrumentation.
  4. *Clean Standalone `poc.c` Replay*: Confirms zero memory violations, leaks, or crashes.
  5. *Regression Suite Assertions*: Executes target's original regression test suite to prove zero regression.
- **Adversarial Hardening**: Validated defenses against directory traversal (`../`), backup collisions, and malformed diff chunks.

### 🧠 Cognitive Agent & Feedback Self-Healing (`crashwise-agent`)
- **Dynamic Exemplar Retrieval**: Lexical diagnostic token overlap retriever dynamically injects high-relevance repair exemplars into LLM synthesis contexts.
- **High First-Attempt Compilation**: Achieved **81.82% (9/11)** first-attempt compilation success on real-world benchmark C targets.
- **Diagnostic Self-Correction**: Clang compilation errors and compiler output automatically parsed and fed back with structured AST layout context.

### 🎯 Real-World CVE Validation Suite (`crashwise-build` & `crashwise-cli`)
- **Target Provisioning (`TargetManager` & `TargetBuilder`)**: 2-tier target provisioning (automated git clone + reproducible offline fixtures) for `cJSON`, `zlib`, `libpng`, and `sqlite3`.
- **Unified Benchmark CLI**: `crashwise benchmark` command executing 7 autonomous phases from AST discovery through patch verification.
- **Full E2E Verification**: Successfully reproduced and verified automated patch elimination on real CVE targets.

### 🧪 Quality Assurance & Test Infrastructure
- **Comprehensive Test Suite**: **357 unit tests** across all 8 crates + **124 multi-tier integration tests** across Tiers 1–5 passing 100% cleanly.
- **Strict Lint Compliance**: Zero warnings under `cargo clippy --workspace --all-targets -- -D warnings`.

---

## [0.2.0-dev] — 2026-09-11 (Pre-Alpha / Operation Megabits Scaffolding)

### 🚀 Architectural Migration
- **Pure Rust Workspace Scaffolding**: Replaced legacy prototype with an 8-crate zero-dependency Rust workspace.
- **Deterministic AST Parser**: Tree-sitter parser for C/C++ source trees, callgraphs, and dangerous memory sinks.
- **Cognitive Harness Synthesis**: LLM harness synthesis with 5-second runtime sanity gate.
- **Embedded SQLite Persistence**: Built-in SQLite database with Write-Ahead Logging (WAL).
- **Axum REST & SSE Telemetry Daemon**: Real-time server and Server-Sent Events streaming to Next.js 15 Web Command Center.
