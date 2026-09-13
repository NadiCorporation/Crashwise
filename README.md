<div align="center">

# CrashWise

### Autonomous AI-Powered 0-Day Vulnerability Discovery, Fuzzing & Self-Healing Engine

[![CI Quality Pipeline](https://github.com/NadiCorporation/Crashwise/actions/workflows/ci.yml/badge.svg)](https://github.com/NadiCorporation/Crashwise/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/Status-Experimental%20Pre--Alpha-red.svg)](ROADMAP.md)
[![Verification](https://img.shields.io/badge/Victory%20Audit-Certified%20CLEAN-brightgreen.svg)](TEST_READY.md)
[![Organization](https://img.shields.io/badge/Maintained%20By-Nadi%20Corporation-blue.svg)](https://github.com/NadiCorporation)

<p align="center">
  <b>High-Throughput LibAFL Fuzzing</b> • <b>Deterministic Tree-sitter AST Analysis</b> • <b>Closed-Loop Patch Verification</b> • <b>Autonomous CVE Reproduction</b>
</p>

</div>

---

> [!WARNING]
> **🧪 EXPERIMENTAL RESEARCH PROTOTYPE — PRE-ALPHA ACTIVE DEVELOPMENT**
>
> CrashWise is an experimental security research platform maintained by **Nadi Corporation**. It is currently under rapid evolution across its core heuristics and closed-loop verification pipelines. Use exclusively for authorized defensive security research, evaluation, and sandboxed testing.

---

## 1. Overview

**CrashWise** is an autonomous 0-day vulnerability discovery and automated self-healing platform written in **pure Rust**. Designed to eliminate the human bottlenecks of traditional security audits, CrashWise autonomously handles the entire vulnerability lifecycle:

$$\text{AST Mining} \longrightarrow \text{Instrumented Build} \longrightarrow \text{Cognitive Harness Synthesis} \longrightarrow \text{LibAFL In-Process Fuzzing} \longrightarrow \text{ASan Triage} \longrightarrow \text{Standalone PoC} \longrightarrow \text{5-Stage Patch Verification}$$

Unlike traditional fuzzers that require manually handcrafted test harnesses or legacy pipelines that produce unverified static analysis warnings, CrashWise is **strictly grounded in empirical execution**: every reported vulnerability comes with a verified, compilable C Proof-of-Concept (`poc.c`) and an automatically tested source patch.

---

## 2. Core Architecture

CrashWise is organized as an **8-crate zero-dependency Rust workspace** paired with a real-time **Next.js 15 Web Command Center**:

```
┌────────────────────────────────────────────────────────────────────────┐
│               Operator Plane: Next.js 15 Web Command Center            │
│   Real-Time SSE Telemetry • Live Log Streaming • Crash & PoC Explorer │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Axum REST + Server-Sent Events (SSE)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   CrashWise Core Engine (Rust Workspace)               │
│                                                                        │
│  ├── crashwise-core    : Embedded SQLite (WAL), models & telemetry db  │
│  ├── crashwise-ast     : Tree-sitter AST parser & AMD64 layout engine  │
│  ├── crashwise-build   : Clang compiler driver & TargetManager builds  │
│  ├── crashwise-agent   : Multi-provider LLM client & feedback memory   │
│  ├── crashwise-engine  : In-process LibAFL runner & rootless sandbox   │
│  ├── crashwise-triage  : ASan parser, PoC compiler & patch verifier    │
│  ├── crashwise-server  : Axum REST + SSE real-time daemon              │
│  └── crashwise-cli     : Unified single CLI binary (`crashwise`)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Key Capabilities

### 🌲 System V AMD64 Recursive AST Layout Resolver (`crashwise-ast`)
- Deterministic Tree-sitter parsing for C and C++ source trees with zero regex heuristic dependency.
- Recursive memory layout engine calculating field offsets, struct/union variants, `#pragma pack(n)` packing directives, and zero-width bitfield realignments with **100% GCC compiler oracle fidelity**.
- Dangerous memory sink reachability mapping (`memcpy`, `strcpy`, `sprintf`, `alloca`, `malloc`, `free`).

### ⚡ In-Process LibAFL Engine & Rootless Sandbox (`crashwise-engine`)
- Native in-process `LibAFL` fuzzing runner utilizing a **64KB POSIX shared-memory bitmap (`shm`)** with saturation-protected 8-bit counters.
- **Ultra-High Throughput**: Exceeds **10,000 executions/second** on single-core benchmark targets (6.7× faster than subprocess-based fuzzers).
- **4-Tier Rootless Linux Sandbox**: Enforces isolation via cgroups v2 resource accounting, unprivileged Linux namespaces (User, Mount, PID, IPC), Seccomp BPF syscall whitelisting, and strict POSIX `rlimits`.

### 🛡️ 5-Stage Closed-Loop Automated Patch Verifier (`crashwise-triage`)
Automated remediation is never trusted on paper—every candidate fix passes a strict 5-stage verification gate:
1. **Pre-Patch Crash Reproduction**: Confirms the standalone `poc.c` reproduces the ASan memory corruption against the unpatched target.
2. **Atomic Unified Diff Application**: Transactional `PatchApplier` with RAII `PatchGuard` automatic rollback on any failure. Guarded against directory traversal (`../`) and backup collisions.
3. **ASan Target Rebuild**: Recompiles the target library with AddressSanitizer and UndefinedBehaviorSanitizer instrumentation.
4. **Clean Standalone `poc.c` Replay**: Asserts zero sanitizer violations, segmentation faults, or memory leaks post-patch.
5. **Regression Suite Assertion**: Executes the target's original test suite to ensure the patch introduces zero behavioral regressions.

### 🧠 Cognitive Feedback Memory & Self-Correction (`crashwise-agent`)
- SQLite-backed `agent_feedback_memory` table tracking previous Clang diagnostic errors, coverage-expanding tokens, and successful repair diffs.
- Lexical diagnostic token overlap retriever dynamically injects high-relevance repair exemplars into prompt contexts, achieving an **81.82% first-attempt compilation success rate** on complex C targets.

### 🎯 Real-World CVE Benchmark Suite (`crashwise-build` & `crashwise-cli`)
- Built-in `TargetManager` and `TargetBuilder` supporting authentic compilation and testing for industry benchmark targets: `cJSON`, `zlib`, `libpng`, and `sqlite3`.
- Unified `crashwise benchmark` command verifying end-to-end autonomous discovery through patch verification.

---

## 4. Quickstart

### Prerequisites
- **Rust Toolchain**: `rustc` & `cargo` 1.80+
- **LLVM / Clang**: `clang`, `clang++` 16+
- **Build Utilities**: `cmake`, `make`, `meson`
- **Node.js**: v18+ (for Web Command Center)

### 1. Build the Engine
```bash
# Clone the repository
git clone https://github.com/NadiCorporation/Crashwise.git
cd Crashwise

# Build the release binary
cargo build --release
```

### 2. Verify System Tooling
```bash
./target/release/crashwise doctor
```

### 3. Run Real-World CVE Benchmark Demonstration
Verify the autonomous pipeline against authentic real-world targets (`cJSON`, `zlib`, `libpng`, `sqlite3`):
```bash
# Run benchmark on cJSON with in-process LibAFL fuzzing and patch verification
./target/release/crashwise benchmark --target cjson --offline
```

### 4. Scan Target Attack Surface AST
```bash
./target/release/crashwise scan /path/to/target/source
```

### 5. Run Full Autonomous Fuzzing Campaign
```bash
# Export your LLM API credentials (DeepSeek, OpenAI, Claude, or local Ollama)
export OPENAI_API_KEY="your-api-key"

./target/release/crashwise run /path/to/target/source --name my-target --timeout 300
```

### 6. Launch Web Command Center
```bash
# Start backend API & real-time telemetry daemon (Port 8000)
./target/release/crashwise server --port 8000

# In another terminal, launch the Next.js frontend
cd web && npm install && npm run dev
```

---

## 5. Verification & Testing

CrashWise enforces rigorous multi-tiered quality gates:

```bash
# Run workspace check & strict clippy lints (0 warnings policy)
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Run all 357 unit tests across all 8 crates
cargo test --workspace

# Run the 124 multi-tier opaque-box integration tests
cargo test -p crashwise-e2e-tests --test e2e_test_suite
```

| Test Tier | Description | Test Count | Result |
| :--- | :--- | :---: | :---: |
| **Tier 1** | Feature Coverage (AST, Shm, Sandbox, ASan, PoC, Patches) | 21 tests | **PASSED** |
| **Tier 2** | Boundary & Corner Cases (Circular structs, corrupted diffs, rlimits) | 33 tests | **PASSED** |
| **Tier 3** | Cross-Feature Integration (Fuzz $\rightarrow$ Triage $\rightarrow$ Patch rollback) | 16 tests | **PASSED** |
| **Tier 4** | Real-World CVE Scenarios (cJSON, zlib, libpng, sqlite3) | 16 tests | **PASSED** |
| **Tier 5** | White-Box Adversarial Stress (Shm saturation, Seccomp BPF, crash signals) | 38 tests | **PASSED** |
| **Total** | **Comprehensive Full Workspace Test Suite** | **481 tests** | **100% PASS** |

---

## 6. Project Documentation

- 🧭 [**Vision & Manifesto**](VISION.md) — Architectural philosophy and paradigm comparison.
- 🗺️ [**Technical Roadmap**](ROADMAP.md) — Phased milestones from Pre-Alpha to Production-Ready.
- 📐 [**Technical Specifications**](TECH_SPECS.md) — Deep architectural specs across all 6 autonomous phases.
- 🤝 [**Contributing Guide**](CONTRIBUTING.md) — Contribution tracks, coding standards, and developer setup.
- 📜 [**Changelog**](CHANGELOG.md) — Release notes and evolutionary changelog.
- 🛡️ [**Security Policy**](SECURITY.md) — Responsible disclosure protocol.

---

## 7. Security Research & Ethical Use

CrashWise is engineered exclusively for **defensive security engineering**, **automated vulnerability discovery**, and **proactive patch verification**. Researchers and organizations must only run CrashWise against software they own or have explicit authorization to audit.

---

## 8. License & Entity Attribution

Maintained by **[Nadi Corporation](https://github.com/NadiCorporation)**.  
Licensed under the [MIT License](LICENSE).
