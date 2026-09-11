# CrashWise — Autonomous AI-Driven 0-Day Discovery Engine

> [!WARNING]
> **🧪 EXPERIMENTAL RESEARCH PROTOTYPE — ACTIVE PRE-ALPHA DEVELOPMENT (Operation Megabits)**
>
> CrashWise is an experimental research prototype under active development and testing. It is **NOT** a mature or production-ready product. Workflows, heuristics, LLM prompts, and command interfaces are rapidly evolving. Use exclusively for security research, evaluation, and sandbox testing.

---

## 1. Overview

**CrashWise** is an autonomous security intelligence platform engineered to discover zero-day vulnerabilities in C/C++, Rust, and Go software targets without requiring manual harness authoring or human-in-the-loop triage.

Built entirely in **Rust** for maximum throughput, memory safety, and sub-second execution control, CrashWise combines **deterministic static AST analysis**, **closed-loop cognitive harness synthesis**, **high-performance fuzzing**, and **automated exploit Proof-of-Concept generation**.

```
┌────────────────────────────────────────────────────────────────────────┐
│               Operator Plane: Next.js 15 Web Command Center            │
│   Real-Time SSE Telemetry • Live Log Streaming • Crash & PoC Explorer │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Axum REST + SSE / WebSockets
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   CrashWise Core Engine (Rust Workspace)               │
│                                                                        │
│  ├── crashwise-core    : Embedded SQLite (WAL), models, config engine  │
│  ├── crashwise-ast     : Tree-sitter C/C++ AST parser & callgraph sinks│
│  ├── crashwise-build   : Clang compiler driver & sanitizer generator   │
│  ├── crashwise-agent   : Multi-provider LLM harness synthesizer & gate │
│  ├── crashwise-engine  : High-throughput fuzz runner & rootless sandbox│
│  ├── crashwise-triage  : ASan parser, PoC reproducer & patch generator │
│  ├── crashwise-server  : Axum REST + Server-Sent Events daemon         │
│  └── crashwise-cli     : Unified single binary CLI (`crashwise`)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Documentation

- 🧭 [**Vision & Manifesto**](VISION.md) — The core philosophy, mission, and how CrashWise compares to legacy fuzzers.
- 🗺️ [**Technical Roadmap**](ROADMAP.md) — Phased milestones from Pre-Alpha to Production-Ready, with focus areas and benchmarks.
- 📐 [**Technical Specifications**](TECH_SPECS.md) — Deep architectural specs across the 6-phase autonomous pipeline.
- 🤝 [**Contributing Guide**](CONTRIBUTING.md) — 6 engineering tracks and local development instructions.
- 📜 [**Changelog**](CHANGELOG.md) — Detailed version history and release notes.

---

## 3. Key Features

- ⚡ **Single-Binary Zero-Dependency Engine**: Pure Rust workspace with embedded SQLite persistence. No external database servers or runtime dependencies required.
- 🌲 **Tree-sitter AST & Callgraph Mining**: Parses thousands of C/C++ functions and headers in milliseconds. Identifies dangerous memory sinks (`memcpy`, `strcpy`, `sprintf`, `malloc`, `free`) with zero regex false positives.
- 🤖 **Closed-Loop Cognitive Synthesis**: Synthesizes `LLVMFuzzerTestOneInput` harnesses using `FuzzedDataProvider`. Catches `clang++` errors and automatically feeds compiler diagnostics back to the LLM to self-heal.
- 🛡️ **5-Second Runtime Sanity Gate**: Pre-flight verification of compiled harnesses against dummy inputs to eliminate false-positive memory leaks and startup crashes before fuzzing begins.
- 🚨 **Autonomous Crash Triage & Standalone PoC**: Parses AddressSanitizer/UBSan crashes, computes MD5 stack frame hashes for 100% deduplication, and generates standalone C reproducer programs (`poc.c`).
- 📊 **Real-Time Control Plane**: Axum REST server streaming real-time telemetry (execs/s, coverage edges, crashes) and live worker logs via Server-Sent Events (SSE).

---

## 4. Quickstart

### Prerequisites
- **Rust Toolchain** (`cargo`, `rustc` 1.80+)
- **LLVM / Clang** (`clang`, `clang++` 16+)
- **Build Tools** (`cmake`, `make`, `meson`)
- **Node.js** (v18+ for Web UI)

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

### 3. Scan Target Attack Surface AST
```bash
./target/release/crashwise scan /path/to/target/source
```

### 4. Run Full Autonomous Fuzzing Campaign
```bash
# Set your LLM API credentials (DeepSeek, OpenAI, Claude, or local Ollama)
export OPENAI_API_KEY="your-api-key"

./target/release/crashwise run /path/to/target/source --name my-target --timeout 300
```

### 5. Launch Web Command Center Daemon
```bash
# Start backend API and telemetry daemon (Port 8000)
./target/release/crashwise server --port 8000

# In a separate terminal, launch the Next.js frontend
cd web && npm install && npm run dev
```

---

## 5. Architecture & Crate Layout

| Crate | Responsibility |
| :--- | :--- |
| [`crashwise-core`](crates/crashwise-core/) | Domain models, zero-hardcode configuration, embedded SQLite storage (WAL mode). |
| [`crashwise-ast`](crates/crashwise-ast/) | Tree-sitter AST parsing, callgraph generation, dangerous sink reachability, and stateful API sequence mining. |
| [`crashwise-build`](crates/crashwise-build/) | Build detection (CMake, Meson, Make, Autotools) and Clang sanitizer injection (`-fsanitize=address,undefined`). |
| [`crashwise-agent`](crates/crashwise-agent/) | Multi-provider LLM client with self-correcting harness synthesis and 5-second runtime sanity gate. |
| [`crashwise-engine`](crates/crashwise-engine/) | Sub-second fuzzing executor, seed corpus manager, and rootless Linux sandbox. |
| [`crashwise-triage`](crates/crashwise-triage/) | ASan stack trace parser, MD5 stack deduplication, CWE/CVSS scorer, and standalone C PoC generator. |
| [`crashwise-server`](crates/crashwise-server/) | Axum web daemon with REST endpoints, SSE telemetry, and real-time log streamer. |
| [`crashwise-cli`](crates/crashwise-cli/) | Unified command-line interface (`crashwise`). |

---

## 6. Security Research & Ethical Use

CrashWise is designed specifically for **defensive security engineering**, **automated vulnerability discovery**, and **remediation**. Researchers and organizations must only run CrashWise against software they own or have explicit authorization to audit.

---

## 7. License

Licensed under the [MIT License](LICENSE).
