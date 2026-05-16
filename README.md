<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

<p align="center">
  <h1 align="center">CrashWise</h1>
  <p align="center"><strong>Autonomous vulnerability discovery for C/C++ targets.</strong></p>
  <p align="center">Point it at a repo. It finds the bugs.</p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/fuzzers-AFL++%20%7C%20libFuzzer-orange" alt="Fuzzers">
  <img src="https://img.shields.io/badge/sandbox-hardened-purple" alt="Sandboxed">
</p>

---

CrashWise is an **AI-powered fuzzing platform** that autonomously discovers memory-safety vulnerabilities in C/C++ projects. It clones your target, builds it with sanitizers, generates a fuzz harness using LLMs, runs AFL++/libFuzzer in hardened Docker containers, triages crashes, and reports exploitable bugs — all without human intervention.

```bash
crashwise init                          # detect build system, generate manifest
crashwise run https://github.com/madler/zlib   # fuzz it
```

---

## Who This Is For

- **Vulnerability researchers** who want to scale their bug hunting across many targets
- **Bug bounty hunters** who need automated first-pass fuzzing before manual review
- **Security teams** running continuous fuzzing on internal C/C++ codebases
- **Open-source maintainers** who want to catch memory bugs before release

## What It Does

```
Target Repo → Clone → Build (ASan+UBSan) → AI Harness Synthesis → Fuzz → Triage → Report
                                                    ↑                          |
                                                    └── Self-Correction Loop ──┘
```

1. **Discovers the API** — Scans public headers to find high-value entry points (parsers, decoders, decompressors)
2. **Generates a harness** — LLM writes a libFuzzer harness, validates it compiles, runs a 5-second sanity check
3. **Self-corrects** — If the harness crashes, GDB extracts the backtrace and the LLM fixes its own code
4. **Fuzzes** — Runs AFL++/libFuzzer in sandboxed Docker containers with coverage feedback
5. **Evolves** — When coverage plateaus, identifies the exact blocker and rewrites the harness to bypass it
6. **Triages** — Classifies crashes (heap-overflow, UAF, null-deref), deduplicates by stack hash, scores severity

---

## Quick Start

```bash
# Install
git clone https://github.com/yahyatoubali/Crashwise.git && cd Crashwise
pip install -e .

# Start infrastructure
docker compose up -d

# Configure LLM (pick one)
echo 'CRASHWISE_LLM_MODEL=claude-sonnet-4-5' >> .env
echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env

# Fuzz a target
crashwise run --timeout 600 https://github.com/madler/zlib
```

See [docs/INSTALL.md](docs/INSTALL.md) for detailed setup instructions.

---

## How It Works

### The Intelligence Layer (Operation Hydra)

CrashWise isn't a dumb fuzzer wrapper. It has three layers of intelligence:

**THE SENSES** — Finds what to fuzz
- Parses `.h` files to discover the real public API (not just grep for function names)
- Resolves typedefs (`Bytef` → `unsigned char`, `z_streamp` → `z_stream *`)
- Scores entry points by attack surface value (decompressors > utility functions)

**THE BRAIN** — Fixes its own mistakes
- 5-second sanity gate rejects dead harnesses before wasting compute
- GDB extracts crash backtraces and feeds them back to the LLM
- Mines test/example code from the target repo as reference patterns
- Self-correction loop: crash → diagnose → fix → retry (up to 3 attempts)

**THE HANDS** — Understands the build system
- Extracts struct definitions so the LLM knows exact field layouts
- Auto-discovers library paths and include directories
- Fixes its own compilation errors by searching the build tree

### Workflow Orchestration

Built on [Temporal](https://temporal.io) for durability:
- Campaigns survive worker crashes and restarts
- Automatic retry with exponential backoff
- Horizontal scaling (add more workers)
- God-Mode signals for live operator control

### Security Sandbox

Every fuzzer container runs with:
- `--network none` (no internet access)
- `--read-only` filesystem
- `--cap-drop ALL` (no Linux capabilities)
- `--pids-limit 1024`
- Size-capped tmpfs mounts
- No `shell=True` anywhere in the codebase

---

## CLI

```bash
crashwise init                    # Auto-detect project, generate manifest
crashwise run <repo-url>          # Submit fuzzing campaign
crashwise run --detach <url>      # Submit and exit immediately
crashwise doctor                  # Check system health
crashwise setup                   # Install missing dependencies
crashwise dashboard               # Launch web UI (localhost:8501)
crashwise signal <id> pause_hunt  # Pause a running campaign
crashwise signal <id> force_pivot # Force strategy switch
```

---

## Configuration

CrashWise needs one LLM API key for harness synthesis. Everything else is optional.

### Minimum (.env)

```bash
CRASHWISE_LLM_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-...
```

### Full Stack (.env)

```bash
# Harness synthesis (required)
CRASHWISE_LLM_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-...

# Crash triage (optional — falls back to regex heuristics)
AI_PROVIDER=ollama
AI_MODEL=llama3.1:8b
OLLAMA_URL=http://localhost:11434

# Infrastructure
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/crashwise
REDIS_URL=redis://localhost:6379/0
TEMPORAL_HOST=localhost:7233
```

Works with: **Anthropic**, **OpenAI**, **NVIDIA NIM**, **Together AI**, **Groq**, **Ollama**, **vLLM**, or any OpenAI-compatible endpoint.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  CLI / API / Dashboard                                        │
├──────────────────────────────────────────────────────────────┤
│  Temporal Workflows (durable, retryable)                      │
│  └─ MainFuzzingWorkflow → 23 Activities                      │
├──────────────────────────────────────────────────────────────┤
│  AI Agents (LangGraph)                                        │
│  ├─ Harness Synthesis (analyze → generate → validate → retry)│
│  ├─ Coverage Analysis (blocker identification)                │
│  ├─ Crash Triage (ASAN/GDB → severity → dedup)              │
│  └─ Exploit Generation (PoC synthesis)                        │
├──────────────────────────────────────────────────────────────┤
│  Execution (Docker sandbox)                                   │
│  ├─ AFL++ (multi-strategy, MAB-guided)                       │
│  ├─ libFuzzer (coverage-guided)                              │
│  └─ QEMU/KVM (kernel targets)                               │
├──────────────────────────────────────────────────────────────┤
│  Storage: PostgreSQL │ Redis │ R2/S3 │ SQLite (dev)          │
└──────────────────────────────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for the full technical deep-dive.

---

## Supported Targets

| ✅ Works Well | ⚠️ May Need Help | ❌ Not Supported |
|--------------|------------------|-----------------|
| C/C++ libraries with CMake/Make | Complex monorepos (Chromium) | Closed-source binaries |
| Parser libraries (image, archive, crypto) | Custom toolchains | Windows-only (MSVC) |
| Projects with existing fuzz harnesses | Deeply nested APIs | Managed languages (Java, Python) |
| Standard build systems | Projects without headers | Network daemons |

**Best targets:** zlib, libpng, libjpeg-turbo, freetype, openssl, libxml2, harfbuzz, libarchive, pcre2

---

## Development

```bash
# Setup
git clone https://github.com/yahyatoubali/Crashwise.git && cd Crashwise
uv sync  # or: pip install -e ".[dev]"

# Test
uv run pytest tests/ -v

# Lint
uv run ruff check crashwise/

# Type check
uv run mypy crashwise/
```

---

## Current Status

**Pre-alpha.** The autonomous pipeline works end-to-end. The main limitation is LLM quality — stronger models (Claude Sonnet, GPT-4o) produce better harnesses than smaller ones. The fallback harness always compiles but provides minimal coverage.

See [CHANGELOG.md](./CHANGELOG.md) for version history.

---

## License

MIT — see [LICENSE](./LICENSE).

Built by [Yahya Toubali](https://github.com/yahyatoubali) under the **Nadicorp** label.
