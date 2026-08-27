<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# CrashWise

Automated vulnerability discovery for C/C++ targets via LLM-driven harness synthesis, coverage-guided fuzzing (AFL++/libFuzzer), and crash triage.

| | |
|---|---|
| **Runtime** | Python 3.11+ |
| **License** | MIT |
| **Fuzzers** | AFL++, libFuzzer |
| **Sanitizers** | ASan, UBSan |
| **Orchestration** | Temporal |
| **Status** | Pre-alpha |

```bash
crashwise run https://github.com/madler/zlib
```

---

## Pipeline

```
Clone → Build (ASan+UBSan+source-cov) → Harness Synthesis → Fuzz → Triage → Report
                                              ↑                          │
                                              └── Self-Correction Loop ──┘
```

1. Scans public headers, resolves typedefs, scores entry points by attack surface
2. LLM generates a `LLVMFuzzerTestOneInput` harness; validates compilation + 5s sanity gate
3. On failure: GDB backtrace → LLM diagnosis → fix → retry (max 3 attempts)
4. Executes AFL++/libFuzzer in sandboxed Docker containers with coverage feedback
5. On plateau: identifies blocker (magic value, length check, checksum, state machine), rewrites harness
6. Classifies crashes by type, deduplicates by stack hash, scores exploitability

---

## Quick Start

```bash
git clone https://github.com/yahyatoubali/Crashwise.git && cd Crashwise
pip install -e .
docker compose up -d
```

```bash
# .env (minimum)
CRASHWISE_LLM_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-...
```

```bash
crashwise run --timeout 600 https://github.com/madler/zlib
```

See [docs/INSTALL.md](docs/INSTALL.md) for full setup.

---

## CLI Reference

| Command | Description |
|---|---|
| `crashwise init` | Detect build system, generate `crashwise.yaml` manifest & create DB tables |
| `crashwise configure` | Interactive setup wizard for LLM providers (Anthropic, OpenAI, Venice, Ollama) |
| `crashwise run <repo-url>` | Submit fuzzing campaign (blocking or manifest-driven) |
| `crashwise run --detach <url>` | Submit campaign and return immediately with workflow ID |
| `crashwise doctor` | Run system health diagnostics (Docker, compilers, memory, services) |
| `crashwise setup` | Auto-install missing build tools and configure Docker permissions |
| `crashwise worker` | Start a Temporal worker polling the task queue |
| `crashwise api` | Launch the FastAPI management server on `localhost:8000` |
| `crashwise dashboard` | Launch the Streamlit dashboard on `localhost:8501` |
| `crashwise signal <id> <signal>` | Dispatch God-Mode signals (`pause_hunt`, `resume_hunt`, `force_pivot`, `inject_seed`) |
| `crashwise exploit <crash_id>` | Synthesize, compile, and verify standalone C PoC exploit for a crash |
| `crashwise info` / `version` | Display runtime configuration and version metadata |

---

## Configuration

### Multi-Provider LLM Setup (Vendor-Neutral)

CrashWise connects to any LLM provider via standard OpenAI-compatible interfaces or native providers. Configure your preferred model in `.env` or pass CLI flags directly at runtime:

```bash
# DeepSeek (Tested on staging)
OPENAI_API_BASE=https://api.deepseek.com
OPENAI_API_KEY=sk-...
MODEL_NAME=deepseek-chat
TEMPERATURE=0.0

# Anthropic Claude
CRASHWISE_LLM_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-...

# Ollama / Local vLLM
OPENAI_API_BASE=http://localhost:11434/v1
OPENAI_API_KEY=ollama
MODEL_NAME=llama3.1:8b
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MODEL_NAME` / `CRASHWISE_LLM_MODEL` | `claude-sonnet-4-5` | Primary model for autonomous harness synthesis and repair |
| `OPENAI_API_BASE` | — | OpenAI-compatible custom base URL (DeepSeek, Ollama, vLLM, Venice) |
| `OPENAI_API_KEY` | — | API key for OpenAI-compatible endpoint |
| `TEMPERATURE` / `CRASHWISE_LLM_TEMPERATURE` | `0.0` | Sampling temperature for deterministic harness synthesis |
| `MAX_TOKENS` | `4096` | Max token budget per turn |
| `REASONING_EFFORT` | `medium` | Reasoning effort parameter (`low`, `medium`, `high`) for reasoning models |
| `AI_PROVIDER` | `openai_compatible` | Crash triage backend (`openai_compatible`, `ollama`, `venice`) |
| `DATABASE_URL` | `sqlite+aiosqlite:///./crashwise.db` | Async SQLAlchemy URL (`postgresql+asyncpg://...` in prod) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis for distributed state, heartbeats, and dedup |
| `TEMPORAL_HOST` | `localhost:7233` | Temporal server address |

### Granular CLI Knobs

```bash
crashwise run <target> \
  --fuzzer libfuzzer \
  --sanitizers address,undefined \
  --custom-flags "-dict=json.dict -max_len=1024" \
  --model deepseek-chat \
  --base-url https://api.deepseek.com \
  --api-key sk-... \
  --temperature 0.0 \
  --reasoning-effort medium \
  --max-synth-retries 4 \
  --mab \
  --mab-algorithm thompson \
  --self-healing \
  --max-repair-attempts 10
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  CLI / FastAPI Gateway (:8000) / Next.js Dashboard (:3000)   │
├──────────────────────────────────────────────────────────────┤
│  Temporal Workflows (durable, replayable)                    │
│  ├─ MainFuzzingWorkflow → 27 Registered Activities          │
│  └─ VerifyPatchWorkflow (autonomous fix verification)        │
├──────────────────────────────────────────────────────────────┤
│  Cognitive AI Agents (LangGraph)                             │
│  ├─ Harness Synthesis (analyze → generate → validate → retry)│
│  ├─ Healing Engine (autonomous build + crasher repair)       │
│  ├─ Coverage Feedback & Analysis (blocker isolation)         │
│  ├─ Crash Triage (ASAN/GDB → CWE classification → dedup)    │
│  ├─ Exploit Generation (standalone PoC synthesis)            │
│  └─ Cross-Campaign Knowledge Base (pattern learning)         │
├──────────────────────────────────────────────────────────────┤
│  Execution Sandboxes (Hardened)                              │
│  ├─ AFL++ (multi-strategy, Thompson Sampling MAB)            │
│  ├─ libFuzzer (in-process, coverage-guided)                  │
│  └─ QEMU/KVM (kernel targets)                               │
├──────────────────────────────────────────────────────────────┤
│  Storage: PostgreSQL 16 │ Redis 7 │ Cloudflare R2/S3 │ SQLite│
└──────────────────────────────────────────────────────────────┘
```

### Harness Synthesis

- Regex-based static analysis of `.h` files identifies function declarations
- Typedef resolution maps library-specific types to canonical C types (`Bytef` → `unsigned char`)
- Entry points scored by argument shape: `(const uint8_t*, size_t)` = 1.0, `(const char*)` = 0.7
- LangGraph state machine: `analyze_code → generate_harness → validate_harness → [retry|end]`
- Struct definitions extracted from headers and injected into LLM context
- Usage examples mined from `test/` and `examples/` directories

### Coverage Feedback Loop

- Source-based coverage via `-fprofile-instr-generate -fcoverage-mapping`
- `llvm-cov export` produces line-level hit/miss data (lcov format)
- Coverage analyzer identifies blockers: magic values, length checks, checksums, state machines, null guards
- Dictionary generator extracts comparison literals into `custom.dict` for token-aware mutation
- MAB strategist (Thompson Sampling) pivots between 5 fuzzer configurations on plateau

### Execution Sandbox

Every fuzzer container runs with:

| Constraint | Value |
|---|---|
| Network | `--network none` |
| Filesystem | `--read-only` |
| Capabilities | `--cap-drop ALL` |
| PIDs | `--pids-limit 1024` |
| Scratch | Size-capped tmpfs on `/tmp` and `/dev/shm` |
| Disk quota | `--storage-opt size=5G` (overlay2+xfs+pquota) |

> AFL++ containers additionally receive `--cap-add SYS_PTRACE` for forkserver operation.

### Workflow Durability

Built on Temporal:
- Campaigns survive worker crashes; activities resume from last heartbeat
- Exponential backoff retry with non-retryable error classification
- Horizontal scaling via additional worker processes
- God-Mode signals: `pause_hunt`, `force_pivot`, `inject_seed` for live operator control

See [docs/architecture.md](docs/architecture.md) for the full technical reference.

---

## Target Compatibility

| Compatible | Requires Manual Tuning | Unsupported |
|---|---|---|
| C/C++ libraries with CMake/Make/Meson | Bazel builds, complex monorepos | Closed-source binaries |
| Parser libraries (image, archive, crypto, font) | Custom toolchains, autotools edge cases | Windows-only (MSVC) |
| Projects with existing fuzz harnesses | Deeply nested struct-init APIs | Managed languages |
| Standard `(buf, size)` entry points | Callback-driven APIs (SAX parsers) | Network daemons (stateful protocols) |

Validated targets: zlib, libpng, libjpeg-turbo, freetype, openssl, libxml2, harfbuzz, libarchive, pcre2.

---

## Scope & Limitations

### Detects

| Class | Sanitizer |
|---|---|
| Heap/stack buffer overflow | ASan |
| Use-after-free, double-free | ASan |
| Null pointer dereference | ASan (SIGSEGV) |
| Integer overflow | UBSan |
| Uninitialized reads | ASan (partial) |

### Does Not Detect

| Class | Reason |
|---|---|
| Race conditions / TOCTOU | Single-threaded harnesses; no TSan |
| Deadlocks, livelock | No thread scheduling manipulation |
| Logic bugs in async code | Incompatible with byte-mutation model |
| Timing side-channels | Requires statistical analysis, not fuzzing |

> CrashWise generates single-threaded `LLVMFuzzerTestOneInput` harnesses instrumented with ASan+UBSan only. Concurrency bugs require [ThreadSanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html) or [rr](https://rr-project.org/).

---

## Development

```bash
git clone https://github.com/yahyatoubali/Crashwise.git && cd Crashwise
uv sync  # or: pip install -e ".[dev]"

uv run pytest tests/ -v        # test
uv run ruff check crashwise/   # lint
uv run mypy crashwise/         # type check
```

---

## License

MIT — see [LICENSE](./LICENSE).

Built by [Yahya Toubali](https://github.com/yahyatoubali).
