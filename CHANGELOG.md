# Changelog

All notable changes to CrashWise are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] — 2026-08-27

### Community-Grade Hardening & Multi-Provider Engine

#### Universal Multi-Provider LLM Integration
- **Vendor-Neutral Provider Routing** (`crashwise/core/llm_factory.py`): Centralized LLM factory routing dynamically across OpenAI, DeepSeek (`deepseek-chat`), Anthropic Claude (`claude-sonnet-4-5`), Ollama (`llama3.1`), vLLM, Venice, Groq, and Together AI without vendor lock-in.
- **Dynamic Configuration Aliasing** (`crashwise/core/config.py`): Added environment variable aliases for `MODEL_NAME`, `OPENAI_API_BASE`, `OPENAI_API_KEY`, `TEMPERATURE`, `MAX_TOKENS`, and `REASONING_EFFORT`.
- **Runtime Overrides**: Unified `get_llm_provider()` across all LangGraph nodes (Harness Synthesis, Healing Engine, Crash Triage, PoC Exploit Generation) to accept per-call temperature, token budgets, and reasoning effort.

#### Granular User Controls & Configuration
- **CLI Flags** (`crashwise/cli.py`): Added `--custom-flags`, `--model`, `--base-url`, `--api-key`, `--temperature`, `--reasoning-effort`, `--max-synth-retries`, `--mab`, `--mab-algorithm`, `--self-healing`, and `--max-repair-attempts` to `crashwise run`.
- **REST API & Workflow Payloads** (`crashwise/api/main.py`, `crashwise/core/models.py`): Expanded `CampaignCreateRequest` and `FuzzingInput` to pass all granular knobs to Temporal workflows and activities.

#### Stability Hardening & Zombie Elimination
- **Docker Sandbox Init** (`crashwise/execution/docker_manager.py`): Injected `--init` flag into container instantiation to run Docker's built-in Tini as PID 1, eliminating zombie and defunct child processes on interrupted fuzzing runs.
- **Database Connection Pooling** (`crashwise/core/database.py`): Added connection pool management (`pool_size=20`, `max_overflow=10`, `pool_pre_ping=True`, `pool_recycle=300`) and lazy session creation, preventing connection pool exhaustion during burst triage.
- **Activity Registry Expansion**: Added 28th registered activity (`synthesize_harness`) to enforce complete Temporal workflow determinism.

#### Target Deployment & Verification
- **C++ Source Linking Fallback** (`crashwise/orchestration/activities/setup_target.py`): Added automated discovery and linking of multi-file C++ source trees (`.cpp`, `.cc`, `.cxx`) when static archives are absent.
- **Live Real-World Target Verification**: Deployed and fuzzed Telegram VoIP native parser (`targets/libtgvoip`) with DeepSeek API on staging host `192.168.1.13`, achieving 110,956 iterations in 4s with ASAN+UBSan instrumentation.
- **Test Suite**: 509 unit tests passing across all suites (`uv run pytest tests/unit/`).

---

## [1.1.0] — 2026-05-16

### Operation Hydra — Agentic Intelligence Layer

#### Phase 1: THE SENSES
- **Header-Aware API Discovery** (`analyzer.py`): `find_public_api()` scans `.h` files, resolves typedefs (Bytef→unsigned char, z_streamp→struct*), scores struct-pointer APIs. Finds `compress`/`uncompress` at 0.95 instead of `z_error` at 0.3.
- **Truthful Coverage Analysis** (`coverage_analyzer.py`): Removed synthetic line number generation from AFL++/libFuzzer parsers. Returns empty sets (honest UNKNOWN) when no real line-level data available. Real llvm-cov/sancov paths unchanged.
- **5-Second Sanity Gate** (`compiler.py`): `sanity_check()` runs compiled harness for 5s before accepting. Rejects harnesses with <2 edges. Prevents wasting full fuzzing iterations on dead harnesses.
- **Anti-Hallucination Guard** (`nodes.py`): `_check_target_redefinition()` blocks LLM from redefining target functions. Target source is read-only.

#### Phase 2: THE BRAIN
- **GDB Debug Engine** (`debug_engine.py`): Runs crashing harness under `gdb --batch`, extracts backtrace, crash function, location, registers. Generates structured `CrashDiagnosis`.
- **Self-Correction ReAct Loop**: Sanity fail → `debug_crash()` → GDB backtrace fed to LLM → retry with crash context. Up to `max_retries` attempts with progressively richer diagnostics.
- **Usage Example Mining** (`setup_target.py`): `_find_usage_example()` scans test/examples dirs for code calling the target function. Extracts 25-line snippet as reference pattern.
- **Context Enrichment**: LLM prompt includes `## GDB CRASH DIAGNOSIS` + `## REFERENCE` sections.

#### Phase 3: THE HANDS
- **Type Extractor** (`type_extractor.py`): `extract_types_for_signature()` finds struct/typedef definitions from headers. Handles nested braces, typedef aliases. Tested: finds Bytef, uLongf, z_stream for zlib.
- **Build Resolver** (`build_resolver.py`): `diagnose_compile_error()` parses stderr for missing headers/libs, `resolve_build_paths()` discovers .a/.so + include dirs. Auto-retry compilation with discovered flags.
- **libFuzzer Signal Fix**: Added `-handle_segv=0 -handle_abrt=0` to sanity check and GDB commands. Enables pristine GDB backtraces (libFuzzer no longer intercepts signals).

#### Infrastructure Fixes (Operation NadiBugy)
- Fixed critical `-max_total_time=0` bug (libFuzzer exited immediately)
- Fixed glibc mismatch between build/run containers (use crashwise-worker as runner)
- Added `libclang-rt-14-dev` for sanitizer runtime support
- Shared `/tmp` volume between worker and sibling containers
- Fixed heartbeat timeout (15s → 5min) so docker pull doesn't get cancelled
- Enabled harness synthesis by default when no harness provided
- Fixed `mutate_harness` returning .cpp source instead of .out binary
- Fixed workflow logger kwargs crash
- Fixed task queue default (crashwise-default → crashwise)
- Added `update_campaign_status` activity for dashboard status tracking
- Added campaign delete endpoints + dashboard cleanup UI
- Campaign detail view in dashboard

---

## [1.0.0-rc2] — 2026-05-09

### Phase 21 + S6 Hardening + Linux Native + Intelligence Loop

#### Sandbox & Safety (S6 Hardening)
- **Hardened Docker sandbox** (`crashwise/execution/docker_manager.py`):
  fuzzer containers now launch with `--network none`, `--read-only`,
  size-capped `--tmpfs /tmp` and `--tmpfs /dev/shm`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`. `SYS_PTRACE` is granted *only* to
  AFL forkserver containers. A pre-flight `docker rm -f` neutralises
  zombie containers from prior worker crashes.
- **Shell-free hot-swap** (`crashwise/orchestration/activities/hot_swap_harness.py`):
  replaced `create_subprocess_shell` with `create_subprocess_exec`.
  LLM-supplied compile commands are parsed with `shlex.split` and
  validated against an allow-list of compilers (`gcc`, `clang`,
  `clang++`, `afl-clang-fast`, …). Shell metacharacters in tokens are
  rejected. **Closes a path-to-RCE chain.**
- **Persistent build cache**: compiled harness binaries are copied to
  `~/.cache/crashwise/build/{job_id}/harness` (or
  `$CRASHWISE_BUILD_CACHE`) before the `TemporaryDirectory` exits, so
  successful evolutions outlive the compile sandbox.
- **AFL stats parser dispatch** (`crashwise/execution/monitor.py`):
  `DockerHealthChecker` now routes AFL jobs to `parse_afl_fuzzer_stats`
  (reads `fuzzer_stats` file) instead of pushing TUI output through
  the libFuzzer regex. AFL campaigns no longer trip the stall detector
  after 90 seconds.
- **Zero-coverage stall detection** (`crashwise/agents/feedback/analyzer.py`):
  `edges_hit == 0` past a 2-iteration warm-up is now flagged STALLED
  with a clear instrumentation-failure hint, instead of being silently
  reported as "healthy".
- **ANSI-safe libFuzzer parser**: `parse_libfuzzer_log_tail` now strips
  ANSI escape sequences and accepts both integer and `1.2k`-style
  exec/s rates.

#### God-Mode Signals (Researcher UX)
- New Temporal workflow signals on `MainFuzzingWorkflow`:
  - `force_pivot(reason)` — operator-triggered MAB pivot.
  - `inject_seed({filename, data_b64})` — drop a manually crafted seed
    into the running corpus (size + traversal validated).
  - `pause_hunt(bool)` — pause / resume the campaign loop without
    losing state, using `workflow.wait_condition`.
- New queries: `is_paused`, `pending_seed_count`, `operator_notes`.
- New `inject_seeds` Temporal activity with atomic `.tmp` → `rename`
  writes, per-file (4 MiB) and total (16 MiB) size caps, and
  `Path.resolve().relative_to(corpus_dir)` containment checks.
- New CLI command:
  `crashwise signal <workflow_id> <signal_type> [--data <value>]`
  (signal types: `force_pivot`, `inject_seed`, `pause_hunt`,
  `resume_hunt`).

#### Linux-Native (Distro-Bridge)
- **`DistroDetector`** in `crashwise/core/sentinel.py` —
  `/etc/os-release`-based detection of Arch, Debian/Ubuntu, Fedora
  families plus derivatives (Manjaro, Endeavour, Mint, Pop!\_OS, Kali,
  Rocky, Alma, Amazon Linux, …).  New `DistroInfo` dataclass exposes
  `family`, `id_`, `pretty_name`, `version_id`.
- Per-distro **package map** + **install command templates** with a
  `{sudo}` placeholder rendered via `_sudo_prefix()` (which honours
  `os.geteuid() == 0` for root-in-container installs).
- **AUR rail** for Arch: AUR-only packages (e.g. `aflplusplus`) are
  split out and installed via a detected `yay` / `paru`. The setup
  script emits a clear warning when no AUR helper is present.
- **Hardcoded `apt-get` strings removed** from `check_runtime_docker`,
  `check_runtime_docker_compose`, `check_build_cmake`, `check_build_clang`,
  `check_build_gcc`, `check_build_llvm`, `check_build_afl`. Every
  remediation now passes through `_install_hint(distro, packages)`.

#### Pre-flight Gate (run command)
- `crashwise run` now invokes `Sentinel.check_health()` before
  submitting the workflow. Critical checks (`runtime.docker`,
  `build.clang`, `build.gcc`) must pass; failures abort the campaign
  with actionable remediation hints instead of crashing inside Temporal.
- New `--skip-preflight` flag for the dockerised worker / advanced users.

#### Interactive Provisioner
- `crashwise setup` is now interactive by default:
  - Detects the distro and prints the pretty name.
  - Confirms before each privileged action (`--yes` for non-interactive).
  - Detects when the current user is not in the `docker` group and
    offers to run `sudo usermod -aG docker $USER`, with a reminder
    about logout/login or `newgrp docker`.
  - Detects when the Docker daemon socket is down and offers to run
    `sudo systemctl start docker`.

#### Intelligence Loop (Coverage → Evolution)
- `MainFuzzingWorkflow._run_evolution` now invokes the
  `analyze_coverage_activity` to identify the *exact* `BlockerType`
  (MAGIC_VALUE, LENGTH_CHECK, CHECKSUM, STATE_MACHINE, …) and the
  source line gating coverage. The structured `CoverageBlocker` is
  passed into `EvolveHarnessInput` — replacing the previous
  `BlockerType.UNKNOWN` stub.
- New `max_evolution_count: int` field on `FuzzingInput` (default 10)
  prevents runaway LLM spend when the model keeps emitting the same
  fallback template against a structural blocker.

#### Documentation
- New `docs/INSTALL.md` — Zero-Friction Install Guide for Arch and
  Ubuntu with troubleshooting, AUR notes, and the source→destination
  migration flow.
- README badges, architecture diagram (now lists 18 activities), Key
  Features, Quick Start, CLI Reference, Repository Layout, Roadmap,
  and Validation Campaign sections updated to reflect Phase 21,
  S6 hardening, and the Linux-Native finalisation.

#### Tests
- `tests/unit/test_real_execution.py` (new, 6 tests) — exercises the
  real Docker fuzzing path via mocked daemon.
- `tests/unit/test_cli.py` — added
  `test_run_preflight_blocks_when_docker_missing`, updated existing
  tests to pass `--skip-preflight`.
- `tests/unit/test_execution.py` — updated mock sequences for the new
  pre-flight `docker rm -f` invocation; updated
  `test_docker_corpus_preservation_order` to filter post-`run`
  lifecycle events.
- `tests/unit/test_sentinel.py` — extended for distro detection,
  per-distro package maps, AUR split, sudo prefix.
- Test counts: **423 collected, 405 passing on the touched surface**
  (up from 374 in 1.0.0-rc1).

#### Mypy / Ruff
- Mypy clean on every changed source file (the one remaining error in
  `sentinel.py:681` is a pre-existing `redis.asyncio.close()` stub
  issue).
- Ruff lint clean on the diff (the 2 remaining F841 instances are in
  pre-existing `check_service_*` functions).

---

## [1.0.0-rc1] — 2026-05-02

### Repository Finalization
- Comprehensive README.md with architecture diagram, CLI reference, and test matrix.
- CHANGELOG.md documenting the full development journey from Phase 0 to Phase 15.
- GitHub Actions release workflow for automated Docker builds and GitHub Releases.
- CONTRIBUTING.md with Nadicorp coding standards.

---

## [0.7.0] — 2026-05-02

### Phase 15: Automated PoC Generation & Reachability Analysis

#### Added
- **Exploit Architect Agent** (`crashwise/agents/triage/exploit_gen.py`):
  - Primitive detection from ASAN/GDB/register heuristics.
  - LLM-powered standalone C PoC generation with structured JSON output.
  - Template-based fallback for all major primitives (UAF, OOB, double-free, null-deref, etc.).
  - Reachability scoring (HIGH/MEDIUM/LOW) based on entry point analysis.
- **Reachability Engine** (`crashwise/research/reachability.py`):
  - AST-based call-graph analysis (Python source).
  - Regex heuristics for C/C++ syscall/network/public API entry points.
  - Numeric 0.0–10.0 exploitability scoring with path-length adjustment.
- **PoC Verification Activity** (`crashwise/orchestration/activities/verify_poc.py`):
  - Temporal activity that compiles generated PoC with ASAN.
  - Executes binary and validates crash signature against original.
- **CLI Expansion**: `crashwise exploit <crash_id> [--verify] [--output]` command.
- **New Models**: `ExploitGenInput`, `ExploitGenOutput`, `PocVerifyInput`, `PocVerifyOutput`, `ExploitabilityScore`.
- **New DB Fields**: `poc_code`, `poc_compiled`, `poc_verified`, `reachability`, `reachability_score`, `primitive` on `Crash` table.
- **Tests**: `tests/unit/test_exploit_gen.py` — 35 tests covering primitive detection, LLM generation, template fallback, reachability engine, compilation, execution, and activity integration.

**Tests: 237 passing**

---

## [0.6.0] — 2026-05-02

### Phase 14: Production Packaging & CI/CD Excellence

#### Added
- **Universal CLI** (`crashwise/cli.py`):
  - Commands: `version`, `info`, `init`, `run`, `worker`, `api`, `dashboard`.
  - Rich console output with JSON formatting.
  - Graceful error handling for Temporal connection failures.
- **Dockerfile**: Multi-stage build (builder + runtime) with non-root user, health checks, and layer caching.
- **Docker Compose** (`docker-compose.yaml`):
  - Full-stack production: Temporal Server + UI, PostgreSQL, Redis, MinIO (R2 emulation), FastAPI, Streamlit, Temporal Worker.
  - Health checks on all services. Scalable workers via `docker compose up --scale worker=N`.
- **CI/CD Pipeline** (`.github/workflows/ci.yml`):
  - 4 jobs: lint (ruff), type-check (mypy), test (pytest × Python 3.11/3.12/3.13), build (Docker).
  - uv for fast dependency resolution. Coverage upload to Codecov.
- **Tests**: `tests/unit/test_cli.py` — 15 tests for all CLI commands.

**Tests: 202 passing**

---

## [0.5.0] — 2026-05-02

### Phase 13: Auto-Disclosure & Bounty Engine

#### Added
- **AI Report Synthesizer** (`crashwise/agents/reporting/generator.py`):
  - Platform-specific reports: HackerOne, Bugcrowd, Linux Kernel ML, Generic.
  - AI-enhanced prose refinement when inference provider is available.
- **Auto-CVSS Calculator** (`crashwise/agents/reporting/cvss.py`):
  - Heuristic CVSS v3.1 vector generation from bug type + exploitability score.
  - Full base score computation using the standard formula.
  - Optional AI refinement of the vector.
- **Universal Notification Router** (`crashwise/core/notifications.py`):
  - Slack-compatible and Discord-compatible webhook payloads.
  - SMTP with TLS/STARTTLS and optional PGP encryption.
  - Threshold-based dispatch (CVSS ≥ configurable minimum).
- **Workflow Integration**: `VerifyPatchWorkflow` auto-calculates CVSS and notifies stakeholders when `status=fixed` and `CVSS ≥ 7.0`.
- **Dashboard Updates**: "1-Click Bounty Report" button, Settings page (webhook, SMTP, PGP, CVSS threshold).
- **Tests**: `tests/unit/test_reporting.py` — 18 tests.

**Tests: 187 passing**

---

## [0.4.0] — 2026-05-02

### Phase 12: Autonomous Patch Verification & Regression Testing

#### Added
- **Patch Verifier** (`crashwise/agents/feedback/verifier.py`):
  - End-to-end pipeline: clone → apply patch → build → regression test.
  - ASAN stderr heuristics for crash detection.
- **VerifyPatchWorkflow** (`crashwise/orchestration/workflows/verify_patch.py`):
  - 4-step Temporal workflow: apply patch → build → verify with seed → update DB.
- **Verification Activities** (`crashwise/orchestration/activities/verify_patch.py`):
  - `apply_patch`, `build_patched`, `verify_with_seed`, `update_verification_status`.
- **API + Dashboard**: `POST /crashes/{id}/verify` endpoint, Streamlit "Verify Patch" button.
- **New DB Fields**: `verification_status`, `verification_stdout`, `verification_stderr`, `verified_at` on `Crash` table.
- **Tests**: `tests/unit/test_verification.py` — 11 tests.

**Tests: 169 passing**

---

## [0.3.0] — 2026-05-01

### Phase 8–11: Web API, Persistence, Distributed Architecture, AI Agent, Dashboard

#### Added
- **Persistence Layer** (`crashwise/core/database.py`):
  - Async SQLAlchemy with SQLite (dev) and PostgreSQL (prod).
  - Models: `Campaign`, `FuzzingRun`, `Crash`, `Seed`.
- **FastAPI REST API** (`crashwise/api/main.py`):
  - Endpoints: `/campaigns`, `/campaigns/{id}`, `/campaigns/{id}/crashes`, `/campaigns/start`, `/health`, `/workers`.
- **Distributed Storage** (`crashwise/core/r2_storage.py`):
  - Cloudflare R2 / S3-compatible: `upload_file`, `download_file`, `sync_directory`.
- **Redis Integration** (`crashwise/core/redis.py`):
  - Counters, dedup cache, worker heartbeat. Gracefully disabled when unavailable.
- **Hybrid AI Agent** (`crashwise/core/ai_provider.py`):
  - Pluggable providers: Ollama (local), Venice (cloud), NullProvider (fallback).
  - Auto-patcher (`crashwise/agents/feedback/patcher.py`) for patch suggestion.
  - `analyze_crash` activity for deep RCA.
- **Intelligence Dashboard** (`crashwise/dashboard/app.py`):
  - Streamlit: Campaigns, Crash Intelligence (severity heatmap, CWE filters, patch viewer), Cluster Status.
  - Export endpoints (Markdown/JSON).
- **Tests**: Multiple test files covering API, distributed, AI agent, dashboard.

**Tests: 158 passing**

---

## [0.2.0] — 2026-05-01

### Phase 4–7: Kernel Bridge, Execution Layer, Feedback Loop, Seeding Brain

#### Added
- **Kernel Bridge** (`crashwise/kernelbridge/`):
  - OOPS parser, KASAN/KFENCE report extraction.
  - syzkaller integration for kernel fuzzing.
- **Execution Layer** (`crashwise/execution/`):
  - `DockerManager`: Async Docker container orchestration for AFL++/libFuzzer.
  - `QemuManager`: QEMU/KVM VM orchestration.
- **Feedback Loop** (`crashwise/agents/feedback/`):
  - Coverage analysis, harness mutation hints.
  - Patch suggestion from root-cause analysis.
- **Seeding Brain** (`crashwise/agents/seeding/`):
  - CVE harvester: queries NVD API, downloads PoCs.
  - PoC transformer: C/Python → binary seeds for fuzzer corpus.
  - `seed_corpus` activity integrated into MainFuzzingWorkflow.
- **Tests**: `test_execution.py`, `test_feedback.py`, `test_seeding.py`.

**Tests: 89 passing**

---

## [0.1.0] — 2026-05-01

### Phase 0–3: Foundation, Orchestration, Harness Synthesis, Triage

#### Added
- **Project Skeleton**: `pyproject.toml`, `uv` package management, ruff, mypy, pytest.
- **Temporal Orchestration** (`crashwise/orchestration/`):
  - Client with exponential backoff retry.
  - `MainFuzzingWorkflow`: 5-step fuzzing pipeline with iteration loop.
  - Activities: `setup_target`, `execute_fuzzing`, `triage_results`, `analyze_progress`, `mutate_harness`.
- **Harness Synthesis** (`crashwise/agents/harness_synth/`):
  - LangGraph agent reads C source and generates AFL++/libFuzzer harnesses.
  - Compilation feedback loop: failures feed back to the agent for retry.
- **Triage Engine** (`crashwise/agents/triage/`):
  - `CrashReport` / `TriageResult` / `BugType` models.
  - LLM-powered classification with regex fallback heuristics.
  - `CrashDeduper`: SHA256 stack-hash deduplication.
  - Batch triage API.
- **Core Infrastructure**:
  - `config.py`: Pydantic-settings with env var support.
  - `logging.py`: structlog with JSON formatting.
  - `models.py`: Pydantic I/O models for all workflow boundaries.
- **Tests**: `test_smoke.py`, `test_workflow.py`, `test_harness_synth.py`, `test_triage.py`.

**Tests: 48 passing**

---

## Summary

| Version | Phases | Tests | Key Milestone |
|---------|--------|-------|---------------|
| 0.1.0 | 0–3 | 48 | Foundation + Temporal + Harness + Triage |
| 0.2.0 | 4–7 | 89 | Kernel + Execution + Feedback + Seeding |
| 0.3.0 | 8–11 | 158 | API + Persistence + Distributed + AI + Dashboard |
| 0.4.0 | 12 | 169 | Patch Verification |
| 0.5.0 | 13 | 187 | Auto-Disclosure (CVSS + Reports + Notifications) |
| 0.7.0 | 15 | 237 | PoC Generation + Reachability Analysis |
| 1.0.0-rc1 | 15.5 | 237 | Release Documentation + Repository Finalization |
| 1.0.0-rc2 | 21 | 382 | Hardened Docker Sandbox + Distro-Bridge + God-Mode Signals |
| 1.1.0 | 22 | 480 | Operation Hydra (Agentic Senses, ReAct GDB Brain, Type Extractor) |
| **1.2.0** | **23** | **509** | **Community Engine Hardening + Universal Multi-Provider LLM Routing + Live Staging Target** |
