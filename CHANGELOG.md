# Changelog

All notable changes to CrashWise are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
| 0.6.0 | 14 | 202 | Production Packaging (CLI + Docker + CI/CD) |
| 0.7.0 | 15 | 237 | PoC Generation + Reachability Analysis |
| **1.0.0-rc1** | 15.5 | **237** | **Release Documentation + Repository Finalization** |
