# Changelog

All notable changes to CrashWise are documented in this file.

## [0.2.0-dev] — 2026-09-11 (Pre-Alpha / Operation Megabits)

### 🚀 Complete Architectural Rewrite (Operation Megabits)
- **Rust Core Workspace**: Replaced Python/Temporal/LangGraph prototype with a unified, high-throughput Rust workspace across 8 core crates.
- **Tree-sitter AST & Callgraph Analysis**: Deterministic parsing of C/C++ source trees, callgraphs, and dangerous memory sinks without regexes.
- **Closed-Loop Cognitive Harness Synthesis**: LLM harness synthesizer with compiler-in-the-loop diagnostic feedback and 5-second runtime sanity gate.
- **Embedded SQLite Persistence**: Built-in SQLite database with Write-Ahead Logging (WAL) for zero-configuration, zero-dependency persistence.
- **Multi-Build System Support**: Automated compilation and sanitizer injection for CMake, Meson, Make, and Autotools.
- **Autonomous Crash Triage & PoC Generator**: AddressSanitizer stack frame hasher, CVSS/CWE scorer, and standalone C PoC generator (`poc.c`).
- **Axum REST & SSE Telemetry Daemon**: Real-time REST endpoints and Server-Sent Events streaming to the Next.js control plane.
- **Next.js Web Command Center**: Migrated frontend to top-level `web/` with dark-mode dashboard.
