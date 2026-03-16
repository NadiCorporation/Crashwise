# Changelog

All notable changes to CrashWise will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-03-16

### 🎉 First Public Release

**CrashWise v1.0.0** - Autonomous AI-Powered Fuzzing & Crash Triage Platform

### ✨ Major Features

#### AI Auto-Mode
- **Binary Analysis**: Automatic language detection, entry point identification, symbol extraction
- **Harness Generation**: LLM-generated fuzz harnesses for C, C++, Python, Go
- **Seed Generation**: AI-created initial corpus with intelligent test cases
- **Dictionary Creation**: Automatic AFL dictionary from binary strings

#### Continuous Fuzzing
- **Campaign Management**: Start, monitor, stop fuzzing campaigns via CLI or dashboard
- **Crash Monitoring**: Real-time crash detection and collection
- **Coverage Tracking**: Edge/block coverage with stall detection
- **Self-Healing Coverage**: Automatic response to coverage stalls

#### Intelligent Crash Triage
- **Multi-Format Parsing**: ASan, UBSan, GDB, coredump support
- **LLM Vulnerability Assessment**: Automatic classification and exploitability scoring
- **Semantic Deduplication**: ChromaDB-powered crash similarity detection
- **Crash Minimization**: AFL-tmin PoC reduction

#### LangGraph Supervisor
- **ReAct-Style Reasoning**: Think → Act → Observe loop
- **Autonomous Decisions**: triage, dedup, minimize, report actions
- **GitHub Integration**: Automatic issue creation for high-severity bugs
- **Self-Healing**: Stall detection with intelligent recovery actions

#### Web Dashboard
- **Real-Time Monitoring**: Campaign status, crash counts, coverage charts
- **Crash Visualization**: Severity badges, exploitability scores, triage JSON
- **SARIF Export**: Generate industry-standard security reports
- **Campaign Launch Forms**: One-click auto-mode fuzzing

#### Notifications
- **Slack Integration**: Webhook notifications for high-severity crashes
- **Discord Integration**: Rich embed notifications with crash details
- **Rate Limiting**: Configurable cooldown per campaign

### 🔧 CLI Commands
- `cw fuzz start` - Start a fuzz campaign
- `cw fuzz status` - Check campaign status
- `cw fuzz stop` - Stop a running campaign
- `cw fuzz list` - List all campaigns
- `cw auto` - Launch AI-powered autonomous campaign

### 📚 Documentation
- Full README with installation and quick start
- ARCHITECTURE.md with system design
- API documentation for SDK

### 🛠 Technical Details
- Python 3.11+
- Temporal.io for workflow orchestration
- LangGraph for supervisor agent
- Streamlit for web dashboard
- ChromaDB for vector similarity
- AFL++ for fuzzing
- Docker Compose for deployment

---

## [Unreleased]

### ✨ New Features

#### Continuous Fuzz Campaign Workflow
- **Added continuous fuzzing with autonomous crash triage**:
  - `start_fuzzer`: Launches AFL fuzzer process with configurable options
  - `stop_fuzzer`: Graceful (SIGTERM) then forced (SIGKILL) fuzzer shutdown
  - `monitor_crashes`: Polls AFL output directory for new crash files
  - `setup_campaign_workspace`: Creates isolated workspace per campaign
  - `cleanup_campaign_workspace`: Removes temporary files after completion
  - `copy_crash_to_workspace`: Prepares crash files for triage
  - `trigger_triage`: Invokes LangGraph supervisor on each crash
  - `get_fuzzer_stats`: Reads AFL fuzzer statistics
- **ContinuousFuzzCampaignWorkflow**: Orchestrates fuzzing loop
  - Monitors for crashes at configurable intervals
  - Triggers supervisor triage on each new crash
  - Stops on: max_duration, max_crashes, or time limit
  - Automatic cleanup of fuzzer process on workflow end

#### Crash Triage Workflow
- **Added crash-triage-worker for automated crash analysis**:
  - `collect_crash_data`: Scans directories for crash artifacts (.log, .asan, .ubsan, .core)
  - `parse_crash_reports`: Parses ASan, UBSan, GDB backtraces with stack hashing
  - `llm_crash_triage`: LLM-powered vulnerability assessment (via LiteLLM proxy)
  - `check_crash_duplicate`: ChromaDB semantic search for crash similarity (distance threshold 0.25), with hash-based fallback
  - `minimize_crash_poc`: AFL-tmin crash minimization with optional LLM hints
  - `create_github_issue`: Create GitHub issues for high-severity new crashes (exploitability >= 7)

#### LangGraph Supervisor Agent
- **Autonomous crash triage with ReAct-style reasoning**:
  - Analyzes crash state → decides action → executes → repeats
  - Actions: triage, dedup, minimize, report, end
  - Reports high-severity unique crashes to GitHub (when configured)
  - `minimize_crash_poc`: AFL-tmin crash minimization with optional LLM hints for further reduction
- **CrashTriagePipelineWorkflow**: Orchestrates full crash analysis pipeline
  - Configurable triage via `enable_triage` parameter (default: True)
  - Configurable deduplication via `enable_deduplication` parameter
- **Worker integration**: `worker-crash-triage` service in docker-compose

#### OpenCode Go LLM Integration
- **LLM triage now uses OpenCode Go subscription models**:
  - Primary: `opencode/glm-5` (strong reasoning for vuln triage)