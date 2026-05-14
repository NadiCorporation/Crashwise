## CrashWise End-to-End Audit — Full Report

I did a deep dive through the entire codebase. Here's the honest assessment:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Verdict: LEGITIMATE

This is a real, substantial codebase (~200KB+ of Python, 428 tests, 27 test files). It's not a skeleton or placeholder project. The core autonomous pipeline works end-to-end.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Critical Bugs That WILL Fail in Production

| # | Bug | Impact |
|---|-----|--------|
| 1 | Docker image selection broken — _resolve_image() checks if "afl" is in the harness filename instead of using the fuzzer_type from the payload | AFL++ campaigns run in the wrong container image (
libFuzzer image instead) |
| 2 | AFL++ stats path mismatch — execute_fuzzing looks for fuzzer_stats at a host path that doesn't match where Docker writes it | Coverage/exec stats always read as 0; feedback loop is blind |
| 3 | api/main.py missing from pathlib import Path — the /crashes/{id}/verify endpoint uses Path() but never imports it | NameError crash at runtime when verify is called |
| 4 | ANTHROPIC_API_KEY not passed to worker in docker-compose.yaml | Claude-based harness synthesis silently fails in Docker worker |
| 5 | CLI blocks forever — crashwise run blocks until workflow completes (could be hours) with no way to get the workflow ID for signals | Users can't use God-Mode signals or monitor progress |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Onboarding & Configuration Pain Points

| Issue | Pain Level | Recommendation |
|-------|-----------|----------------|
| Relative .env path — config loads from CWD, not project root | 🔴 High | Anchor to __file__ or search upward |
| No LLM key validation at startup — cryptic LangChain auth error deep in the pipeline | 🔴 High | Add crashwise doctor check for API keys |
| No guided config wizard — user must manually edit .env with 40+ variables | 🟡 Medium | Add crashwise config interactive command |
| No --background mode — can't detach a campaign | 🟡 Medium | Print workflow ID immediately, add --detach flag |
| No crashwise status or crashwise list — no way to check running campaigns from CLI | 🟡 Medium | Add these commands |

Should you add onboarding for config? Yes, absolutely. The .env.example is well-documented but 218 lines long. A crashwise config wizard that asks "Which LLM provider? [anthropic/openai/ollama/none]" and 
writes the .env would dramatically reduce friction.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### What Works Well (Strengths)

- **Security posture is excellent**: shell-free compilation, compiler allowlist, --network none containers, prompt injection markers
- **Graceful degradation**: every LLM path has a deterministic fallback (regex triage, template harness)
- **Test suite is real**: 428 tests covering MAB, Docker execution, harness evolution, sentinel, etc.
- **Temporal orchestration is sophisticated**: God-Mode signals, pause/resume, bounded evolution
- **Distro support is genuine**: Arch/Ubuntu/Fedora with proper package manager dispatch
- **Docker hardening is production-grade**: read-only rootfs, cap-drop ALL, no-new-privileges, pids-limit

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### What's Skeleton/Incomplete

| Component | Status |
|-----------|--------|
| tests/integration/ | Empty — no integration tests |
| Kernel fuzzing (syzkaller) | Parsers only, no orchestration |
| agents/feedback/patcher.py | Thin wrapper (~1.8KB) |
| Multi-target scheduling | Not implemented (v2.0) |
| Honggfuzz support | No Docker image defined |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Recommended Fixes (Priority Order)

1. Fix Docker image selection — use fuzzer_type from the job payload, not filename heuristic
2. Fix AFL++ stats path — map to the correct Docker volume mount path
3. Add from pathlib import Path to api/main.py
4. Add ANTHROPIC_API_KEY passthrough in docker-compose.yaml worker service
5. Add --detach mode to crashwise run that prints workflow ID and exits
6. Add crashwise config interactive wizard for first-time setup
7. Validate LLM keys in crashwise doctor output

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Bottom Line

This is a legitimate open-source autonomous fuzzing platform with real engineering behind it. The architecture is sound, the security model is thoughtful, and the test coverage is genuine. However, there 
are 5 production bugs that will cause real failures, and the onboarding experience needs a guided config wizard to be accessible to the broader security community. The fixes are all straightforward — none 
require architectural changes.

Want me to start fixing these bugs?
