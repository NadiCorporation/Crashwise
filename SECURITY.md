<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# Security Policy

## Reporting Vulnerabilities

Do **not** open a public issue for security vulnerabilities.

Email: **crashwise@yahyatoubali.me**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

Response time: best effort. CrashWise is pre-alpha research software with one maintainer, so no fixed response time is promised. Coordinated disclosure timeline is negotiated per report.

---

## Supported Versions

| Version | Supported |
|---|---|
| 0.2.0-alpha (current, pre-release) | Best effort |
| Earlier versions | No |

There is no 1.x release yet, and no security-fix backport promise for older versions.

---

## Threat Model — current Rust implementation

CrashWise processes **untrusted input** at multiple layers. The description below follows the Rust workspace at commit a5a8718, verified against the code, not against legacy documentation.

| Layer | Untrusted Source | Mitigation in current design |
|---|---|---|
| Target repository | Malicious `CMakeLists.txt`, `Makefile`, source code | Build input is untrusted. See the build-step boundary below. |
| Monorepo scoping | Malicious `target_subdir` path | Strict path resolution & directory traversal sanitization |
| LLM output | Harness code, compilation commands | Validate before execution: syntax check, compiler allowlist, no shell execution of unvalidated commands |
| Operator signals | `inject_seed` payload | Filename sanitization, base64 validation, size caps, path containment |
| Crash data | ASan output, backtraces | Treat as untrusted target data in prompts and reports |

### Known architectural boundaries, verified in code

**The build step is not sandboxed in the current code.** `crates/crashwise-build/src/builder.rs` runs `cmake`, `meson`, `make` and `clang` directly as host processes, with no sandbox wrapper. A malicious target repository can therefore execute arbitrary code during the build step. Mitigations, as operator practice, not as code guarantees:

- Run builds only in disposable containers or VMs with limited network access
- Do not run builds on machines with access to production credentials
- Do not run CrashWise against a target you do not own or have explicit authorisation to audit

**The fuzzing step is sandboxed, rootless, in-process — not Docker, not AFL++ forkserver.** `crates/crashwise-engine/src/sandbox.rs` implements a 4-tier rootless Linux sandbox, applied by `crates/crashwise-engine/src/libafl_runner.rs` to the fuzzing worker: cgroups v2 resource limits, Linux namespaces (user, PID, network, mount, IPC), Seccomp BPF syscall filtering, and POSIX rlimits. The fuzzer itself is LibAFL in-process (`libafl` 0.16.1 in `crates/crashwise-engine/Cargo.toml`), not an AFL++ forkserver.

**LLM-generated code is validated before execution.** Harness code is checked before it is compiled or run, and compiled code runs only inside the fuzzing sandbox described above.

---

## Secure Configuration

- Store API keys in `.env` files with `chmod 600`. Never commit a real key.
- Use the `.env.example` variables (workdir, timeouts, API host/port, LLM provider/model) as the configuration reference for this version.
- Run CrashWise only against software you own or have explicit authorisation to audit, in sandboxed testing.
- This Rust workspace does not use Python, pydantic, Redis, PostgreSQL, R2/S3, or `uv`. Do not re-add those as configuration requirements unless the code that uses them is also added, with a code pointer.

---

## Dependencies

CrashWise pins its Rust dependencies in `Cargo.toml` / `Cargo.lock`. Report suspicious dependency behavior to the security contact above.
