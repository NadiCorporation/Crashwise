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

**The fuzzing step is sandboxed, rootless, in-process — not Docker, not AFL++ forkserver.** `crates/crashwise-engine/src/sandbox.rs` implements a 4-tier rootless Linux sandbox, applied by `crates/crashwise-engine/src/libafl_runner.rs` to the fuzzing worker: cgroups v2 resource limits, Linux namespaces (user, network, mount, IPC — no PID namespace in `NamespaceManager::apply_namespaces`), Seccomp BPF syscall filtering, and POSIX rlimits. The sandbox tiers warn and continue on failure; they are not fail-closed, so a failed tier does not by itself stop a run. The fuzzer itself is LibAFL in-process (`libafl` 0.16.1 in `crates/crashwise-engine/Cargo.toml`), not an AFL++ forkserver.

**LLM-generated code is validated before execution, but not only inside the fuzzing sandbox.** Harness code is checked before it is compiled. After compilation, the 5-second sanity gate in `crates/crashwise-agent/src/sanity_gate.rs` executes the compiled harness directly on the host (`Command::new(harness_bin)`), with no sandbox wrapper in that path. Only the later fuzzing worker is sandboxed as described above. Treat the sanity gate as host execution: run it, like the build step, in a disposable container or VM, not on a machine holding production credentials.

---

## Secure Configuration

- Store API keys in `.env` files with `chmod 600`. Never commit a real key.
- Use the `.env.example` variables (workdir, timeouts, API host/port, LLM provider/model) as the configuration reference for this version.
- Warning on the API server: `.env.example` sets `CRASHWISE_API_HOST=0.0.0.0`, and `crates/crashwise-core/src/config.rs` also defaults to `0.0.0.0` when the variable is unset. The server is unauthenticated, so do not expose it to a network as-is. Bind it to loopback (`127.0.0.1`) or put it behind an authenticated reverse proxy.
- Run CrashWise only against software you own or have explicit authorisation to audit, in sandboxed testing.
- This Rust workspace does not use Python, pydantic, Redis, PostgreSQL, R2/S3, or `uv`. Do not re-add those as configuration requirements unless the code that uses them is also added, with a code pointer.

---

## Dependencies

CrashWise pins its direct Rust dependencies in `Cargo.toml`. `Cargo.lock` is listed in `.gitignore` and is not tracked in this repository, so the lockfile is not shipped with the repo and downstream builds are not pinned by a repo lockfile. Report suspicious dependency behavior to the security contact above.
