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

Response time: 48 hours. Coordinated disclosure timeline negotiated per report.

---

## Supported Versions

| Version | Supported |
|---|---|
| 1.3.x (current) | Yes |
| 1.2.x | Yes |
| 1.1.x | Security fixes only |
| < 1.1 | No |

---

## Threat Model

CrashWise processes **untrusted input** at multiple layers:

| Layer | Untrusted Source | Mitigation |
|---|---|---|
| Target repository | Malicious `CMakeLists.txt`, `Makefile`, source code | Build runs in worker process (not sandboxed — see below) |
| Monorepo scoping | Malicious `target_subdir` path | Strict path resolution & directory traversal sanitization |
| LLM output | Harness code, compilation commands | Regex validator → `clang -fsyntax-only` → compiler allowlist → Docker sandbox |
| Operator signals | `inject_seed` payload | Filename sanitization, base64 validation, size caps, path containment |
| Crash data | ASAN output, GDB backtraces | Wrapped in `<UNTRUSTED_TARGET_SOURCE>` markers in LLM prompts |

### Known architectural boundaries

**The worker host is a trust boundary.** The `setup_target` activity executes the target's build system (`cmake`, `make`) on the worker host without sandboxing. A malicious target repository can execute arbitrary code during the build step. Mitigations:

- Run workers in disposable VMs or containers with limited network access
- Do not run workers on machines with access to production credentials
- Use `--network none` on the worker container if running CrashWise itself in Docker

**The fuzzer sandbox is hardened.** Once built, the fuzzer binary runs inside Docker with:
- `--init` (Tini as PID 1 to clean up zombie/defunct child processes)
- `--network none` (complete network isolation)
- `--read-only` (immutable root filesystem)
- `--cap-drop ALL` (AFL++ gets `SYS_PTRACE` only for forkserver)
- `--pids-limit 1024` (fork-bomb protection)
- Size-capped tmpfs on `/tmp` and `/dev/shm`
- No shell access

**LLM-generated code is validated before execution.** The pipeline:
1. Regex blocklist (fork, exec, system, socket, ptrace, asm)
2. `clang -fsyntax-only -Werror`
3. Compiler binary must be in the allowlist
4. `shlex.split` parsing — no `shell=True`
5. Compiled binary runs only inside the Docker sandbox

---

## Secure Configuration

- Store API keys in `.env` files with `chmod 600`
- Use `pydantic.SecretStr` for all secret fields (keys are never logged)
- Set `REDIS_URL` with authentication in production
- Set `DATABASE_URL` with TLS for PostgreSQL connections
- Enable R2/S3 storage to avoid crash data accumulating on worker filesystems

---

## Dependencies

CrashWise pins all direct dependencies. Run `uv lock --check` to verify lockfile integrity. Report suspicious dependency behavior to the security contact above.
