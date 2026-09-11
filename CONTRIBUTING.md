# Contributing to CrashWise (Operation Megabits)

Thank you for contributing to CrashWise! We are building an open-source, autonomous AI-powered 0-day vulnerability discovery engine in Rust.

---

## 1. Contributor Tracks

You can contribute across any of our 6 core engineering tracks:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CrashWise Contributor Tracks                    │
└───────┬──────────────┬──────────────┬──────────────┬─────────────┬─────┘
        │              │              │              │             │
        ▼              ▼              ▼              ▼             ▼
┌──────────────┐┌──────────────┐┌──────────────┐┌───────────┐┌───────────┐
│ Track 1:     ││ Track 2:     ││ Track 3:     ││ Track 4:  ││ Track 5:  │
│ AST & Static ││ Build Systems││ Cognitive LLM││ Fuzzing   ││ Web UI &  │
│ Analysis     ││ & Compilers  ││ Agent Engine ││ Runtime   ││ DevSecOps │
│              ││              ││              ││           ││           │
│ Tree-sitter  ││ CMake/Meson/ ││ Tool-calling ││ LibAFL &  ││ Next.js 15│
│ type/struct  ││ Bazel/Cargo  ││ prompts &    ││ rootless  ││ Tailwind  │
│ resolvers.   ││ drivers.     ││ sanity gate. ││ sandbox.  ││ shadcn UI.│
└──────────────┘└──────────────┘└──────────────┘└───────────┘└───────────┘
```

- **Track 1: Static Analysis & AST (`crates/crashwise-ast`)**:
  - Implement deep struct and type layout resolvers.
  - Expand grammar support for Rust and Go targets.
  - Optimize callgraph reachability scoring.

- **Track 2: Build Systems & Compilers (`crates/crashwise-build`)**:
  - Add build executors for Bazel monorepos, Meson subprojects, and Cargo crates.
  - Parse `compile_commands.json` to extract precise compiler flags.

- **Track 3: Cognitive Agent Engine (`crates/crashwise-agent`)**:
  - Refine LLM prompt strategies for complex stateful harnesses.
  - Add interactive tool-calling loops (`inspect_struct`, `test_compile`).
  - Develop concolic/symbolic blocker-bypass prompts.

- **Track 4: Fuzzing Runtime & Sandboxing (`crates/crashwise-engine`)**:
  - Integrate native in-process `LibAFL` fuzzing executors.
  - Enhance Linux namespace (`unshare`), cgroups v2, and Seccomp isolation.
  - Build intelligent seed corpus minimization algorithms.

- **Track 5: Crash Triage & Patching (`crates/crashwise-triage`)**:
  - Enhance ASan/UBSan/MSan stack trace deduplication.
  - Build the closed-loop patch verification engine.

- **Track 6: Web Command Center (`web/`)**:
  - Enhance the real-time Next.js 15 dashboard, telemetry graphs, and live log stream.

---

## 2. Development Setup & Workflow

### Prerequisites
```bash
# Rust Toolchain (1.80+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# System Dependencies (Arch/Debian/Fedora)
# Clang, Clang++, CMake, Make, Meson
```

### Local Build & Test
```bash
# Verify all workspace crates build cleanly
cargo check --workspace --all-targets

# Run the complete test suite
cargo test --workspace

# Check formatting and linter
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 3. Pull Request Guidelines

1. **Keep Changes Focused**: Each PR should address a specific track or issue.
2. **Add Tests**: All new AST parsers, compiler drivers, and triage modules must include unit tests.
3. **Preserve Zero-Dependency Principle**: Avoid adding heavy external system dependencies; prefer pure Rust crates.
4. **Document Changes**: Update `CHANGELOG.md` and relevant crate documentation.
