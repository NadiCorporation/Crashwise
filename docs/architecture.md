<!--
SPDX-License-Identifier: MIT
Copyright (c) 2026 CrashWise Contributors
-->

# CrashWise Architecture

> Status: **Phase 0 scaffold.** This document is a living spec; it will be expanded as Phases 1–3 land.

## High-Level Topology

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CrashWise Control Plane                       │
│                                                                        │
│   ┌──────────────────┐        ┌────────────────────────────────────┐   │
│   │   Typer CLI      │───────▶│       Temporal Client              │   │
│   │  (crashwise …)   │        │  (start workflows, query state)    │   │
│   └──────────────────┘        └──────────────┬─────────────────────┘   │
│                                              │ gRPC :7233              │
└──────────────────────────────────────────────┼─────────────────────────┘
                                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       Temporal Server (durable state)                  │
│                       PostgreSQL persistence                           │
└──────────────────────────────────────────────┬─────────────────────────┘
                                               │
                ┌──────────────────────────────┼────────────────────────────┐
                ▼                              ▼                            ▼
   ┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
   │  Harness Synthesis   │     │   Execution Fleet     │     │   Triage Engine      │
   │  Worker (LangGraph)  │     │   Worker (AFL++/      │     │   Worker (LangGraph  │
   │                      │     │   libFuzzer runners)  │     │   + LLM)             │
   └──────────────────────┘     └──────────────────────┘     └──────────────────────┘
```

## Component Map

| Component        | Package                         | Phase |
|------------------|---------------------------------|-------|
| CLI              | `crashwise.cli`                 | 0     |
| Config / Logging | `crashwise.core`                | 0     |
| Temporal client/worker | `crashwise.orchestration` | 1     |
| Harness Synth Agent    | `crashwise.agents.harness_synth` | 2 |
| Triage Agent           | `crashwise.agents.triage`        | 3 |
| Fuzz runners           | `crashwise.execution`            | 2 |
| KernelBridge           | `crashwise.kernelbridge`         | 4+ |

## Design Principles

1. **Determinism boundary.** Workflows are pure; all I/O lives in activities.
2. **Pydantic everywhere.** Every cross-component payload is a versioned model.
3. **LLM autonomy.** Compilation/exec failures feed back into the LangGraph
   loop for autonomous correction — no human in the hot path.
4. **Multi-LLM friendly.** Modules are typed and documented so independent
   agents can implement them in parallel without merge conflicts.
