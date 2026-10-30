# CrashWise architecture: an autonomous vulnerability researcher

Status: approved design, 2026-10-30. This document is the design of
record. Code that contradicts it is a bug in the code or a proposal
to amend this document, not a silent exception.

## Goal, in one sentence

An autonomous researcher that, given an authorised target and a
freedom set by its master, plans over a long horizon, explores,
hypothesises, chooses tools, and iterates until it finds a valid,
critical zero-day, proves it with a reproducible PoC, and patches
it with verified regression tests — under the master's control at
all times.

## Non-goals

- Not a general internet hacker. No unauthorised targets, no live
  system attacks, no autonomous external disclosure.
- Not a replacement for the master's final review. No merge,
  release, submission, publication, or disclosure happens on the
  agent's say-so.
- Not a claim machine. A finding only counts with an evidence
  bundle (see §7). No PoC, no finding.

## Design principle

**The LLM is the brain, deterministic tools are the hands, and a
separate verifier is the judge.**

- The LLM plans and chooses tools. It never executes code directly.
- Tools are deterministic, versioned, and allowlisted. Their
  output, not the LLM's assertion, is the evidence.
- The verifier is separate from the finder. The finder does not
  grade its own finding.
- The master sets scope, freedom, tools, network egress, and
  budget. The agent cannot raise any of them.

## System overview

```
Master (human)
  │
  ▼
Control plane ── scope, freedom dial, budgets, pause, kill switch,
  │              audit log, human gates
  ▼
Agent loop ──── observe → plan → act → learn → repeat, with
  │            checkpoints and resumable state
  ▼
Tool registry ─ AST, build, harness, fuzz, triage, PoC, patch,
  │            verifier, research (read-only)
  ▼
Execution ───── disposable container/VM for builds and for any
  │            compiled-code execution, sandboxed fuzz worker
  ▼
Evidence store ─ campaign state, hypotheses, tool history,
                 crashes, PoCs, patches, verification results
```

## 1. Control plane

Owner: `crashwise-server` (dashboard/API) plus the CLI's campaign
configuration. The control plane is the only place that can set:

- Target and authorised scope (repository, commit, subdir, bug class)
- Freedom mode: `Off`, `Read-only`, `Assisted` (recommended start),
  `Limited-autonomous`
- Tool allowlist and network egress allowlist
- Time budget, token budget, and cost accounting per campaign
- Pause and kill switch, implemented outside the agent loop so
  stopping the agent does not depend on the agent cooperating
- Audit log: every plan revision, tool call, tool result, and
  decision, with timestamps

Freedom is principled, not unlimited: freedom of exploration and
reasoning inside the sandbox is high; freedom of external effect
is gated. Sending, publishing, disclosing, submitting, or spending
is never an agent tool — it is a human gate.

## 2. Agent loop

Owner: new module in `crashwise-agent` (see §8). The loop is:

1. **Observe.** Load campaign state: plan tree, hypotheses with
   confidence, last tool result, crash data, remaining budget.
2. **Plan.** Revise the plan. Pick the next hypothesis to test,
   or stop with a reason (verified finding, budget exhausted,
   no promising hypothesis, master pause).
3. **Act.** Call exactly one tool from the registry, with
   explicit arguments. No shell execution of LLM-generated
   commands, no tool outside the allowlist.
4. **Learn.** Record the result, update hypothesis confidence,
   and append to the audit log.
5. **Checkpoint.** Persist state before the next iteration, so
   a crash, pause, or kill resumes from the last checkpoint,
   not from zero.
6. **Repeat** until a verified finding, a stop condition, or a
   master action.

The loop must be resumable, budgeted, and observable. A loop
that only works in one uninterrupted run is not a long-horizon
agent.

## 3. Tool registry

Every tool is a named, versioned entry with: input schema,
allowlist status, execution location (host, sandbox, disposable
VM), and output schema. The LLM may only call tools in the
campaign's allowlist.

| Tool | Purpose | Execution |
| --- | --- | --- |
| `ast_scan` | Attack-surface mapping, exported functions, call graph | Host, read-only |
| `build_target` | Build target with ASan/UBSan | Disposable container/VM only |
| `synthesize_harness` | LLM writes harness; compiler + sanity run validate it | Compile in disposable VM; sanity run in disposable VM (see §5) |
| `run_fuzz` | LibAFL in-process fuzzing, corpus, crash capture | Sandboxed fuzz worker |
| `triage_crash` | ASan parsing, CWE/CVSS, stack-hash dedup | Host |
| `generate_poc` | Standalone `poc.c`, compiled and run | Compile/run in disposable VM |
| `synthesize_patch` | Patch candidate from crash + PoC | Host (text only) |
| `verify_patch` | 5-stage verification: PoC fixed, tests pass | Disposable VM |
| `research_read` | CVE docs, public code, docs for the authorised target | Read-only, allowlisted hosts only |

Tools that do not exist yet are marked as such in the registry.
A tool is not "available" because the LLM can describe it.

## 4. LLM provider layer

Owner: `crashwise-agent/src/llm.rs`, behind a provider interface.

- First provider: DeepSeek, as already configured in
  `.env.example` (`CRASHWISE_LLM_PROVIDER=deepseek`,
  `CRASHWISE_LLM_MODEL=deepseek-chat`, `OPENAI_API_BASE`).
- Provider, model, base URL, and key come from configuration,
  never hard-coded. Keys are never logged.
- Tool-calling format is normalised by the provider layer, so
  OpenAI-compatible APIs and a local Ollama model can be added
  without rewriting the loop.
- The verifier uses a separate prompt and, where possible, a
  separate model from the finder, so the finder does not grade
  itself.
- Token usage and cost are accounted per campaign and shown
  in the control plane.

The model decides the plan and the next tool. It does not
decide safety rules, budgets, or scope.

## 5. Execution and sandboxing — known gaps, stated honestly

Current code, verified in the truth pass (PR #19, follow-up
PR #20):

- The fuzzing worker **is** sandboxed: rootless 4-tier sandbox
  in `crashwise-engine/src/sandbox.rs` (cgroups v2, Linux
  namespaces user/network/mount/IPC — no PID namespace,
  warn-and-continue, not fail-closed).
- The build step **is not** sandboxed: `crashwise-build`
  runs `cmake`/`meson`/`make`/`clang` directly on the host.
- The sanity gate **is not** sandboxed: `crashwise-agent`
  executes the compiled harness directly on the host.

Architecture rule, therefore: builds, sanity runs, PoC runs,
and patch verification run in a disposable container or VM,
never on a machine holding production credentials, until the
sandbox is extended to cover those paths. The demo in
`demo/` (PR #21, unmerged at the time of writing) is a smoke
test of the plumbing only; it is not the agent path.

## 6. State, memory, and long horizon

Owner: `crashwise-core` (models, config, database).

Campaign state, persisted per campaign:

- Plan tree: goal, sub-goals, current step, stop conditions
- Hypotheses: description, target function/input class,
  confidence, evidence for and against, status
- Tool history: every call and result, with timestamps
- Crashes: input, ASan log, stack hash, dedup status
- Budgets: time used, tokens used, cost, remaining

State is the agent's memory. If it is lost, the horizon is
lost. No campaign state lives only in a prompt or a chat
transcript.

## 7. Evidence and human gates

A finding counts only as an evidence bundle:

- Target name, version, and commit
- Crash input and ASan log
- Standalone, reproducible `poc.c` and its run result
- Patch (unified diff) and regression test
- 5-stage verification result
- Campaign and tool history that produced it

Human gates, always: merge, release, submission, publication,
and disclosure. The agent prepares the bundle; the master
decides what leaves the system.

## 8. Mapping to the current crates

| Layer | Current crate(s) | Status |
| --- | --- | --- |
| Control plane | `crashwise-server`, CLI config | Exists, needs freedom dial, budgets, kill switch |
| Agent loop | `crashwise-agent` (new module) | **To build** — today there is harness synthesis and an LLM client, but no observe/plan/act/learn loop with checkpoints |
| LLM provider | `crashwise-agent/src/llm.rs` | Exists, needs provider interface + verifier separation |
| AST | `crashwise-ast` | Exists (tree-sitter-c/cpp only) |
| Build | `crashwise-build` | Exists, needs disposable-VM execution |
| Fuzz engine | `crashwise-engine` | Exists (LibAFL in-process, sandboxed worker) |
| Triage/PoC/patch | `crashwise-triage` | Exists, needs disposable-VM execution for PoC/patch runs |
| State | `crashwise-core` | Exists, needs plan/hypothesis/tool-history models |
| Dashboard | `web/` | Exists, needs control-plane views |

## 9. Build order

1. This document (architecture, approved).
2. Control plane + agent loop skeleton: loop, tool registry,
   persistent state, freedom dial, budgets, pause/kill switch,
   DeepSeek as provider one. No new target, no new claims.
3. First real test: the agent, with no hand-written harness
   for that target, against cJSON, measured against a known
   CVE. Pass = verified finding with an evidence bundle.
   Fail = fix the loop, not the demo.
4. Second target, then one-step CI, then hardening — in
   that order.

## 10. How success is measured

- The loop runs, checkpoints, resumes, and respects budget
  and kill switch, without a hand-written harness.
- A known CVE is found, reproduced, and patched by the
  agent path, with an evidence bundle.
- No finding is reported without a reproducible PoC.
- No external effect happens without a human gate.

Stars, forks, and users are consequences of that, never the
measure itself.
