# CrashWise M1 demo: five minutes, offline, no LLM key

Run one command from the repository root:

```sh
./demo/run-demo.sh
```

That builds a tiny, deliberately vulnerable C target, fuzzes it with
libFuzzer + AddressSanitizer, reproduces the crash with a standalone
`poc.c`, applies a patch, and re-runs the PoC cleanly. It writes a
report to the output directory (default `./demo-out/demo-report.md`).

## What is in this directory

- `vuln.c` / `vuln.h` — the vulnerable target. `parse()` copies input
  into a 16-byte stack buffer with no length check when the first
  byte is `'C'`. This is a demo bug only; do not use it in real code.
- `harness.c` — the libFuzzer harness: `LLVMFuzzerTestOneInput`
  calls `parse()`.
- `poc.c` — standalone reproducer. It feeds `parse()` `'C'` followed
  by more than 16 bytes. Under ASan it must crash before the patch
  and run cleanly after it.
- `patch.diff` — the fix: copy at most `sizeof(buf)` bytes.
- `run-demo.sh` — the demo script. It never modifies the source
  tree; all build, fuzz, and patch work happens under the output
  directory.

## Why this demo is honest

- The seed corpus (`Chello`, 6 bytes) does **not** crash. The fuzzer
  must discover an overflowing input itself; if it produces no
  `crash-*` file, the script fails instead of inventing one.
- The PoC is checked twice: it must crash against the vulnerable
  code and must exit cleanly against the patched code.
- No network, no LLM, no API key. Prerequisites: `clang` 16+ and
  standard C tools. Total runtime on a small VM is well under
  five minutes; the fuzzer is capped at 60 seconds.

## Limitations (by design)

This is M1, not the full autonomous researcher. The target is
hand-written and tiny, the harness is hand-written (no LLM synthesis
in this path), and the patch is hand-written. M3 replaces the
hand-written harness and patch steps with the agent loop; M1 only
proves the end-to-end shape — fuzz, crash, PoC, patch, report —
works offline in one command.
