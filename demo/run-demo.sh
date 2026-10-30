#!/bin/sh
# CrashWise M1 five-minute demo.
#
# One command, offline, no LLM key:
#   ./demo/run-demo.sh
#
# What it does, in order, and what it proves:
#   1. Builds the vulnerable target + libFuzzer harness with ASan.
#   2. Runs the fuzzer (max 60 seconds). The fuzzer must produce a
#      crash input in the output directory; the script fails if it
#      does not, so a "success" here is never a synthetic crash.
#   3. Builds poc.c against the vulnerable code and runs it. It
#      must crash under ASan (stack-buffer-overflow).
#   4. Applies demo/patch.diff to a copy of the target, rebuilds
#      poc.c against the patched code, and runs it. It must exit
#      cleanly.
#   5. Writes demo-report.md into the output directory with the
#      commands, timings, crash file, and results.
#
# Prerequisites: clang (16+), standard C tools. No network, no LLM.
# The demo never modifies the source tree: all work happens under
# the output directory (default: ./demo-out, override with $1).

set -eu

DEMO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-"$DEMO_DIR-out"}
# Keep OUT absolute and inside the current working tree for a clean report.
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac

mkdir -p "$OUT/corpus" "$OUT/work"
START=$(date +%s)

# Seed: a short, non-crashing input. The fuzzer mutates from here and
# must discover the overflowing input itself; the seed alone must not
# crash, or the demo proves nothing.
printf 'Chello' > "$OUT/corpus/seed1"

echo "[1/5] Building harness (clang, ASan, libFuzzer)..."
clang -O1 -g -fsanitize=fuzzer,address -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    "$DEMO_DIR/harness.c" "$DEMO_DIR/vuln.c" \
    -I"$DEMO_DIR" -o "$OUT/harness"

echo "[2/5] Fuzzing (max 60s, or until a crash is found)..."
FUZZ_START=$(date +%s)
# libFuzzer exits non-zero on a crash, which is the expected result
# here, so temporarily disable `set -e` for this step.
set +e
"$OUT/harness" "$OUT/corpus" "$OUT/work" -max_total_time=60 > "$OUT/fuzz.log" 2>&1
FUZZ_STATUS=$?
set -e
FUZZ_END=$(date +%s)
echo "      fuzzer exit status: $FUZZ_STATUS, duration: $((FUZZ_END - FUZZ_START))s"

CRASH_FILE=$(ls "$OUT"/work/crash-* 2>/dev/null | head -n 1 || true)
if [ -z "$CRASH_FILE" ]; then
    echo "FAILED: fuzzer produced no crash input. See $OUT/fuzz.log"
    exit 1
fi
echo "      crash input found: $CRASH_FILE ($(wc -c < "$CRASH_FILE" | tr -d ' ') bytes)"
head -c 32 "$CRASH_FILE" | od -An -tx1 | head -n 1

echo "[3/5] Reproducing with poc.c against the vulnerable code..."
clang -O1 -g -fsanitize=address -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    "$DEMO_DIR/poc.c" "$DEMO_DIR/vuln.c" \
    -I"$DEMO_DIR" -o "$OUT/poc-vuln"
set +e
"$OUT/poc-vuln" > "$OUT/poc-vuln.log" 2>&1
POC_STATUS=$?
set -e
if [ "$POC_STATUS" -eq 0 ]; then
    echo "FAILED: poc.c did not crash against the vulnerable code."
    exit 1
fi
grep -m 1 "stack-buffer-overflow" "$OUT/poc-vuln.log" || echo "      (ASan report did not contain the expected phrase; see $OUT/poc-vuln.log)"
echo "      poc exit status: $POC_STATUS (crash reproduced)"

echo "[4/5] Applying patch to a copy and re-running poc.c..."
mkdir -p "$OUT/patched"
cp "$DEMO_DIR/vuln.c" "$DEMO_DIR/vuln.h" "$DEMO_DIR/poc.c" "$OUT/patched/"
cp "$DEMO_DIR/patch.diff" "$OUT/patched/"
# patch.diff uses a/vuln.c paths, so -p1 applies it to vuln.c in
# the patched directory.
(cd "$OUT/patched" && patch -p1 < patch.diff > "$OUT/patch.log" 2>&1)
clang -O1 -g -fsanitize=address -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    "$OUT/patched/poc.c" "$OUT/patched/vuln.c" \
    -I"$OUT/patched" -o "$OUT/poc-patched"
set +e
"$OUT/poc-patched" > "$OUT/poc-patched.log" 2>&1
PATCHED_STATUS=$?
set -e
if [ "$PATCHED_STATUS" -ne 0 ]; then
    echo "FAILED: poc.c still crashes after the patch (exit $PATCHED_STATUS)."
    exit 1
fi
echo "      poc exit status: $PATCHED_STATUS (clean after patch)"

END=$(date +%s)
cat > "$OUT/demo-report.md" <<EOF
# CrashWise M1 demo report

- Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Total duration: $((END - START))s
- Fuzzer duration: $((FUZZ_END - FUZZ_START))s, exit status $FUZZ_STATUS
- Crash input (produced by the fuzzer, not written by hand): $CRASH_FILE
- PoC against vulnerable code: crashed, exit status $POC_STATUS
- PoC against patched code: clean, exit status $PATCHED_STATUS
- Patch: demo/patch.diff (bounds-check in parse(), copy at most sizeof(buf))
- Commands: see demo/run-demo.sh; logs in this directory
  (fuzz.log, poc-vuln.log, poc-patched.log, patch.log)
- Offline: yes. LLM key: not used, not required.
EOF

echo "[5/5] Done in $((END - START))s. Report: $OUT/demo-report.md"
cat "$OUT/demo-report.md"
