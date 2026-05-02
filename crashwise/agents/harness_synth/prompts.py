# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Prompt templates used by the harness-synthesis agent.

Kept here so they can be tuned and version-controlled separately from the
graph wiring.
"""

from __future__ import annotations

SYSTEM_PROMPT = """\
You are a senior C/C++ vulnerability researcher writing libFuzzer harnesses.

You will be given:
  • A short C/C++ source file the user wants fuzzed.
  • A specific target function inside that file.
  • The compiler stderr from any previous failed attempt.

Your job: produce a minimal, *self-contained* libFuzzer harness file that
compiles successfully under:

    clang++ -O1 -g -fsanitize=fuzzer,address,undefined harness.cpp -o out

Hard rules:
  1. Output ONLY a single fenced code block tagged ``cpp`` (or ``c``).
     No prose, no commentary, no markdown headings — just the code block.
  2. The harness MUST define exactly:
        extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
  3. Inline the target function's source (or #include the original file
     directly with `#include "<basename>"`) so no separate build step is
     required. Prefer #include — it's safer and keeps the diff small.
  4. Drive the target with the libFuzzer input buffer; respect realistic
     pre-conditions (e.g. NUL-terminate when passing to a `char*` API).
  5. Never call exit(), abort(), or perform I/O. Free anything you allocate.
  6. If the previous attempt failed, fix the SPECIFIC error reported in
     stderr. Do not change unrelated parts of the harness.
"""

USER_PROMPT_TEMPLATE = """\
## Target file: {source_path}
## Target function: {entry_point_name}
## Signature: {entry_point_signature}
## Defined at line: {entry_point_line}

```{language}
{source_code}
```

{feedback_section}

{retry_section}

Produce the harness now. Code block only.
"""

RETRY_SECTION_TEMPLATE = """\
## Previous compile failed (attempt {attempt_number}). clang stderr (truncated):

```
{compile_stderr}
```

## Earlier attempts also failed with:
{prior_errors}

Fix the harness. Pay close attention to the SPECIFIC error above.
"""

SIMPLIFY_NOTE = """\
## NOTE: Earlier attempts hit hard errors. Produce the SIMPLEST possible
## harness — even if it only passes the input as a NUL-terminated string
## to the target. Correctness over coverage.
"""

FEEDBACK_SECTION_TEMPLATE = """\
## FEEDBACK FROM PREVIOUS FUZZING RUN

{feedback}

Use this feedback to improve the harness. If the feedback says coverage
plateaued, try a different entry point or bypass input-validation guards.
If it says execution rate collapsed, simplify the harness and call the
target directly without expensive setup.
"""

__all__ = [
    "FEEDBACK_SECTION_TEMPLATE",
    "RETRY_SECTION_TEMPLATE",
    "SIMPLIFY_NOTE",
    "SYSTEM_PROMPT",
    "USER_PROMPT_TEMPLATE",
]
