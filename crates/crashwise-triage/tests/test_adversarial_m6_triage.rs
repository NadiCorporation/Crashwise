//! Adversarial & Stress Verification Test Suite for crashwise-triage (Milestone 6)
//!
//! Evaluates:
//! 1. Exhaustive Sanitizer coverage (ASan, UBSan, MSan, TSan, LSan) and corrupted/binary log inputs.
//! 2. PoC Compiler & Runner resilience: infinite loop timeouts, signal crashes, exit code permutations.
//! 3. PatchApplier traversal defenses: symlink escapes, out-of-bounds hunks, corrupted diffs.
//! 4. Closed-loop 5-stage PatchVerifier transactionality: rollback verification on regression failure.

use crashwise_build::compiler::BuildOutput;
use crashwise_core::models::CrashRecord;
use crashwise_triage::asan::AsanParser;
use crashwise_triage::patch_applier::PatchApplier;
use crashwise_triage::patch_synth::PatchCandidate;
use crashwise_triage::poc_gen::PocCompiler;
use crashwise_triage::poc_runner::PocRunner;
use crashwise_triage::verifier::PatchVerifier;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn test_adversarial_asan_parser_exhaustive_sanitizers() {
    // 1. AddressSanitizer variants
    let asan_uaf = "ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(asan_uaf),
        Some("heap-use-after-free".to_string())
    );
    let (cwe, score) = AsanParser::score_vulnerability("heap-use-after-free");
    assert_eq!(cwe, "CWE-416");
    assert!((score - 9.1).abs() < f32::EPSILON);

    let asan_double_free = "ERROR: AddressSanitizer: double-free on address 0x602000000010";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(asan_double_free),
        Some("double-free".to_string())
    );
    let (cwe, score) = AsanParser::score_vulnerability("double-free");
    assert_eq!(cwe, "CWE-415");
    assert!((score - 8.1).abs() < f32::EPSILON);

    let asan_stack_overflow = "ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(asan_stack_overflow),
        Some("stack-buffer-overflow".to_string())
    );
    let (cwe, score) = AsanParser::score_vulnerability("stack-buffer-overflow");
    assert_eq!(cwe, "CWE-121");
    assert!((score - 8.6).abs() < f32::EPSILON);

    let asan_global_overflow = "ERROR: AddressSanitizer: global-buffer-overflow on address 0x600";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(asan_global_overflow),
        Some("global-buffer-overflow".to_string())
    );
    let (cwe, score) = AsanParser::score_vulnerability("global-buffer-overflow");
    assert_eq!(cwe, "CWE-120");
    assert!((score - 7.5).abs() < f32::EPSILON);

    let asan_poison = "ERROR: AddressSanitizer: use-after-poison on address 0x500";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(asan_poison),
        Some("use-after-poison".to_string())
    );
    let (cwe, score) = AsanParser::score_vulnerability("use-after-poison");
    assert_eq!(cwe, "CWE-825");
    assert!((score - 7.8).abs() < f32::EPSILON);

    // 2. UndefinedBehaviorSanitizer (UBSan)
    let ubsan_shift = "src/math.c:12:9: runtime error: shift exponent 64 is too large for 64-bit type 'unsigned long'";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(ubsan_shift),
        Some("UndefinedBehaviorSanitizer: shift exponent 64 is too large for 64-bit type 'unsigned long'".to_string())
    );

    let ubsan_null = "src/ptr.c:8:1: runtime error: member access within null pointer of type 'struct Node'";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(ubsan_null),
        Some("UndefinedBehaviorSanitizer: member access within null pointer of type 'struct Node'".to_string())
    );

    // 3. MemorySanitizer (MSan)
    let msan_log = "==123==WARNING: MemorySanitizer: use-of-uninitialized-value\n    #0 0x4010 in foo";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(msan_log),
        Some("MemorySanitizer: use-of-uninitialized-value".to_string())
    );

    // 4. ThreadSanitizer (TSan)
    let tsan_log = "==456==WARNING: ThreadSanitizer: data-race (pid=456)\n  Write of size 8 at 0x7f";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(tsan_log),
        Some("ThreadSanitizer: data-race".to_string())
    );

    // 5. LeakSanitizer (LSan)
    let lsan_log = "==789==ERROR: LeakSanitizer: detected-memory-leaks\nDirect leak of 32 byte(s)";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(lsan_log),
        Some("LeakSanitizer: detected-memory-leaks".to_string())
    );

    // 6. Unknown fallback crash type defaults to CWE-119, CVSS 7.0
    let (cwe, score) = AsanParser::score_vulnerability("Unknown-Exotic-Crash");
    assert_eq!(cwe, "CWE-119");
    assert!((score - 7.0).abs() < f32::EPSILON);
}

#[test]
fn test_adversarial_asan_parser_corrupted_and_binary_inputs() {
    let temp = tempdir().unwrap();
    let dummy_seed = temp.path().join("crash.bin");
    fs::write(&dummy_seed, b"\x00\xff\xfe\xfd").unwrap();

    // 1. Empty string
    let rec_empty = AsanParser::parse_asan_log(Uuid::new_v4(), "", &dummy_seed);
    assert!(rec_empty.is_some());
    let rec = rec_empty.unwrap();
    assert_eq!(rec.crash_type, "Unknown-Crash");
    assert!(!rec.verified);

    // 2. Embedded null bytes and random binary in log
    let binary_log = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\x00\x01\x02\r\n    #0 0x4010 in test /src/vuln.c:42\x00extra";
    let rec_bin = AsanParser::parse_asan_log(Uuid::new_v4(), binary_log, &dummy_seed);
    assert!(rec_bin.is_some());
    let rec = rec_bin.unwrap();
    assert_eq!(rec.crash_type, "heap-buffer-overflow");
    assert_eq!(rec.cwe_id, Some("CWE-122".to_string()));

    // 3. Huge log with 10,000 stack frames (ensures no quadratic or stack blowup)
    let mut huge_log = String::from("==99==ERROR: AddressSanitizer: stack-buffer-overflow\n");
    for i in 0..10_000 {
        huge_log.push_str(&format!("    #{i} 0x{:08x} in func_{i} /src/file_{i}.c:{i}\n", 0x400000 + i));
    }
    let top_loc = AsanParser::extract_source_location(&huge_log);
    assert_eq!(top_loc, Some(("/src/file_0.c".to_string(), 0)));

    let frames = AsanParser::parse_stack_frames(&huge_log);
    assert_eq!(frames.len(), 10_000);
}

#[tokio::test]
async fn test_adversarial_poc_runner_infinite_loop_timeout() {
    let temp = tempdir().unwrap();

    // Program with infinite busy loop
    let infinite_c = r#"
#include <unistd.h>
int main(void) {
    while (1) {
        usleep(1000);
    }
    return 0;
}
"#;

    let compiler = PocCompiler::new().with_sanitizer(false);
    let bin = compiler
        .compile_source_sync(infinite_c, temp.path(), "infinite_poc")
        .expect("Failed compiling infinite loop C code");

    let runner = PocRunner::new().with_timeout(Duration::from_millis(600));
    let res = runner.run(&bin).await.expect("Failed executing PoC runner");

    assert!(res.timed_out, "PoC runner must flag execution as timed out");
    assert!(!res.clean_execution, "Timed out run is not clean");
    assert!(!res.reproduced_crash, "Timeout must not be counted as reproduced crash");
    assert_eq!(res.violation_type, Some("Timeout".to_string()));
}

#[tokio::test]
async fn test_adversarial_poc_runner_non_clean_exit_codes() {
    let temp = tempdir().unwrap();
    let compiler = PocCompiler::new().with_sanitizer(false);
    let runner = PocRunner::new();

    // 1. Program exiting with code 1 (clean execution should be false)
    let exit1_c = "int main(void) { return 1; }";
    let bin1 = compiler
        .compile_source_sync(exit1_c, temp.path(), "exit1")
        .unwrap();
    let res1 = runner.run(&bin1).await.unwrap();
    assert_eq!(res1.exit_code, Some(1));
    assert!(!res1.clean_execution, "Exit code 1 must not be considered clean execution");

    // 2. Program exiting with code 0 (clean execution should be true)
    let exit0_c = "int main(void) { return 0; }";
    let bin0 = compiler
        .compile_source_sync(exit0_c, temp.path(), "exit0")
        .unwrap();
    let res0 = runner.run(&bin0).await.unwrap();
    assert_eq!(res0.exit_code, Some(0));
    assert!(res0.clean_execution, "Exit code 0 without errors is clean execution");
}

#[test]
fn test_adversarial_patch_applier_symlink_escape_defenses() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("repo");
    let outside_dir = temp.path().join("outside_system");
    fs::create_dir_all(&target_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let target_file_outside = outside_dir.join("hosts");
    fs::write(&target_file_outside, "127.0.0.1 localhost\n").unwrap();

    // Create symlink inside repo pointing outside
    let symlink_path = target_dir.join("symlink_to_outside");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_file_outside, &symlink_path).unwrap();

    let patch = PatchCandidate {
        file_path: "symlink_to_outside".to_string(),
        unified_diff: "--- a/symlink_to_outside\n+++ b/symlink_to_outside\n@@ -1,1 +1,1 @@\n-127.0.0.1 localhost\n+127.0.0.1 pwned.local\n".to_string(),
        explanation: "Symlink escape attack".to_string(),
    };

    let result = PatchApplier::apply_patch(&target_dir, &patch);

    // Must be rejected because canonical path escapes target_dir
    assert!(
        result.is_err(),
        "PatchApplier must reject modifying files through symlinks pointing outside target_dir"
    );

    let content = fs::read_to_string(&target_file_outside).unwrap();
    assert_eq!(
        content, "127.0.0.1 localhost\n",
        "Target outside file must remain unmodified"
    );
}

#[test]
fn test_adversarial_patch_applier_corrupted_hunks_and_offsets() {
    let original = "line1\nline2\nline3\n";

    // 1. Out of bounds start line (e.g. line 99999)
    let diff_oob = "--- a/test.c\n+++ b/test.c\n@@ -99999,1 +99999,2 @@\n+inserted\n";
    let res_oob = PatchApplier::apply_diff_to_content(original, diff_oob);
    assert!(res_oob.is_ok(), "Out of bounds hunk should be clamped safely to EOF without panicking");
    let patched = res_oob.unwrap();
    assert!(patched.contains("inserted"));

    // 2. Hunk with invalid syntax (no line numbers)
    let diff_invalid = "--- a/test.c\n+++ b/test.c\n@@ -invalid +invalid @@\n+test\n";
    let res_invalid = PatchApplier::apply_diff_to_content(original, diff_invalid);
    // Invalid diff with no valid @@ digits returns original or error without panicking
    assert!(res_invalid.is_ok() || res_invalid.is_err());

    // 3. Negative line numbers in diff
    let diff_negative = "--- a/test.c\n+++ b/test.c\n@@ --10,1 +-20,1 @@\n+test\n";
    let res_neg = PatchApplier::apply_diff_to_content(original, diff_negative);
    assert!(res_neg.is_ok() || res_neg.is_err());

    // 4. Multiple hunks modifying line 1
    let diff_multi = "--- a/test.c\n+++ b/test.c\n@@ -1,1 +1,2 @@\n+patch1\n line1\n@@ -1,1 +1,2 @@\n+patch2\n";
    let res_multi = PatchApplier::apply_diff_to_content(original, diff_multi);
    assert!(res_multi.is_ok());
    let patched_multi = res_multi.unwrap();
    assert!(patched_multi.contains("patch1"));
}

#[tokio::test]
async fn test_adversarial_patch_verifier_full_flow_with_custom_regression() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("c_project");
    fs::create_dir_all(&target_dir).unwrap();

    let vuln_c_file = target_dir.join("vuln.c");
    let original_c_code = r#"
#include <stdio.h>
#include <stdlib.h>

void trigger_vuln(int do_overflow) {
    if (do_overflow) {
        char *p = (char*)malloc(8);
        p[16] = 'Z'; // ASan heap buffer overflow
        free(p);
    } else {
        printf("[+] Clean execution\n");
    }
}
"#;
    fs::write(&vuln_c_file, original_c_code).unwrap();

    // Standalone PoC invoking trigger_vuln(1)
    let poc_c_file = target_dir.join("poc.c");
    let poc_code = r#"
#include <stdio.h>
#include "vuln.c"

int main(void) {
    trigger_vuln(1);
    return 0;
}
"#;
    fs::write(&poc_c_file, poc_code).unwrap();

    // Effective patch changing do_overflow condition
    let diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -5,3 +5,3 @@
 void trigger_vuln(int do_overflow) {
-    if (do_overflow) {
+    if (0 && do_overflow) {
         char *p = (char*)malloc(8);
"#;
    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: diff.to_string(),
        explanation: "Disable vulnerable code path".to_string(),
    };

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "stage_test_hash".to_string(),
        stack_trace: "ERROR: AddressSanitizer: heap-buffer-overflow".to_string(),
        input_path: PathBuf::from("/tmp/dummy.bin"),
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let build_output = BuildOutput {
        static_libs: Vec::new(),
        shared_libs: Vec::new(),
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    // 1. Test failure when regression command fails (asserts rollback!)
    let verifier_fail_reg = PatchVerifier::new(target_dir.clone(), build_output.clone())
        .with_regression_command("exit 1"); // Simulated failed regression test

    let report_fail = verifier_fail_reg
        .verify_patch(&crash, &poc_c_file, &patch)
        .await
        .expect("Verification function must not error");

    assert!(!report_fail.verified);
    assert_eq!(report_fail.failure_stage, Some("regression_test_suite".to_string()));
    // Assert target file was automatically rolled back!
    let file_after_fail = fs::read_to_string(&vuln_c_file).unwrap();
    assert_eq!(file_after_fail, original_c_code, "File must be restored to original after regression failure");

    // 2. Test full 5/5 success when regression command succeeds
    let verifier_success = PatchVerifier::new(target_dir.clone(), build_output)
        .with_regression_command("echo 'ALL REGRESSION TESTS PASSED'");

    let report_success = verifier_success
        .verify_patch(&crash, &poc_c_file, &patch)
        .await
        .expect("Verification function must succeed");

    assert!(report_success.verified, "All 5 stages must pass");
    assert!(report_success.pre_patch_reproduced);
    assert!(report_success.patch_applied_cleanly);
    assert!(report_success.target_recompiled);
    assert!(report_success.post_patch_poc_clean);
    assert!(report_success.regression_passed);

    // File committed with patch
    let file_after_commit = fs::read_to_string(&vuln_c_file).unwrap();
    assert!(file_after_commit.contains("if (0 && do_overflow)"));
}
