use crashwise_build::compiler::BuildOutput;
use crashwise_core::models::CrashRecord;
use crashwise_triage::asan::AsanParser;
use crashwise_triage::patch_applier::PatchApplier;
use crashwise_triage::patch_synth::PatchCandidate;
use crashwise_triage::verifier::PatchVerifier;
use std::fs;
use tempfile::tempdir;
use uuid::Uuid;

// =========================================================================
// 1. Path Traversal & File Boundary Stress Tests
// =========================================================================

#[test]
fn test_path_traversal_parent_directory_escape() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    let outside_dir = temp.path().join("outside");
    fs::create_dir_all(&target_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let secret_file = outside_dir.join("secret.txt");
    let secret_content = "TOP_SECRET_CREDENTIALS\n";
    fs::write(&secret_file, secret_content).unwrap();

    // Adversarial patch attempting to escape target_dir into outside_dir
    let patch = PatchCandidate {
        file_path: "../outside/secret.txt".to_string(),
        unified_diff: "--- a/secret.txt\n+++ b/secret.txt\n@@ -1,1 +1,1 @@\n-TOP_SECRET_CREDENTIALS\n+PWNED\n".to_string(),
        explanation: "Directory traversal attack".to_string(),
    };

    let result = PatchApplier::apply_patch(&target_dir, &patch);

    // If result is Ok, check whether outside/secret.txt was modified!
    if let Ok(mut guard) = result {
        let current_secret = fs::read_to_string(&secret_file).unwrap();
        let was_modified = current_secret.contains("PWNED");
        guard.rollback().unwrap();
        assert!(
            !was_modified,
            "CRITICAL VULNERABILITY: PatchApplier permitted modifying files outside target_dir via parent traversal '../'!"
        );
    }
    // If it returned Err, that's safe behavior!
}

#[test]
fn test_path_traversal_absolute_path_escape() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    let outside_dir = temp.path().join("outside");
    fs::create_dir_all(&target_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let outside_file = outside_dir.join("system_config.cfg");
    fs::write(&outside_file, "ALLOW_LOGIN=false\n").unwrap();

    let patch = PatchCandidate {
        file_path: outside_file.to_str().unwrap().to_string(),
        unified_diff: "--- a/system_config.cfg\n+++ b/system_config.cfg\n@@ -1,1 +1,1 @@\n-ALLOW_LOGIN=false\n+ALLOW_LOGIN=true\n".to_string(),
        explanation: "Absolute path traversal attack".to_string(),
    };

    let result = PatchApplier::apply_patch(&target_dir, &patch);
    if let Ok(mut guard) = result {
        let current = fs::read_to_string(&outside_file).unwrap();
        let was_modified = current.contains("ALLOW_LOGIN=true");
        guard.rollback().unwrap();
        assert!(
            !was_modified,
            "CRITICAL VULNERABILITY: PatchApplier permitted modifying arbitrary files via absolute path!"
        );
    }
}

// =========================================================================
// 2. Atomic Patch Rollback, Backup Collision & Idempotency
// =========================================================================

#[test]
fn test_backup_path_extension_collision_hazard() {
    let temp = tempdir().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Two distinct files in the same directory: module.c and module.h
    let c_file = src_dir.join("module.c");
    let h_file = src_dir.join("module.h");

    let original_c = "/* ORIGINAL C SOURCE */\nint foo(void) { return 42; }\n";
    let original_h = "/* ORIGINAL HEADER SOURCE */\nint foo(void);\n";

    fs::write(&c_file, original_c).unwrap();
    fs::write(&h_file, original_h).unwrap();

    let diff_h = "--- a/module.h\n+++ b/module.h\n@@ -1,2 +1,3 @@\n+/* PATCHED H */\n /* ORIGINAL HEADER SOURCE */\n int foo(void);\n";
    let diff_c = "--- a/module.c\n+++ b/module.c\n@@ -1,2 +1,3 @@\n+/* PATCHED C */\n /* ORIGINAL C SOURCE */\n int foo(void) { return 42; }\n";

    // Apply patch to module.h
    let mut guard_h = PatchApplier::apply(&h_file, diff_h).expect("Failed to apply header patch");
    let h_backup = guard_h.backup_path().to_path_buf();

    // Apply patch to module.c
    let mut guard_c = PatchApplier::apply(&c_file, diff_c).expect("Failed to apply c patch");
    let c_backup = guard_c.backup_path().to_path_buf();

    // If both guards use target_file.with_extension("orig.bak"), h_backup == c_backup == "module.orig.bak"!
    let collided = h_backup == c_backup;

    // Rollback C first
    guard_c.rollback().expect("Rollback c failed");

    // Rollback H second
    let _ = guard_h.rollback();

    let restored_c = fs::read_to_string(&c_file).unwrap();
    let restored_h = fs::read_to_string(&h_file).unwrap();

    assert_eq!(restored_c, original_c, "module.c must be correctly restored");
    assert_eq!(
        restored_h, original_h,
        "module.h must be correctly restored without corruption from backup collision (collided: {collided}, h_backup: {}, c_backup: {})",
        h_backup.display(),
        c_backup.display()
    );
}

#[test]
fn test_patch_guard_rollback_idempotency() {
    let temp = tempdir().unwrap();
    let src_file = temp.path().join("idempotent.c");
    let orig = "int test(void) { return 1; }\n";
    fs::write(&src_file, orig).unwrap();

    let diff = "--- a/idempotent.c\n+++ b/idempotent.c\n@@ -1,1 +1,2 @@\n+/* patch */\n int test(void) { return 1; }\n";
    let mut guard = PatchApplier::apply(&src_file, diff).unwrap();

    // First rollback
    assert!(guard.rollback().is_ok());
    assert_eq!(fs::read_to_string(&src_file).unwrap(), orig);

    // Second rollback should be a safe no-op
    assert!(guard.rollback().is_ok());
    assert_eq!(fs::read_to_string(&src_file).unwrap(), orig);
}

#[test]
fn test_patch_guard_panic_safety_restoration() {
    let temp = tempdir().unwrap();
    let src_file = temp.path().join("panic_target.c");
    let original = "void critical_function(void) {}\n";
    fs::write(&src_file, original).unwrap();

    let diff = "--- a/panic_target.c\n+++ b/panic_target.c\n@@ -1,1 +1,2 @@\n+/* corrupt */\n void critical_function(void) {}\n";

    // Run in catch_unwind to simulate panic during build or testing
    let src_clone = src_file.clone();
    let panic_result = std::panic::catch_unwind(move || {
        let _guard = PatchApplier::apply(&src_clone, diff).unwrap();
        assert!(fs::read_to_string(&src_clone).unwrap().contains("/* corrupt */"));
        panic!("Simulated worker or compiler crash mid-verification");
    });

    assert!(panic_result.is_err(), "Panic should have been caught");
    // Verify RAII drop restored original file
    let current = fs::read_to_string(&src_file).unwrap();
    assert_eq!(
        current, original,
        "Source file MUST be 100% restored from backup after thread panic"
    );
}

// =========================================================================
// 3. Corrupted Diffs & Adversarial Hunk Formats
// =========================================================================

#[test]
fn test_corrupted_diff_malformed_headers() {
    let orig = "int a = 1;\nint b = 2;\nint c = 3;\n";

    // 1. Negative line count in hunk
    let diff_neg = "@@ --5,1 ++5,1 @@\n+corrupted\n";
    let res1 = PatchApplier::apply_diff_to_content(orig, diff_neg).unwrap();
    assert_eq!(res1, orig, "Malformed header with negative line numbers must not alter content");

    // 2. Non-numeric coordinates
    let diff_alpha = "@@ -foo,bar +baz,qux @@\n+corrupted\n";
    let res2 = PatchApplier::apply_diff_to_content(orig, diff_alpha).unwrap();
    assert_eq!(res2, orig, "Non-numeric hunk headers must not alter content");

    // 3. Empty lines only in hunk
    let diff_empty_hunk = "@@ -1,1 +1,1 @@\n";
    let res3 = PatchApplier::apply_diff_to_content(orig, diff_empty_hunk).unwrap();
    assert_eq!(res3, orig);
}

#[test]
fn test_corrupted_diff_extreme_out_of_bounds() {
    let orig = "alpha\nbeta\n";
    // Target line index exceeding usize or massive offset
    let diff_oob = "@@ -18446744073709551614,1 +18446744073709551614,1 @@\n+omega\n";
    let res = PatchApplier::apply_diff_to_content(orig, diff_oob).unwrap();
    assert!(res.contains("omega"), "Massive line number should be clamped safely to EOF without panic");
}

#[test]
fn test_diff_with_multiple_hunks_sequential() {
    let orig = "line 1\nline 2\nline 3\nline 4\nline 5\n";
    let diff = r#"--- a/file.c
+++ b/file.c
@@ -1,2 +1,3 @@
+/* top comment */
 line 1
 line 2
@@ -4,2 +5,3 @@
 line 4
 line 5
+/* bottom comment */
"#;
    let res = PatchApplier::apply_diff_to_content(orig, diff).unwrap();
    assert!(res.contains("/* top comment */"));
    assert!(res.contains("/* bottom comment */"));
}

// =========================================================================
// 4. ASan Log Parser Corner Cases & Multi-Sanitizer Verification
// =========================================================================

#[test]
fn test_asan_parser_cpp_namespaced_functions() {
    let log = r#"
==10101==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000040
READ of size 4 at 0x603000000040 thread T0
    #0 0x405566 in std::__1::vector<int, std::__1::allocator<int>>::push_back(int const&) /usr/include/c++/v1/vector:1500
    #1 0x406677 in crashwise::ast::LayoutResolver::resolve(std::__1::string const&) /home/user/crashwise/crates/crashwise-ast/src/resolver.cpp:88
    #2 0x407788 in main /home/user/crashwise/crates/crashwise-cli/src/main.cpp:25
"#;
    let loc = AsanParser::extract_source_location(log);
    assert_eq!(
        loc,
        Some(("/usr/include/c++/v1/vector".to_string(), 1500)),
        "extract_source_location should extract top frame #0 even with C++ template/namespace function symbols"
    );
}

#[test]
fn test_asan_parser_multithreaded_and_nested_dumps() {
    let multithread_log = r#"
=================================================================
==9999==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x0000004012ab bp 0x7fff5fbff820 sp 0x7fff5fbff818
READ of size 4 at 0x602000000010 thread T1 (worker_pool_1)
    #0 0x4012aa in process_queue /src/worker.c:142
    #1 0x402345 in thread_start /src/thread.c:55

0x602000000010 is located 0 bytes inside of 8-byte region [0x602000000010,0x602000000018)
freed by thread T2 (deallocator) here:
    #0 0x7ffff7000100 in free /build/asan/asan_malloc.cpp:45
    #1 0x401999 in queue_cleanup /src/worker.c:88

previously allocated by thread T0 here:
    #0 0x7ffff7000050 in malloc /build/asan/asan_malloc.cpp:30
    #1 0x401888 in queue_init /src/worker.c:20
    #2 0x403000 in main /src/main.c:12

Thread T1 (worker_pool_1) created by T0 here:
    #0 0x7ffff7000200 in pthread_create /build/asan/asan_interceptors.cpp:200
    #1 0x402000 in main /src/main.c:10
=================================================================
"#;

    let loc = AsanParser::extract_source_location(multithread_log);
    assert_eq!(
        loc,
        Some(("/src/worker.c".to_string(), 142)),
        "Top crashing frame in multithreaded log should be extracted"
    );

    let all_locs = AsanParser::extract_all_source_locations(multithread_log);
    assert!(all_locs.len() >= 5, "All stack locations across multiple threads should be parsed");

    let frames = AsanParser::parse_stack_frames(multithread_log);
    assert!(frames.len() >= 5, "Detailed stack frames should include multiple threads");
}

#[test]
fn test_asan_parser_truncated_and_sanitized_logs() {
    // 1. Truncated log
    let truncated = "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010\n    #0 0x401000 in";
    let loc_trunc = AsanParser::extract_source_location(truncated);
    assert_eq!(loc_trunc, None, "Truncated log without full frame coordinates should return None");

    // 2. Empty log
    assert_eq!(AsanParser::extract_source_location(""), None);

    // 3. Log with no source coordinates (unsymbolized)
    let unsymbolized = "    #0 0x401000 in vuln_func\n    #1 0x402000 in main\n";
    assert_eq!(AsanParser::extract_source_location(unsymbolized), None);
    let frames = AsanParser::parse_stack_frames(unsymbolized);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].source_file, None);
}

#[test]
fn test_detect_all_sanitizer_violation_types() {
    // ASan global overflow
    let out_asan = "==1==ERROR: AddressSanitizer: global-buffer-overflow on address 0x123";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out_asan),
        Some("global-buffer-overflow".to_string())
    );

    // UBSan null pointer dereference
    let out_ubsan = "calc.c:12:3: runtime error: member access within null pointer of type 'struct Node'";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out_ubsan),
        Some("UndefinedBehaviorSanitizer: member access within null pointer of type 'struct Node'".to_string())
    );

    // TSan data race
    let out_tsan = "==2==WARNING: ThreadSanitizer: data race (pid=123)";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out_tsan),
        Some("ThreadSanitizer: data".to_string())
    );

    // MSan uninitialized value
    let out_msan = "==3==ERROR: MemorySanitizer: use-of-uninitialized-value";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out_msan),
        Some("MemorySanitizer: use-of-uninitialized-value".to_string())
    );

    // Clean output with exit 0
    assert!(AsanParser::is_clean_execution("Done.\nExit 0\n", Some(0)));

    // Clean text but non-zero exit code
    assert!(!AsanParser::is_clean_execution("Done.\n", Some(1)));
    assert!(!AsanParser::is_clean_execution("Done.\n", None));
}

// =========================================================================
// 5. Comprehensive 5-Stage PatchVerifier Failure & Success Tests
// =========================================================================

#[tokio::test]
async fn test_verifier_stage1_fails_when_poc_syntax_error() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    // Valid target source
    let src_file = target_dir.join("vuln.c");
    fs::write(&src_file, "int foo(void) { return 0; }\n").unwrap();

    // Standalone PoC with invalid C syntax
    let poc_file = temp.path().join("broken_poc.c");
    fs::write(&poc_file, "INVALID C CODE SYNTAX ERROR !#@$\n").unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"seed").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash_broken_poc".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: "--- a/vuln.c\n+++ b/vuln.c\n@@ -1,1 +1,1 @@\n".to_string(),
        explanation: "noop".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    let verifier = PatchVerifier::new(target_dir, build_output);
    let report = verifier
        .verify_patch_record(&mut crash, &poc_file, &patch)
        .await
        .unwrap();

    assert!(!report.pre_patch_reproduced);
    assert!(!report.verified);
    assert_eq!(report.failure_stage, Some("pre_patch_compilation".to_string()));
    assert!(!crash.verified);
}

#[tokio::test]
async fn test_verifier_stage2_fails_when_target_missing() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    // Target source file does NOT exist
    let poc_file = temp.path().join("poc.c");
    fs::write(
        &poc_file,
        r#"
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *p = (char*)malloc(4);
    p[16] = 'Z';
    free(p);
    return 0;
}
"#,
    )
    .unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"seed").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash_stage2".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Patch targets a completely missing file
    let patch = PatchCandidate {
        file_path: "missing_file.c".to_string(),
        unified_diff: "--- a/missing_file.c\n+++ b/missing_file.c\n@@ -1,1 +1,1 @@\n+fix\n".to_string(),
        explanation: "missing".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    let verifier = PatchVerifier::new(target_dir, build_output);
    let report = verifier
        .verify_patch_record(&mut crash, &poc_file, &patch)
        .await
        .unwrap();

    assert!(report.pre_patch_reproduced, "Stage 1 PoC crashed as expected");
    assert!(!report.patch_applied_cleanly, "Stage 2 should fail on missing target file");
    assert!(!report.verified);
    assert_eq!(report.failure_stage, Some("patch_application".to_string()));
    assert!(!crash.verified);
}

#[tokio::test]
async fn test_verifier_stage3_recompilation_failure_restores_file() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let orig_code = "int run_func(void) {\n    return 42;\n}\n";
    fs::write(&src_file, orig_code).unwrap();

    let poc_file = temp.path().join("poc.c");
    fs::write(
        &poc_file,
        r#"
#include <stdlib.h>
int main(void) {
    char *buf = (char*)malloc(8);
    buf[32] = 'A';
    free(buf);
    return 0;
}
"#,
    )
    .unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"seed").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash_stage3".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Patch that introduces an uncompilable syntax error
    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: "--- a/vuln.c\n+++ b/vuln.c\n@@ -1,3 +1,4 @@\n+int syntax_error !!!@@@;\n int run_func(void) {\n     return 42;\n }\n".to_string(),
        explanation: "syntax error".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    let verifier = PatchVerifier::new(target_dir.clone(), build_output);
    let report = verifier
        .verify_patch_record(&mut crash, &poc_file, &patch)
        .await
        .unwrap();

    assert!(report.pre_patch_reproduced);
    assert!(report.patch_applied_cleanly);
    assert!(!report.target_recompiled);
    assert!(!report.verified);
    assert_eq!(report.failure_stage, Some("target_recompilation".to_string()));
    assert!(!crash.verified);

    // Assert that target source is 100% restored
    let current_code = fs::read_to_string(&src_file).unwrap();
    assert_eq!(current_code, orig_code, "Source file must be rolled back on stage 3 compilation error");
}

#[tokio::test]
async fn test_verifier_stage4_crash_persists_triggers_rollback() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let orig_code = r#"
#include <stdlib.h>
int do_vulnerable_action(void) {
    char *b = (char*)malloc(8);
    b[64] = 'X';
    free(b);
    return 0;
}
"#;
    fs::write(&src_file, orig_code).unwrap();

    let poc_file = temp.path().join("poc.c");
    fs::write(
        &poc_file,
        r#"
#include <stdio.h>
#include "vuln.c"
int main(void) {
    do_vulnerable_action();
    return 0;
}
"#,
    )
    .unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"seed").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash_stage4".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Patch adds a no-op comment and doesn't fix the heap overflow
    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: "--- a/vuln.c\n+++ b/vuln.c\n@@ -1,3 +1,4 @@\n+/* ineffectual comment */\n #include <stdlib.h>\n".to_string(),
        explanation: "comment only".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    let verifier = PatchVerifier::new(target_dir.clone(), build_output);
    let report = verifier
        .verify_patch_record(&mut crash, &poc_file, &patch)
        .await
        .unwrap();

    assert!(report.pre_patch_reproduced);
    assert!(report.patch_applied_cleanly);
    assert!(report.target_recompiled);
    assert!(!report.post_patch_poc_clean, "PoC should still crash post-patch");
    assert!(!report.verified);
    assert_eq!(report.failure_stage, Some("post_patch_poc_replay".to_string()));
    assert!(!crash.verified);

    // Assert that target source is 100% restored
    let current_code = fs::read_to_string(&src_file).unwrap();
    assert_eq!(current_code, orig_code);
}

#[tokio::test]
async fn test_verifier_stage5_regression_failure_triggers_rollback() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let orig_code = r#"
#include <stdlib.h>
int fixable_code(int size) {
    char *b = (char*)malloc(8);
    b[size] = 'X';
    free(b);
    return 0;
}
"#;
    fs::write(&src_file, orig_code).unwrap();

    let poc_file = temp.path().join("poc.c");
    fs::write(
        &poc_file,
        r#"
#include <stdio.h>
#include "vuln.c"
int main(void) {
    fixable_code(64);
    return 0;
}
"#,
    )
    .unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"seed").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash_stage5".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Valid patch fixing the overflow
    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: r#"--- a/vuln.c
+++ b/vuln.c
@@ -3,3 +3,6 @@
 int fixable_code(int size) {
+    if (size >= 8) {
+        return -1;
+    }
     char *b = (char*)malloc(8);
"#
        .to_string(),
        explanation: "Fix overflow with bounds check".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    // Regression command fails (e.g. broken test suite)
    let verifier = PatchVerifier::new(target_dir.clone(), build_output)
        .with_regression_command("echo 'Test regression failed'; exit 42");

    let report = verifier
        .verify_patch_record(&mut crash, &poc_file, &patch)
        .await
        .unwrap();

    assert!(report.pre_patch_reproduced);
    assert!(report.patch_applied_cleanly);
    assert!(report.target_recompiled);
    assert!(report.post_patch_poc_clean);
    assert!(!report.regression_passed);
    assert!(!report.verified);
    assert_eq!(report.failure_stage, Some("regression_test_suite".to_string()));
    assert!(!crash.verified);

    // Assert that target source is 100% restored
    let current_code = fs::read_to_string(&src_file).unwrap();
    assert_eq!(current_code, orig_code);
}

#[tokio::test]
async fn test_verifier_corrupted_diff_handling() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let orig_code = r#"
#include <stdlib.h>
int do_vulnerable_action(void) {
    char *b = (char*)malloc(8);
    b[64] = 'X';
    free(b);
    return 0;
}
"#;
    fs::write(&src_file, orig_code).unwrap();

    let poc_file = temp.path().join("poc.c");
    fs::write(
        &poc_file,
        r#"
#include <stdio.h>
#include "vuln.c"
int main(void) {
    do_vulnerable_action();
    return 0;
}
"#,
    )
    .unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"seed").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash_corrupt_diff".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Corrupted diff that is not a valid unified diff
    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: "THIS IS COMPLETELY CORRUPTED GARBAGE THAT DOES NOT CONTAIN HUNKS\n".to_string(),
        explanation: "garbage diff".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    let verifier = PatchVerifier::new(target_dir.clone(), build_output);
    let report = verifier
        .verify_patch_record(&mut crash, &poc_file, &patch)
        .await
        .unwrap();

    println!("Corrupted diff patch_applied_cleanly: {}, failure_stage: {:?}", report.patch_applied_cleanly, report.failure_stage);
    assert!(!report.verified);
    // Observe: Did Stage 2 detect that the diff was corrupted and failed to apply,
    // or did PatchApplier falsely report patch_applied_cleanly = true?
    assert!(!report.patch_applied_cleanly, "Corrupted diff without valid hunks must NOT be marked patch_applied_cleanly = true");
}
