use crashwise_build::compiler::BuildOutput;
use crashwise_core::models::CrashRecord;
use crashwise_triage::patch_synth::PatchCandidate;
use crashwise_triage::verifier::PatchVerifier;
use std::fs;
use tempfile::tempdir;
use uuid::Uuid;

#[tokio::test]
async fn test_patch_verifier_complete_5_stage_success() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    // 1. Create a vulnerable C source file in target
    let src_file = target_dir.join("vuln.c");
    let original_c = "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n\nint process_data(const uint8_t *data, size_t len) {\n    char *buf = (char*)malloc(8);\n    buf[len] = 'X';\n    int res = (int)buf[0];\n    free(buf);\n    return res;\n}\n";
    fs::write(&src_file, original_c).unwrap();

    // 2. Create standalone PoC reproducer source file
    let poc_file = temp.path().join("poc.c");
    let poc_c = r#"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "vuln.c"

static const uint8_t poc_payload[] = { 0x01, 0x02, 0x03, 0x04 };

int main(int argc, char **argv) {
    process_data(poc_payload, 16);
    printf("[+] Target executed without crashing (patch verified).\n");
    return 0;
}
"#;
    fs::write(&poc_file, poc_c).unwrap();

    // 3. Create CrashRecord
    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"payload1234567890").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash001".to_string(),
        stack_trace: "ERROR: AddressSanitizer: heap-buffer-overflow".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // 4. Create PatchCandidate that adds bounds check
    let patch_diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -5,3 +5,6 @@
 int process_data(const uint8_t *data, size_t len) {
+    if (len >= 8) {
+        return -1;
+    }
     char *buf = (char*)malloc(8);
"#;

    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: patch_diff.to_string(),
        explanation: "Bounds check to prevent heap overflow".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    // Regression command: test helper script that exits 0
    let verifier = PatchVerifier::new(target_dir.clone(), build_output)
        .with_regression_command("exit 0");

    let report = verifier
        .verify_patch_record(&mut crash, &poc_file, &patch)
        .await
        .expect("Verification execution failed");

    assert!(report.pre_patch_reproduced, "Stage 1 must pass");
    assert!(report.patch_applied_cleanly, "Stage 2 must pass");
    assert!(report.target_recompiled, "Stage 3 must pass: {:?}", report.compiler_output);
    assert!(report.post_patch_poc_clean, "Stage 4 must pass");
    assert!(report.regression_passed, "Stage 5 must pass");
    assert!(report.verified, "Report must be verified");
    assert!(crash.verified, "CrashRecord verified must be true");
    assert_eq!(crash.suggested_patch, Some(patch_diff.to_string()));
    assert_eq!(report.failure_stage, None);
}

#[tokio::test]
async fn test_patch_verifier_stage1_fails_when_poc_does_not_crash() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("safe.c");
    fs::write(&src_file, "int safe_code(void) { return 0; }\n").unwrap();

    let poc_file = temp.path().join("safe_poc.c");
    let safe_poc_c = r#"
#include <stdio.h>
int main(void) {
    printf("[+] Completely safe execution.\n");
    return 0;
}
"#;
    fs::write(&poc_file, safe_poc_c).unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"dummy").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash002".to_string(),
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
        file_path: "safe.c".to_string(),
        unified_diff: "--- a/safe.c\n+++ b/safe.c\n".to_string(),
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
    assert_eq!(report.failure_stage, Some("pre_patch_reproduction".to_string()));
    assert!(!crash.verified);
}

#[tokio::test]
async fn test_patch_verifier_stage5_regression_failure_triggers_rollback() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let original_c = "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n\nint process_data(const uint8_t *data, size_t len) {\n    char *buf = (char*)malloc(8);\n    buf[len] = 'X';\n    int res = (int)buf[0];\n    free(buf);\n    return res;\n}\n";
    fs::write(&src_file, original_c).unwrap();

    let poc_file = temp.path().join("poc.c");
    let poc_c = r#"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "vuln.c"

int main(void) {
    process_data((const uint8_t*)"A", 16);
    return 0;
}
"#;
    fs::write(&poc_file, poc_c).unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"dummy").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash003".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let patch_diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -5,3 +5,6 @@
 int process_data(const uint8_t *data, size_t len) {
+    if (len >= 8) {
+        return -1;
+    }
     char *buf = (char*)malloc(8);
"#;

    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: patch_diff.to_string(),
        explanation: "Fix heap overflow".to_string(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    // Provide regression command that fails (exit 1)
    let verifier = PatchVerifier::new(target_dir.clone(), build_output)
        .with_regression_command("exit 1");

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

    // Verify source file was rolled back to original
    let current_c = fs::read_to_string(&src_file).unwrap();
    assert_eq!(current_c, original_c, "Source file must be rolled back on regression failure");
}

#[tokio::test]
async fn test_patch_verifier_stage2_patch_apply_failure() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let original_c = "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n\nint process_data(const uint8_t *data, size_t len) {\n    char *buf = (char*)malloc(8);\n    buf[len] = 'X';\n    int res = (int)buf[0];\n    free(buf);\n    return res;\n}\n";
    fs::write(&src_file, original_c).unwrap();

    let poc_file = temp.path().join("poc.c");
    let poc_c = r#"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "vuln.c"

int main(void) {
    process_data((const uint8_t*)"A", 16);
    return 0;
}
"#;
    fs::write(&poc_file, poc_c).unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"dummy").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash004".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Patch targeting a nonexistent file
    let patch = PatchCandidate {
        file_path: "nonexistent_file.c".to_string(),
        unified_diff: "--- a/nonexistent_file.c\n+++ b/nonexistent_file.c\n@@ -1,1 +1,1 @@\n".to_string(),
        explanation: "bad file".to_string(),
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

    assert!(report.pre_patch_reproduced);
    assert!(!report.patch_applied_cleanly);
    assert!(!report.verified);
    assert_eq!(report.failure_stage, Some("patch_application".to_string()));
    assert!(!crash.verified);
}

#[tokio::test]
async fn test_patch_verifier_stage3_recompilation_failure_triggers_rollback() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let original_c = "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n\nint process_data(const uint8_t *data, size_t len) {\n    char *buf = (char*)malloc(8);\n    buf[len] = 'X';\n    int res = (int)buf[0];\n    free(buf);\n    return res;\n}\n";
    fs::write(&src_file, original_c).unwrap();

    let poc_file = temp.path().join("poc.c");
    let poc_c = r#"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "vuln.c"

int main(void) {
    process_data((const uint8_t*)"A", 16);
    return 0;
}
"#;
    fs::write(&poc_file, poc_c).unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"dummy").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash005".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Patch that introduces a C syntax error
    let syntax_error_diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -5,3 +5,4 @@
 int process_data(const uint8_t *data, size_t len) {
+    THIS_IS_A_SYNTAX_ERROR_THAT_WILL_NOT_COMPILE;;;
     char *buf = (char*)malloc(8);
"#;

    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: syntax_error_diff.to_string(),
        explanation: "broken patch".to_string(),
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

    // Verify rollback restored original code
    let current_c = fs::read_to_string(&src_file).unwrap();
    assert_eq!(current_c, original_c);
}

#[tokio::test]
async fn test_patch_verifier_stage4_ineffective_patch_fails_replay() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();

    let src_file = target_dir.join("vuln.c");
    let original_c = "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n\nint process_data(const uint8_t *data, size_t len) {\n    char *buf = (char*)malloc(8);\n    buf[len] = 'X';\n    int res = (int)buf[0];\n    free(buf);\n    return res;\n}\n";
    fs::write(&src_file, original_c).unwrap();

    let poc_file = temp.path().join("poc.c");
    let poc_c = r#"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "vuln.c"

int main(void) {
    process_data((const uint8_t*)"A", 16);
    return 0;
}
"#;
    fs::write(&poc_file, poc_c).unwrap();

    let dummy_seed = temp.path().join("seed.bin");
    fs::write(&dummy_seed, b"dummy").unwrap();

    let mut crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash006".to_string(),
        stack_trace: "".to_string(),
        input_path: dummy_seed,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    // Ineffective patch that adds a comment but does NOT fix the overflow
    let ineffective_diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -5,3 +5,4 @@
 int process_data(const uint8_t *data, size_t len) {
+    /* Ineffective comment patch */
     char *buf = (char*)malloc(8);
"#;

    let patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: ineffective_diff.to_string(),
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
    assert!(!report.post_patch_poc_clean);
    assert!(!report.verified);
    assert_eq!(report.failure_stage, Some("post_patch_poc_replay".to_string()));
    assert!(!crash.verified);

    // Verify rollback restored original code
    let current_c = fs::read_to_string(&src_file).unwrap();
    assert_eq!(current_c, original_c);
}

