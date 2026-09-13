pub mod asan;
pub mod patch_applier;
pub mod patch_synth;
pub mod poc_gen;
pub mod poc_runner;
pub mod verifier;

pub use asan::{AsanParser, StackFrame};
pub use patch_applier::{PatchApplier, PatchGuard};
pub use patch_synth::{PatchCandidate, PatchSynthesizer};
pub use poc_gen::{PocCompileResult, PocCompiler, PocGenerator};
pub use poc_runner::{PocRunResult, PocRunner};
pub use verifier::{PatchVerifier, VerificationReport};

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn test_asan_extract_source_location_single_and_multi() {
        let log = r#"
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 4 at 0x602000000010 thread T0
    #0 0x401234 in cJSON_ParseWithLength /src/cJSON.c:1042
    #1 0x402567 in main /src/fuzz_main.c:20
    #2 0x7fff123 in __libc_start_main /build/glibc.c:300
"#;
        let top_loc = AsanParser::extract_source_location(log);
        assert_eq!(top_loc, Some(("/src/cJSON.c".to_string(), 1042)));

        let all_locs = AsanParser::extract_all_source_locations(log);
        assert_eq!(all_locs.len(), 3);
        assert_eq!(all_locs[0], ("/src/cJSON.c".to_string(), 1042));
        assert_eq!(all_locs[1], ("/src/fuzz_main.c".to_string(), 20));
        assert_eq!(all_locs[2], ("/build/glibc.c".to_string(), 300));
    }

    #[test]
    fn test_asan_parse_stack_frames_detailed() {
        let log = r#"
    #0 0x501000 in vuln_function /path/to/target.c:88
    #1 0x502000 in helper_func
    #2 0x503000 in main /path/to/main.c:15
"#;
        let frames = AsanParser::parse_stack_frames(log);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].frame_num, 0);
        assert_eq!(frames[0].function, "vuln_function");
        assert_eq!(frames[0].source_file, Some("/path/to/target.c".to_string()));
        assert_eq!(frames[0].line_number, Some(88));

        assert_eq!(frames[1].frame_num, 1);
        assert_eq!(frames[1].function, "helper_func");
        assert_eq!(frames[1].source_file, None);
        assert_eq!(frames[1].line_number, None);

        assert_eq!(frames[2].frame_num, 2);
        assert_eq!(frames[2].function, "main");
        assert_eq!(frames[2].source_file, Some("/path/to/main.c".to_string()));
        assert_eq!(frames[2].line_number, Some(15));
    }

    #[test]
    fn test_asan_detect_sanitizer_violation_variants() {
        let asan_out = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123";
        assert_eq!(
            AsanParser::detect_sanitizer_violation(asan_out),
            Some("heap-buffer-overflow".to_string())
        );

        let summary_out = "SUMMARY: AddressSanitizer: stack-buffer-overflow /src/test.c:10 in foo";
        assert_eq!(
            AsanParser::detect_sanitizer_violation(summary_out),
            Some("AddressSanitizer: stack-buffer-overflow".to_string())
        );

        let ubsan_out = "src/calc.c:42:15: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented";
        assert_eq!(
            AsanParser::detect_sanitizer_violation(ubsan_out),
            Some("UndefinedBehaviorSanitizer: signed integer overflow: 2147483647 + 1 cannot be represented".to_string())
        );

        let clean_out = "[*] All checks passed successfully.\nExiting 0.";
        assert_eq!(AsanParser::detect_sanitizer_violation(clean_out), None);
    }

    #[test]
    fn test_asan_is_clean_execution() {
        assert!(AsanParser::is_clean_execution("Clean output", Some(0)));
        assert!(!AsanParser::is_clean_execution("Clean output", Some(1)));
        assert!(!AsanParser::is_clean_execution("Clean output", None));
        assert!(!AsanParser::is_clean_execution(
            "ERROR: AddressSanitizer: heap-buffer-overflow",
            Some(0)
        ));
        assert!(!AsanParser::is_clean_execution(
            "Segmentation fault (core dumped)",
            Some(139)
        ));
    }

    #[test]
    fn test_parse_asan_log_initial_verified_false() {
        let temp = tempdir().unwrap();
        let input_path = temp.path().join("crash.bin");
        fs::write(&input_path, b"A").unwrap();

        let log = r#"
==999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234
    #0 0x401000 in parse_token /src/parser.c:50
"#;
        let record = AsanParser::parse_asan_log(Uuid::new_v4(), log, &input_path).unwrap();
        assert_eq!(record.crash_type, "heap-buffer-overflow");
        assert_eq!(record.cwe_id, Some("CWE-122".to_string()));
        assert_eq!(record.cvss_score, Some(8.8));
        assert!(!record.verified, "Initial CrashRecord must have verified = false");
    }

    #[test]
    fn test_patch_applier_diff_application_and_rollback() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("source.c");
        let original_code = "int calc(int x) {\n    return x + 1;\n}\n";
        fs::write(&file_path, original_code).unwrap();

        let diff = r#"--- a/source.c
+++ b/source.c
@@ -1,3 +1,6 @@
 int calc(int x) {
+    if (x < 0) return 0;
     return x + 1;
 }
"#;

        let mut guard = PatchApplier::apply(&file_path, diff).expect("Failed to apply patch");
        let patched_code = fs::read_to_string(&file_path).unwrap();
        assert!(patched_code.contains("if (x < 0) return 0;"));

        // Roll back
        guard.rollback().expect("Rollback failed");
        let restored_code = fs::read_to_string(&file_path).unwrap();
        assert_eq!(restored_code, original_code);
    }

    #[test]
    fn test_patch_guard_drop_rolls_back_automatically() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("source.c");
        let original_code = "int test(void) { return 42; }\n";
        fs::write(&file_path, original_code).unwrap();

        let diff = r#"--- a/source.c
+++ b/source.c
@@ -1,1 +1,2 @@
+/* guard */
 int test(void) { return 42; }
"#;

        {
            let _guard = PatchApplier::apply(&file_path, diff).unwrap();
            let patched = fs::read_to_string(&file_path).unwrap();
            assert!(patched.contains("/* guard */"));
            // _guard drops here without commit()
        }

        let rolled_back = fs::read_to_string(&file_path).unwrap();
        assert_eq!(rolled_back, original_code);
    }

    #[test]
    fn test_poc_compiler_and_runner_clean_and_asan_crash() {
        let temp = tempdir().unwrap();

        // 1. Clean program
        let safe_c = r#"
#include <stdio.h>
int main(void) {
    printf("[+] Clean execution (patch verified).\n");
    return 0;
}
"#;
        let compiler = PocCompiler::new();
        let safe_bin = compiler
            .compile_source_sync(safe_c, temp.path(), "safe_test")
            .expect("Failed to compile safe C code");

        let runner = PocRunner::new();
        let safe_res = runner.run_sync(&safe_bin).expect("Failed to run safe binary");
        assert!(safe_res.clean_execution);
        assert!(!safe_res.reproduced_crash);
        assert_eq!(safe_res.exit_code, Some(0));

        // 2. Vulnerable program with ASan heap overflow
        let vuln_c = r#"
#include <stdlib.h>
int main(void) {
    char *buf = (char*)malloc(8);
    buf[16] = 'X'; // Heap buffer overflow
    free(buf);
    return 0;
}
"#;
        let vuln_bin = compiler
            .compile_source_sync(vuln_c, temp.path(), "vuln_test")
            .expect("Failed to compile vuln C code");

        let vuln_res = runner.run_sync(&vuln_bin).expect("Failed to run vuln binary");
        assert!(!vuln_res.clean_execution);
        assert!(vuln_res.reproduced_crash);
        assert!(
            vuln_res.stderr.contains("AddressSanitizer: heap-buffer-overflow")
                || vuln_res.violation_type.is_some()
        );
    }
}
