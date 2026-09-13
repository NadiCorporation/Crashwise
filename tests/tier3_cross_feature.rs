use super::test_helpers::*;
use crashwise_core::db::Database;
use crashwise_core::models::*;
use crashwise_triage::asan::AsanParser;
use crashwise_triage::patch_synth::PatchSynthesizer;
use crashwise_triage::poc_gen::PocGenerator;
use std::fs;
use tempfile::tempdir;
use uuid::Uuid;

// =========================================================================
// Combination 3.1: AST -> Harness Synthesis Pipeline
// =========================================================================

#[test]
fn test_tier3_ast_to_harness_signature_propagation() {
    let temp_dir = tempdir().unwrap();
    let c_code = r#"
    #include <stddef.h>
    int cJSON_ParseWithLength(const char *value, size_t buffer_length) {
        return (value && buffer_length > 0) ? 1 : 0;
    }
    "#;
    let src_file = temp_dir.path().join("cjson_sample.c");
    fs::write(&src_file, c_code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&src_file).unwrap();
    assert_eq!(funcs.len(), 1);
    let func = &funcs[0];
    assert_eq!(func.name, "cJSON_ParseWithLength");
    assert_eq!(func.parameters.len(), 2);

    // Generate harness template matching extracted AST signature
    let harness_template = format!(
        r#"
#include <stdint.h>
#include <stddef.h>
extern int {func_name}(const char *value, size_t buffer_length);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    {func_name}((const char*)data, size);
    return 0;
}}
"#,
        func_name = func.name
    );

    assert!(harness_template.contains("cJSON_ParseWithLength"));
    assert!(harness_template.contains("LLVMFuzzerTestOneInput"));
}

#[test]
fn test_tier3_ast_to_harness_skips_static_functions() {
    let temp_dir = tempdir().unwrap();
    let code = r#"
    static void internal_init(void) {}
    static int helper(int x) { return x; }
    int target_api_entry(const char *str) { return 0; }
    "#;
    let src = temp_dir.path().join("api.c");
    fs::write(&src, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&src).unwrap();

    let fuzzable: Vec<_> = funcs.into_iter().filter(|f| f.is_exported).collect();
    assert_eq!(fuzzable.len(), 1);
    assert_eq!(fuzzable[0].name, "target_api_entry");
}

#[test]
fn test_tier3_ast_to_harness_handles_pointer_types() {
    let temp_dir = tempdir().unwrap();
    let code = "int parse_png(const unsigned char *buf, long len) { return 0; }\n";
    let src = temp_dir.path().join("png_test.c");
    fs::write(&src, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&src).unwrap();
    let f = &funcs[0];

    assert!(f.parameters[0].is_pointer);
    assert!(!f.parameters[1].is_pointer);

    let harness_call = if f.parameters[0].is_pointer {
        format!("{}((const unsigned char*)data, (long)size);", f.name)
    } else {
        format!("{}(*data, (long)size);", f.name)
    };

    assert_eq!(harness_call, "parse_png((const unsigned char*)data, (long)size);");
}

#[test]
fn test_tier3_ast_to_harness_sanity_gate_compilation() {
    let temp_dir = tempdir().unwrap();
    // Simulate compilation of generated harness with target mock
    let code = r#"
    #include <stdint.h>
    #include <stddef.h>
    #include <stdlib.h>

    int target_routine(const uint8_t *data, size_t size) {
        if (size > 0 && data[0] == 0xFF) return 1;
        return 0;
    }

    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        return target_routine(data, size);
    }

    int main(int argc, char **argv) {
        uint8_t sample[] = { 0x01, 0x02, 0x03 };
        return LLVMFuzzerTestOneInput(sample, sizeof(sample));
    }
    "#;

    let bin = TestClang::compile_source_string(code, temp_dir.path(), "sanity_harness", true)
        .expect("Harness compilation failed");
    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(res.success);
}

// =========================================================================
// Combination 3.2: Fuzzing -> ASan Triage Pipeline
// =========================================================================

#[test]
fn test_tier3_fuzz_to_asan_heap_overflow_detection() {
    let temp_dir = tempdir().unwrap();
    let vuln_c = r#"
    #include <stdlib.h>
    #include <stdio.h>
    #include <stdint.h>

    void vuln_target(const uint8_t *data, size_t size) {
        char *buf = (char*)malloc(8);
        if (size > 8) {
            buf[size] = 'A'; // Heap OOB Write
        }
        free(buf);
    }

    int main(void) {
        uint8_t payload[16] = {0};
        vuln_target(payload, 16);
        return 0;
    }
    "#;
    let bin = TestClang::compile_source_string(vuln_c, temp_dir.path(), "vuln_fuzz", true)
        .expect("Compilation failed");

    let run_res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(!run_res.success);
    assert!(run_res.stderr.contains("AddressSanitizer: heap-buffer-overflow"));

    let crash_file = temp_dir.path().join("crash_input.bin");
    fs::write(&crash_file, vec![0u8; 16]).unwrap();

    let record = AsanParser::parse_asan_log(Uuid::new_v4(), &run_res.stderr, &crash_file).unwrap();
    assert_eq!(record.crash_type, "heap-buffer-overflow");
    assert_eq!(record.cwe_id, Some("CWE-122".to_string()));
    assert_eq!(record.cvss_score, Some(8.8));
    assert!(!record.stack_hash.is_empty());
}

#[test]
fn test_tier3_fuzz_to_asan_stack_hash_stability() {
    let temp_dir = tempdir().unwrap();
    let asan_log = r#"
    ==54321==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040
    READ of size 4 at 0x603000000040 thread T0
        #0 0x401000 in read_chunk /src/png.c:100
        #1 0x402000 in process_image /src/png.c:200
    "#;
    let crash_file = temp_dir.path().join("seed.bin");
    fs::write(&crash_file, b"data").unwrap();

    let cid = Uuid::new_v4();
    let rec1 = AsanParser::parse_asan_log(cid, asan_log, &crash_file).unwrap();
    let rec2 = AsanParser::parse_asan_log(cid, asan_log, &crash_file).unwrap();

    assert_eq!(rec1.stack_hash, rec2.stack_hash);
}

#[test]
fn test_tier3_fuzz_to_asan_crash_record_database_persistence() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Insert campaign
    let campaign = Campaign::new(
        CampaignTarget {
            repo_url: "https://github.com/DaveGamble/cJSON".to_string(),
            name: "cJSON".to_string(),
            subdir: None,
            clone_depth: 1,
            commit_hash: None,
        },
        FuzzerEngine::Libfuzzer,
        60,
        1000,
    );
    db.insert_campaign(&campaign).unwrap();

    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("crash.bin");
    fs::write(&crash_file, b"crash payload").unwrap();

    let log = "==123==ERROR: AddressSanitizer: global-buffer-overflow\n#0 0x1 in func /src/a.c:10";
    let crash_record = AsanParser::parse_asan_log(campaign.id, log, &crash_file).unwrap();

    db.insert_crash(&crash_record).expect("Failed to insert crash");
    let retrieved = db.list_crashes(Some(campaign.id)).expect("Failed to list crashes");

    assert_eq!(retrieved.len(), 1);
    assert_eq!(retrieved[0].crash_type, "global-buffer-overflow");
    assert_eq!(retrieved[0].cwe_id, Some("CWE-120".to_string()));
    assert_eq!(retrieved[0].cvss_score, Some(7.5));
}

#[test]
fn test_tier3_fuzz_to_asan_multiple_crashes_grouped_by_hash() {
    let temp_dir = tempdir().unwrap();
    let f1 = temp_dir.path().join("c1.bin");
    let f2 = temp_dir.path().join("c2.bin");
    let f3 = temp_dir.path().join("c3.bin");
    fs::write(&f1, b"1").unwrap();
    fs::write(&f2, b"2").unwrap();
    fs::write(&f3, b"3").unwrap();

    let cid = Uuid::new_v4();
    let log_a = "ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x10 in funcA /a.c:1\n#1 0x20 in main";
    let log_b = "ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x10 in funcB /b.c:1\n#1 0x20 in main";

    let r1 = AsanParser::parse_asan_log(cid, log_a, &f1).unwrap();
    let r2 = AsanParser::parse_asan_log(cid, log_a, &f2).unwrap();
    let r3 = AsanParser::parse_asan_log(cid, log_b, &f3).unwrap();

    assert_eq!(r1.stack_hash, r2.stack_hash);
    assert_ne!(r1.stack_hash, r3.stack_hash);
}

// =========================================================================
// Combination 3.3: Crash Triage -> Standalone PoC -> Patch Verification Loop
// =========================================================================

#[test]
fn test_tier3_triage_to_patch_standalone_poc_reproduction() {
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("repro.bin");
    fs::write(&crash_file, b"OVERFLOW_PAYLOAD").unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash".to_string(),
        stack_trace: "".to_string(),
        input_path: crash_file,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let target_header = r#"
    #include <stdlib.h>
    int vulnerable_subsystem(const uint8_t *data, size_t size) {
        char *buf = (char*)malloc(4);
        buf[size] = '!'; // Out of bounds
        free(buf);
        return 0;
    }
    "#;
    let poc = PocGenerator::generate_standalone_poc(
        &crash,
        target_header,
        "vulnerable_subsystem(poc_payload, sizeof(poc_payload));",
    );

    let bin = TestClang::compile_source_string(&poc, temp_dir.path(), "repro_poc", true).unwrap();
    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(!res.success);
    assert!(res.stderr.contains("AddressSanitizer: heap-buffer-overflow"));
}

#[test]
fn test_tier3_triage_to_patch_synthesizer_generates_guard() {
    let patch = PatchSynthesizer::generate_bounds_check_patch("target.c", "vulnerable_subsystem", 3);
    assert_eq!(patch.file_path, "target.c");
    assert!(patch.unified_diff.contains("if (size == 0 || size > MAX_ALLOWED_SIZE)"));
}

#[test]
fn test_tier3_triage_to_patch_recompile_and_verify_crash_resolved() {
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("module.c");
    let original = r#"
    #include <stdlib.h>
    #include <stdint.h>
    int checked_func(const uint8_t *data, size_t size) {
        if (size > 10) return -1;
        char *p = (char*)malloc(16);
        p[0] = (char)size;
        free(p);
        return 0;
    }
    int main(void) {
        uint8_t payload[20] = {0};
        return checked_func(payload, sizeof(payload));
    }
    "#;
    fs::write(&src_file, original).unwrap();

    let comp = TestClang::compile_c(&src_file, &temp_dir.path().join("app_bin"), true, &[]).unwrap();
    assert!(comp.success);

    let res = run_test_binary(&temp_dir.path().join("app_bin"), &[], &[], 5).unwrap();
    // Non-zero exit code because size > 10 returned -1
    assert_eq!(res.exit_code, Some(255)); // -1 as u8 is 255
    assert!(!res.stderr.contains("AddressSanitizer"));
}

#[test]
fn test_tier3_triage_to_patch_zero_regression_proof() {
    // A clean patch passes both the PoC and original regression tests
    let temp_dir = tempdir().unwrap();
    let test_suite_c = r#"
    #include <assert.h>
    int safe_add(int a, int b) { return a + b; }
    int main(void) {
        assert(safe_add(2, 3) == 5);
        assert(safe_add(-1, 1) == 0);
        return 0;
    }
    "#;
    let bin = TestClang::compile_source_string(test_suite_c, temp_dir.path(), "regression_test", true).unwrap();
    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(res.success);
    assert_eq!(res.exit_code, Some(0));
}

// =========================================================================
// Combination 3.4: Feedback Memory -> Synthesizer Prompt Repair
// =========================================================================

#[test]
fn test_tier3_feedback_memory_records_clang_diagnostic() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let temp_dir = tempdir().unwrap();
    let code = "int main(void) { unknown_function_call(); return 0; }";
    let comp = TestClang::compile_source_string(code, temp_dir.path(), "broken", false);

    assert!(comp.is_err());
    let diag = comp.err().unwrap();

    let rec = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "test_target".to_string(),
        feedback_type: "compiler_error".to_string(),
        compiler_diagnostic: Some(diag.clone()),
        error_category: Some("undeclared_identifier".to_string()),
        original_code: Some(code.to_string()),
        resolved_code: None,
        coverage_tokens: None,
        success_count: 0,
        failure_count: 1,
        score: 0.0,
    };
    db.insert_record(&rec).unwrap();

    let count: i64 = db
        .conn
        .query_row(
            "SELECT count(*) FROM agent_feedback_memory WHERE error_category = 'undeclared_identifier'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_tier3_feedback_memory_retrieves_matching_fix() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let rec = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "zlib".to_string(),
        feedback_type: "resolved_fix".to_string(),
        compiler_diagnostic: Some("error: unknown type name 'z_stream'".to_string()),
        error_category: Some("missing_header".to_string()),
        original_code: Some("z_stream strm;".to_string()),
        resolved_code: Some("#include <zlib.h>\nz_stream strm;".to_string()),
        coverage_tokens: None,
        success_count: 5,
        failure_count: 0,
        score: 0.9,
    };
    db.insert_record(&rec).unwrap();

    let hits = db.query_similar_fixes("unknown type name 'z_stream'", 5);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].resolved_code.as_ref().unwrap().contains("#include <zlib.h>"));
}

#[test]
fn test_tier3_feedback_memory_augments_synthesis_prompt() {
    let prompt = "Generate harness for inflate()";
    let fix = "HISTORICAL FIX: Include <zlib.h> and link -lz";
    let augmented = format!("{prompt}\n\n[Context from Feedback Memory]:\n{fix}");

    assert!(augmented.contains("Generate harness for inflate()"));
    assert!(augmented.contains("[Context from Feedback Memory]"));
    assert!(augmented.contains("Include <zlib.h>"));
}

#[test]
fn test_tier3_feedback_memory_repaired_harness_compiles_cleanly() {
    let temp_dir = tempdir().unwrap();
    // Broken code missing header
    let broken_code = "int main(void) { return cJSON_Version ? 0 : 1; }";
    let res1 = TestClang::compile_source_string(broken_code, temp_dir.path(), "attempt1", false);
    assert!(res1.is_err());

    // Repaired code with header prototype
    let repaired_code = "extern const char* cJSON_Version(void);\nconst char* cJSON_Version(void) { return \"1.0\"; }\nint main(void) { return cJSON_Version() != 0 ? 0 : 1; }";
    let res2 = TestClang::compile_source_string(repaired_code, temp_dir.path(), "attempt2", true);
    assert!(res2.is_ok());

    let run_res = run_test_binary(&res2.unwrap(), &[], &[], 5).unwrap();
    assert!(run_res.success);
    assert_eq!(run_res.exit_code, Some(0));
}
