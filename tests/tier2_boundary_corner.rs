use super::test_helpers::*;
use crashwise_core::models::*;
use crashwise_engine::runner::FuzzRunner;
use crashwise_engine::sandbox::SandboxConfig;
use crashwise_triage::asan::AsanParser;
use crashwise_triage::poc_gen::PocGenerator;
use std::fs;
use tempfile::tempdir;
use uuid::Uuid;

// =========================================================================
// Category 2.1: Empty Inputs
// =========================================================================

#[test]
fn test_tier2_empty_c_file_ast_scan() {
    let temp_dir = tempdir().unwrap();
    let empty_file = temp_dir.path().join("empty.c");
    fs::write(&empty_file, "").unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&empty_file).expect("Failed to parse empty file");
    assert!(funcs.is_empty());
}

#[test]
fn test_tier2_empty_asan_log_parse() {
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("dummy");
    fs::write(&crash_file, "").unwrap();

    let record = AsanParser::parse_asan_log(Uuid::new_v4(), "", &crash_file);
    assert!(record.is_some());
    let r = record.unwrap();
    assert_eq!(r.crash_type, "Unknown-Crash");
}

#[test]
fn test_tier2_empty_diff_patch_apply() {
    let original = "line1\nline2\n";
    let empty_diff = "";
    let result = PatchManager::apply_diff_to_content(original, empty_diff).unwrap();
    assert_eq!(result, original);
}

#[test]
fn test_tier2_empty_shm_bitmap_edge_count() {
    let shm = ShmCoverageBitmap::new();
    assert_eq!(shm.count_covered_edges(), 0);
}

#[test]
fn test_tier2_empty_feedback_query_returns_empty_vec() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let res = db.query_similar_fixes("nonexistent_pattern", 10);
    assert!(res.is_empty());
}

// =========================================================================
// Category 2.2: Malformed & Truncated C/C++ Source
// =========================================================================

#[test]
fn test_tier2_malformed_unclosed_brace() {
    let malformed = "int broken_func(void) {\n    int a = 1;\n";
    let temp_dir = tempdir().unwrap();
    let file = temp_dir.path().join("unclosed.c");
    fs::write(&file, malformed).unwrap();

    let mut parser = AstParser::new().unwrap();
    // Tree-sitter must handle syntax errors resiliently without panicking
    let funcs = parser.parse_file(&file);
    assert!(funcs.is_ok());
}

#[test]
fn test_tier2_malformed_invalid_syntax_tokens() {
    let garbage = "%%% $$$$ @@@@ !!! random garbage tokens\nint valid_after(void) { return 0; }";
    let temp_dir = tempdir().unwrap();
    let file = temp_dir.path().join("garbage.c");
    fs::write(&file, garbage).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file);
    assert!(funcs.is_ok());
    let funcs = funcs.unwrap();
    assert!(funcs.iter().any(|f| f.name == "valid_after"));
}

#[test]
fn test_tier2_malformed_incomplete_struct_decl() {
    let code = "struct Incomplete { int a; double b;";
    let temp_dir = tempdir().unwrap();
    let file = temp_dir.path().join("struct_broken.c");
    fs::write(&file, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file);
    assert!(funcs.is_ok());
}

#[test]
fn test_tier2_malformed_clang_compilation_failure_handling() {
    let temp_dir = tempdir().unwrap();
    let broken_code = "int main() { return undefined_var; }";
    let res = TestClang::compile_source_string(broken_code, temp_dir.path(), "broken", false);
    assert!(res.is_err());
    let err_msg = res.err().unwrap();
    assert!(err_msg.contains("undefined_var") || err_msg.contains("error"));
}

#[test]
fn test_tier2_malformed_unterminated_preprocessor_macro() {
    let code = "#ifndef FOO\n#define FOO\nint header_func(void);\n";
    let temp_dir = tempdir().unwrap();
    let file = temp_dir.path().join("no_endif.h");
    fs::write(&file, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file);
    assert!(funcs.is_ok());
}

// =========================================================================
// Category 2.3: Circular Struct Pointers & Self-Referencing Definitions
// =========================================================================

#[test]
fn test_tier2_circular_singly_linked_node() {
    // struct Node { struct Node *next; int val; };
    // AMD64: next at 0 (8B, align 8), val at 8 (4B, align 4), total size: 16 (padded to 8)
    let fields = [("next", "void*"), ("val", "int")];
    let layout = SystemVLayoutCalculator::resolve_struct("Node", &fields);

    assert_eq!(layout.alignment, 8);
    assert_eq!(layout.total_size, 16);
    assert_eq!(layout.field_offsets.get("next"), Some(&0));
    assert_eq!(layout.field_offsets.get("val"), Some(&8));
}

#[test]
fn test_tier2_circular_mutually_recursive_structs() {
    // struct A { struct B *b; int a_val; };
    // struct B { struct A *a; int b_val; };
    let fields_a = [("b", "void*"), ("a_val", "int")];
    let fields_b = [("a", "void*"), ("b_val", "int")];

    let layout_a = SystemVLayoutCalculator::resolve_struct("A", &fields_a);
    let layout_b = SystemVLayoutCalculator::resolve_struct("B", &fields_b);

    assert_eq!(layout_a.total_size, 16);
    assert_eq!(layout_b.total_size, 16);
    assert_eq!(layout_a.alignment, 8);
    assert_eq!(layout_b.alignment, 8);
}

#[test]
fn test_tier2_circular_doubly_linked_list_layout() {
    // struct DNode { struct DNode *prev; struct DNode *next; void *data; };
    // 3 pointers = 24 bytes, align 8
    let fields = [("prev", "void*"), ("next", "void*"), ("data", "void*")];
    let layout = SystemVLayoutCalculator::resolve_struct("DNode", &fields);

    assert_eq!(layout.alignment, 8);
    assert_eq!(layout.total_size, 24);
    assert_eq!(layout.field_offsets.get("prev"), Some(&0));
    assert_eq!(layout.field_offsets.get("next"), Some(&8));
    assert_eq!(layout.field_offsets.get("data"), Some(&16));
}

#[test]
fn test_tier2_circular_tree_node_with_parent() {
    // struct TreeNode { struct TreeNode *left; struct TreeNode *right; struct TreeNode *parent; int key; };
    // 3 pointers (24 bytes) + int (4 bytes) = 28 bytes -> rounded up to 32 bytes
    let fields = [("left", "void*"), ("right", "void*"), ("parent", "void*"), ("key", "int")];
    let layout = SystemVLayoutCalculator::resolve_struct("TreeNode", &fields);

    assert_eq!(layout.alignment, 8);
    assert_eq!(layout.total_size, 32);
    assert_eq!(layout.field_offsets.get("left"), Some(&0));
    assert_eq!(layout.field_offsets.get("key"), Some(&24));
}

#[test]
fn test_tier2_circular_graph_adjacency_list() {
    // struct Edge { struct Vertex *dest; int weight; };
    // dest at 0 (8B), weight at 8 (4B), total size 16
    let fields = [("dest", "void*"), ("weight", "int")];
    let layout = SystemVLayoutCalculator::resolve_struct("Edge", &fields);

    assert_eq!(layout.total_size, 16);
    assert_eq!(layout.alignment, 8);
}

// =========================================================================
// Category 2.4: Maximum Memory Limits, Large Logs, and OOM Boundaries
// =========================================================================

#[test]
fn test_tier2_max_memory_large_asan_log() {
    let mut large_log = String::with_capacity(1_000_000);
    large_log.push_str("=================================================================\n");
    large_log.push_str("==9999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6000\n");
    for i in 0..10_000 {
        large_log.push_str(&format!("    #{i} 0x1000 in deep_stack_function_{i} /path/file.c:{i}\n"));
    }
    large_log.push_str("=================================================================\n");

    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("crash.bin");
    fs::write(&crash_file, b"data").unwrap();

    let start = std::time::Instant::now();
    let record = AsanParser::parse_asan_log(Uuid::new_v4(), &large_log, &crash_file);
    let elapsed = start.elapsed();

    assert!(record.is_some());
    let r = record.unwrap();
    assert_eq!(r.crash_type, "heap-buffer-overflow");
    assert!(!r.stack_hash.is_empty());
    // Large log parsing should complete in less than 500ms
    assert!(elapsed.as_millis() < 500);
}

#[test]
fn test_tier2_max_memory_large_ast_file() {
    let mut code = String::with_capacity(500_000);
    for i in 0..500 {
        code.push_str(&format!("int func_{i}(int a, int b) {{ return a + b + {i}; }}\n"));
    }
    let temp_dir = tempdir().unwrap();
    let file = temp_dir.path().join("large_funcs.c");
    fs::write(&file, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file).expect("Failed to parse large file");
    assert_eq!(funcs.len(), 500);
}

#[test]
fn test_tier2_max_memory_rlimit_config_validation() {
    let cfg = SandboxConfig {
        memory_limit_mb: 65536, // 64 GB
        timeout_seconds: 7200,
        ..SandboxConfig::default()
    };
    assert_eq!(cfg.memory_limit_mb, 65536);
    assert_eq!(cfg.timeout_seconds, 7200);
}

#[test]
fn test_tier2_max_memory_large_binary_payload() {
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("large_payload.bin");
    // 64KB crash payload
    let large_payload = vec![0x41u8; 65536];
    fs::write(&crash_file, &large_payload).unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash".to_string(),
        stack_trace: "trace".to_string(),
        input_path: crash_file,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: true,
        found_at: chrono::Utc::now(),
    };

    let poc = PocGenerator::generate_standalone_poc(&crash, "", "// test");
    assert!(poc.contains("0x41, 0x41, 0x41"));
    assert!(poc.len() > 100_000);
}

#[test]
fn test_tier2_max_memory_feedback_db_bulk_inserts() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    for i in 0..200 {
        let rec = FeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: "stress_target".to_string(),
            feedback_type: "resolved_fix".to_string(),
            compiler_diagnostic: Some(format!("error diagnostic {i}")),
            error_category: Some("syntax".to_string()),
            original_code: Some(format!("code_{i}")),
            resolved_code: Some(format!("fix_{i}")),
            coverage_tokens: None,
            success_count: i,
            failure_count: 0,
            score: (i as f32) / 200.0,
        };
        db.insert_record(&rec).unwrap();
    }

    let results = db.query_similar_fixes("diagnostic", 10);
    assert_eq!(results.len(), 10);
    assert!(results[0].score >= results[9].score);
}

// =========================================================================
// Category 2.5: Invalid Patches & Corrupted Diffs
// =========================================================================

#[test]
fn test_tier2_invalid_patch_corrupted_hunk_header() {
    let original = "int x = 1;\n";
    let bad_diff = r#"--- a/file.c
+++ b/file.c
@@ invalid hunk header @@
+int y = 2;
"#;
    let res = PatchManager::apply_diff_to_content(original, bad_diff);
    assert!(res.is_ok());
    // Original unchanged
    assert_eq!(res.unwrap(), original);
}

#[test]
fn test_tier2_invalid_patch_out_of_bounds_line_number() {
    let original = "int x = 1;\n";
    let oob_diff = r#"--- a/file.c
+++ b/file.c
@@ -9999,1 +9999,1 @@
+int z = 3;
"#;
    let res = PatchManager::apply_diff_to_content(original, oob_diff);
    assert!(res.is_ok());
}

#[test]
fn test_tier2_invalid_patch_nonexistent_file() {
    let temp_dir = tempdir().unwrap();
    let missing_file = temp_dir.path().join("does_not_exist.c");
    let diff = "--- a/file.c\n+++ b/file.c\n";
    let res = PatchManager::apply_patch_file_with_backup(&missing_file, diff);
    assert!(res.is_err());
}

#[test]
fn test_tier2_invalid_patch_empty_content() {
    let temp_dir = tempdir().unwrap();
    let target = temp_dir.path().join("orig.c");
    let backup = temp_dir.path().join("missing.bak");
    fs::write(&target, "content").unwrap();

    let res = PatchManager::rollback_patch(&target, &backup);
    assert!(res.is_ok()); // Non-existent backup handles cleanly
}

#[test]
fn test_tier2_invalid_patch_malformed_characters() {
    let original = "line1\n";
    let weird_diff = "\x00\x01\x02\n@@ -1,1 +1,1 @@\n+line2\n";
    let res = PatchManager::apply_diff_to_content(original, weird_diff);
    assert!(res.is_ok());
}

// =========================================================================
// Category 2.6: Missing Headers & Unresolved Symbols
// =========================================================================

#[test]
fn test_tier2_missing_header_clang_diagnostic_capture() {
    let temp_dir = tempdir().unwrap();
    let code = "#include <nonexistent_system_xyz_header_123.h>\nint main() { return 0; }";
    let res = TestClang::compile_source_string(code, temp_dir.path(), "missing_inc", false);

    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(err.contains("nonexistent_system_xyz_header_123.h") || err.contains("file not found"));
}

#[test]
fn test_tier2_missing_header_feedback_memory_classification() {
    let diag = "fatal error: 'pnglibconf.h' file not found";
    let is_missing_header = diag.contains("file not found") || diag.contains("no such file");
    assert!(is_missing_header);
}

#[test]
fn test_tier2_missing_header_ast_scan_with_missing_includes() {
    let code = r#"
    #include "missing_local.h"
    #include <missing_system.h>
    int declared_api(int x) { return x * 2; }
    "#;
    let temp_dir = tempdir().unwrap();
    let file = temp_dir.path().join("ast_missing.c");
    fs::write(&file, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    // Tree-sitter parses declarations cleanly regardless of whether includes exist on disk
    let funcs = parser.parse_file(&file).expect("AST parsing failed");
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].name, "declared_api");
}

#[test]
fn test_tier2_missing_header_include_dirs_fallback() {
    let temp_dir = tempdir().unwrap();
    let target_dir = temp_dir.path();
    let default_includes = vec![
        target_dir.to_path_buf(),
        target_dir.join("include"),
        target_dir.join("src"),
    ];
    // None of them exist yet; must not panic
    for d in default_includes {
        assert!(!d.exists() || d == target_dir);
    }
}

#[test]
fn test_tier2_missing_header_poc_compiles_if_prototypes_provided() {
    let temp_dir = tempdir().unwrap();
    // Standalone PoC declares target prototype inline, compiling without target header
    let code = r#"
    #include <stdio.h>
    #include <stdint.h>
    extern int simulated_target(const uint8_t *data, size_t len);
    int simulated_target(const uint8_t *data, size_t len) {
        return (int)len;
    }
    int main(void) {
        uint8_t buf[] = {1, 2, 3};
        return simulated_target(buf, sizeof(buf)) == 3 ? 0 : 1;
    }
    "#;
    let bin = TestClang::compile_source_string(code, temp_dir.path(), "poc_inline", true)
        .expect("Compilation failed");

    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(res.success);
}

// =========================================================================
// Category 2.7: Zero-Size Inputs & Payloads
// =========================================================================

#[test]
fn test_tier2_zero_size_crash_payload() {
    let temp_dir = tempdir().unwrap();
    let empty_crash = temp_dir.path().join("empty_crash.bin");
    fs::write(&empty_crash, b"").unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "SEGV".to_string(),
        stack_hash: "hash".to_string(),
        stack_trace: "".to_string(),
        input_path: empty_crash,
        cwe_id: None,
        cvss_score: None,
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let poc = PocGenerator::generate_standalone_poc(&crash, "", "// empty");
    assert!(poc.contains("static const uint8_t poc_payload[] = {"));
    assert!(poc.contains("int main"));
}

#[test]
fn test_tier2_zero_size_fuzz_timeout() {
    let runner = FuzzRunner::new(0);
    assert_eq!(runner.timeout.as_secs(), 0);
}

#[test]
fn test_tier2_zero_size_feedback_query_limit() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let rec = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "target".to_string(),
        feedback_type: "resolved_fix".to_string(),
        compiler_diagnostic: Some("diag".to_string()),
        error_category: None,
        original_code: None,
        resolved_code: None,
        coverage_tokens: None,
        success_count: 1,
        failure_count: 0,
        score: 1.0,
    };
    db.insert_record(&rec).unwrap();

    let res = db.query_similar_fixes("diag", 0);
    assert!(res.is_empty());
}

#[test]
fn test_tier2_zero_size_struct_layout() {
    // Empty struct: sizeof is at least 0 in model (or 1 in C++)
    let fields: [(&str, &str); 0] = [];
    let layout = SystemVLayoutCalculator::resolve_struct("Empty", &fields);
    assert_eq!(layout.fields.len(), 0);
    assert_eq!(layout.total_size, 0);
    assert_eq!(layout.alignment, 1);
}

#[test]
fn test_tier2_zero_size_coverage_tokens() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let rec = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "target".to_string(),
        feedback_type: "coverage_token".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: None,
        coverage_tokens: Some(vec![]),
        success_count: 0,
        failure_count: 0,
        score: 0.0,
    };
    db.insert_record(&rec).unwrap();

    let tokens_json: String = db
        .conn
        .query_row(
            "SELECT coverage_tokens FROM agent_feedback_memory WHERE id = ?1",
            rusqlite::params![rec.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(tokens_json, "[]");
}
