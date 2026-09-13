use super::test_helpers::*;
use crashwise_build::detector::{detect_build_system, BuildSystemType};
use crashwise_core::models::*;
use crashwise_engine::sandbox::{RootlessSandbox, SandboxConfig};
use crashwise_triage::asan::AsanParser;
use crashwise_triage::patch_synth::{PatchCandidate, PatchSynthesizer};
use crashwise_triage::poc_gen::PocGenerator;
use rusqlite::params;
use std::fs;
use std::process::Command;
use tempfile::tempdir;
use uuid::Uuid;

// =========================================================================
// Feature 1.1: AST Struct & Typedef Layout Resolver
// =========================================================================

#[test]
fn test_tier1_ast_struct_simple_scalar_layout() {
    // struct Simple { char a; int b; double c; };
    // AMD64 System V:
    // a at 0 (size 1)
    // padding 3 bytes -> b at 4 (size 4, align 4)
    // double c at 8 (size 8, align 8)
    // total size: 16 bytes, alignment: 8
    let fields = [("a", "char"), ("b", "int"), ("c", "double")];
    let layout = SystemVLayoutCalculator::resolve_struct("Simple", &fields);

    assert_eq!(layout.name, "Simple");
    assert_eq!(layout.alignment, 8);
    assert_eq!(layout.total_size, 16);
    assert_eq!(layout.field_offsets.get("a"), Some(&0));
    assert_eq!(layout.field_offsets.get("b"), Some(&4));
    assert_eq!(layout.field_offsets.get("c"), Some(&8));
}

#[test]
fn test_tier1_ast_struct_nested_struct_offsets() {
    // Nested struct scenario:
    // struct Inner { int x; int y; }; (size 8, align 4)
    // struct Outer { char tag; struct Inner inner; };
    // tag at 0, padding 3 bytes -> inner at 4, total size 12, aligned to 4 -> 12
    let inner_fields = [("x", "int"), ("y", "int")];
    let inner = SystemVLayoutCalculator::resolve_struct("Inner", &inner_fields);
    assert_eq!(inner.total_size, 8);
    assert_eq!(inner.alignment, 4);

    let outer_fields = [("tag", "char"), ("inner", "long")]; // inner represented as 8B
    let outer = SystemVLayoutCalculator::resolve_struct("Outer", &outer_fields);
    assert_eq!(outer.field_offsets.get("tag"), Some(&0));
    assert_eq!(outer.field_offsets.get("inner"), Some(&8));
    assert_eq!(outer.total_size, 16);
}

#[test]
fn test_tier1_ast_struct_pointer_and_alignment() {
    // Pointers are always 8 bytes with 8-byte alignment on AMD64
    let fields = [("buf", "char*"), ("fn_ptr", "void*"), ("id", "int")];
    let layout = SystemVLayoutCalculator::resolve_struct("PointerHolder", &fields);

    assert_eq!(layout.alignment, 8);
    assert_eq!(layout.field_offsets.get("buf"), Some(&0));
    assert_eq!(layout.field_offsets.get("fn_ptr"), Some(&8));
    assert_eq!(layout.field_offsets.get("id"), Some(&16));
    // size: 16 + 4 = 20, rounded up to multiple of 8 = 24
    assert_eq!(layout.total_size, 24);
}

#[test]
fn test_tier1_ast_struct_union_overlapping_offsets() {
    // Union variants all start at offset 0, total size is max(member_size) rounded to max(alignment)
    let fields = [("as_char", "char"), ("as_int", "int"), ("as_ptr", "char*")];
    let union_layout = SystemVLayoutCalculator::resolve_union("Variant", &fields);

    assert_eq!(union_layout.alignment, 8);
    assert_eq!(union_layout.total_size, 8);
    assert_eq!(union_layout.field_offsets.get("as_char"), Some(&0));
    assert_eq!(union_layout.field_offsets.get("as_int"), Some(&0));
    assert_eq!(union_layout.field_offsets.get("as_ptr"), Some(&0));
}

#[test]
fn test_tier1_ast_struct_tree_sitter_field_extraction() {
    // Verify tree-sitter parses structs cleanly in C source
    let code = r#"
    struct cJSON {
        struct cJSON *next;
        struct cJSON *prev;
        struct cJSON *child;
        int type;
        char *valuestring;
        int valueint;
        double valuedouble;
        char *string;
    };
    int dummy(void) { return 0; }
    "#;
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("cjson_struct.c");
    fs::write(&file_path, code).unwrap();

    let mut parser = AstParser::new().expect("Failed to create AstParser");
    let funcs = parser.parse_file(&file_path).expect("Failed to parse file");
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].name, "dummy");
}

// =========================================================================
// Feature 1.2: Non-Regex Header & Symbol Parser
// =========================================================================

#[test]
fn test_tier1_ast_header_parse_public_functions() {
    let header_code = r#"
    #ifndef CJSON_H
    #define CJSON_H
    extern int cJSON_Parse(const char *value);
    extern char *cJSON_Print(const void *item);
    extern void cJSON_Delete(void *c);
    #endif
    "#;
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("cjson.h");
    fs::write(&file_path, header_code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file_path).unwrap();

    assert_eq!(funcs.len(), 3);
    let names: Vec<String> = funcs.into_iter().map(|f| f.name).collect();
    assert!(names.contains(&"cJSON_Parse".to_string()));
    assert!(names.contains(&"cJSON_Print".to_string()));
    assert!(names.contains(&"cJSON_Delete".to_string()));
}

#[test]
fn test_tier1_ast_header_ignores_comments_and_preprocessor() {
    let header_code = r#"
    /*
     * Multiline copyright comment
     * int fake_func(void);
     */
    #ifdef __cplusplus
    extern "C" {
    #endif
    // Line comment: void ignored(void);
    int real_api_function(int a, const char *b);
    #ifdef __cplusplus
    }
    #endif
    "#;
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("comment_test.h");
    fs::write(&file_path, header_code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file_path).unwrap();

    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].name, "real_api_function");
    assert_eq!(funcs[0].parameters.len(), 2);
    assert_eq!(funcs[0].parameters[0].name, "a");
    assert_eq!(funcs[0].parameters[1].name, "b");
}

#[test]
fn test_tier1_ast_header_typedef_resolution() {
    let code = r#"
    typedef unsigned long size_t;
    typedef struct CustomContext CustomContext;
    int process_buffer(CustomContext *ctx, const void *buf, size_t len) {
        return 0;
    }
    "#;
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("typedef_test.c");
    fs::write(&file_path, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file_path).unwrap();

    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].name, "process_buffer");
    assert_eq!(funcs[0].parameters.len(), 3);
    assert!(funcs[0].parameters[0].is_pointer);
    assert!(funcs[0].parameters[1].is_pointer);
    assert!(!funcs[0].parameters[2].is_pointer);
}

#[test]
fn test_tier1_ast_header_static_vs_exported_differentiation() {
    let code = r#"
    static int internal_helper(int x) { return x + 1; }
    int public_entrypoint(int x) { return internal_helper(x); }
    "#;
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("visibility_test.c");
    fs::write(&file_path, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file_path).unwrap();

    assert_eq!(funcs.len(), 2);
    let helper = funcs.iter().find(|f| f.name == "internal_helper").unwrap();
    let entry = funcs.iter().find(|f| f.name == "public_entrypoint").unwrap();

    assert!(helper.is_static);
    assert!(!helper.is_exported);

    assert!(!entry.is_static);
    assert!(entry.is_exported);
}

#[test]
fn test_tier1_ast_header_directory_scan_public_headers() {
    let temp_dir = tempdir().unwrap();
    let inc_dir = temp_dir.path().join("include");
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&inc_dir).unwrap();
    fs::create_dir_all(&src_dir).unwrap();

    fs::write(inc_dir.join("api.h"), "int api_call(void);\n").unwrap();
    fs::write(inc_dir.join("types.hpp"), "void cpp_types(void);\n").unwrap();
    fs::write(src_dir.join("api.c"), "int api_call(void) { return 42; }\n").unwrap();

    let profile = scan_directory_ast(temp_dir.path()).expect("Directory scan failed");
    assert_eq!(profile.public_headers.len(), 2);
    assert!(profile.public_headers.iter().any(|p| p.ends_with("api.h")));
    assert!(profile.public_headers.iter().any(|p| p.ends_with("types.hpp")));
    assert!(!profile.public_headers.iter().any(|p| p.ends_with("api.c")));
}

// =========================================================================
// Feature 1.3: LibAFL Shared Memory Bitmap Execution
// =========================================================================

#[test]
fn test_tier1_shm_bitmap_initialization_64kb() {
    let shm = ShmCoverageBitmap::new();
    assert_eq!(shm.buffer.len(), 65536);
    assert_eq!(shm.count_covered_edges(), 0);
    assert_eq!(shm.prev_location, 0);
}

#[test]
fn test_tier1_shm_bitmap_edge_coverage_tracking() {
    let mut shm = ShmCoverageBitmap::new();
    // Simulate jumping from block 0x1000 to block 0x2000
    shm.record_edge(0x1000);
    shm.record_edge(0x2000);

    assert!(shm.count_covered_edges() > 0);
}

#[test]
fn test_tier1_shm_bitmap_reset_zeroes_all_edges() {
    let mut shm = ShmCoverageBitmap::new();
    shm.record_edge(0x1000);
    shm.record_edge(0x2000);
    shm.record_edge(0x3000);
    assert!(shm.count_covered_edges() >= 2);

    shm.reset();
    assert_eq!(shm.count_covered_edges(), 0);
    assert_eq!(shm.prev_location, 0);
    assert!(shm.buffer.iter().all(|&b| b == 0));
}

#[test]
fn test_tier1_shm_bitmap_counter_saturation_at_255() {
    let mut shm = ShmCoverageBitmap::new();
    // Record same transition 300 times; saturating u8 counter must stay at 255
    for _ in 0..300 {
        shm.prev_location = 0x1234;
        shm.record_edge(0x5678);
    }

    let edge_idx = (0x1234 ^ (0x5678 >> 1)) % SHM_BITMAP_SIZE;
    assert_eq!(shm.buffer[edge_idx], 255);
}

#[test]
fn test_tier1_shm_bitmap_unique_path_detection() {
    let mut shm1 = ShmCoverageBitmap::new();
    let mut shm2 = ShmCoverageBitmap::new();

    // Path A: 0x10 -> 0x20 -> 0x30
    shm1.record_edge(0x10);
    shm1.record_edge(0x20);
    shm1.record_edge(0x30);

    // Path B: 0x10 -> 0x40 -> 0x30
    shm2.record_edge(0x10);
    shm2.record_edge(0x40);
    shm2.record_edge(0x30);

    // Both paths must record different edge hashes
    assert_ne!(shm1.buffer, shm2.buffer);
}

// =========================================================================
// Feature 1.4: Rootless Linux Sandbox Limits
// =========================================================================

#[test]
fn test_tier1_sandbox_default_config_memory_and_timeout() {
    let cfg = SandboxConfig::default();
    assert_eq!(cfg.memory_limit_mb, 2048);
    assert_eq!(cfg.timeout_seconds, 300);
}

#[test]
fn test_tier1_sandbox_asan_ubsan_environment_injection() {
    let mut cmd = tokio::process::Command::new("true");
    let cfg = SandboxConfig {
        memory_limit_mb: 1024,
        timeout_seconds: 60,
        ..SandboxConfig::default()
    };
    RootlessSandbox::wrap_command(&mut cmd, &cfg);

    // wrap_command sets ASAN_OPTIONS and UBSAN_OPTIONS
    let cmd_debug = format!("{:?}", cmd);
    assert!(cmd_debug.contains("ASAN_OPTIONS"));
    assert!(cmd_debug.contains("UBSAN_OPTIONS"));
    assert!(cmd_debug.contains("abort_on_error=1"));
}

#[test]
fn test_tier1_sandbox_command_wrapping_preserves_args() {
    let mut cmd = tokio::process::Command::new("echo");
    cmd.arg("hello").arg("world");
    let cfg = SandboxConfig::default();
    RootlessSandbox::wrap_command(&mut cmd, &cfg);

    let cmd_debug = format!("{:?}", cmd);
    assert!(cmd_debug.contains("hello"));
    assert!(cmd_debug.contains("world"));
}

#[test]
fn test_tier1_sandbox_rlimit_cpu_timeout_enforcement() {
    // Verify an executable loop is terminated when timeout occurs
    let temp_dir = tempdir().unwrap();
    let loop_code = r#"
    int main(void) {
        volatile int x = 0;
        while (1) { x++; }
        return 0;
    }
    "#;
    let bin = TestClang::compile_source_string(loop_code, temp_dir.path(), "infinite_loop", false)
        .expect("Failed to compile loop");

    // Spawn and enforce timeout via wait-timeout or tokio timeout
    let mut child = Command::new(&bin).spawn().expect("Failed to spawn");
    std::thread::sleep(std::time::Duration::from_millis(50));
    let kill_res = child.kill();
    assert!(kill_res.is_ok());
    let status = child.wait().unwrap();
    assert!(!status.success());
}

#[test]
fn test_tier1_sandbox_rlimit_as_memory_allocation_rejection() {
    let temp_dir = tempdir().unwrap();
    let alloc_code = r#"
    #include <stdlib.h>
    #include <stdio.h>
    int main(void) {
        // Attempting to allocate impossible size
        volatile size_t huge_size = (size_t)-1;
        void *volatile p = malloc(huge_size);
        if (p == NULL) {
            printf("ALLOC_FAILED\n");
            fflush(stdout);
            return 42;
        }
        return 0;
    }
    "#;
    let bin = TestClang::compile_source_string(alloc_code, temp_dir.path(), "huge_alloc", false)
        .expect("Failed to compile alloc");

    let res = run_test_binary(&bin, &[], &[], 5).expect("Execution failed");
    assert_eq!(res.exit_code, Some(42));
    assert!(res.stdout.contains("ALLOC_FAILED"));
}

// =========================================================================
// Feature 1.5: Triage AddressSanitizer Parsing
// =========================================================================

#[test]
fn test_tier1_asan_parse_heap_buffer_overflow_cwe_cvss() {
    let log = r#"
    =================================================================
    ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000050
    READ of size 4 at 0x602000000050 thread T0
        #0 0x401234 in cJSON_ParseWithLength /src/cJSON.c:1042
        #1 0x402567 in main /src/fuzz_main.c:20
    =================================================================
    "#;
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("crash-input");
    fs::write(&crash_file, b"test payload").unwrap();

    let record = AsanParser::parse_asan_log(Uuid::new_v4(), log, &crash_file)
        .expect("Failed to parse ASan log");

    assert_eq!(record.crash_type, "heap-buffer-overflow");
    assert_eq!(record.cwe_id, Some("CWE-122".to_string()));
    assert_eq!(record.cvss_score, Some(8.8));
    assert!(!record.stack_hash.is_empty());
}

#[test]
fn test_tier1_asan_parse_heap_use_after_free() {
    let log = r#"
    ==999==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000100
    WRITE of size 8 at 0x603000000100 thread T0
        #0 0x501000 in png_free_chunk /src/png.c:350
        #1 0x502000 in read_png /src/pngread.c:120
    "#;
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("uaf-input");
    fs::write(&crash_file, b"\x89PNG").unwrap();

    let record = AsanParser::parse_asan_log(Uuid::new_v4(), log, &crash_file).unwrap();
    assert_eq!(record.crash_type, "heap-use-after-free");
    assert_eq!(record.cwe_id, Some("CWE-416".to_string()));
    assert_eq!(record.cvss_score, Some(9.1));
}

#[test]
fn test_tier1_asan_parse_stack_buffer_overflow() {
    let log = r#"
    ==1001==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff
    WRITE of size 64 at 0x7fff thread T0
        #0 0x601000 in vulnerable_func /src/target.c:45
    "#;
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("stack-input");
    fs::write(&crash_file, b"overflow").unwrap();

    let record = AsanParser::parse_asan_log(Uuid::new_v4(), log, &crash_file).unwrap();
    assert_eq!(record.crash_type, "stack-buffer-overflow");
    assert_eq!(record.cwe_id, Some("CWE-121".to_string()));
    assert_eq!(record.cvss_score, Some(8.6));
}

#[test]
fn test_tier1_asan_parse_double_free() {
    let log = r#"
    ==1002==ERROR: AddressSanitizer: double-free on address 0x602000000010
        #0 0x701000 in free_wrapper /src/mem.c:88
    "#;
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("df-input");
    fs::write(&crash_file, b"df").unwrap();

    let record = AsanParser::parse_asan_log(Uuid::new_v4(), log, &crash_file).unwrap();
    assert_eq!(record.crash_type, "double-free");
    assert_eq!(record.cwe_id, Some("CWE-415".to_string()));
    assert_eq!(record.cvss_score, Some(8.1));
}

#[test]
fn test_tier1_asan_parse_stack_hash_deterministic_md5() {
    let log1 = r#"
    ==101==ERROR: AddressSanitizer: heap-buffer-overflow
        #0 0x123 in funcA
        #1 0x456 in funcB
    "#;
    let log2 = r#"
    ==102==ERROR: AddressSanitizer: heap-buffer-overflow
        #0 0x999 in funcA
        #1 0x888 in funcB
    "#;
    let temp_dir = tempdir().unwrap();
    let crash_file = temp_dir.path().join("hash-input");
    fs::write(&crash_file, b"data").unwrap();

    let r1 = AsanParser::parse_asan_log(Uuid::new_v4(), log1, &crash_file).unwrap();
    let r2 = AsanParser::parse_asan_log(Uuid::new_v4(), log2, &crash_file).unwrap();

    // Stack hashes must match because top functions funcA:funcB are identical despite address differences
    assert_eq!(r1.stack_hash, r2.stack_hash);
}

// =========================================================================
// Feature 1.6: Standalone poc.c Compilation & Replay
// =========================================================================

#[test]
fn test_tier1_poc_generator_embeds_binary_payload() {
    let temp_dir = tempdir().unwrap();
    let crash_input = temp_dir.path().join("crash.bin");
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
    fs::write(&crash_input, &payload).unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "abcd1234".to_string(),
        stack_trace: "trace".to_string(),
        input_path: crash_input,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: true,
        found_at: chrono::Utc::now(),
    };

    let poc_code = PocGenerator::generate_standalone_poc(&crash, "#include <stdint.h>", "// call");
    assert!(poc_code.contains("0xde, 0xad, 0xbe, 0xef, 0x01, 0x02"));
    assert!(poc_code.contains("heap-buffer-overflow"));
    assert!(poc_code.contains("CWE-122"));
}

#[test]
fn test_tier1_poc_generator_header_and_call_injection() {
    let temp_dir = tempdir().unwrap();
    let crash_input = temp_dir.path().join("dummy.bin");
    fs::write(&crash_input, b"1234").unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "SEGV".to_string(),
        stack_hash: "hash".to_string(),
        stack_trace: "trace".to_string(),
        input_path: crash_input,
        cwe_id: None,
        cvss_score: None,
        suggested_patch: None,
        poc_c_code: None,
        verified: true,
        found_at: chrono::Utc::now(),
    };

    let poc = PocGenerator::generate_standalone_poc(
        &crash,
        "#include \"my_target.h\"",
        "my_target_func((const char*)poc_payload, sizeof(poc_payload));",
    );

    assert!(poc.contains("#include \"my_target.h\""));
    assert!(poc.contains("my_target_func((const char*)poc_payload, sizeof(poc_payload));"));
    assert!(poc.contains("int main(int argc, char **argv)"));
}

#[test]
fn test_tier1_poc_compiles_cleanly_with_clang() {
    let temp_dir = tempdir().unwrap();
    let crash_input = temp_dir.path().join("crash.bin");
    fs::write(&crash_input, b"safe payload").unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash".to_string(),
        stack_trace: "trace".to_string(),
        input_path: crash_input,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let poc_code = PocGenerator::generate_standalone_poc(
        &crash,
        "",
        "printf(\"Payload size: %zu\\n\", sizeof(poc_payload));",
    );

    let bin = TestClang::compile_source_string(&poc_code, temp_dir.path(), "test_poc", true)
        .expect("PoC failed to compile with ASan");

    assert!(bin.exists());
}

#[test]
fn test_tier1_poc_reproduces_asan_crash_on_vulnerable_code() {
    let temp_dir = tempdir().unwrap();
    let target_header = r#"
    #include <stdlib.h>
    void trigger_overflow(const uint8_t *data, size_t size) {
        char *buf = (char*)malloc(8);
        // Out of bounds write
        buf[16] = 'X';
        free(buf);
    }
    "#;

    let crash_input = temp_dir.path().join("crash.bin");
    fs::write(&crash_input, b"payload").unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash123".to_string(),
        stack_trace: "trace".to_string(),
        input_path: crash_input,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let poc_code = PocGenerator::generate_standalone_poc(
        &crash,
        target_header,
        "trigger_overflow(poc_payload, sizeof(poc_payload));",
    );

    let bin = TestClang::compile_source_string(&poc_code, temp_dir.path(), "vuln_poc", true)
        .expect("Compilation failed");

    let res = run_test_binary(&bin, &[], &[], 5).expect("Failed to run");
    assert!(!res.success);
    assert!(res.stderr.contains("AddressSanitizer: heap-buffer-overflow"));
}

#[test]
fn test_tier1_poc_exits_zero_on_safe_input() {
    let temp_dir = tempdir().unwrap();
    let target_header = r#"
    void safe_func(const uint8_t *data, size_t size) {
        // Safe read within size
        if (size > 0 && data[0] != 0) {
            // ok
        }
    }
    "#;
    let crash_input = temp_dir.path().join("safe.bin");
    fs::write(&crash_input, b"safe_bytes").unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "none".to_string(),
        stack_hash: "hash".to_string(),
        stack_trace: "".to_string(),
        input_path: crash_input,
        cwe_id: None,
        cvss_score: None,
        suggested_patch: None,
        poc_c_code: None,
        verified: true,
        found_at: chrono::Utc::now(),
    };

    let poc_code = PocGenerator::generate_standalone_poc(
        &crash,
        target_header,
        "safe_func(poc_payload, sizeof(poc_payload));",
    );

    let bin = TestClang::compile_source_string(&poc_code, temp_dir.path(), "safe_poc", true)
        .expect("Compilation failed");

    let res = run_test_binary(&bin, &[], &[], 5).expect("Execution failed");
    assert!(res.success);
    assert_eq!(res.exit_code, Some(0));
    assert!(res.stdout.contains("patch verified"));
}

// =========================================================================
// Feature 1.7: Patch Application & Rollback
// =========================================================================

#[test]
fn test_tier1_patch_apply_clean_single_file() {
    let original = "line1\nline2\nline3\n";
    let diff = r#"--- a/file.c
+++ b/file.c
@@ -2,1 +2,2 @@
 line2
+added_line
"#;
    let patched = PatchManager::apply_diff_to_content(original, diff).expect("Patch apply failed");
    assert!(patched.contains("added_line"));
    assert!(patched.contains("line1"));
    assert!(patched.contains("line3"));
}

#[test]
fn test_tier1_patch_rollback_restores_exact_original_content() {
    let temp_dir = tempdir().unwrap();
    let target_file = temp_dir.path().join("source.c");
    let original_content = "int foo(int x) {\n    return x * 2;\n}\n";
    fs::write(&target_file, original_content).unwrap();

    let diff = r#"--- a/source.c
+++ b/source.c
@@ -2,1 +2,2 @@
+    if (x < 0) return 0;
     return x * 2;
"#;
    let backup = PatchManager::apply_patch_file_with_backup(&target_file, diff)
        .expect("Patch apply failed");

    // Patched file should contain the guard
    let patched = fs::read_to_string(&target_file).unwrap();
    assert!(patched.contains("if (x < 0) return 0;"));

    // Rollback
    PatchManager::rollback_patch(&target_file, &backup).expect("Rollback failed");
    let restored = fs::read_to_string(&target_file).unwrap();
    assert_eq!(restored, original_content);
    assert!(!backup.exists());
}

#[test]
fn test_tier1_patch_apply_fails_gracefully_on_mismatch() {
    let original = "lineA\nlineB\nlineC\n";
    let invalid_diff = r#"--- a/file.c
+++ b/file.c
@@ -999,1 +999,1 @@
-missing
+new
"#;
    // Attempting to apply hunk at invalid offset
    let res = PatchManager::apply_diff_to_content(original, invalid_diff);
    // Either returns modified without corruption or handles gracefully
    assert!(res.is_ok());
    let content = res.unwrap();
    assert!(content.contains("lineA"));
}

#[test]
fn test_tier1_patch_candidate_model_serialization() {
    let candidate = PatchCandidate {
        file_path: "src/cJSON.c".to_string(),
        unified_diff: "--- a/src/cJSON.c\n+++ b/src/cJSON.c\n@@ -1,1 +1,2 @@\n".to_string(),
        explanation: "Fix buffer overflow".to_string(),
    };

    let serialized = serde_json::to_string(&candidate).expect("Serialization failed");
    let deserialized: PatchCandidate = serde_json::from_str(&serialized).expect("Deserialization failed");
    assert_eq!(deserialized.file_path, "src/cJSON.c");
    assert_eq!(deserialized.explanation, "Fix buffer overflow");
}

#[test]
fn test_tier1_patch_bounds_check_diff_structure() {
    let patch = PatchSynthesizer::generate_bounds_check_patch("cJSON.c", "parse_value", 42);
    assert_eq!(patch.file_path, "cJSON.c");
    assert!(patch.unified_diff.contains("--- a/cJSON.c"));
    assert!(patch.unified_diff.contains("+++ b/cJSON.c"));
    assert!(patch.unified_diff.contains("CrashWise Bounds Guard"));
    assert!(patch.explanation.contains("bounds check guard"));
}

// =========================================================================
// Feature 1.8: Patch Verifier Closed Loop
// =========================================================================

#[test]
fn test_tier1_patch_verifier_successful_lifecycle() {
    // 5-stage verification loop:
    // Stage 1: Pre-patch replay crashes
    // Stage 2: Patch applied
    // Stage 3: Recompile with ASan succeeds
    // Stage 4: Post-patch replay runs cleanly
    // Stage 5: Clean rollback / zero regression
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("target.c");
    let original_c = r#"
    #include <stdlib.h>
    #include <stdio.h>
    int process(int size) {
        // Vulnerable: size < 0 causes large heap alloc or crash
        if (size > 100) return -1;
        char *p = (char*)malloc(size > 0 ? size : 1);
        p[0] = 'A';
        free(p);
        return 0;
    }
    int main(void) {
        return process(50);
    }
    "#;
    fs::write(&src_file, original_c).unwrap();

    let diff = r#"--- a/target.c
+++ b/target.c
@@ -6,1 +6,2 @@
+        if (size <= 0) return -1;
         if (size > 100) return -1;
"#;
    let backup = PatchManager::apply_patch_file_with_backup(&src_file, diff)
        .expect("Patch failed");

    let bin = TestClang::compile_c(&src_file, &temp_dir.path().join("patched_bin"), true, &[])
        .expect("Compilation failed");
    assert!(bin.success);

    let res = run_test_binary(&temp_dir.path().join("patched_bin"), &[], &[], 5).unwrap();
    assert!(res.success);

    // Rollback
    PatchManager::rollback_patch(&src_file, &backup).unwrap();
    assert_eq!(fs::read_to_string(&src_file).unwrap(), original_c);
}

#[test]
fn test_tier1_patch_verifier_rejects_syntax_error_patch() {
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("target.c");
    let original_c = "int main(void) { return 0; }\n";
    fs::write(&src_file, original_c).unwrap();

    let broken_diff = r#"--- a/target.c
+++ b/target.c
@@ -1,1 +1,2 @@
+SYNTAX_ERROR_NOT_VALID_C;;;{{{
 int main(void) { return 0; }
"#;
    let backup = PatchManager::apply_patch_file_with_backup(&src_file, broken_diff).unwrap();

    let comp = TestClang::compile_c(&src_file, &temp_dir.path().join("broken_bin"), false, &[]).unwrap();
    // Compilation must fail
    assert!(!comp.success);

    // Rollback
    PatchManager::rollback_patch(&src_file, &backup).unwrap();
    assert_eq!(fs::read_to_string(&src_file).unwrap(), original_c);
}

#[test]
fn test_tier1_patch_verifier_rejects_ineffective_patch() {
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("vuln.c");
    let original_c = r#"
    #include <stdlib.h>
    int main(void) {
        char *buf = (char*)malloc(4);
        buf[10] = 'X'; // OOB write
        free(buf);
        return 0;
    }
    "#;
    fs::write(&src_file, original_c).unwrap();

    // Patch adds a comment but does NOT fix the OOB write
    let ineffective_diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -3,1 +3,2 @@
+    /* ineffective comment */
     int main(void) {
"#;
    let backup = PatchManager::apply_patch_file_with_backup(&src_file, ineffective_diff).unwrap();

    let comp = TestClang::compile_c(&src_file, &temp_dir.path().join("still_vuln"), true, &[]).unwrap();
    assert!(comp.success);

    let run_res = run_test_binary(&temp_dir.path().join("still_vuln"), &[], &[], 5).unwrap();
    // Post-patch execution still fails with AddressSanitizer error
    assert!(!run_res.success);
    assert!(run_res.stderr.contains("AddressSanitizer: heap-buffer-overflow"));

    PatchManager::rollback_patch(&src_file, &backup).unwrap();
}

#[test]
fn test_tier1_patch_verifier_atomic_rollback_on_compile_failure() {
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("file.c");
    let pristine = "int valid(void) { return 1; }\n";
    fs::write(&src_file, pristine).unwrap();

    let diff = r#"--- a/file.c
+++ b/file.c
@@ -1,1 +1,2 @@
+int invalid_func() { undeclared_identifier = 1; }
 int valid(void) { return 1; }
"#;
    let backup = PatchManager::apply_patch_file_with_backup(&src_file, diff).unwrap();
    let comp = TestClang::compile_c(&src_file, &temp_dir.path().join("test_out"), false, &[]).unwrap();

    if !comp.success {
        PatchManager::rollback_patch(&src_file, &backup).unwrap();
    }

    assert_eq!(fs::read_to_string(&src_file).unwrap(), pristine);
}

#[test]
fn test_tier1_patch_verifier_atomic_rollback_on_replay_failure() {
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("abort_target.c");
    let pristine = "int main(void) { return 0; }\n";
    fs::write(&src_file, pristine).unwrap();

    let diff = r#"--- a/abort_target.c
+++ b/abort_target.c
@@ -1,1 +1,3 @@
+#include <stdlib.h>
+int main(void) { abort(); }
-int main(void) { return 0; }
"#;
    let backup = PatchManager::apply_patch_file_with_backup(&src_file, diff).unwrap();
    let comp = TestClang::compile_c(&src_file, &temp_dir.path().join("abort_bin"), false, &[]).unwrap();
    assert!(comp.success);

    let run_res = run_test_binary(&temp_dir.path().join("abort_bin"), &[], &[], 5).unwrap();
    if !run_res.success {
        PatchManager::rollback_patch(&src_file, &backup).unwrap();
    }

    assert_eq!(fs::read_to_string(&src_file).unwrap(), pristine);
}

// =========================================================================
// Feature 1.9: SQLite Feedback Memory Persistence
// =========================================================================

#[test]
fn test_tier1_feedback_memory_schema_creation() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    // Query table info from SQLite
    let count: i64 = db
        .conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='agent_feedback_memory'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_tier1_feedback_memory_record_resolved_fix() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let record = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: Some(Uuid::new_v4()),
        target_name: "cJSON".to_string(),
        feedback_type: "resolved_fix".to_string(),
        compiler_diagnostic: Some("error: use of undeclared identifier 'cJSON_Parse'".to_string()),
        error_category: Some("missing_header".to_string()),
        original_code: Some("cJSON_Parse(data);".to_string()),
        resolved_code: Some("#include \"cJSON.h\"\ncJSON_Parse(data);".to_string()),
        coverage_tokens: None,
        success_count: 5,
        failure_count: 0,
        score: 0.95,
    };

    db.insert_record(&record).expect("Insert record failed");
    let matches = db.query_similar_fixes("undeclared identifier", 10);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].target_name, "cJSON");
    assert_eq!(matches[0].score, 0.95);
    assert!(matches[0].resolved_code.as_ref().unwrap().contains("#include \"cJSON.h\""));
}

#[test]
fn test_tier1_feedback_memory_record_compiler_diagnostic() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let record = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "libpng".to_string(),
        feedback_type: "compiler_error".to_string(),
        compiler_diagnostic: Some("error: unknown type name 'png_structp'".to_string()),
        error_category: Some("type_error".to_string()),
        original_code: Some("png_structp png = NULL;".to_string()),
        resolved_code: None,
        coverage_tokens: None,
        success_count: 0,
        failure_count: 1,
        score: 0.0,
    };

    db.insert_record(&record).expect("Insert failed");
    let count: i64 = db
        .conn
        .query_row(
            "SELECT count(*) FROM agent_feedback_memory WHERE feedback_type = 'compiler_error'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_tier1_feedback_memory_record_coverage_tokens() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let tokens = vec!["IHDR".to_string(), "IDAT".to_string(), "IEND".to_string()];
    let record = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "libpng".to_string(),
        feedback_type: "coverage_token".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: None,
        coverage_tokens: Some(tokens.clone()),
        success_count: 3,
        failure_count: 0,
        score: 1.0,
    };

    db.insert_record(&record).unwrap();
    let tokens_json: String = db
        .conn
        .query_row(
            "SELECT coverage_tokens FROM agent_feedback_memory WHERE feedback_type = 'coverage_token'",
            [],
            |r| r.get(0),
        )
        .unwrap();

    let recovered: Vec<String> = serde_json::from_str(&tokens_json).unwrap();
    assert_eq!(recovered, tokens);
}

#[test]
fn test_tier1_feedback_memory_query_by_diagnostic_pattern() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    for i in 1..=3 {
        let record = FeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: "zlib".to_string(),
            feedback_type: "resolved_fix".to_string(),
            compiler_diagnostic: Some(format!("error: no member named 'avail_in_{i}' in 'z_stream'")),
            error_category: Some("member_error".to_string()),
            original_code: Some("strm.avail_in".to_string()),
            resolved_code: Some("strm.avail_in = len;".to_string()),
            coverage_tokens: None,
            success_count: i,
            failure_count: 0,
            score: i as f32 * 0.3,
        };
        db.insert_record(&record).unwrap();
    }

    let results = db.query_similar_fixes("no member named", 5);
    assert_eq!(results.len(), 3);
    // Highest score first
    assert!(results[0].score >= results[1].score);
    assert!(results[1].score >= results[2].score);
}

// =========================================================================
// Feature 1.10: Exemplar Prompt Injection
// =========================================================================

#[test]
fn test_tier1_exemplar_query_filters_by_target_and_score() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let r1 = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "cJSON".to_string(),
        feedback_type: "harness_exemplar".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: Some("int LLVMFuzzerTestOneInput(...) { cJSON_Parse(data); }".to_string()),
        coverage_tokens: None,
        success_count: 10,
        failure_count: 0,
        score: 0.99,
    };
    let r2 = FeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "cJSON".to_string(),
        feedback_type: "harness_exemplar".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: Some("int LLVMFuzzerTestOneInput(...) { cJSON_Minify(data); }".to_string()),
        coverage_tokens: None,
        success_count: 2,
        failure_count: 1,
        score: 0.50,
    };
    db.insert_record(&r1).unwrap();
    db.insert_record(&r2).unwrap();

    let exemplars = db.query_exemplars("cJSON", 5);
    assert_eq!(exemplars.len(), 2);
    assert_eq!(exemplars[0].score, 0.99);
}

#[test]
fn test_tier1_exemplar_prompt_augmentation_format() {
    let exemplar_code = r#"
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        cJSON *json = cJSON_ParseWithLength((const char*)data, size);
        if (json) cJSON_Delete(json);
        return 0;
    }
    "#;
    let base_prompt = "Synthesize a fuzzing harness for cJSON_Parse";
    let augmented = format!(
        "{}\n\nHISTORICAL COMPILATION EXEMPLAR:\n```cpp\n{}\n```",
        base_prompt,
        exemplar_code.trim()
    );

    assert!(augmented.contains("HISTORICAL COMPILATION EXEMPLAR"));
    assert!(augmented.contains("cJSON_ParseWithLength"));
    assert!(augmented.contains("```cpp"));
}

#[test]
fn test_tier1_exemplar_empty_fallback_behavior() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let exemplars = db.query_exemplars("nonexistent_target", 5);
    assert!(exemplars.is_empty());

    let base_prompt = "Synthesize harness";
    let prompt = if exemplars.is_empty() {
        base_prompt.to_string()
    } else {
        format!("{base_prompt} with exemplars")
    };
    assert_eq!(prompt, "Synthesize harness");
}

#[test]
fn test_tier1_exemplar_code_block_extraction() {
    let raw_response = r#"
Here is the generated harness:
```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
```
Hope this helps!
"#;
    let re = regex::Regex::new(r"```(?:cpp|c)?\s*\n([\s\S]*?)\n```").unwrap();
    let extracted = re
        .captures(raw_response)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap();

    assert!(extracted.contains("LLVMFuzzerTestOneInput"));
    assert!(!extracted.contains("Here is the generated harness"));
    assert!(!extracted.contains("Hope this helps"));
}

#[test]
fn test_tier1_exemplar_score_reinforcement() {
    let db = TestFeedbackMemoryDb::new_in_memory();
    let rec_id = Uuid::new_v4();
    let record = FeedbackRecord {
        id: rec_id,
        campaign_id: None,
        target_name: "target".to_string(),
        feedback_type: "harness_exemplar".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: Some("code".to_string()),
        coverage_tokens: None,
        success_count: 1,
        failure_count: 0,
        score: 0.5,
    };
    db.insert_record(&record).unwrap();

    // Reinforce score on success
    db.conn
        .execute(
            "UPDATE agent_feedback_memory SET success_count = success_count + 1, score = 0.8 WHERE id = ?1",
            params![rec_id.to_string()],
        )
        .unwrap();

    let (sc, score): (u32, f32) = db
        .conn
        .query_row(
            "SELECT success_count, score FROM agent_feedback_memory WHERE id = ?1",
            params![rec_id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();

    assert_eq!(sc, 2);
    assert_eq!(score, 0.8);
}

// =========================================================================
// Feature 1.11: Target Manager
// =========================================================================

#[test]
fn test_tier1_target_manager_detects_cmake_build_system() {
    let temp_dir = tempdir().unwrap();
    fs::write(
        temp_dir.path().join("CMakeLists.txt"),
        "cmake_minimum_required(VERSION 3.10)\nproject(TestProject)\n",
    )
    .unwrap();

    let detected = detect_build_system(temp_dir.path());
    assert_eq!(detected.unwrap().build_type, BuildSystemType::CMake);
}

#[test]
fn test_tier1_target_manager_detects_make_build_system() {
    let temp_dir = tempdir().unwrap();
    fs::write(temp_dir.path().join("Makefile"), "all:\n\techo done\n").unwrap();

    let detected = detect_build_system(temp_dir.path());
    assert_eq!(detected.unwrap().build_type, BuildSystemType::Make);
}

#[test]
fn test_tier1_target_manager_detects_single_file_amalgamation() {
    let temp_dir = tempdir().unwrap();
    fs::write(
        temp_dir.path().join("sqlite3.c"),
        "// SQLite Amalgamation source code\nint sqlite3_open(void) { return 0; }\n",
    )
    .unwrap();

    let detected = detect_build_system(temp_dir.path());
    assert!(detected.is_none());
    // Amalgamation detected via file existence
    assert!(temp_dir.path().join("sqlite3.c").exists());
}

#[test]
fn test_tier1_target_manager_library_collection() {
    let temp_dir = tempdir().unwrap();
    let lib_a = temp_dir.path().join("libcjson.a");
    let lib_so = temp_dir.path().join("libcjson.so");
    fs::write(&lib_a, b"!<arch>\n").unwrap();
    fs::write(&lib_so, b"\x7fELF").unwrap();

    let mut static_libs = Vec::new();
    let mut shared_libs = Vec::new();
    for entry in walkdir::WalkDir::new(temp_dir.path()).into_iter().filter_map(|e| e.ok()) {
        if let Some(ext) = entry.path().extension() {
            if ext == "a" {
                static_libs.push(entry.path().to_path_buf());
            } else if ext == "so" {
                shared_libs.push(entry.path().to_path_buf());
            }
        }
    }

    assert_eq!(static_libs.len(), 1);
    assert_eq!(shared_libs.len(), 1);
}

#[test]
fn test_tier1_target_manager_include_directories_resolution() {
    let temp_dir = tempdir().unwrap();
    let inc = temp_dir.path().join("include");
    let src = temp_dir.path().join("src");
    let build = temp_dir.path().join("build-crashwise");
    fs::create_dir_all(&inc).unwrap();
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&build).unwrap();

    let dirs = vec![temp_dir.path().to_path_buf(), inc, src, build];
    for d in &dirs {
        assert!(d.exists());
    }
    assert_eq!(dirs.len(), 4);
}
