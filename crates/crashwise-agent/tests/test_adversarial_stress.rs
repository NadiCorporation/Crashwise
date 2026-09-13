use chrono::Utc;
use crashwise_agent::{ExemplarRetriever, HarnessSynthesizer, MockLlmClient};
use crashwise_ast::types::{FunctionSignature, ParameterInfo};
use crashwise_core::db::Database;
use crashwise_core::models::AgentFeedbackRecord;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;
use uuid::Uuid;

fn sample_signature(name: &str, ret: &str, params: Vec<ParameterInfo>, file: &str) -> FunctionSignature {
    FunctionSignature {
        name: name.to_string(),
        return_type: ret.to_string(),
        parameters: params,
        file_path: PathBuf::from(file),
        line_number: 42,
        is_static: false,
        is_exported: true,
        has_body: true,
    }
}

// ---------------------------------------------------------------------------
// 1. ExemplarRetriever: Empty Database Stress
// ---------------------------------------------------------------------------

#[test]
fn test_empty_database_retrieval_and_formatting() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Retrieve from completely empty DB
    let exemplars = ExemplarRetriever::retrieve_exemplars(&db, None, 10).unwrap();
    assert!(exemplars.is_empty());

    let exemplars_target = ExemplarRetriever::retrieve_exemplars(&db, Some("cJSON"), 10).unwrap();
    assert!(exemplars_target.is_empty());

    let tokens = ExemplarRetriever::retrieve_coverage_tokens(&db, None, 10).unwrap();
    assert!(tokens.is_empty());

    let tokens_target = ExemplarRetriever::retrieve_coverage_tokens(&db, Some("zlib"), 10).unwrap();
    assert!(tokens_target.is_empty());

    let fixes = ExemplarRetriever::retrieve_similar_fixes(&db, "error: header not found", None, 5).unwrap();
    assert!(fixes.is_empty());

    // Formatting empty collections must yield empty string without panicking
    assert_eq!(ExemplarRetriever::format_exemplars_section(&[]), "");
    assert_eq!(ExemplarRetriever::format_coverage_tokens_section(&[]), "");
    assert_eq!(ExemplarRetriever::format_compiler_fixes_section(&[]), "");

    // Augmented user prompt with empty feedback memory should return base prompt untouched
    let base = "Synthesize harness for foo()";
    let augmented = ExemplarRetriever::build_augmented_user_prompt(base, &[], &[]);
    assert_eq!(augmented, base);

    // Compiler retry prompt with empty fixes should format diagnostic and failing code cleanly
    let retry = ExemplarRetriever::build_compiler_retry_prompt("error: syntax", "int foo;", &[]);
    assert!(retry.contains("Previous harness failed to compile with clang++:"));
    assert!(retry.contains("error: syntax"));
    assert!(retry.contains("int foo;"));
    assert!(!retry.contains("### HISTORICAL RESOLUTIONS"));
}

// ---------------------------------------------------------------------------
// 2. ExemplarRetriever: Malformed and Extreme Diagnostics Stress
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_and_extreme_diagnostic_stress() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Case A: Empty string and whitespace-only
    assert_eq!(ExemplarRetriever::extract_diagnostic_summary(""), "");
    assert_eq!(ExemplarRetriever::extract_diagnostic_summary("   \n\t  \n  "), "");
    assert_eq!(ExemplarRetriever::classify_error(""), "compiler_error");
    assert_eq!(ExemplarRetriever::classify_error("   \n\t  "), "compiler_error");

    // Case B: Unicode, non-ASCII, emojis, ANSI escape sequences
    let unicode_diag = "\x1b[31;1mfatal error:\x1b[0m '🦀💥_unicode_헤더_مرحبا.h' file not found\n\
                        \x1b[32mnote:\x1b[0m in expansion of macro 'FOO_ÜBER_ÄÖÜ'\n\
                        undefined reference to `символ_привет`";
    let summary = ExemplarRetriever::extract_diagnostic_summary(unicode_diag);
    assert!(summary.contains("fatal error:"));
    assert!(summary.contains("🦀💥_unicode_헤더_مرحبا.h"));
    assert!(summary.contains("undefined reference"));

    let cat_unicode = ExemplarRetriever::classify_error(unicode_diag);
    assert_eq!(cat_unicode, "missing_header");

    // Query similar fixes with unicode diagnostic against DB
    let similar = ExemplarRetriever::retrieve_similar_fixes(&db, unicode_diag, Some("cJSON"), 5).unwrap();
    assert!(similar.is_empty());

    // Case C: Extreme diagnostic length (20,000 lines, ~2 MB of compiler vomit)
    let mut huge_diag = String::with_capacity(2 * 1024 * 1024);
    for i in 0..10_000 {
        huge_diag.push_str(&format!("/usr/include/c++/11/bits/stl_vector.h:{}: note: in expansion of template struct std::vector<Type{}>\n", i, i));
        if i % 500 == 0 {
            huge_diag.push_str(&format!("/tmp/harness.cpp:{}: error: no matching function for call to 'target_api_{}'\n", i, i));
        }
    }
    huge_diag.push_str("/tmp/harness.cpp:9999: fatal error: too many errors emitted, stopping now [-ferror-limit=]\n");

    let huge_summary = ExemplarRetriever::extract_diagnostic_summary(&huge_diag);
    assert!(!huge_summary.is_empty());
    assert!(huge_summary.contains("fatal error: too many errors emitted"));
    assert!(huge_summary.contains("no matching function for call to 'target_api_0'"));

    let retry_prompt = ExemplarRetriever::build_compiler_retry_prompt(&huge_diag, "int x = 0;", &[]);
    assert!(retry_prompt.contains("int x = 0;"));
    assert!(retry_prompt.contains("fatal error: too many errors emitted"));

    // Case D: Stored fixes with missing optional fields in format_compiler_fixes_section
    let incomplete_fix = AgentFeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "test".to_string(),
        feedback_type: "resolved_fix".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: None,
        coverage_tokens: None,
        success_count: 1,
        failure_count: 0,
        score: 1.0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let formatted = ExemplarRetriever::format_compiler_fixes_section(&[incomplete_fix]);
    assert!(formatted.contains("Resolution #1 [Category: compiler_error] (Target: test)"));
}

// ---------------------------------------------------------------------------
// 3. ExemplarRetriever: High-Volume Scaling and Limit Enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_large_numbers_of_exemplars_and_tokens_limits() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Insert 50 exemplars for cJSON and 50 for zlib
    for i in 0..50 {
        let rec = AgentFeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: if i % 2 == 0 { "cJSON".to_string() } else { "zlib".to_string() },
            feedback_type: "harness_exemplar".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: Some(format!("extern \"C\" int LLVMFuzzerTestOneInput(...) {{ return {}; }}", i)),
            coverage_tokens: None,
            success_count: i + 1,
            failure_count: 0,
            score: (i as f32) / 50.0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_feedback_record(&rec).unwrap();
    }

    // Insert 100 coverage tokens
    let mut tokens_cjson = Vec::new();
    let mut tokens_zlib = Vec::new();
    for i in 0..50 {
        tokens_cjson.push(format!("cJSON_Token_{}", i));
        tokens_zlib.push(format!("zlib_token_{}", i));
    }
    db.record_coverage_tokens(None, "cJSON", &tokens_cjson).unwrap();
    db.record_coverage_tokens(None, "zlib", &tokens_zlib).unwrap();

    // Verify limit enforcement on exemplars: limit = 1, 5, 25
    for requested_limit in [1, 5, 25] {
        let hits = ExemplarRetriever::retrieve_exemplars(&db, Some("cJSON"), requested_limit).unwrap();
        assert_eq!(hits.len(), requested_limit);
        // All hits must be target matches when available
        assert_eq!(hits[0].target_name, "cJSON");
    }

    // Verify limit enforcement on coverage tokens: limit = 3, 15, 30
    for requested_limit in [3, 15, 30] {
        let tokens = ExemplarRetriever::retrieve_coverage_tokens(&db, Some("cJSON"), requested_limit).unwrap();
        assert_eq!(tokens.len(), requested_limit);
        assert!(tokens[0].starts_with("cJSON_Token_"));
    }

    // Format section with 20 exemplars
    let retrieved_exemplars = ExemplarRetriever::retrieve_exemplars(&db, Some("cJSON"), 20).unwrap();
    let formatted_section = ExemplarRetriever::format_exemplars_section(&retrieved_exemplars);
    assert!(formatted_section.contains("Exemplar #20"));
    assert!(formatted_section.contains("Exemplar #1"));

    // Verify limit = 0 does not panic
    let zero_exemplars = ExemplarRetriever::retrieve_exemplars(&db, Some("cJSON"), 0).unwrap();
    assert_eq!(zero_exemplars.len(), 0);
}

// ---------------------------------------------------------------------------
// 4. Compiler Error Cascading: Multi-step Error Cascade to Success
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_compiler_error_cascade_three_retries_to_success() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();
    let db = Database::open_in_memory().expect("Failed to open DB");

    let campaign_id = Uuid::new_v4();
    let target = crashwise_core::models::CampaignTarget {
        repo_url: "local".to_string(),
        name: "cJSON".to_string(),
        subdir: None,
        clone_depth: 1,
        commit_hash: None,
    };
    let mut campaign = crashwise_core::models::Campaign::new(
        target,
        crashwise_core::models::FuzzerEngine::Libfuzzer,
        60,
        1,
    );
    campaign.id = campaign_id;
    db.insert_campaign(&campaign).unwrap();

    // Attempt 1: Syntax error (missing semicolon)
    let attempt1_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int unclosed_syntax_error = 42
    return 0;
}
```"#;

    // Attempt 2: Missing function / undeclared identifier
    let attempt2_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    undeclared_target_function_xyz(data, size);
    return 0;
}
```"#;

    // Attempt 3: Valid libFuzzer harness
    let attempt3_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return 0;
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        attempt1_code.to_string(),
        attempt2_code.to_string(),
        attempt3_code.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_db(db.clone())
        .with_target_name("cJSON")
        .with_campaign_id(campaign_id)
        .with_max_retries(3);

    let func = sample_signature("cJSON_TestCascade", "void", vec![], "cJSON.c");

    let bin = synth
        .synthesize_and_validate(&func, &[], &[], output_dir)
        .await
        .expect("Synthesis should succeed on Attempt 3 after 2 cascading compiler failures");

    assert!(bin.exists());

    // Verify LLM prompt progression across the 3 attempts
    let prompts = mock_llm.recorded_prompts();
    assert_eq!(prompts.len(), 3);

    // Prompt 1: Initial synthesis prompt
    assert!(prompts[0].1.contains("Function Name: cJSON_TestCascade"));

    // Prompt 2: First retry prompt incorporates attempt 1 compiler error
    assert!(prompts[1].1.contains("Previous harness failed to compile with clang++:"));
    assert!(prompts[1].1.contains("unclosed_syntax_error"));

    // Prompt 3: Second retry prompt incorporates attempt 2 compiler error
    assert!(prompts[2].1.contains("Previous harness failed to compile with clang++:"));
    assert!(prompts[2].1.contains("undeclared_target_function_xyz"));

    // Verify SQLite persistence:
    // The resolved fix must record the transition from Attempt 2 (the immediate failing predecessor) to Attempt 3!
    let fixes = db
        .query_similar_compiler_fixes("undeclared_target_function_xyz", Some("cJSON"), 5)
        .unwrap();
    assert_eq!(fixes.len(), 1);
    let fix = &fixes[0];
    assert_eq!(fix.target_name, "cJSON");
    assert_eq!(fix.feedback_type, "resolved_fix");
    assert!(fix.original_code.as_ref().unwrap().contains("undeclared_target_function_xyz"));
    assert!(fix.resolved_code.as_ref().unwrap().contains("if (size == 0) return 0;"));

    // Verified harness must be stored as exemplar
    let exemplars = db.query_harness_exemplars(Some("cJSON"), 5).unwrap();
    assert_eq!(exemplars.len(), 1);
    assert_eq!(exemplars[0].feedback_type, "harness_exemplar");
}

// ---------------------------------------------------------------------------
// 5. Retry Limits and Exhaustion Handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_retry_limits_strict_exhaustion() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();
    let db = Database::open_in_memory().expect("Failed to open DB");

    let bad_code = r#"```cpp
extern "C" int LLVMFuzzerTestOneInput() {
    non_existent_symbol();
}
```"#;

    // Test with max_retries = 1
    let mock_llm_1 = Arc::new(MockLlmClient::new(vec![bad_code.to_string()]));
    let synth_1 = HarnessSynthesizer::from_provider(mock_llm_1.clone())
        .with_db(db.clone())
        .with_max_retries(1);

    let func = sample_signature("test_exhaust_1", "void", vec![], "test.c");
    let res_1 = synth_1.synthesize_and_validate(&func, &[], &[], output_dir).await;
    assert!(res_1.is_err());
    assert_eq!(mock_llm_1.recorded_prompts().len(), 1);

    // Test with max_retries = 0 (empty loop)
    let mock_llm_0 = Arc::new(MockLlmClient::new(vec![]));
    let synth_0 = HarnessSynthesizer::from_provider(mock_llm_0.clone())
        .with_db(db.clone())
        .with_max_retries(0);

    let res_0 = synth_0.synthesize_and_validate(&func, &[], &[], output_dir).await;
    assert!(res_0.is_err());
    assert_eq!(mock_llm_0.recorded_prompts().len(), 0);

    // Verify no spurious records were saved to SQLite
    let exemplars = db.query_harness_exemplars(None, 10).unwrap();
    assert!(exemplars.is_empty());
    let fixes = db.query_similar_compiler_fixes("non_existent_symbol", None, 10).unwrap();
    assert!(fixes.is_empty());
}

// ---------------------------------------------------------------------------
// 6. Multithreaded Concurrency: SQLite Lock & Contention Stress
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multithreaded_concurrent_synthesis_no_deadlock() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Spawn 8 parallel synthesis tasks sharing the same Database
    let mut handles = Vec::new();

    for task_id in 0..8 {
        let db_clone = db.clone();
        let handle = tokio::spawn(async move {
            let temp_dir = tempdir().expect("Failed to create tempdir");
            let output_dir = temp_dir.path();

            let attempt1 = format!(r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    failing_call_task_{}(data, size);
    return 0;
}}
```"#, task_id);

            let attempt2 = format!(r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    // Task {} success
    return 0;
}}
```"#, task_id);

            let mock_llm = Arc::new(MockLlmClient::new(vec![attempt1, attempt2]));
            let target = format!("target_{}", task_id);

            let synth = HarnessSynthesizer::from_provider(mock_llm)
                .with_db(db_clone)
                .with_target_name(&target)
                .with_max_retries(3);

            let func = sample_signature(&format!("func_{}", task_id), "int", vec![], "t.c");
            let bin = synth.synthesize_and_validate(&func, &[], &[], output_dir).await.expect("Each concurrent synthesis task must succeed");
            assert!(bin.exists());
            bin
        });
        handles.push(handle);
    }

    for h in handles {
        let _bin = h.await.expect("Task panicked");
    }

    // Verify all 8 resolved fixes and 8 exemplars are committed
    let all_exemplars = db.query_harness_exemplars(None, 20).unwrap();
    assert_eq!(all_exemplars.len(), 8);

    let all_fixes = db.query_similar_compiler_fixes("failing_call_task", None, 20).unwrap();
    assert_eq!(all_fixes.len(), 8);
}

// ---------------------------------------------------------------------------
// 7. Adversarial Code Block Extraction
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_code_block_extraction() {
    let dummy_llm = crashwise_agent::LlmClient::new("http://localhost".to_string(), None, "t".to_string());
    let synth = HarnessSynthesizer::new(dummy_llm);

    // Case 1: Multiple code blocks in explanation - should extract the first fenced block
    let multi_block = "Here is an example structure:\n```cpp\nstruct Point { int x; int y; };\n```\nAnd here is the harness:\n```cpp\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    return 0;\n}\n```\nDone!";
    let extracted = synth.extract_code_block(multi_block).unwrap();
    assert!(extracted.contains("struct Point"));

    // Case 2: Unfenced code containing LLVMFuzzerTestOneInput
    let unfenced = "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    return 0;\n}";
    let extracted_unfenced = synth.extract_code_block(unfenced).unwrap();
    assert_eq!(extracted_unfenced, unfenced);

    // Case 3: Code block with uppercase or no language tag
    let no_tag = "```\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    return 0;\n}\n```";
    let extracted_no_tag = synth.extract_code_block(no_tag).unwrap();
    assert!(extracted_no_tag.contains("LLVMFuzzerTestOneInput"));

    // Case 4: No code and no symbol
    let invalid = "I cannot generate this harness because I lack context.";
    assert!(synth.extract_code_block(invalid).is_err());
}

// ---------------------------------------------------------------------------
// 8. Header and Target Inference Robustness
// ---------------------------------------------------------------------------

#[test]
fn test_header_and_target_inference_edge_cases() {
    // Empty path
    assert_eq!(ExemplarRetriever::infer_target_header(Path::new("")), None);
    assert_eq!(HarnessSynthesizer::infer_target_name(Path::new("")), None);

    // Root path
    assert_eq!(ExemplarRetriever::infer_target_header(Path::new("/")), None);

    // Deeply nested paths
    let deep_cjson = Path::new("/var/tmp/build/deps/cJSON/src/sub/cJSON.c");
    assert_eq!(ExemplarRetriever::infer_target_header(deep_cjson), Some("cJSON.h".to_string()));
    assert_eq!(HarnessSynthesizer::infer_target_name(deep_cjson), Some("cJSON".to_string()));

    let deep_zlib = Path::new("/workspace/vendor/zlib/deflate.c");
    assert_eq!(ExemplarRetriever::infer_target_header(deep_zlib), Some("deflate.h".to_string()));
    assert_eq!(HarnessSynthesizer::infer_target_name(deep_zlib), Some("zlib".to_string()));

    let deep_png = Path::new("/workspace/libpng/pngread.c");
    assert_eq!(HarnessSynthesizer::infer_target_name(deep_png), Some("libpng".to_string()));

    let deep_sqlite = Path::new("/workspace/sqlite/sqlite3.c");
    assert_eq!(HarnessSynthesizer::infer_target_name(deep_sqlite), Some("sqlite3".to_string()));

    // Deterministic harness with complex signature: double pointers, consts, structs
    let complex_func = sample_signature(
        "custom_matrix_init",
        "int",
        vec![
            ParameterInfo {
                name: "matrix".to_string(),
                type_name: "double".to_string(),
                is_pointer: true,
                is_const: false,
            },
            ParameterInfo {
                name: "rows".to_string(),
                type_name: "size_t".to_string(),
                is_pointer: false,
                is_const: false,
            },
            ParameterInfo {
                name: "name".to_string(),
                type_name: "char".to_string(),
                is_pointer: true,
                is_const: true,
            },
        ],
        "matrix.c",
    );

    let harness = HarnessSynthesizer::synthesize_deterministic_harness(
        &complex_func,
        Some("matrix_lib"),
        Some("matrix.h"),
    );

    assert!(harness.contains("#include <matrix.h>"));
    assert!(harness.contains("double *arg_0 = (double *)malloc(sizeof(double));"));
    assert!(harness.contains("size_t arg_1 = (size_t)size;"));
    assert!(harness.contains("char *arg_2 = (char *)malloc(size + 1);"));
    assert!(harness.contains("free(arg_2);"));
    assert!(harness.contains("custom_matrix_init(arg_0, arg_1, arg_2);"));
}

// ---------------------------------------------------------------------------
// 9. SQLite Persistence: On-Disk Database Survival & Re-open Verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sqlite_file_persistence_and_reopen_verification() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let db_path = temp_dir.path().join("feedback_persistent.db");
    let output_dir = temp_dir.path().join("harness_out");
    std::fs::create_dir_all(&output_dir).unwrap();

    let campaign_id = Uuid::new_v4();

    // 1. First session: open on-disk DB, insert campaign, run repair loop
    {
        let db = Database::open(&db_path).expect("Failed to open on-disk DB");
        let target = crashwise_core::models::CampaignTarget {
            repo_url: "local".to_string(),
            name: "persistent_target".to_string(),
            subdir: None,
            clone_depth: 1,
            commit_hash: None,
        };
        let mut campaign = crashwise_core::models::Campaign::new(
            target,
            crashwise_core::models::FuzzerEngine::Libfuzzer,
            60,
            1,
        );
        campaign.id = campaign_id;
        db.insert_campaign(&campaign).unwrap();

        let failing_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    bad_syntax_line_with_undeclared_call();
    return 0;
}
```"#;

        let working_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return 0;
}
```"#;

        let mock_llm = Arc::new(MockLlmClient::new(vec![
            failing_code.to_string(),
            working_code.to_string(),
        ]));

        let synth = HarnessSynthesizer::from_provider(mock_llm)
            .with_db(db)
            .with_target_name("persistent_target")
            .with_campaign_id(campaign_id)
            .with_max_retries(2);

        let func = sample_signature("test_persistent", "void", vec![], "test.c");
        let bin = synth.synthesize_and_validate(&func, &[], &[], &output_dir).await;
        assert!(bin.is_ok());
    } // Database closed and dropped here

    // 2. Second session: re-open from disk and verify full state preservation
    {
        let db_reopened = Database::open(&db_path).expect("Failed to re-open on-disk DB");

        // Verify resolved fix persisted with accurate diffs
        let fixes = db_reopened
            .query_similar_compiler_fixes("bad_syntax_line_with_undeclared_call", Some("persistent_target"), 5)
            .unwrap();

        assert_eq!(fixes.len(), 1);
        let fix = &fixes[0];
        assert_eq!(fix.target_name, "persistent_target");
        assert_eq!(fix.feedback_type, "resolved_fix");
        assert_eq!(fix.error_category.as_deref(), Some("undefined_symbol"));
        assert!(fix.compiler_diagnostic.as_ref().unwrap().contains("bad_syntax_line_with_undeclared_call"));
        assert!(fix.original_code.as_ref().unwrap().contains("bad_syntax_line_with_undeclared_call"));
        assert!(fix.resolved_code.as_ref().unwrap().contains("if (size == 0) return 0;"));
        assert_eq!(fix.campaign_id, Some(campaign_id));
        assert_eq!(fix.success_count, 1);
        assert_eq!(fix.failure_count, 0);

        // Verify exemplar persisted
        let exemplars = db_reopened
            .query_harness_exemplars(Some("persistent_target"), 5)
            .unwrap();
        assert_eq!(exemplars.len(), 1);
        assert_eq!(exemplars[0].feedback_type, "harness_exemplar");
        assert!(exemplars[0].resolved_code.as_ref().unwrap().contains("LLVMFuzzerTestOneInput"));
    }
}

// ---------------------------------------------------------------------------
// 10. Opaque Type Compiler Error Self-Correction Loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_opaque_type_compiler_failure_and_llm_repair_loop() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Header with forward-declared opaque struct
    let header_dir = temp_dir.path().join("include");
    std::fs::create_dir_all(&header_dir).unwrap();
    let opaque_h = r#"#ifndef OPAQUE_H
#define OPAQUE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct opaque_engine_t opaque_engine_t;
int opaque_engine_process(opaque_engine_t *engine, const uint8_t *data, size_t size);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(header_dir.join("opaque.h"), opaque_h).unwrap();

    // Attempt 1: LLM tries to malloc sizeof(opaque_engine_t) -> fails compilation because of incomplete type!
    let attempt1_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
extern "C" {
#include <opaque.h>
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    opaque_engine_t *engine = (opaque_engine_t *)malloc(sizeof(opaque_engine_t));
    if (!engine) return 0;
    opaque_engine_process(engine, data, size);
    free(engine);
    return 0;
}
```"#;

    // Attempt 2: LLM receives diagnostic: "invalid application of 'sizeof' to an incomplete type",
    // and correctly repairs the harness to pass NULL or guard without sizeof
    let attempt2_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
extern "C" {
#include <opaque.h>
}
// Stub for link
extern "C" int opaque_engine_process(opaque_engine_t *engine, const uint8_t *data, size_t size) {
    (void)engine; (void)data; (void)size;
    return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    opaque_engine_process(NULL, data, size);
    return 0;
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        attempt1_code.to_string(),
        attempt2_code.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_db(db.clone())
        .with_target_name("opaque_test")
        .with_max_retries(3);

    let func = sample_signature("opaque_engine_process", "int", vec![], "opaque.c");

    let bin = synth
        .synthesize_and_validate(&func, &[header_dir], &[], output_dir)
        .await
        .expect("Synthesis must succeed after compiler repair of incomplete type error");

    assert!(bin.exists());

    // Verify retry prompt contained the clang diagnostic
    let prompts = mock_llm.recorded_prompts();
    assert_eq!(prompts.len(), 2);
    let (_, retry_prompt) = &prompts[1];
    assert!(retry_prompt.contains("Previous harness failed to compile with clang++:"));
    assert!(retry_prompt.contains("incomplete type") || retry_prompt.contains("opaque_engine_t"));

    // Verify SQLite fix record
    let fixes = db.query_similar_compiler_fixes("incomplete type", Some("opaque_test"), 5).unwrap();
    assert_eq!(fixes.len(), 1);
    assert_eq!(fixes[0].target_name, "opaque_test");
    assert_eq!(fixes[0].error_category.as_deref(), Some("compiler_error"));
    assert!(fixes[0].original_code.as_ref().unwrap().contains("sizeof(opaque_engine_t)"));
    assert!(fixes[0].resolved_code.as_ref().unwrap().contains("opaque_engine_process(NULL, data, size)"));
}
