use crashwise_agent::{HarnessSynthesizer, MockLlmClient};
use crashwise_ast::types::FunctionSignature;
use crashwise_core::db::Database;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use uuid::Uuid;

#[tokio::test]
async fn test_compiler_self_correction_and_feedback_persistence_end_to_end() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();

    let db = Database::open_in_memory().expect("Failed to create in-memory database");
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

    // Failing code in attempt 1: undefined symbol / syntax error
    let attempt1_failing_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    undeclared_function_call_should_fail_clang(data, size);
    return 0;
}
```"#;

    // Corrected working code in attempt 2: valid libFuzzer harness
    let attempt2_working_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    if (data[0] == 0x42) return 0;
    return 0;
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        attempt1_failing_code.to_string(),
        attempt2_working_code.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_db(db.clone())
        .with_target_name("cJSON")
        .with_campaign_id(campaign_id)
        .with_max_retries(3);

    let func = FunctionSignature {
        name: "test_parse".to_string(),
        return_type: "int".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("targets/cJSON/test.c"),
        line_number: 10,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    // Execute synthesis and validation
    let harness_bin = synth
        .synthesize_and_validate(&func, &[], &[], output_dir)
        .await
        .expect("Synthesis should succeed after self-correction on attempt 2");

    assert!(harness_bin.exists());

    // Verify that LLM was called twice
    let prompts = mock_llm.recorded_prompts();
    assert_eq!(prompts.len(), 2);

    // Verify that the second prompt contained compiler diagnostic feedback
    let (_, retry_user_prompt) = &prompts[1];
    assert!(retry_user_prompt.contains("Previous harness failed to compile with clang++:"));
    assert!(retry_user_prompt.contains("undeclared_function_call_should_fail_clang"));

    // Verify that the resolved fix was recorded in SQLite agent_feedback_memory
    let similar_fixes = db
        .query_similar_compiler_fixes("undeclared_function_call_should_fail_clang", Some("cJSON"), 5)
        .expect("Query similar fixes should succeed");

    assert_eq!(similar_fixes.len(), 1);
    let fix = &similar_fixes[0];
    assert_eq!(fix.target_name, "cJSON");
    assert_eq!(fix.feedback_type, "resolved_fix");
    assert!(fix.compiler_diagnostic.as_ref().unwrap().contains("undeclared_function_call"));
    assert!(fix.original_code.as_ref().unwrap().contains("undeclared_function_call_should_fail_clang"));
    assert!(fix.resolved_code.as_ref().unwrap().contains("if (data[0] == 0x42) return 0;"));

    // Verify that the verified harness was recorded as a harness_exemplar in SQLite
    let exemplars = db
        .query_harness_exemplars(Some("cJSON"), 5)
        .expect("Query harness exemplars should succeed");

    assert_eq!(exemplars.len(), 1);
    let ex = &exemplars[0];
    assert_eq!(ex.target_name, "cJSON");
    assert_eq!(ex.feedback_type, "harness_exemplar");
    assert!(ex.resolved_code.as_ref().unwrap().contains("LLVMFuzzerTestOneInput"));
}

#[tokio::test]
async fn test_historical_fix_injection_into_compiler_retry_prompt() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();

    let db = Database::open_in_memory().expect("Failed to create in-memory database");

    // Pre-populate database with a historical fix for unknown type
    db.record_resolved_fix(
        None,
        "zlib",
        "error: unknown type name 'z_stream'",
        "void test() { z_stream strm; }",
        "#include <zlib.h>\nvoid test() { z_stream strm; }",
    )
    .unwrap();

    // First attempt fails with unknown type name 'z_stream'
    let failing_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unknown_type_z_stream_unresolved var;
    return 0;
}
```"#;

    let working_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        failing_code.to_string(),
        working_code.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_db(db)
        .with_target_name("zlib")
        .with_max_retries(2);

    let func = FunctionSignature {
        name: "test_zlib".to_string(),
        return_type: "int".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("targets/zlib/compress.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let bin = synth
        .synthesize_and_validate(&func, &[], &[], output_dir)
        .await
        .expect("Synthesis should succeed on attempt 2");

    assert!(bin.exists());

    let prompts = mock_llm.recorded_prompts();
    assert_eq!(prompts.len(), 2);
    let (_, retry_user_prompt) = &prompts[1];

    // Retry prompt must contain diagnostic and historical resolution section
    assert!(retry_user_prompt.contains("Previous harness failed to compile with clang++:"));
    assert!(retry_user_prompt.contains("### HISTORICAL RESOLUTIONS FOR SIMILAR COMPILER ERRORS:"));
    assert!(retry_user_prompt.contains("#include <zlib.h>"));
}
