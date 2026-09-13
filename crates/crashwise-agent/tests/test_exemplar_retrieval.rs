use chrono::Utc;
use crashwise_agent::{ExemplarRetriever, HarnessSynthesizer, MockLlmClient};
use crashwise_ast::types::{FunctionSignature, ParameterInfo};
use crashwise_core::db::Database;
use crashwise_core::models::AgentFeedbackRecord;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

#[test]
fn test_target_specific_and_cross_target_exemplar_retrieval() {
    let db = Database::open_in_memory().expect("Failed to create in-memory database");

    // 1. Insert exemplars for zlib
    let zlib_ex = AgentFeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "zlib".to_string(),
        feedback_type: "harness_exemplar".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: Some("extern \"C\" int LLVMFuzzerTestOneInput(...) { z_stream strm; deflateInit(&strm, 1); return 0; }".to_string()),
        coverage_tokens: None,
        success_count: 10,
        failure_count: 0,
        score: 0.98,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.insert_feedback_record(&zlib_ex).unwrap();

    // 2. Insert exemplars for cJSON
    let cjson_ex = AgentFeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "cJSON".to_string(),
        feedback_type: "harness_exemplar".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: Some("extern \"C\" int LLVMFuzzerTestOneInput(...) { cJSON *j = cJSON_Parse((const char*)data); return 0; }".to_string()),
        coverage_tokens: None,
        success_count: 8,
        failure_count: 0,
        score: 0.95,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.insert_feedback_record(&cjson_ex).unwrap();

    // Query with limit 1: returns exactly the target match
    let zlib_hits_1 = ExemplarRetriever::retrieve_exemplars(&db, Some("zlib"), 1).unwrap();
    assert_eq!(zlib_hits_1.len(), 1);
    assert_eq!(zlib_hits_1[0].target_name, "zlib");
    assert!(zlib_hits_1[0].resolved_code.as_ref().unwrap().contains("deflateInit"));

    let cjson_hits_1 = ExemplarRetriever::retrieve_exemplars(&db, Some("cJSON"), 1).unwrap();
    assert_eq!(cjson_hits_1.len(), 1);
    assert_eq!(cjson_hits_1[0].target_name, "cJSON");
    assert!(cjson_hits_1[0].resolved_code.as_ref().unwrap().contains("cJSON_Parse"));

    // Query with limit 5: prioritizes target match, then falls back to fill remaining from other targets
    let zlib_hits = ExemplarRetriever::retrieve_exemplars(&db, Some("zlib"), 5).unwrap();
    assert_eq!(zlib_hits.len(), 2);
    assert_eq!(zlib_hits[0].target_name, "zlib");

    let cjson_hits = ExemplarRetriever::retrieve_exemplars(&db, Some("cJSON"), 5).unwrap();
    assert_eq!(cjson_hits.len(), 2);
    assert_eq!(cjson_hits[0].target_name, "cJSON");

    // Query for unknown target should fallback to general pool
    let fallback_hits = ExemplarRetriever::retrieve_exemplars(&db, Some("libpng"), 5).unwrap();
    assert_eq!(fallback_hits.len(), 2);
}

#[test]
fn test_coverage_tokens_retrieval_and_limits() {
    let db = Database::open_in_memory().expect("Failed to create in-memory database");

    let tokens = vec![
        "deflate".to_string(),
        "inflate".to_string(),
        "deflateInit".to_string(),
        "deflateEnd".to_string(),
        "crc32".to_string(),
    ];
    db.record_coverage_tokens(None, "zlib", &tokens).unwrap();

    let retrieved = ExemplarRetriever::retrieve_coverage_tokens(&db, Some("zlib"), 3).unwrap();
    assert_eq!(retrieved.len(), 3);
    assert_eq!(retrieved[0], "deflate");
    assert_eq!(retrieved[1], "inflate");
    assert_eq!(retrieved[2], "deflateInit");

    let formatted = ExemplarRetriever::format_coverage_tokens_section(&retrieved);
    assert!(formatted.contains("### HIGH-VALUE COVERAGE TOKENS:"));
    assert!(formatted.contains("\"deflate\""));
}

#[test]
fn test_prompt_injection_with_exemplars_and_tokens() {
    let db = Database::open_in_memory().expect("Failed to create in-memory database");

    // Add exemplar
    let ex = AgentFeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "cJSON".to_string(),
        feedback_type: "harness_exemplar".to_string(),
        compiler_diagnostic: None,
        error_category: None,
        original_code: None,
        resolved_code: Some("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { cJSON *json = cJSON_Parse((const char*)data); if(json) cJSON_Delete(json); return 0; }".to_string()),
        coverage_tokens: None,
        success_count: 5,
        failure_count: 0,
        score: 1.0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.insert_feedback_record(&ex).unwrap();

    // Add coverage tokens
    db.record_coverage_tokens(
        None,
        "cJSON",
        &["cJSON_ParseWithLength".to_string(), "cJSON_Print".to_string()],
    )
    .unwrap();

    let mock_llm = Arc::new(MockLlmClient::new(vec![]));
    let synth = HarnessSynthesizer::from_provider(mock_llm)
        .with_db(db)
        .with_target_name("cJSON");

    let func = FunctionSignature {
        name: "cJSON_Print".to_string(),
        return_type: "char *".to_string(),
        parameters: vec![ParameterInfo {
            name: "item".to_string(),
            type_name: "cJSON".to_string(),
            is_pointer: true,
            is_const: true,
        }],
        file_path: PathBuf::from("cJSON.c"),
        line_number: 42,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let (sys_prompt, user_prompt) = synth.build_synthesis_prompts(&func, Some("cJSON")).unwrap();

    // Verify system prompt contains LibFuzzer rules
    assert!(sys_prompt.contains("LLVMFuzzerTestOneInput"));
    assert!(sys_prompt.contains("extern \"C\""));

    // Verify user prompt contains signature, feedback context, exemplars, and tokens
    assert!(user_prompt.contains("Function Name: cJSON_Print"));
    assert!(user_prompt.contains("char * cJSON_Print(const cJSON* item)"));
    assert!(user_prompt.contains("[Context from Feedback Memory]:"));
    assert!(user_prompt.contains("### VERIFIED HARNESS EXEMPLARS FOR THIS TARGET:"));
    assert!(user_prompt.contains("cJSON_Parse((const char*)data)"));
    assert!(user_prompt.contains("### HIGH-VALUE COVERAGE TOKENS:"));
    assert!(user_prompt.contains("cJSON_ParseWithLength"));
}
