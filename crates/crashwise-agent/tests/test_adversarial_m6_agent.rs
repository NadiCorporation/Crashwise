use chrono::Utc;
use crashwise_agent::sanity_gate::SanityGate;
use crashwise_agent::{ExemplarRetriever, HarnessSynthesizer, MockLlmClient};
use crashwise_ast::types::FunctionSignature;
use crashwise_core::db::Database;
use crashwise_core::error::CrashwiseError;
use crashwise_core::models::AgentFeedbackRecord;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn test_m6_exemplar_retrieval_priority_and_deduplication() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Insert 3 exemplars for sqlite3 and 2 for zlib
    for i in 1..=3 {
        let rec = AgentFeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: "sqlite3".to_string(),
            feedback_type: "harness_exemplar".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: Some(format!("// sqlite3 exemplar #{}", i)),
            coverage_tokens: None,
            success_count: i,
            failure_count: 0,
            score: i as f32,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_feedback_record(&rec).unwrap();
    }

    for i in 1..=2 {
        let rec = AgentFeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: "zlib".to_string(),
            feedback_type: "harness_exemplar".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: Some(format!("// zlib exemplar #{}", i)),
            coverage_tokens: None,
            success_count: i,
            failure_count: 0,
            score: i as f32,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_feedback_record(&rec).unwrap();
    }

    // Query with target_name = "sqlite3" and limit = 4 (should return 3 sqlite3 exemplars + 1 zlib fallback)
    let retrieved = ExemplarRetriever::retrieve_exemplars(&db, Some("sqlite3"), 4).unwrap();
    assert_eq!(retrieved.len(), 4);
    assert_eq!(retrieved[0].target_name, "sqlite3");
    assert_eq!(retrieved[1].target_name, "sqlite3");
    assert_eq!(retrieved[2].target_name, "sqlite3");
    assert_eq!(retrieved[3].target_name, "zlib", "Fallback should supply remaining exemplars");

    // Insert duplicate coverage tokens
    db.record_coverage_tokens(None, "sqlite3", &["SQLITE_OK".to_string(), "sqlite3_open".to_string(), "dup_token".to_string()]).unwrap();
    db.record_coverage_tokens(None, "sqlite3", &["dup_token".to_string(), "sqlite3_exec".to_string()]).unwrap();
    db.record_coverage_tokens(None, "*", &["GLOBAL_TOKEN".to_string(), "SQLITE_OK".to_string()]).unwrap();

    let tokens = ExemplarRetriever::retrieve_coverage_tokens(&db, Some("sqlite3"), 10).unwrap();
    assert!(tokens.contains(&"SQLITE_OK".to_string()));
    assert!(tokens.contains(&"sqlite3_open".to_string()));
    assert!(tokens.contains(&"dup_token".to_string()));
    assert!(tokens.contains(&"sqlite3_exec".to_string()));
    assert!(tokens.contains(&"GLOBAL_TOKEN".to_string()));

    // Assert deduplication
    let dup_count = tokens.iter().filter(|t| *t == "dup_token").count();
    assert_eq!(dup_count, 1, "Tokens must be deduplicated");
    let sqlite_ok_count = tokens.iter().filter(|t| *t == "SQLITE_OK").count();
    assert_eq!(sqlite_ok_count, 1, "Global and target token overlaps must be deduplicated");
}

#[tokio::test]
async fn test_m6_sanity_gate_crash_interception() {
    let temp = tempdir().expect("tempdir");
    let crash_src = temp.path().join("crash_harness.c");
    let crash_bin = temp.path().join("crash_harness_bin");

    // Libfuzzer-like binary that causes AddressSanitizer crash
    let c_code = r#"
        #include <stdlib.h>
        #include <string.h>

        int main(int argc, char **argv) {
            char *buf = (char*)malloc(8);
            // Write out of bounds to trigger AddressSanitizer
            buf[16] = 'X';
            free(buf);
            return 0;
        }
    "#;
    fs::write(&crash_src, c_code).unwrap();

    let compile_status = Command::new("clang")
        .args(["-fsanitize=address", "-O0", "-g"])
        .arg(&crash_src)
        .arg("-o")
        .arg(&crash_bin)
        .status()
        .expect("clang compile failed");
    assert!(compile_status.success(), "Compilation of crash harness should succeed");

    let result = SanityGate::verify_harness_binary(&crash_bin).await;
    match result {
        Err(CrashwiseError::HarnessError(msg)) => {
            assert!(
                msg.contains("AddressSanitizer") || msg.contains("crashed"),
                "SanityGate must intercept AddressSanitizer crash, got: {msg}"
            );
        }
        other => panic!("Expected HarnessError from crashing binary, got {:?}", other),
    }
}

#[tokio::test]
async fn test_m6_sanity_gate_infinite_loop_timeout_interception() {
    let temp = tempdir().expect("tempdir");
    let loop_src = temp.path().join("loop_harness.c");
    let loop_bin = temp.path().join("loop_harness_bin");

    let c_code = r#"
        #include <unistd.h>

        int main(int argc, char **argv) {
            // Sleep longer than 6 second timeout
            sleep(15);
            return 0;
        }
    "#;
    fs::write(&loop_src, c_code).unwrap();

    let compile_status = Command::new("clang")
        .arg(&loop_src)
        .arg("-o")
        .arg(&loop_bin)
        .status()
        .expect("clang compile failed");
    assert!(compile_status.success());

    let result = SanityGate::verify_harness_binary(&loop_bin).await;
    match result {
        Err(CrashwiseError::HarnessError(msg)) => {
            assert!(
                msg.contains("Sanity gate timeout") || msg.contains("infinite loop"),
                "SanityGate must catch timeout on hung harness, got: {msg}"
            );
        }
        other => panic!("Expected timeout error from sleeping binary, got {:?}", other),
    }
}

#[tokio::test]
async fn test_m6_synthesizer_retry_exhaustion_and_zero_false_exemplars() {
    let temp = tempdir().expect("tempdir");
    let output_dir = temp.path();

    let db = Database::open_in_memory().expect("Failed to open DB");

    // Mock LLM that returns invalid code on every attempt
    let invalid_code_1 = r#"```cpp
        #include <stdint.h>
        extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
            SYNTAX_ERROR_UNDECLARED_1;
            return 0;
        }
    ```"#;

    let invalid_code_2 = r#"```cpp
        #include <stdint.h>
        extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
            SYNTAX_ERROR_UNDECLARED_2;
            return 0;
        }
    ```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        invalid_code_1.to_string(),
        invalid_code_2.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm)
        .with_db(db.clone())
        .with_target_name("sqlite3")
        .with_max_retries(2);

    let func = FunctionSignature {
        name: "test_unreachable".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("sqlite3.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let res = synth.synthesize_and_validate(&func, &[], &[], output_dir).await;
    match res {
        Err(CrashwiseError::HarnessError(msg)) => {
            assert!(msg.contains("Failed to synthesize valid harness"), "Expected exhaustion message, got: {msg}");
            assert!(msg.contains("after 2 attempts"));
        }
        other => panic!("Expected HarnessError on retry exhaustion, got {:?}", other),
    }

    // Critical assertion: NO harness_exemplar should be recorded in SQLite for a failed harness!
    let exemplars = db.query_harness_exemplars(Some("sqlite3"), 10).unwrap();
    assert!(exemplars.is_empty(), "Database must NOT store exemplars for failed harnesses!");
}
