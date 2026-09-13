use crashwise_agent::{HarnessSynthesizer, MockLlmClient};
use crashwise_ast::types::FunctionSignature;
use crashwise_core::db::Database;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_synthesis_flow_without_database_fallback() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();

    // Valid code that compiles and runs cleanly
    let working_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return 0;
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![working_code.to_string()]));
    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_target_name("no_db_target");

    assert!(synth.db().is_none());

    let func = FunctionSignature {
        name: "test_no_db".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("targets/test/func.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let bin = synth
        .synthesize_and_validate(&func, &[], &[], output_dir)
        .await
        .expect("Synthesis without DB should work cleanly");

    assert!(bin.exists());
    assert_eq!(mock_llm.recorded_prompts().len(), 1);
}

#[tokio::test]
async fn test_sanity_gate_failure_recovery_loop() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();

    let db = Database::open_in_memory().expect("Failed to create in-memory database");

    // Attempt 1: compiles cleanly, but triggers AddressSanitizer crash in SanityGate
    let crashing_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        volatile int *crash_ptr = (volatile int *)0x0;
        *crash_ptr = 42;
    }
    return 0;
}
```"#;

    // Attempt 2: corrected code that does not crash
    let safe_code = r#"```cpp
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    return 0;
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        crashing_code.to_string(),
        safe_code.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_db(db.clone())
        .with_target_name("crash_target")
        .with_max_retries(2);

    let func = FunctionSignature {
        name: "test_crash_recovery".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("test.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let bin = synth
        .synthesize_and_validate(&func, &[], &[], output_dir)
        .await
        .expect("Synthesis should recover from sanity crash on attempt 2");

    assert!(bin.exists());

    let prompts = mock_llm.recorded_prompts();
    assert_eq!(prompts.len(), 2);
    let (_, retry_user_prompt) = &prompts[1];
    assert!(retry_user_prompt.contains("Previous harness failed runtime sanity verification:"));

    // Exemplar of the safe harness should be recorded
    let exemplars = db
        .query_harness_exemplars(Some("crash_target"), 5)
        .expect("Query exemplars should succeed");
    assert_eq!(exemplars.len(), 1);
    assert_eq!(exemplars[0].target_name, "crash_target");
}

#[tokio::test]
async fn test_max_retries_exhaustion_returns_error() {
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let output_dir = temp_dir.path();

    // Broken code that fails compilation on all attempts
    let broken_code = r#"```cpp
extern "C" int LLVMFuzzerTestOneInput() {
    syntax_error_undefined_symbol_always();
}
```"#;

    let mock_llm = Arc::new(MockLlmClient::new(vec![
        broken_code.to_string(),
        broken_code.to_string(),
        broken_code.to_string(),
    ]));

    let synth = HarnessSynthesizer::from_provider(mock_llm.clone())
        .with_max_retries(3);

    let func = FunctionSignature {
        name: "test_exhaustion".to_string(),
        return_type: "void".to_string(),
        parameters: vec![],
        file_path: PathBuf::from("test.c"),
        line_number: 1,
        is_static: false,
        is_exported: true,
        has_body: true,
    };

    let result = synth
        .synthesize_and_validate(&func, &[], &[], output_dir)
        .await;

    assert!(result.is_err());
    let err_msg = result.err().unwrap().to_string();
    assert!(err_msg.contains("Failed to synthesize valid harness for test_exhaustion after 3 attempts"));
    assert_eq!(mock_llm.recorded_prompts().len(), 3);
}
